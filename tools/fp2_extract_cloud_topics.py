#!/usr/bin/env python3
"""Extract readable Aqara/Lumi topic strings from tshark TCP payload TSV.

Generate input with a command like:

    tshark -r capture.pcap -Y 'ip.addr==10.88.0.162 && tcp.len>0' \
      -T fields -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport \
      -e ip.dst -e tcp.dstport -e tcp.len -e data > fp2_tcp_payloads.tsv

The FP2 cloud channel on TCP/11111 is mostly binary, but the outer protocol
keeps readable topic strings such as ``lumi/res/report/attr``. This helper
summarizes those strings and checks a simple outer length-field hypothesis.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


TOPIC_RE = re.compile(rb"lumi/[A-Za-z0-9_./-]+")
SEGMENT_RE = re.compile(rb"^[A-Za-z0-9_-]+$")


def parse_payload_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 8 or not parts[7]:
            continue
        frame, timestamp, src, src_port, dst, dst_port, tcp_len_text, hex_data = parts[:8]
        try:
            data = bytes.fromhex(hex_data)
            tcp_len = int(tcp_len_text)
        except ValueError:
            continue
        rows.append(
            {
                "frame": frame,
                "timestamp": timestamp,
                "src": src,
                "src_port": src_port,
                "dst": dst,
                "dst_port": dst_port,
                "tcp_len": tcp_len,
                "data": data,
            }
        )
    return rows


def slash_topics(data: bytes) -> list[str]:
    topics = []
    for match in TOPIC_RE.findall(data):
        topic = match.decode("ascii", "replace")
        # The next binary field often begins with bytes that render as "Ms";
        # trim that marker if the regex consumed it as printable text.
        topic = topic.split("Ms", 1)[0]
        topics.append(topic)
    return topics


def segmented_topics(data: bytes) -> list[str]:
    topics = []
    start = 0
    while True:
        idx = data.find(b"lumi", start)
        if idx < 0:
            break
        start = idx + 4
        pos = start
        parts = ["lumi"]
        while pos < len(data):
            size = data[pos]
            if size == 0 or size > 32 or pos + 1 + size > len(data):
                break
            segment = data[pos + 1:pos + 1 + size]
            if not SEGMENT_RE.match(segment):
                break
            parts.append(segment.decode("ascii", "replace"))
            pos += 1 + size
        if len(parts) > 1:
            topics.append("/".join(parts))
    return topics


def extract_topics(data: bytes) -> list[str]:
    seen = set()
    topics = []
    for topic in slash_topics(data) + segmented_topics(data):
        if topic not in seen:
            seen.add(topic)
            topics.append(topic)
    return topics


def summarize(rows: list[dict[str, Any]], device_ip: str) -> tuple[str, str]:
    topics: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"total": 0, "fp2_to_cloud": 0, "cloud_to_fp2": 0, "frames": []}
    )
    length_total = 0
    length_ok = 0
    headers: Counter[str] = Counter()

    for row in rows:
        data = row["data"]
        if len(data) >= 2:
            length_total += 1
            if int.from_bytes(data[:2], "big") == row["tcp_len"] - 2:
                length_ok += 1
        if len(data) >= 6:
            headers[data[2:6].hex()] += 1
        direction = "fp2_to_cloud" if row["src"] == device_ip else "cloud_to_fp2"
        for topic in extract_topics(data):
            entry = topics[topic]
            entry["total"] += 1
            entry[direction] += 1
            if len(entry["frames"]) < 8:
                entry["frames"].append(row["frame"])

    topic_lines = ["topic\ttotal\tfp2_to_cloud\tcloud_to_fp2\tframes"]
    for topic, entry in sorted(topics.items(), key=lambda item: (-item[1]["total"], item[0])):
        topic_lines.append(
            "\t".join(
                [
                    topic,
                    str(entry["total"]),
                    str(entry["fp2_to_cloud"]),
                    str(entry["cloud_to_fp2"]),
                    ",".join(entry["frames"]),
                ]
            )
        )

    shape_lines = [
        f"payload_rows_with_data\t{length_total}",
        f"be16_len_equals_tcp_len_minus_2\t{length_ok}",
        "",
        "header_bytes_2_5\tcount",
    ]
    for header, count in headers.most_common(32):
        shape_lines.append(f"{header}\t{count}")

    return "\n".join(topic_lines) + "\n", "\n".join(shape_lines) + "\n"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload_tsv", type=Path)
    parser.add_argument("--device-ip", default="10.88.0.162")
    parser.add_argument("--topics-out", type=Path)
    parser.add_argument("--shape-out", type=Path)
    args = parser.parse_args()

    rows = parse_payload_rows(args.payload_tsv)
    topics_text, shape_text = summarize(rows, args.device_ip)

    if args.topics_out:
        args.topics_out.parent.mkdir(parents=True, exist_ok=True)
        args.topics_out.write_text(topics_text, encoding="utf-8")
    else:
        print(topics_text, end="")

    if args.shape_out:
        args.shape_out.parent.mkdir(parents=True, exist_ok=True)
        args.shape_out.write_text(shape_text, encoding="utf-8")
    else:
        print()
        print(shape_text, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
