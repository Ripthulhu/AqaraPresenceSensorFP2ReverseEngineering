#!/usr/bin/env python3
"""Extract FP2 live-position pushes from Aqara Home logcat output.

The Aqara app logs H5 bridge calls shaped like:

    H5Invoke("handleWSPushPositionData",'{"code":0,...}')

For FP2 live tracking the outer JSON contains resource ``4.22.700`` and a
nested JSON string in ``result.value``. This helper decodes both layers and
summarizes target ids/coordinates without printing full app payloads.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MARKER = "H5Invoke(\"handleWSPushPositionData\",'"
LOG_TS_RE = re.compile(r"^(\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})")


@dataclass
class TargetStats:
    count: int = 0
    x_values: list[int] = field(default_factory=list)
    y_values: list[int] = field(default_factory=list)
    range_ids: Counter[str] = field(default_factory=Counter)
    target_types: Counter[str] = field(default_factory=Counter)

    def add(self, target: dict[str, Any]) -> None:
        self.count += 1
        if isinstance(target.get("x"), int):
            self.x_values.append(target["x"])
        if isinstance(target.get("y"), int):
            self.y_values.append(target["y"])
        self.range_ids[str(target.get("rangeId", ""))] += 1
        self.target_types[str(target.get("targetType", ""))] += 1


@dataclass
class Event:
    line_no: int
    log_time: str
    attr: str
    model: str
    subject_id: str
    push_type: str
    source: str
    timestamp: str
    total_targets: int
    active_targets: list[dict[str, Any]]
    value_preview: str


def clip(text: object, limit: int = 120) -> str:
    value = "" if text is None else str(text)
    value = value.replace("\t", " ").replace("\r", "\\r").replace("\n", "\\n")
    if len(value) > limit:
        return value[:limit] + "...<clipped>"
    return value


def is_active(target: dict[str, Any]) -> bool:
    state = target.get("state")
    return state not in (None, "", 0, "0", False)


def extract_h5_json(line: str) -> str | None:
    start = line.find(MARKER)
    if start < 0:
        return None
    start += len(MARKER)
    end = line.rfind("')")
    if end < start:
        return None
    return line[start:end]


def parse_value(value: Any) -> tuple[list[dict[str, Any]] | None, str]:
    if not isinstance(value, str):
        return None, clip(value)
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return None, clip(value)
    if isinstance(decoded, list):
        targets = [item for item in decoded if isinstance(item, dict)]
        return targets, clip(json.dumps(targets[:2], separators=(",", ":")))
    return None, clip(decoded)


def parse_events(path: Path) -> tuple[list[Event], list[str]]:
    events: list[Event] = []
    errors: list[str] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        payload = extract_h5_json(line)
        if payload is None:
            continue
        log_match = LOG_TS_RE.search(line)
        log_time = log_match.group(1) if log_match else ""
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError as exc:
            # The H5 bridge log sometimes double-escapes quotes in result.value
            # (literal backslash, backslash, quote), which is a JS-log artifact
            # rather than the actual payload shape.
            normalized = payload.replace('\\\\\"', '\\\"')
            try:
                decoded = json.loads(normalized)
            except json.JSONDecodeError:
                errors.append(f"line {line_no}: outer JSON parse failed: {exc}")
                continue
        result = decoded.get("result", {})
        if not isinstance(result, dict):
            errors.append(f"line {line_no}: result is not an object")
            continue
        targets, value_preview = parse_value(result.get("value"))
        active_targets = [target for target in targets or [] if is_active(target)]
        events.append(
            Event(
                line_no=line_no,
                log_time=log_time,
                attr=str(result.get("attr", "")),
                model=str(result.get("model", "")),
                subject_id=str(result.get("subjectId", "")),
                push_type=str(result.get("pushType", "")),
                source=str(result.get("source", "")),
                timestamp=str(result.get("timeStamp", "")),
                total_targets=len(targets or []),
                active_targets=active_targets,
                value_preview=value_preview,
            )
        )
    return events, errors


def active_points_text(targets: list[dict[str, Any]]) -> str:
    parts = []
    for target in targets:
        parts.append(
            "{id}:{x}:{y}:range={range_id}:type={target_type}:state={state}".format(
                id=clip(target.get("id"), 16),
                x=clip(target.get("x"), 16),
                y=clip(target.get("y"), 16),
                range_id=clip(target.get("rangeId"), 16),
                target_type=clip(target.get("targetType"), 16),
                state=clip(target.get("state"), 16),
            )
        )
    return ";".join(parts)


def write_events_tsv(path: Path, events: list[Event]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(
            [
                "line",
                "log_time",
                "attr",
                "model",
                "subject_id",
                "push_type",
                "source",
                "timestamp",
                "total_targets",
                "active_count",
                "active_points",
                "value_preview",
            ]
        )
        for event in events:
            writer.writerow(
                [
                    event.line_no,
                    event.log_time,
                    event.attr,
                    event.model,
                    event.subject_id,
                    event.push_type,
                    event.source,
                    event.timestamp,
                    event.total_targets,
                    len(event.active_targets),
                    active_points_text(event.active_targets),
                    event.value_preview,
                ]
            )


def build_summary(events: list[Event], errors: list[str], max_samples: int) -> str:
    attr_counts = Counter(event.attr for event in events)
    active_count_hist = Counter(len(event.active_targets) for event in events)
    subjects = Counter(event.subject_id for event in events if event.subject_id)
    models = Counter(event.model for event in events if event.model)
    push_types = Counter(event.push_type for event in events if event.push_type)
    target_stats: dict[str, TargetStats] = defaultdict(TargetStats)

    for event in events:
        for target in event.active_targets:
            target_stats[str(target.get("id", ""))].add(target)

    lines = [
        f"decoded_events\t{len(events)}",
        f"parse_errors\t{len(errors)}",
        "",
        "attr\tcount",
    ]
    for attr, count in sorted(attr_counts.items()):
        lines.append(f"{attr}\t{count}")

    lines.extend(["", "active_count\tframes"])
    for active_count, frames in sorted(active_count_hist.items()):
        lines.append(f"{active_count}\t{frames}")

    lines.extend(["", "subject_id\tcount"])
    for subject, count in subjects.most_common():
        lines.append(f"{subject}\t{count}")

    lines.extend(["", "model\tcount"])
    for model, count in models.most_common():
        lines.append(f"{model}\t{count}")

    lines.extend(["", "push_type\tcount"])
    for push_type, count in push_types.most_common():
        lines.append(f"{push_type}\t{count}")

    lines.extend(["", "target_id\tactive_frames\tx_min\tx_max\ty_min\ty_max\trange_ids\ttarget_types"])
    for target_id, stats in sorted(target_stats.items(), key=lambda item: (item[0] == "", item[0])):
        x_min = min(stats.x_values) if stats.x_values else ""
        x_max = max(stats.x_values) if stats.x_values else ""
        y_min = min(stats.y_values) if stats.y_values else ""
        y_max = max(stats.y_values) if stats.y_values else ""
        range_ids = ",".join(f"{key}:{value}" for key, value in sorted(stats.range_ids.items()))
        target_types = ",".join(f"{key}:{value}" for key, value in sorted(stats.target_types.items()))
        lines.append(f"{target_id}\t{stats.count}\t{x_min}\t{x_max}\t{y_min}\t{y_max}\t{range_ids}\t{target_types}")

    lines.extend(["", "samples"])
    sample_events = [event for event in events if event.active_targets][:max_samples]
    for event in sample_events:
        lines.append(
            "\t".join(
                [
                    event.log_time,
                    event.attr,
                    event.timestamp,
                    str(len(event.active_targets)),
                    active_points_text(event.active_targets),
                ]
            )
        )

    if errors:
        lines.extend(["", "errors"])
        lines.extend(errors[:max_samples])

    return "\n".join(lines) + "\n"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logcat", type=Path, help="filtered or full Aqara Home logcat text")
    parser.add_argument("--events-out", type=Path, help="optional decoded event TSV path")
    parser.add_argument("--summary-out", type=Path, help="optional summary TSV-ish text path")
    parser.add_argument("--max-samples", type=int, default=8)
    args = parser.parse_args()

    events, errors = parse_events(args.logcat)
    if args.events_out:
        write_events_tsv(args.events_out, events)
    summary = build_summary(events, errors, args.max_samples)
    if args.summary_out:
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        args.summary_out.write_text(summary, encoding="utf-8")
    else:
        print(summary, end="")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
