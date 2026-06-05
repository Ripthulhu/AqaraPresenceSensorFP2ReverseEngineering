#!/usr/bin/env python3
"""Dump DEX images from a rooted Android process via adb.

This is intentionally small and dependency-free. It reads /proc/<pid>/maps,
copies likely readable memory ranges through toybox dd, scans for DEX magic,
validates the header size/file size, and writes deduplicated .dex files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


MAP_RE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\S+\s*(.*)$"
)


@dataclass
class DumpedDex:
    path: str
    sha256: str
    size: int
    map_start: str
    dex_vaddr: str
    map_name: str


def adb(args: list[str], *, binary: bool = False, timeout: int = 60) -> bytes | str:
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"{' '.join(args)} failed: {err}")
    if binary:
        return proc.stdout
    return proc.stdout.decode("utf-8", "replace")


def adb_base(adb_path: str, serial: str | None) -> list[str]:
    cmd = [adb_path]
    if serial:
        cmd += ["-s", serial]
    return cmd


def get_pid(adb_path: str, serial: str | None, package: str) -> int:
    out = adb(adb_base(adb_path, serial) + ["shell", "pidof", package])
    pids = [int(x) for x in out.split() if x.isdigit()]
    if not pids:
        raise RuntimeError(f"no pid found for {package}")
    return pids[0]


def parse_maps(text: str) -> list[dict[str, object]]:
    maps: list[dict[str, object]] = []
    for line in text.splitlines():
        match = MAP_RE.match(line)
        if not match:
            continue
        start_s, end_s, perms, offset_s, name = match.groups()
        start = int(start_s, 16)
        end = int(end_s, 16)
        maps.append(
            {
                "start": start,
                "end": end,
                "perms": perms,
                "offset": int(offset_s, 16),
                "name": name.strip(),
                "line": line,
            }
        )
    return maps


def likely_region(
    region: dict[str, object],
    package: str,
    max_region: int,
    include_empty: bool,
    map_regex: re.Pattern[str] | None,
) -> bool:
    perms = str(region["perms"])
    if not perms.startswith("r"):
        return False
    size = int(region["end"]) - int(region["start"])
    if size <= 0 or size > max_region:
        return False
    name = str(region["name"])
    if not name:
        return include_empty
    if map_regex is not None:
        return bool(map_regex.search(name))
    if package in name:
        return True
    if name.startswith("[anon:") and "dalvik" in name:
        return True
    if name.startswith("[anon:") and "scudo" in name:
        return True
    if "memfd" in name.lower() and ("dex" in name.lower() or "jit" in name.lower()):
        return True
    if "libdexjni.so" in name or "libDexHelper.so" in name:
        return True
    return False


def read_mem(adb_path: str, serial: str | None, pid: int, start: int, size: int) -> bytes:
    shell_cmd = (
        f"dd if=/proc/{pid}/mem bs=1 skip={start} count={size} "
        "iflag=skip_bytes,count_bytes status=none"
    )
    return adb(adb_base(adb_path, serial) + ["exec-out", shell_cmd], binary=True, timeout=120)


def dex_candidates(buf: bytes) -> list[tuple[int, int]]:
    hits: list[tuple[int, int]] = []
    pos = 0
    while True:
        idx = buf.find(b"dex\n", pos)
        if idx == -1:
            return hits
        pos = idx + 4
        if idx + 0x70 > len(buf):
            continue
        if buf[idx + 4 : idx + 7] not in (b"035", b"037", b"038", b"039"):
            continue
        file_size = struct.unpack_from("<I", buf, idx + 0x20)[0]
        header_size = struct.unpack_from("<I", buf, idx + 0x24)[0]
        if header_size not in (0x70, 0x78):
            continue
        if file_size < header_size or file_size > 128 * 1024 * 1024:
            continue
        if idx + file_size > len(buf):
            continue
        hits.append((idx, file_size))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial")
    parser.add_argument("--package", required=True)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-region-mb", type=int, default=64)
    parser.add_argument(
        "--include-empty",
        action="store_true",
        help="also scan unnamed readable mappings; slow, but useful as a last pass",
    )
    parser.add_argument(
        "--map-regex",
        help="only scan mappings whose name matches this Python regex",
    )
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    pid = args.pid or get_pid(args.adb, args.serial, args.package)
    maps_text = adb(adb_base(args.adb, args.serial) + ["shell", "cat", f"/proc/{pid}/maps"])
    (args.out / f"pid_{pid}_maps.txt").write_text(maps_text, encoding="utf-8")
    maps = parse_maps(maps_text)
    max_region = args.max_region_mb * 1024 * 1024
    map_regex = re.compile(args.map_regex) if args.map_regex else None
    regions = [
        r for r in maps if likely_region(r, args.package, max_region, args.include_empty, map_regex)
    ]

    dumped: list[DumpedDex] = []
    seen: set[str] = set()
    errors: list[str] = []
    scanned = 0
    for region in regions:
        start = int(region["start"])
        end = int(region["end"])
        size = end - start
        name = str(region["name"])
        scanned += 1
        print(f"[{scanned}/{len(regions)}] {start:x}-{end:x} {size} {name}", flush=True)
        try:
            data = read_mem(args.adb, args.serial, pid, start, size)
        except Exception as exc:
            errors.append(f"{start:x}-{end:x} {name}: {exc}")
            continue
        if not data:
            continue
        for idx, file_size in dex_candidates(data):
            dex = data[idx : idx + file_size]
            digest = hashlib.sha256(dex).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            out_path = args.out / f"dex_{len(dumped):03d}_{start + idx:x}_{file_size}_{digest[:12]}.dex"
            out_path.write_bytes(dex)
            dumped.append(
                DumpedDex(
                    path=str(out_path),
                    sha256=digest,
                    size=file_size,
                    map_start=f"0x{start:x}",
                    dex_vaddr=f"0x{start + idx:x}",
                    map_name=name,
                )
            )
            print(f"  dumped {out_path.name}", flush=True)

    report = {
        "package": args.package,
        "pid": pid,
        "regions_considered": len(regions),
        "dex_files": [asdict(d) for d in dumped],
        "errors": errors[:100],
    }
    (args.out / "dexdump_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
