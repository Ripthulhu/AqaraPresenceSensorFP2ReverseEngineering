#!/usr/bin/env python3
"""Aqara FP2 radar MSS patch workbench.

This handles the TI RPRC/MSTR radar image inside the stock ESP32 `mcu_ota`
partition. The first practical instrumentation variant redirects the radar
firmware's broad internal logger into the existing `0x0201 debug_log` report
path, which should appear on the ESP32<->radar UART rather than the exposed
ESP32 UART0 console.

The tool intentionally does not flash anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


TI_MSTR_MAGIC = b"MSTR"
TI_MEND_MAGIC = b"MEND"
TI_RPRC_MAGIC = b"RPRC"

DEFAULT_RPRC = Path("dumps/extracted/mcu_ota_carved/appimage_4_mss_core_0x35510000_off_0x1a0080_len_0x33668.rprc")
DEFAULT_MCU_OTA = Path("dumps/extracted/mcu_ota_0x433000_0x400000.bin")
DEFAULT_APPIMAGE_OFFSET = 0x1A0000
DEFAULT_MSS_CORE_ID = 0x35510000
ESP_FLASH_MCU_OTA_OFFSET = 0x433000


@dataclass(frozen=True)
class Section:
    name: str
    file_offset: int
    load_addr: int
    size: int

    def contains_vaddr(self, vaddr: int) -> bool:
        return self.load_addr <= vaddr < self.load_addr + self.size


@dataclass(frozen=True)
class BytePatch:
    name: str
    reason: str
    vaddr: int
    expected: bytes
    replacement: bytes


RADAR_DEBUG_PATCHES = [
    BytePatch(
        "mss_printf_to_debug_log_report",
        (
            "Replace the broad MSS printf-like logger at 0x29360 with a Thumb-2 "
            "branch to the firmware's own varargs 0x0201 debug_log reporter at 0x2b998."
        ),
        0x00029360,
        bytes.fromhex("0f b4 42 f6"),
        bytes.fromhex("02 f0 1a bb"),
    ),
    BytePatch(
        "mss_debug_log_runtime_gate_nop",
        (
            "NOP the wrapper's runtime skip gate at 0x2b9aa so formatted strings are "
            "sent even when the stock debug flag would suppress them."
        ),
        0x0002B9AA,
        bytes.fromhex("a8 b9"),
        bytes.fromhex("00 bf"),
    ),
]


VARIANTS: dict[str, list[BytePatch]] = {
    "printf-to-debug": [RADAR_DEBUG_PATCHES[0]],
    "printf-to-debug-forced": RADAR_DEBUG_PATCHES,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_rprc(data: bytes) -> dict:
    if not data.startswith(TI_RPRC_MAGIC):
        raise ValueError("not a TI RPRC image: missing RPRC magic")
    if len(data) < 0x14:
        raise ValueError("truncated RPRC header")

    _magic, entry, _reserved, section_count, version = struct.unpack_from("<IIIII", data, 0)
    offset = 0x14
    sections: list[Section] = []
    for index in range(section_count):
        if offset + 0x1C > len(data):
            raise ValueError(f"truncated RPRC section header {index}")
        fields = struct.unpack_from("<IIIIIII", data, offset)
        load_addr = fields[1]
        size = fields[3]
        data_offset = offset + 0x1C
        if data_offset + size > len(data):
            raise ValueError(f"truncated RPRC section data {index}")
        sections.append(Section(f"sec{index}", data_offset, load_addr, size))
        offset = data_offset + size

    return {
        "entry": entry,
        "section_count": section_count,
        "version": version,
        "sections": sections,
        "parsed_end": offset,
        "trailing": len(data) - offset,
    }


def parse_mstr_appimage(data: bytes, appimage_offset: int) -> dict:
    if data[appimage_offset : appimage_offset + 4] != TI_MSTR_MAGIC:
        raise ValueError(f"no MSTR appimage at mcu_ota offset 0x{appimage_offset:x}")
    core_count = struct.unpack_from("<I", data, appimage_offset + 4)[0]
    if core_count < 1 or core_count > 8:
        raise ValueError(f"unreasonable MSTR core count {core_count}")
    total_size = struct.unpack_from("<I", data, appimage_offset + 0x14)[0]
    meta_end = appimage_offset + 0x18 + core_count * 0x20
    if data[meta_end : meta_end + 4] != b"\x06\x00\x00\x00" or data[meta_end + 4 : meta_end + 8] != TI_MEND_MAGIC:
        raise ValueError("MSTR metadata terminator is not the expected 0x00000006/MEND pair")
    if total_size <= 0 or appimage_offset + total_size > len(data):
        raise ValueError(f"MSTR total size 0x{total_size:x} is outside mcu_ota image")

    entries = []
    for index in range(core_count):
        base = appimage_offset + 0x18 + index * 0x20
        active, core_id, image_rel, crc0, crc1, image_size, reserved0, reserved1 = struct.unpack_from("<IIIIIIII", data, base)
        image_abs = appimage_offset + image_rel
        payload = data[image_abs : image_abs + image_size]
        entries.append(
            {
                "index": index,
                "active": active,
                "core_id": core_id,
                "image_rel": image_rel,
                "image_abs": image_abs,
                "size": image_size,
                "crc_words": [crc0, crc1],
                "reserved": [reserved0, reserved1],
                "first4": payload[:4].hex(" "),
                "sha256": sha256(payload),
            }
        )
    return {
        "offset": appimage_offset,
        "core_count": core_count,
        "total_size": total_size,
        "header_words": [
            struct.unpack_from("<I", data, appimage_offset + rel)[0] for rel in (0x08, 0x0C, 0x10, 0x14)
        ],
        "sha256": sha256(data[appimage_offset : appimage_offset + total_size]),
        "entries": entries,
    }


def map_vaddr_to_offset(vaddr: int, sections: Iterable[Section]) -> int:
    for section in sections:
        if section.contains_vaddr(vaddr):
            return section.file_offset + (vaddr - section.load_addr)
    raise KeyError(f"vaddr 0x{vaddr:08x} is not covered by an RPRC section")


def describe_patch_points(data: bytes, sections: list[Section]) -> list[dict]:
    rows = []
    for patch in RADAR_DEBUG_PATCHES:
        off = map_vaddr_to_offset(patch.vaddr, sections)
        current = data[off : off + len(patch.expected)]
        rows.append(
            {
                "name": patch.name,
                "reason": patch.reason,
                "vaddr": patch.vaddr,
                "offset": off,
                "expected": patch.expected.hex(" "),
                "current": current.hex(" "),
                "replacement": patch.replacement.hex(" "),
                "matches_expected": current == patch.expected,
            }
        )
    return rows


def apply_patches(data: bytearray, sections: list[Section], patches: Iterable[BytePatch]) -> list[dict]:
    applied = []
    for patch in patches:
        off = map_vaddr_to_offset(patch.vaddr, sections)
        current = bytes(data[off : off + len(patch.expected)])
        if current != patch.expected:
            raise ValueError(
                f"{patch.name} expected {patch.expected.hex(' ')} at RPRC offset 0x{off:x} "
                f"/ vaddr 0x{patch.vaddr:08x}, found {current.hex(' ')}"
            )
        data[off : off + len(patch.expected)] = patch.replacement
        applied.append(
            {
                "name": patch.name,
                "vaddr": patch.vaddr,
                "rprc_offset": off,
                "before": current.hex(" "),
                "after": patch.replacement.hex(" "),
                "reason": patch.reason,
            }
        )
    return applied


def patch_rprc(rprc_path: Path, out_path: Path, variant: str) -> dict:
    original = rprc_path.read_bytes()
    meta = parse_rprc(original)
    data = bytearray(original)
    applied = apply_patches(data, meta["sections"], VARIANTS[variant])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    return {
        "source": str(rprc_path),
        "source_sha256": sha256(original),
        "output": str(out_path),
        "output_sha256": sha256(data),
        "rprc": serializable_rprc(meta),
        "applied": applied,
    }


def patch_mcu_ota(
    mcu_ota_path: Path,
    patched_rprc_path: Path,
    out_path: Path,
    appimage_offset: int,
    mss_core_id: int,
) -> dict:
    original = mcu_ota_path.read_bytes()
    data = bytearray(original)
    before = parse_mstr_appimage(original, appimage_offset)
    mss_entries = [entry for entry in before["entries"] if entry["core_id"] == mss_core_id]
    if len(mss_entries) != 1:
        raise ValueError(f"expected one MSS entry for core 0x{mss_core_id:08x}, found {len(mss_entries)}")
    entry = mss_entries[0]
    patched_rprc = patched_rprc_path.read_bytes()
    if len(patched_rprc) != entry["size"]:
        raise ValueError(
            f"patched RPRC size 0x{len(patched_rprc):x} does not match MSTR entry size 0x{entry['size']:x}"
        )
    data[entry["image_abs"] : entry["image_abs"] + entry["size"]] = patched_rprc
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    after = parse_mstr_appimage(data, appimage_offset)
    patched_entry = [item for item in after["entries"] if item["core_id"] == mss_core_id][0]
    return {
        "source": str(mcu_ota_path),
        "source_sha256": sha256(original),
        "output": str(out_path),
        "output_sha256": sha256(data),
        "appimage_before": before,
        "appimage_after": after,
        "patched_entry": patched_entry,
        "esp_flash_offsets": {
            "mcu_ota_partition": ESP_FLASH_MCU_OTA_OFFSET,
            "appimage": ESP_FLASH_MCU_OTA_OFFSET + appimage_offset,
            "mss_rprc": ESP_FLASH_MCU_OTA_OFFSET + entry["image_abs"],
        },
        "integrity_note": (
            "The MSTR crc_words/header words are preserved. They are not plain CRC32, MD5/SHA prefixes, "
            "or common CRC64 variants in current tests, so treat this partition image as experimental until "
            "the TI metadata algorithm or loader behavior is confirmed."
        ),
    }


def serializable_rprc(meta: dict) -> dict:
    return {
        "entry": meta["entry"],
        "section_count": meta["section_count"],
        "version": meta["version"],
        "parsed_end": meta["parsed_end"],
        "trailing": meta["trailing"],
        "sections": [
            {
                "name": section.name,
                "file_offset": section.file_offset,
                "load_addr": section.load_addr,
                "size": section.size,
            }
            for section in meta["sections"]
        ],
    }


def make_report(report: dict) -> str:
    lines = [
        "# FP2 Radar MSS Patch Workbench",
        "",
        "## Target",
        "",
        f"- Variant: `{report['variant']}`",
        f"- RPRC source: `{report['rprc_source']}`",
        f"- RPRC SHA-256: `{report['rprc_source_sha256']}`",
        "",
        "## Patch Points",
        "",
        "| Name | VAddr | RPRC Offset | Current | Replacement | Match |",
        "| --- | ---: | ---: | --- | --- | --- |",
    ]
    for item in report["patch_points"]:
        lines.append(
            f"| `{item['name']}` | `0x{item['vaddr']:08x}` | `0x{item['offset']:x}` | "
            f"`{item['current']}` | `{item['replacement']}` | `{item['matches_expected']}` |"
        )

    if report.get("patched_rprc"):
        patched = report["patched_rprc"]
        lines.extend(
            [
                "",
                "## Patched RPRC",
                "",
                f"- Output: `{patched['output']}`",
                f"- SHA-256: `{patched['output_sha256']}`",
                "",
                "| Patch | VAddr | RPRC Offset | Before | After |",
                "| --- | ---: | ---: | --- | --- |",
            ]
        )
        for item in patched["applied"]:
            lines.append(
                f"| `{item['name']}` | `0x{item['vaddr']:08x}` | `0x{item['rprc_offset']:x}` | "
                f"`{item['before']}` | `{item['after']}` |"
            )

    if report.get("patched_mcu_ota"):
        patched = report["patched_mcu_ota"]
        entry = patched["patched_entry"]
        offsets = patched["esp_flash_offsets"]
        lines.extend(
            [
                "",
                "## Patched MCU OTA Partition",
                "",
                f"- Output: `{patched['output']}`",
                f"- SHA-256: `{patched['output_sha256']}`",
                f"- Patched MSS core entry SHA-256: `{entry['sha256']}`",
                f"- Flash partition offset: `0x{offsets['mcu_ota_partition']:x}`",
                f"- Appimage flash offset: `0x{offsets['appimage']:x}`",
                f"- MSS RPRC flash offset: `0x{offsets['mss_rprc']:x}`",
                "",
                "### Integrity Note",
                "",
                patched["integrity_note"],
            ]
        )

    lines.append("")
    return "\n".join(lines)


def build_report(rprc_path: Path, variant: str) -> dict:
    data = rprc_path.read_bytes()
    meta = parse_rprc(data)
    return {
        "variant": variant,
        "rprc_source": str(rprc_path),
        "rprc_source_sha256": sha256(data),
        "rprc": serializable_rprc(meta),
        "patch_points": describe_patch_points(data, meta["sections"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rprc", type=Path, default=DEFAULT_RPRC)
    parser.add_argument("--mcu-ota", type=Path, default=DEFAULT_MCU_OTA)
    parser.add_argument("--appimage-offset", type=lambda value: int(value, 0), default=DEFAULT_APPIMAGE_OFFSET)
    parser.add_argument("--mss-core-id", type=lambda value: int(value, 0), default=DEFAULT_MSS_CORE_ID)
    parser.add_argument("--variant", choices=sorted(VARIANTS), default="printf-to-debug-forced")
    parser.add_argument("--out-rprc", type=Path)
    parser.add_argument("--out-mcu-ota", type=Path)
    parser.add_argument("--report-json", type=Path, default=Path("artifacts/stock_patch/fp2_radar_patch_report.json"))
    parser.add_argument("--report-md", type=Path, default=Path("artifacts/stock_patch/fp2_radar_patch_report.md"))
    args = parser.parse_args()

    report = build_report(args.rprc, args.variant)

    if args.out_rprc:
        patched_rprc = patch_rprc(args.rprc, args.out_rprc, args.variant)
        report["patched_rprc"] = patched_rprc
        if args.out_mcu_ota:
            report["patched_mcu_ota"] = patch_mcu_ota(
                args.mcu_ota,
                args.out_rprc,
                args.out_mcu_ota,
                args.appimage_offset,
                args.mss_core_id,
            )

    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_md.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.report_md.write_text(make_report(report), encoding="utf-8")
    print(f"wrote {args.report_json}")
    print(f"wrote {args.report_md}")
    if report.get("patched_rprc"):
        print(f"wrote {report['patched_rprc']['output']}")
    if report.get("patched_mcu_ota"):
        print(f"wrote {report['patched_mcu_ota']['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
