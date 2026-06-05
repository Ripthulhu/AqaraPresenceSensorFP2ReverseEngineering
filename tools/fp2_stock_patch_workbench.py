#!/usr/bin/env python3
"""Stock Aqara FP2 firmware patch workbench.

This tool is deliberately small and boring: parse an ESP32 app image, map
known virtual addresses to file offsets, apply named byte patches, and repair
the ESP image checksum/hash. It does not flash anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ESP_CHECKSUM_MAGIC = 0xEF


@dataclass(frozen=True)
class Section:
    name: str
    file_offset: int
    load_addr: int
    size: int

    def contains_vaddr(self, vaddr: int) -> bool:
        return self.load_addr <= vaddr < self.load_addr + self.size

    def contains_offset(self, offset: int) -> bool:
        return self.file_offset <= offset < self.file_offset + self.size


@dataclass(frozen=True)
class BytePatch:
    name: str
    reason: str
    vaddr: int
    expected: bytes
    replacement: bytes


RADAR_LOG_GATE_PATCHES: list[BytePatch] = [
    BytePatch(
        "sleep_data_cloud_log_gate",
        "Relax stock verbose-log gate before `sleep_data: attr = ...` / `cloud_sleep_data` handling.",
        0x400DF3DE,
        bytes.fromhex("b6 7a 32"),
        bytes.fromhex("b6 2a 32"),
    ),
    BytePatch(
        "people_counting_cloud_log_gate",
        "Relax stock verbose-log gate before `people_counting: attr = ...` / `cloud_people_counting` handling.",
        0x400DF44E,
        bytes.fromhex("b6 7a 32"),
        bytes.fromhex("b6 2a 32"),
    ),
    BytePatch(
        "thermodynamic_cloud_log_gate",
        "Relax stock verbose-log gate before `thermodynamic_chart_data: attr = ...` cloud handling.",
        0x400DF64E,
        bytes.fromhex("b6 7a 32"),
        bytes.fromhex("b6 2a 32"),
    ),
    BytePatch(
        "debug_log_report_gate",
        "Relax stock verbose-log gate before `radar_debug_log: %s` / `radar_debug_log_report` handling.",
        0x400DF6AD,
        bytes.fromhex("b6 7a 30"),
        bytes.fromhex("b6 2a 30"),
    ),
    BytePatch(
        "sleep_data_radar_log_gate",
        "Relax stock verbose-log gate before `sleep_data: %s` / `radar_sleep_data` handling.",
        0x400E490D,
        bytes.fromhex("b6 7a 2f"),
        bytes.fromhex("b6 2a 2f"),
    ),
    BytePatch(
        "thermodynamic_radar_log_gate",
        "Relax stock verbose-log gate before `thermodynamic_chart_data: %s` / `radar_thermodynamic_chart_data` handling.",
        0x400E4A09,
        bytes.fromhex("b6 7a 2f"),
        bytes.fromhex("b6 2a 2f"),
    ),
]


ROM_PRINTF_PATCHES: list[BytePatch] = [
    BytePatch(
        "radar_resource_printf_to_rom_ets_printf",
        "Redirect the radar/resource handler printf literal pool to ESP32 ROM ets_printf for UART-console probing.",
        0x400D077C,
        struct.pack("<I", 0x401C6AF4),
        struct.pack("<I", 0x40007D54),
    ),
]


ROM_PRINTF_ALL_PATCHES: list[BytePatch] = [
    *ROM_PRINTF_PATCHES,
    BytePatch(
        "single_late_printf_to_rom_ets_printf",
        "Redirect the one-off later printf literal pool to ESP32 ROM ets_printf.",
        0x400D413C,
        struct.pack("<I", 0x401C6AF4),
        struct.pack("<I", 0x40007D54),
    ),
    BytePatch(
        "esp_log_printf_to_rom_ets_printf",
        "Redirect the broad ESP log printf literal pool to ESP32 ROM ets_printf.",
        0x4010F998,
        struct.pack("<I", 0x401C6AF4),
        struct.pack("<I", 0x40007D54),
    ),
]


UART_BOOT_BEACON_PATCHES: list[BytePatch] = [
    BytePatch(
        "cpu_start_printf_literal_to_uart_tx_one_char",
        "Redirect the app-entry boot-log function pointer from ROM ets_printf to ROM uart_tx_one_char.",
        0x40080470,
        struct.pack("<I", 0x40007D54),
        struct.pack("<I", 0x40009200),
    ),
    BytePatch(
        "cpu_start_unicore_app_beacon_B",
        "Replace the first boot-log format pointer load with a direct low-byte UART beacon character.",
        0x400818D8,
        bytes.fromhex("a1 d9 fa"),
        bytes.fromhex("42 a1 a2"),
    ),
    BytePatch(
        "cpu_start_ext_ram_fail_beacon_I",
        "Replace a second boot-log format pointer load with a direct low-byte UART beacon character.",
        0x40081915,
        bytes.fromhex("a1 ca fa"),
        bytes.fromhex("49 a1 a2"),
    ),
    BytePatch(
        "cpu_start_pro_cpu_up_beacon_R",
        "Replace a third boot-log format pointer load with a direct low-byte UART beacon character.",
        0x4008193C,
        bytes.fromhex("a1 c3 fa"),
        bytes.fromhex("52 a1 a2"),
    ),
    BytePatch(
        "cpu_start_single_core_beacon_D",
        "Replace a fourth boot-log format pointer load with a direct low-byte UART beacon character.",
        0x40081955,
        bytes.fromhex("a1 bd fa"),
        bytes.fromhex("44 a1 a2"),
    ),
    BytePatch(
        "cpu_start_ext_ram_test_beacon_lf",
        "Replace a fifth boot-log format pointer load with a direct low-byte UART newline beacon.",
        0x40081992,
        bytes.fromhex("a1 b0 fa"),
        bytes.fromhex("0a a1 a2"),
    ),
]


DATA_PROBES = {
    "esp_log_level_byte": 0x3FFB2B58,
    "radar_text_buffer_ptr": 0x3FFB6620,
    "active_radar_context_ptr": 0x3FFB238C,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_esp_image(data: bytes) -> tuple[int, int, list[Section]]:
    if len(data) < 24 or data[0] != 0xE9:
        raise ValueError("not an ESP32 image: missing 0xE9 magic")

    seg_count = data[1]
    entry = struct.unpack_from("<I", data, 4)[0]
    offset = 24
    sections: list[Section] = []
    for i in range(seg_count):
        if offset + 8 > len(data):
            raise ValueError(f"truncated segment header {i}")
        load_addr, size = struct.unpack_from("<II", data, offset)
        data_offset = offset + 8
        if data_offset + size > len(data):
            raise ValueError(f"truncated segment data {i}")
        sections.append(Section(f"seg{i}", data_offset, load_addr, size))
        offset = data_offset + size
    return entry, offset, sections


def checksum_offset(image_data_end: int) -> int:
    offset = image_data_end
    while offset % 16 != 15:
        offset += 1
    return offset


def calc_image_checksum(data: bytes, sections: Iterable[Section]) -> int:
    checksum = ESP_CHECKSUM_MAGIC
    for section in sections:
        for byte in data[section.file_offset : section.file_offset + section.size]:
            checksum ^= byte
    return checksum


def map_vaddr_to_offset(vaddr: int, sections: list[Section]) -> int:
    for section in sections:
        if section.contains_vaddr(vaddr):
            return section.file_offset + (vaddr - section.load_addr)
    raise KeyError(f"vaddr 0x{vaddr:08x} is not covered by an ESP image segment")


def map_offset_to_vaddr(offset: int, sections: list[Section]) -> int | None:
    for section in sections:
        if section.contains_offset(offset):
            return section.load_addr + (offset - section.file_offset)
    return None


def image_metadata(data: bytes) -> dict:
    entry, image_end, sections = parse_esp_image(data)
    chk_offset = checksum_offset(image_end)
    hash_offset = chk_offset + 1
    stored_checksum = data[chk_offset] if chk_offset < len(data) else None
    calc_checksum = calc_image_checksum(data, sections)
    stored_hash = data[hash_offset : hash_offset + 32] if hash_offset + 32 <= len(data) else b""
    calc_hash = hashlib.sha256(data[:hash_offset]).digest()
    hash_present = len(stored_hash) == 32 and stored_hash != b"\xff" * 32

    return {
        "entry": entry,
        "segment_count": len(sections),
        "sections": [
            {
                "name": section.name,
                "file_offset": section.file_offset,
                "load_addr": section.load_addr,
                "size": section.size,
            }
            for section in sections
        ],
        "image_data_end": image_end,
        "checksum_offset": chk_offset,
        "stored_checksum": stored_checksum,
        "calculated_checksum": calc_checksum,
        "checksum_ok": stored_checksum == calc_checksum,
        "hash_offset": hash_offset,
        "hash_present": hash_present,
        "stored_hash": stored_hash.hex() if hash_present else "",
        "calculated_hash": calc_hash.hex(),
        "hash_ok": stored_hash == calc_hash if hash_present else None,
    }


def rebuild_integrity(data: bytearray, sections: list[Section], image_end: int) -> dict:
    chk_offset = checksum_offset(image_end)
    hash_offset = chk_offset + 1
    checksum = calc_image_checksum(data, sections)
    data[chk_offset] = checksum

    hash_present = hash_offset + 32 <= len(data) and data[hash_offset : hash_offset + 32] != b"\xff" * 32
    digest = hashlib.sha256(data[:hash_offset]).digest()
    if hash_present:
        data[hash_offset : hash_offset + 32] = digest

    return {
        "checksum_offset": chk_offset,
        "checksum": checksum,
        "hash_offset": hash_offset,
        "hash_present": hash_present,
        "hash": digest.hex() if hash_present else "",
    }


def describe_known_points(data: bytes, sections: list[Section]) -> dict:
    probes: dict[str, dict] = {}
    for name, vaddr in DATA_PROBES.items():
        try:
            off = map_vaddr_to_offset(vaddr, sections)
            probes[name] = {
                "vaddr": vaddr,
                "offset": off,
                "bytes": data[off : off + 16].hex(" "),
                "u8": data[off],
                "u32": struct.unpack_from("<I", data, off)[0],
            }
        except KeyError:
            probes[name] = {"vaddr": vaddr, "offset": None}

    patches = []
    for patch in [*RADAR_LOG_GATE_PATCHES, *ROM_PRINTF_ALL_PATCHES, *UART_BOOT_BEACON_PATCHES]:
        off = map_vaddr_to_offset(patch.vaddr, sections)
        current = data[off : off + len(patch.expected)]
        patches.append(
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
    return {"data_probes": probes, "patch_candidates": patches}


def apply_patches(data: bytearray, sections: list[Section], patches: Iterable[BytePatch]) -> list[dict]:
    applied = []
    for patch in patches:
        off = map_vaddr_to_offset(patch.vaddr, sections)
        current = bytes(data[off : off + len(patch.expected)])
        if current != patch.expected:
            raise ValueError(
                f"{patch.name} expected {patch.expected.hex(' ')} at 0x{off:x}/0x{patch.vaddr:08x}, "
                f"found {current.hex(' ')}"
            )
        data[off : off + len(patch.expected)] = patch.replacement
        applied.append(
            {
                "name": patch.name,
                "vaddr": patch.vaddr,
                "offset": off,
                "before": current.hex(" "),
                "after": patch.replacement.hex(" "),
                "reason": patch.reason,
            }
        )
    return applied


def make_markdown(report: dict) -> str:
    meta = report["image"]
    lines = [
        "# FP2 Stock Patch Workbench",
        "",
        "## Image Integrity",
        "",
        f"- Source: `{report['source']}`",
        f"- SHA-256: `{report['source_sha256']}`",
        f"- Entry: `0x{meta['entry']:08x}`",
        f"- Image data end: `0x{meta['image_data_end']:x}`",
        f"- Checksum: stored `0x{meta['stored_checksum']:02x}`, calculated `0x{meta['calculated_checksum']:02x}`, ok `{meta['checksum_ok']}`",
        f"- Appended hash present: `{meta['hash_present']}`, ok `{meta['hash_ok']}`",
        "",
        "## Runtime Data Probes",
        "",
        "| Name | VAddr | Offset | First Bytes | U8 | U32 |",
        "| --- | ---: | ---: | --- | ---: | ---: |",
    ]
    for name, probe in report["known_points"]["data_probes"].items():
        offset = "" if probe["offset"] is None else f"`0x{probe['offset']:x}`"
        u8 = "" if "u8" not in probe else f"`0x{probe['u8']:02x}`"
        u32 = "" if "u32" not in probe else f"`0x{probe['u32']:08x}`"
        lines.append(f"| `{name}` | `0x{probe['vaddr']:08x}` | {offset} | `{probe.get('bytes', '')}` | {u8} | {u32} |")

    lines.extend(
        [
            "",
            "## Patch Candidates",
            "",
            "| Name | VAddr | Offset | Current | Replacement | Match |",
            "| --- | ---: | ---: | --- | --- | --- |",
        ]
    )
    for item in report["known_points"]["patch_candidates"]:
        lines.append(
            f"| `{item['name']}` | `0x{item['vaddr']:08x}` | `0x{item['offset']:x}` | "
            f"`{item['current']}` | `{item['replacement']}` | `{item['matches_expected']}` |"
        )

    if report.get("patched"):
        patched = report["patched"]
        lines.extend(
            [
                "",
                "## Patched Artifact",
                "",
                f"- Variant: `{patched['variant']}`",
                f"- Output: `{patched['output']}`",
                f"- SHA-256: `{patched['sha256']}`",
                f"- Rebuilt checksum byte: `0x{patched['integrity']['checksum']:02x}` at `0x{patched['integrity']['checksum_offset']:x}`",
                f"- Rebuilt appended hash: `{patched['integrity']['hash']}`",
                "",
                "| Patch | VAddr | Offset | Before | After |",
                "| --- | ---: | ---: | --- | --- |",
            ]
        )
        for item in patched["applied"]:
            lines.append(
                f"| `{item['name']}` | `0x{item['vaddr']:08x}` | `0x{item['offset']:x}` | "
                f"`{item['before']}` | `{item['after']}` |"
            )

    lines.append("")
    return "\n".join(lines)


def build_report(image_path: Path) -> dict:
    data = image_path.read_bytes()
    _, _, sections = parse_esp_image(data)
    return {
        "source": str(image_path),
        "source_sha256": sha256(data),
        "image": image_metadata(data),
        "known_points": describe_known_points(data, sections),
    }


def patch_image(image_path: Path, output_path: Path, variant: str) -> dict:
    original = image_path.read_bytes()
    data = bytearray(original)
    _, image_end, sections = parse_esp_image(data)

    if variant == "relax-log-gates":
        selected = RADAR_LOG_GATE_PATCHES
    elif variant == "rom-printf-radar":
        selected = [*RADAR_LOG_GATE_PATCHES, *ROM_PRINTF_PATCHES]
    elif variant == "rom-printf-all":
        selected = [*RADAR_LOG_GATE_PATCHES, *ROM_PRINTF_ALL_PATCHES]
    elif variant == "uart-boot-beacon":
        selected = [*RADAR_LOG_GATE_PATCHES, *ROM_PRINTF_PATCHES, *UART_BOOT_BEACON_PATCHES]
    else:
        raise ValueError(f"unknown variant: {variant}")

    applied = apply_patches(data, sections, selected)
    integrity = rebuild_integrity(data, sections, image_end)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)

    report = build_report(image_path)
    report["patched"] = {
        "variant": variant,
        "output": str(output_path),
        "sha256": sha256(data),
        "applied": applied,
        "integrity": integrity,
        "post_image": image_metadata(data),
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="dumps/extracted/aqara_fw2_0x220000_0x200000.bin")
    parser.add_argument("--report-json", default="artifacts/stock_patch/fp2_stock_patch_report.json")
    parser.add_argument("--report-md", default="artifacts/stock_patch/fp2_stock_patch_report.md")
    parser.add_argument(
        "--variant",
        choices=["relax-log-gates", "rom-printf-radar", "rom-printf-all", "uart-boot-beacon"],
    )
    parser.add_argument("--out")
    args = parser.parse_args()

    image_path = Path(args.image)
    if args.variant:
        if not args.out:
            raise SystemExit("--out is required when --variant is used")
        report = patch_image(image_path, Path(args.out), args.variant)
    else:
        report = build_report(image_path)

    json_path = Path(args.report_json)
    md_path = Path(args.report_md)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(make_markdown(report), encoding="utf-8")
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    if report.get("patched"):
        print(f"wrote {report['patched']['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
