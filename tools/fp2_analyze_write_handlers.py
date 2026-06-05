#!/usr/bin/env python3
"""Summarize ESP32 cloud descriptor write handlers from an objdump listing.

The descriptor table tells us the cloud resource shape, but several handlers
transform that cloud value before calling the common radar UART write helper.
This script makes that distinction easier to audit by pairing descriptor rows
with nearby handler strings, stores, and calls to the known write helper.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

from fp2_extract_cloud_tables import (
    DATA_TYPE_NAMES,
    SUBID_NAMES,
    WRITE_HANDLER_HINTS,
    extract_descriptor_records,
    parse_esp_sections,
    read_cstr,
)


OBJ_LINE_RE = re.compile(r"^([0-9a-fA-F]{8}):\s+[0-9a-fA-F ]+\s+\t(.+)$")
L32R_CSTR_RE = re.compile(r"\bl32r\s+a10,.*\((0x[0-9a-fA-F]+)\)")
MOVI_RE = re.compile(r"\bmovi(?:\.n)?\s+(a1[0-5]|a[0-9]),\s+(-?0x[0-9a-fA-F]+|-?\d+)")
ADDI_RE = re.compile(r"\baddi(?:\.n)?\s+(a1[0-5]|a[0-9]),\s+(a1[0-5]|a[0-9]),\s+(-?0x[0-9a-fA-F]+|-?\d+)")
OR_SELF_RE = re.compile(r"\bor\s+(a1[0-5]|a[0-9]),\s+(a1[0-5]|a[0-9]),\s+\2")
MOV_RE = re.compile(r"\bmov(?:\.n)?\s+(a1[0-5]|a[0-9]),\s+(a1[0-5]|a[0-9])")
STORE_RE = re.compile(r"\b(s(?:8|16|32)i)\s+(a1[0-5]|a[0-9]),\s+(a1[0-5]|a[0-9]),\s+(-?0x[0-9a-fA-F]+|-?\d+)")
WRITE_CALL = "call8\t0x400e7e20"


@dataclass(frozen=True)
class Instruction:
    addr: int
    text: str
    raw: str


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_objdump(path: Path) -> list[Instruction]:
    instructions: list[Instruction] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = OBJ_LINE_RE.match(raw)
        if not match:
            continue
        instructions.append(Instruction(int(match.group(1), 16), match.group(2), raw))
    return instructions


def find_start(instructions: list[Instruction], vaddr: int) -> int | None:
    for index, instr in enumerate(instructions):
        if instr.addr >= vaddr:
            return index
    return None


def function_window(
    instructions: list[Instruction],
    vaddr: int,
    max_bytes: int,
    *,
    next_vaddr: int | None = None,
) -> list[Instruction]:
    start = find_start(instructions, vaddr)
    if start is None:
        return []

    end_vaddr = vaddr + max_bytes
    if next_vaddr is not None and vaddr < next_vaddr < end_vaddr:
        end_vaddr = next_vaddr

    window: list[Instruction] = []
    for instr in instructions[start:]:
        if instr.addr >= end_vaddr:
            break
        window.append(instr)
        if "retw.n" in instr.text and len(window) > 4:
            break
    return window


def describe_arg(history: list[Instruction], reg: str) -> str:
    for instr in reversed(history):
        movi = MOVI_RE.search(instr.text)
        if movi and movi.group(1) == reg:
            return str(parse_int(movi.group(2)))

        addi = ADDI_RE.search(instr.text)
        if addi and addi.group(1) == reg:
            return f"{addi.group(2)}+{parse_int(addi.group(3))}"

        or_self = OR_SELF_RE.search(instr.text)
        if or_self and or_self.group(1) == reg:
            return or_self.group(2)

        mov = MOV_RE.search(instr.text)
        if mov and mov.group(1) == reg:
            return mov.group(2)

    return ""


def summarize_calls(window: list[Instruction]) -> list[str]:
    calls: list[str] = []
    for index, instr in enumerate(window):
        if WRITE_CALL not in instr.text:
            continue
        history = window[max(0, index - 8) : index]
        args = ", ".join(
            f"{reg}={describe_arg(history, reg) or '?'}" for reg in ["a10", "a11", "a12"]
        )
        calls.append(f"0x{instr.addr:08x}:{args}")
    return calls


def summarize_strings(data: bytes, sections, window: list[Instruction]) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()
    for instr in window:
        match = L32R_CSTR_RE.search(instr.text)
        if not match:
            continue
        text = read_cstr(data, sections, int(match.group(1), 16))
        if not text or text in seen:
            continue
        seen.add(text)
        strings.append(text)
    return strings


def summarize_stores(window: list[Instruction]) -> list[str]:
    stores: list[str] = []
    for instr in window:
        match = STORE_RE.search(instr.text)
        if not match:
            continue
        op, src, base, offset = match.groups()
        stores.append(f"0x{instr.addr:08x}:{op} {src},{base},{parse_int(offset)}")
    return stores


def h(value: int, width: int = 4) -> str:
    return f"0x{value:0{width}x}"


def print_tsv(rows: list[dict]) -> None:
    keys = [
        "resource",
        "subid",
        "subid_name",
        "descriptor_type",
        "write_handler",
        "write_handler_hint",
        "strings",
        "stores",
        "radar_write_calls",
    ]
    print("\t".join(keys))
    for row in rows:
        print("\t".join(str(row.get(key, "")) for key in keys))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path, help="ESP32 app image")
    parser.add_argument("objdump", type=Path, help="Xtensa objdump listing for the app image")
    parser.add_argument(
        "--resource-filter",
        default=r"^(0\.121\.85|13\.3\.85|1\.10\.85|1\.11\.85|14\.59\.85|4\.41\.705|4\.74\.85|4\.75\.85)$",
        help="regex for descriptor resource ids to print",
    )
    parser.add_argument("--all", action="store_true", help="print every descriptor row")
    parser.add_argument("--max-bytes", type=lambda value: int(value, 0), default=0x180)
    args = parser.parse_args()

    data = args.image.read_bytes()
    sections = parse_esp_sections(data)
    instructions = parse_objdump(args.objdump)
    descriptor_re = re.compile(".*" if args.all else args.resource_filter)

    rows: list[dict] = []
    descriptors = extract_descriptor_records(data, sections)
    handler_addrs = sorted({descriptor["write_handler"] for descriptor in descriptors})
    next_handler_by_addr = {
        handler: handler_addrs[index + 1] if index + 1 < len(handler_addrs) else None
        for index, handler in enumerate(handler_addrs)
    }

    for descriptor in descriptors:
        if not descriptor_re.search(descriptor["resource"]):
            continue
        window = function_window(
            instructions,
            descriptor["write_handler"],
            args.max_bytes,
            next_vaddr=next_handler_by_addr[descriptor["write_handler"]],
        )
        subid = descriptor["subid_low16"]
        descriptor_type = descriptor["packed_high16"]
        rows.append(
            {
                "resource": descriptor["resource"],
                "subid": h(subid),
                "subid_name": SUBID_NAMES.get(subid, ""),
                "descriptor_type": DATA_TYPE_NAMES.get(descriptor_type, h(descriptor_type)),
                "write_handler": h(descriptor["write_handler"], 8),
                "write_handler_hint": WRITE_HANDLER_HINTS.get(descriptor["write_handler"], ""),
                "strings": " | ".join(summarize_strings(data, sections, window)),
                "stores": " | ".join(summarize_stores(window)),
                "radar_write_calls": " | ".join(summarize_calls(window)),
            }
        )

    print_tsv(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
