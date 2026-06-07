#!/usr/bin/env python3
"""Summarize FP2 radar MSS sleep/tracker xrefs from build-server objdump.

This is intentionally lightweight: it works from the generated Thumb objdump and
string TSV instead of requiring Ghidra. The output is a breadcrumb for deeper
manual analysis of the stock IWR6843AOP MSS image.
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path


DEFAULT_DISASM = Path("../dumps/buildserver_reports/appimage4_mss_full_thumb.txt")
DEFAULT_STRINGS = Path("../dumps/buildserver_reports/appimage4_mss_strings.tsv")

OBJ_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+[0-9a-fA-F ]+\s+\t(.+)$")
ADR_RE = re.compile(r"\badr\s+(r\d+),\s*(0x[0-9a-fA-F]+)")
CALL_RE = re.compile(r"\b(?:bl|b\.w)\s+0x([0-9a-fA-F]+)")
STORE_R4_RE = re.compile(r"\b(str(?:b|h)?(?:\.w)?|vstr)\s+([^,]+),\s+\[r4(?:,\s*#(\d+))?\]")
STACK_LOAD_RE = re.compile(r"\b(?:ldr|ldrb|vldr)(?:\.w)?\s+([^,]+),\s+\[sp,\s*#(\d+)\]")


@dataclass(frozen=True)
class Instruction:
    addr: int
    text: str
    raw: str


def clean_string(text: str) -> str:
    if len(text) > 1 and text[0] == "F" and (text[1].isalpha() or text[1] == "<"):
        return text[1:]
    return text


def parse_disasm(path: Path) -> list[Instruction]:
    rows: list[Instruction] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = OBJ_LINE_RE.match(raw)
        if match:
            rows.append(Instruction(int(match.group(1), 16), match.group(2), raw.rstrip()))
    return rows


def parse_strings(path: Path) -> dict[int, str]:
    rows: dict[int, str] = {}
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t", fieldnames=["offset", "vaddr", "text", "extra"])
        for row in reader:
            try:
                rows[int(row["vaddr"], 16)] = clean_string(row["text"])
            except (TypeError, ValueError):
                continue
    return rows


def next_calls(instructions: list[Instruction], start_index: int, limit: int) -> list[str]:
    calls: list[str] = []
    for instr in instructions[start_index + 1 : start_index + 1 + limit]:
        match = CALL_RE.search(instr.text)
        if match:
            calls.append(f"0x{instr.addr:08x}->0x{int(match.group(1), 16):08x}")
    return calls


def print_xrefs(instructions: list[Instruction], strings: dict[int, str], keywords: list[str], lookahead: int) -> None:
    lowered = [item.lower() for item in keywords]
    print("xref\tstring_vaddr\tstring\tnext_calls")
    for index, instr in enumerate(instructions):
        match = ADR_RE.search(instr.text)
        if not match:
            continue
        target = int(match.group(2), 16)
        text = strings.get(target) or strings.get(target - 1) or ""
        if not text:
            continue
        if not any(keyword in text.lower() for keyword in lowered):
            continue
        calls = ", ".join(next_calls(instructions, index, lookahead))
        print(f"0x{instr.addr:08x}\t0x{target:08x}\t{text}\t{calls}")


def print_sleep_builder(instructions: list[Instruction], start: int, end: int) -> None:
    print("")
    print("sleep_builder_stores")
    print("addr\toperation\tsource\tbase\toffset\tstack_source_hint")

    recent_stack_loads: dict[str, str] = {}
    for instr in instructions:
        if instr.addr < start:
            continue
        if instr.addr > end:
            break

        stack_load = STACK_LOAD_RE.search(instr.text)
        if stack_load:
            recent_stack_loads[stack_load.group(1)] = f"sp+{int(stack_load.group(2))}"

        store = STORE_R4_RE.search(instr.text)
        if not store:
            continue
        op, source, offset_text = store.groups()
        offset = int(offset_text or "0")
        hint = recent_stack_loads.get(source, "")
        print(f"0x{instr.addr:08x}\t{op}\t{source}\tr4\t0x{offset:02x}\t{hint}")


def print_r4_store_window(instructions: list[Instruction], label: str, start: int, end: int) -> None:
    print("")
    print(label)
    print("addr\toperation\tsource\tbase\toffset")
    for instr in instructions:
        if instr.addr < start:
            continue
        if instr.addr > end:
            break
        store = STORE_R4_RE.search(instr.text)
        if not store:
            continue
        op, source, offset_text = store.groups()
        offset = int(offset_text or "0")
        print(f"0x{instr.addr:08x}\t{op}\t{source}\tr4\t0x{offset:02x}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--disasm", type=Path, default=DEFAULT_DISASM)
    parser.add_argument("--strings", type=Path, default=DEFAULT_STRINGS)
    parser.add_argument("--lookahead", type=int, default=12)
    parser.add_argument("--sleep-builder-start", type=lambda value: int(value, 0), default=0x0FEE)
    parser.add_argument("--sleep-builder-end", type=lambda value: int(value, 0), default=0x1140)
    parser.add_argument("--sleep-state-start", type=lambda value: int(value, 0), default=0x13654)
    parser.add_argument("--sleep-state-end", type=lambda value: int(value, 0), default=0x138CA)
    parser.add_argument(
        "--keywords",
        nargs="*",
        default=[
            "SleepData",
            "sleep tid",
            "HR =",
            "sleep_state",
            "sleep_event",
            "sleep_inout",
            "det2act",
            "sleep2free",
            "staticBoundaryBox",
            "presenceBoundaryBox",
            "query radar calibration",
        ],
    )
    args = parser.parse_args()

    instructions = parse_disasm(args.disasm)
    strings = parse_strings(args.strings)
    print_xrefs(instructions, strings, args.keywords, args.lookahead)
    print_sleep_builder(instructions, args.sleep_builder_start, args.sleep_builder_end)
    print_r4_store_window(instructions, "sleep_state_machine_r4_stores", args.sleep_state_start, args.sleep_state_end)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
