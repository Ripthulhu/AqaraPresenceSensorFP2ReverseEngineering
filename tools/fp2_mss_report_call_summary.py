#!/usr/bin/env python3
"""Summarize TI MSS calls into the radar UART report helper.

The extracted MSS Thumb listing contains many small wrappers that log a value
and then call a common helper with a radar SubID. This script backtracks from
calls to that helper and prints the nearest SubID immediate plus nearby format
string, which is useful when anchoring report-only attributes.
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path

from fp2_extract_cloud_tables import SUBID_NAMES


OBJ_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+[0-9a-fA-F ]+\s+\t(.+)$")
CALL_RE = re.compile(r"\b(?:bl|b\.w)\s+0x([0-9a-fA-F]+)")
IMM_RE = re.compile(r"\b(?:movs?|movw)(?:\.w)?\s+(r\d+),\s+#(\d+)")
MOV_RE = re.compile(r"\bmov\s+(r\d+),\s+(r\d+)")
ADD_SP_RE = re.compile(r"\b(?:add|add\.w)\s+(r\d+),\s+sp(?:,\s+#(\d+))?")
ADR_RE = re.compile(r"\badr\s+r0,\s*(0x[0-9a-fA-F]+)")


@dataclass(frozen=True)
class Instruction:
    addr: int
    text: str
    raw: str


def parse_objdump(path: Path) -> list[Instruction]:
    instructions: list[Instruction] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = OBJ_LINE_RE.match(raw)
        if match:
            instructions.append(Instruction(int(match.group(1), 16), match.group(2), raw))
    return instructions


def parse_strings(path: Path | None) -> dict[int, str]:
    if path is None:
        return {}
    rows: dict[int, str] = {}
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            try:
                rows[int(row["vaddr"], 16)] = row["text"]
            except (KeyError, TypeError, ValueError):
                continue
    return rows


def clean_string(text: str) -> str:
    if len(text) > 1 and text[0] == "F" and text[1].isalpha():
        return text[1:]
    return text


def string_for(strings: dict[int, str], vaddr: int) -> str:
    text = strings.get(vaddr) or strings.get(vaddr - 1) or ""
    return clean_string(text)


def describe_reg(history: list[Instruction], reg: str) -> str:
    for instr in reversed(history):
        imm = IMM_RE.search(instr.text)
        if imm and imm.group(1) == reg:
            return f"#{int(imm.group(2))}"

        add_sp = ADD_SP_RE.search(instr.text)
        if add_sp and add_sp.group(1) == reg:
            offset = int(add_sp.group(2) or "0")
            return f"sp+{offset}"

        mov = MOV_RE.search(instr.text)
        if mov and mov.group(1) == reg:
            return mov.group(2)

    return ""


def nearest_format(strings: dict[int, str], history: list[Instruction]) -> str:
    for instr in reversed(history):
        adr = ADR_RE.search(instr.text)
        if not adr:
            continue
        text = string_for(strings, int(adr.group(1), 16))
        if text:
            return text
    return ""


def print_tsv(rows: list[dict]) -> None:
    keys = ["call", "subid", "subid_name", "r0", "r1", "r2", "r3", "format"]
    print("\t".join(keys))
    for row in rows:
        print("\t".join(str(row.get(key, "")) for key in keys))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("objdump", type=Path, help="MSS Thumb objdump listing")
    parser.add_argument("--strings", type=Path, help="appimage4_mss_strings.tsv")
    parser.add_argument("--helper", type=lambda value: int(value, 0), default=0x1C7C4)
    parser.add_argument("--lookback", type=int, default=18)
    args = parser.parse_args()

    instructions = parse_objdump(args.objdump)
    strings = parse_strings(args.strings)
    rows: list[dict] = []

    for index, instr in enumerate(instructions):
        call = CALL_RE.search(instr.text)
        if not call or int(call.group(1), 16) != args.helper:
            continue
        history = instructions[max(0, index - args.lookback) : index]
        r1 = describe_reg(history, "r1")
        subid = ""
        subid_name = ""
        if r1.startswith("#"):
            value = int(r1[1:])
            subid = f"0x{value:04x}"
            subid_name = SUBID_NAMES.get(value, "")
        rows.append(
            {
                "call": f"0x{instr.addr:08x}",
                "subid": subid,
                "subid_name": subid_name,
                "r0": describe_reg(history, "r0"),
                "r1": r1,
                "r2": describe_reg(history, "r2"),
                "r3": describe_reg(history, "r3"),
                "format": nearest_format(strings, history),
            }
        )

    print_tsv(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
