#!/usr/bin/env python3
"""Inspect pulled Aqara Home app data for FP2 reverse-engineering clues.

The app data contains account/session material. This helper is deliberately
read-only and clips values so notes can capture structure without dumping
tokens or full cached payloads.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Iterable


DEFAULT_TERMS = [
    "lumi1.54ef4462de8c",
    "lumi.motion.agl001",
    "track-ger.aqara.com",
    "rpc-ger.aqara.com",
    "cdn.aqara.com",
    "Fp2",
    "fp2",
    "radar",
    "people_counting",
    "people_number",
    "walking_distance",
    "dwell_time",
    "sleep_report",
    "14.56.85",
    "4.72.85",
    "4.75.85",
    "1.10.85",
    "4.69.85",
    "14.30.85",
    "14.59.85",
    "4.41.705",
    "4.74.85",
]


def clip(value: object, limit: int) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    else:
        text = str(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\0")
    if len(text) > limit:
        return text[:limit] + "...<clipped>"
    return text


def db_files(root: Path) -> Iterable[Path]:
    for path in sorted((root / "databases").glob("*.db")):
        if path.name.endswith(("-wal", "-shm")):
            continue
        yield path


def table_names(conn: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in conn.execute(
            "select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name"
        )
    ]


def columns(conn: sqlite3.Connection, table: str) -> list[tuple[str, str]]:
    return [(row[1], row[2]) for row in conn.execute(f'pragma table_info("{table}")')]


def row_count(conn: sqlite3.Connection, table: str) -> int:
    try:
        return int(conn.execute(f'select count(*) from "{table}"').fetchone()[0])
    except sqlite3.DatabaseError:
        return -1


def inspect_db(path: Path, terms: list[str], value_limit: int) -> dict[str, object]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.text_factory = lambda b: b.decode("utf-8", "replace")
    try:
        tables = []
        hits = []
        for table in table_names(conn):
            cols = columns(conn, table)
            tables.append(
                {
                    "table": table,
                    "rows": row_count(conn, table),
                    "columns": [{"name": name, "type": typ} for name, typ in cols],
                }
            )
            col_names = [name for name, _ in cols]
            if not col_names:
                continue
            query_cols = ", ".join(f'"{name}"' for name in col_names)
            try:
                rows = conn.execute(f'select {query_cols} from "{table}" limit 5000')
            except sqlite3.DatabaseError:
                continue
            for row in rows:
                for name, value in zip(col_names, row):
                    text = clip(value, value_limit)
                    matched = [term for term in terms if term.lower() in text.lower()]
                    if matched:
                        hits.append(
                            {
                                "table": table,
                                "column": name,
                                "terms": matched,
                                "row": {
                                    col: clip(val, value_limit)
                                    for col, val in zip(col_names, row)
                                },
                            }
                        )
                        break
        return {"db": str(path), "tables": tables, "hits": hits}
    finally:
        conn.close()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--term", action="append", dest="terms")
    parser.add_argument("--value-limit", type=int, default=500)
    parser.add_argument("--out", type=Path, help="optional JSON report path")
    args = parser.parse_args()

    terms = args.terms or DEFAULT_TERMS
    reports = []
    for path in db_files(args.root):
        try:
            reports.append(inspect_db(path, terms, args.value_limit))
        except sqlite3.DatabaseError as exc:
            reports.append({"db": str(path), "error": str(exc)})
    text = json.dumps(reports, indent=2, ensure_ascii=False)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
        print(args.out)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
