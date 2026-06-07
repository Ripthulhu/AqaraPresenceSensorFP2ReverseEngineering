#!/usr/bin/env python3
"""Capture stock FP2 ESP/radar UART traffic from Windows COM adapters.

Default channel mapping matches the 2026-06-07 bench wiring:

* COM4 -> ESP32 GPIO19 / radar RX line / ESP -> radar, decoder channel 0.
* COM7 -> ESP32 GPIO18 / radar TX line / radar -> ESP, decoder channel 1.
* COM5 -> ESP32 UART0 at 115200 baud, raw capture only.

The decoder-ready output is `radar_dual.decoder_input.txt`.
"""

from __future__ import annotations

import argparse
import json
import queue
import sys
import threading
import time
from pathlib import Path

import serial


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--duration", type=float, default=90.0, help="Capture duration in seconds")
    parser.add_argument("--esp-tx-port", default="COM4", help="ESP -> radar sniff adapter")
    parser.add_argument("--radar-tx-port", default="COM7", help="Radar -> ESP sniff adapter")
    parser.add_argument("--uart0-port", default="COM5", help="ESP32 UART0 adapter")
    parser.add_argument("--radar-baud", type=int, default=890000, help="ESP/radar UART baud")
    parser.add_argument("--uart0-baud", type=int, default=115200, help="ESP32 UART0 baud")
    return parser.parse_args()


def reader(cfg: dict, stop: threading.Event, events: "queue.Queue[tuple]") -> None:
    try:
        ser = serial.Serial(
            port=cfg["name"],
            baudrate=cfg["baud"],
            bytesize=8,
            parity="N",
            stopbits=1,
            timeout=0.02,
            xonxoff=False,
            rtscts=False,
            dsrdtr=False,
        )
        ser.dtr = False
        ser.rts = False
        with ser:
            while not stop.is_set():
                data = ser.read(8192)
                if data:
                    events.put((time.time(), cfg, data))
    except Exception as exc:  # pragma: no cover - hardware dependent
        events.put((time.time(), cfg, None, repr(exc)))


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    ports = [
        {
            "name": args.esp_tx_port,
            "baud": args.radar_baud,
            "channel": 0,
            "label": "esp_gpio19_to_radar",
        },
        {
            "name": args.radar_tx_port,
            "baud": args.radar_baud,
            "channel": 1,
            "label": "radar_gpio18_to_esp",
        },
        {
            "name": args.uart0_port,
            "baud": args.uart0_baud,
            "channel": None,
            "label": "esp32_uart0",
        },
    ]

    events: "queue.Queue[tuple]" = queue.Queue()
    stop = threading.Event()
    summary = {
        "started": time.time(),
        "duration_s": args.duration,
        "ports": ports,
        "chunks": {p["name"]: 0 for p in ports},
        "bytes": {p["name"]: 0 for p in ports},
        "errors": [],
    }

    threads = [threading.Thread(target=reader, args=(cfg, stop, events), daemon=True) for cfg in ports]
    for thread in threads:
        thread.start()

    raw_files = {
        cfg["name"]: open(out_dir / f'{cfg["name"]}_{cfg["baud"]}_{cfg["label"]}.bin', "wb")
        for cfg in ports
    }
    hex_files = {
        cfg["name"]: open(out_dir / f'{cfg["name"]}_{cfg["baud"]}_{cfg["label"]}.hex.txt', "w", encoding="ascii")
        for cfg in ports
    }
    decoder = open(out_dir / "radar_dual.decoder_input.txt", "w", encoding="ascii")
    event_log = open(out_dir / "capture_events.jsonl", "w", encoding="utf-8")

    try:
        end = time.time() + args.duration
        while time.time() < end:
            try:
                item = events.get(timeout=0.1)
            except queue.Empty:
                continue

            if len(item) == 4:
                tstamp, cfg, _none, error = item
                record = {"t": tstamp, "port": cfg["name"], "error": error}
                summary["errors"].append(record)
                event_log.write(json.dumps(record) + "\n")
                event_log.flush()
                continue

            tstamp, cfg, data = item
            name = cfg["name"]
            raw_files[name].write(data)
            raw_files[name].flush()

            hex_data = " ".join(f"{byte:02x}" for byte in data)
            hex_files[name].write(f"t{tstamp:.6f} {hex_data}\n")
            hex_files[name].flush()

            event_log.write(
                json.dumps(
                    {
                        "t": tstamp,
                        "port": name,
                        "baud": cfg["baud"],
                        "label": cfg["label"],
                        "len": len(data),
                    }
                )
                + "\n"
            )
            event_log.flush()

            summary["chunks"][name] += 1
            summary["bytes"][name] += len(data)
            if cfg["channel"] is not None:
                decoder.write(f't{tstamp:.6f} {cfg["channel"]} {hex_data}\n')
                decoder.flush()
    finally:
        stop.set()
        time.sleep(0.2)
        for handle in list(raw_files.values()) + list(hex_files.values()) + [decoder, event_log]:
            handle.close()

    summary["ended"] = time.time()
    (out_dir / "capture_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({"out_dir": str(out_dir), "bytes": summary["bytes"], "errors": summary["errors"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
