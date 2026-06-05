#!/usr/bin/env python3
"""Extract Aqara FP2 ESP32 cloud/resource tables from a stock app image.

This is intentionally read-only. It parses the ESP32 app image segment table and
decodes known resource dispatch tables that are useful for correlating Aqara
cloud resource ids with radar UART SubIDs.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from dataclasses import asdict, dataclass
from pathlib import Path


RESOURCE_RE = re.compile(r"^\d+\.\d+\.\d+$")


DATA_TYPE_NAMES = {
    0x00: "UINT8",
    0x01: "UINT16",
    0x02: "UINT32",
    0x03: "VOID",
    0x04: "BOOL",
    0x05: "BLOB1",
    0x06: "BLOB2",
    0x07: "STRUCT",
}


SUBID_NAMES = {
    0x0101: "radar_hw_version",
    0x0102: "radar_sw_version",
    0x0103: "motion_detection",
    0x0104: "presence_detection",
    0x0105: "monitor_mode",
    0x0106: "closing_setting",
    0x0107: "edge_label",
    0x0109: "import_export_label",
    0x0110: "interference_source",
    0x0111: "presence_detection_sensitivity",
    0x0112: "location_report_enable",
    0x0113: "reset_absent_status",
    0x0114: "zone_detect_setting",
    0x0115: "detect_zone_motion",
    0x0116: "work_mode",
    0x0117: "location_track_data",
    0x0120: "angle_sensor_data",
    0x0121: "fall_detection",
    0x0122: "left_right_reverse",
    0x0123: "fall_detection_sensitivity",
    0x0125: "radar_interference_auto_setting",
    0x0127: "ota_set_flag",
    0x0128: "temperature",
    0x0134: "fall_overtime_report_period",
    0x0135: "fall_overtime_detection",
    0x0138: "thermodynamic_chart_enable",
    0x0139: "interference_auto_enable",
    0x0141: "thermodynamic_chart_data",
    0x0142: "detect_zone_presence",
    0x0143: "device_direction",
    0x0149: "edge_auto_setting",
    0x0150: "edge_auto_enable",
    0x0151: "detect_zone_sensitivity",
    0x0152: "detect_zone_type",
    0x0153: "detect_zone_close_away_enable",
    0x0154: "target_posture",
    0x0155: "people_counting",
    0x0156: "sleep_report_enable",
    0x0157: "posture_report_enable",
    0x0158: "people_counting_report_enable",
    0x0159: "sleep_data",
    0x0160: "delete_false_target",
    0x0161: "sleep_state",
    0x0162: "people_number_enable",
    0x0163: "target_type_enable",
    0x0164: "realtime_people_number",
    0x0165: "ontime_people_number",
    0x0166: "realtime_people_counting",
    0x0167: "sleep_presence",
    0x0168: "sleep_zone_mount_position",
    0x0169: "sleep_zone_size",
    0x0170: "wall_corner_mount_position",
    0x0171: "sleep_inout_state",
    0x0172: "dwell_time_enable",
    0x0173: "walking_distance_enable",
    0x0174: "walking_distance_all",
    0x0176: "sleep_event",
    0x0177: "sleep_event_descriptor",
    0x0178: "sleep_bed_height",
    0x0179: "overhead_height",
    0x0180: "fall_delay_time",
    0x0201: "debug_log",
    0x0202: "aux_data",
}


WRITE_HANDLER_HINTS = {
    0x400DEFC4: "cloud_sleep_event",
    0x400E20E0: "cloud_fall_delay_time",
    0x400E217C: "cloud_overhead_height",
    0x400E2218: "cloud_sleep_bed_height",
}


@dataclass(frozen=True)
class Section:
    name: str
    file_offset: int
    load_addr: int
    size: int

    def contains_vaddr(self, vaddr: int) -> bool:
        return self.load_addr <= vaddr < self.load_addr + self.size


def parse_esp_sections(data: bytes) -> list[Section]:
    if len(data) < 24 or data[0] != 0xE9:
        raise ValueError("not an ESP32 app image")

    sections: list[Section] = []
    offset = 24
    for index in range(data[1]):
        load_addr, size = struct.unpack_from("<II", data, offset)
        data_offset = offset + 8
        sections.append(Section(f"seg{index}", data_offset, load_addr, size))
        offset = data_offset + size
    return sections


def vaddr_to_offset(vaddr: int, sections: list[Section]) -> int:
    for section in sections:
        if section.contains_vaddr(vaddr):
            return section.file_offset + (vaddr - section.load_addr)
    raise ValueError(f"vaddr 0x{vaddr:08x} is outside parsed ESP image sections")


def offset_to_vaddr(offset: int, sections: list[Section]) -> int | None:
    for section in sections:
        start = section.file_offset
        end = section.file_offset + section.size
        if start <= offset < end:
            return section.load_addr + (offset - start)
    return None


def read_u8(data: bytes, sections: list[Section], vaddr: int) -> int:
    return data[vaddr_to_offset(vaddr, sections)]


def read_u16(data: bytes, sections: list[Section], vaddr: int) -> int:
    return struct.unpack_from("<H", data, vaddr_to_offset(vaddr, sections))[0]


def read_u32(data: bytes, sections: list[Section], vaddr: int) -> int:
    return struct.unpack_from("<I", data, vaddr_to_offset(vaddr, sections))[0]


def read_cstr(data: bytes, sections: list[Section], vaddr: int) -> str | None:
    try:
        offset = vaddr_to_offset(vaddr, sections)
    except ValueError:
        return None
    end = data.find(b"\0", offset)
    if end < 0:
        return None
    raw = data[offset:end]
    if not raw or any(byte < 0x20 or byte >= 0x7F for byte in raw):
        return None
    return raw.decode("ascii")


def extract_direct_dispatch(
    data: bytes,
    sections: list[Section],
    *,
    resource_table: int = 0x3F40AF5C,
    subid_table: int = 0x3F40AF38,
    type_table: int = 0x3F40AF24,
    count: int = 17,
) -> list[dict]:
    rows = []
    for index in range(count):
        resource_ptr = read_u32(data, sections, resource_table + index * 4)
        resource = read_cstr(data, sections, resource_ptr)
        subid = read_u16(data, sections, subid_table + index * 2)
        data_type = read_u8(data, sections, type_table + index)
        rows.append(
            {
                "index": index,
                "resource": resource,
                "subid": subid,
                "subid_name": SUBID_NAMES.get(subid, ""),
                "data_type": data_type,
                "data_type_name": DATA_TYPE_NAMES.get(data_type, ""),
                "resource_ptr": resource_ptr,
            }
        )
    return rows


def extract_descriptor_records(data: bytes, sections: list[Section]) -> list[dict]:
    rows = []
    for section in sections:
        if not (0x3FFB0000 <= section.load_addr < 0x40000000):
            continue
        start = section.file_offset
        end = section.file_offset + section.size - 32
        for offset in range(start, end + 1, 4):
            record_vaddr = offset_to_vaddr(offset, sections)
            if record_vaddr is None or record_vaddr % 4:
                continue
            read_handler = struct.unpack_from("<I", data, offset)[0]
            write_handler = struct.unpack_from("<I", data, offset + 4)[0]
            if not (0x400D0000 <= read_handler < 0x40200000 and 0x400D0000 <= write_handler < 0x40200000):
                continue
            resource_ptr = struct.unpack_from("<I", data, offset + 28)[0]
            resource = read_cstr(data, sections, resource_ptr)
            if not resource or not RESOURCE_RE.match(resource):
                continue
            packed = struct.unpack_from("<I", data, offset + 24)[0]
            data_type = packed >> 16
            subid = packed & 0xFFFF
            rows.append(
                {
                    "record_vaddr": record_vaddr,
                    "read_handler": read_handler,
                    "write_handler": write_handler,
                    "write_handler_hint": WRITE_HANDLER_HINTS.get(write_handler, ""),
                    "flags0": struct.unpack_from("<I", data, offset + 16)[0],
                    "flags1": struct.unpack_from("<I", data, offset + 20)[0],
                    "packed": packed,
                    "subid_low16": subid,
                    "subid_name": SUBID_NAMES.get(subid, ""),
                    "packed_high16": data_type,
                    "data_type": data_type,
                    "data_type_name": DATA_TYPE_NAMES.get(data_type, ""),
                    "resource": resource,
                    "resource_ptr": resource_ptr,
                }
            )
    return rows


def as_hex_row(row: dict) -> dict:
    out = dict(row)
    for key in [
        "subid",
        "data_type",
        "resource_ptr",
        "record_vaddr",
        "read_handler",
        "write_handler",
        "flags0",
        "flags1",
        "packed",
        "subid_low16",
        "packed_high16",
    ]:
        if isinstance(out.get(key), int):
            width = 2 if key == "data_type" else 4 if "subid" in key or key == "packed_high16" else 8
            out[key] = f"0x{out[key]:0{width}x}"
    return out


def print_tsv(rows: list[dict], keys: list[str]) -> None:
    print("\t".join(keys))
    for row in rows:
        display = as_hex_row(row)
        print("\t".join(str(display.get(key, "")) for key in keys))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path, help="ESP32 app image, e.g. aqara_fw2_0x220000_0x200000.bin")
    parser.add_argument("--format", choices=["json", "tsv"], default="tsv")
    parser.add_argument(
        "--descriptor-filter",
        default=r"^(1\.10\.85|1\.11\.85|14\.59\.85|4\.74\.85|4\.75\.85|14\.49\.85|14\.30\.85|14\.51\.85)$",
        help="regex for descriptor-table rows to print in TSV mode",
    )
    parser.add_argument(
        "--all-descriptors",
        action="store_true",
        help="print every descriptor-table row in TSV mode",
    )
    args = parser.parse_args()

    data = args.image.read_bytes()
    sections = parse_esp_sections(data)
    direct = extract_direct_dispatch(data, sections)
    descriptors = extract_descriptor_records(data, sections)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "image": str(args.image),
                    "sections": [asdict(section) for section in sections],
                    "direct_dispatch": direct,
                    "descriptor_records": descriptors,
                },
                indent=2,
            )
        )
        return 0

    print("# direct_dispatch")
    print_tsv(direct, ["index", "resource", "subid", "subid_name", "data_type", "data_type_name", "resource_ptr"])

    descriptor_re = re.compile(".*" if args.all_descriptors else args.descriptor_filter)
    filtered = [row for row in descriptors if descriptor_re.search(row["resource"])]
    print("\n# descriptor_records")
    print_tsv(
        filtered,
        [
            "record_vaddr",
            "resource",
            "subid_low16",
            "subid_name",
            "packed_high16",
            "data_type_name",
            "flags0",
            "flags1",
            "read_handler",
            "write_handler",
            "write_handler_hint",
        ],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
