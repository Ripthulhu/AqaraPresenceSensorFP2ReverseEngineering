# FP2 Firmware Reverse-Engineering Findings - 2026-06-04

These notes summarize the current dump and build-server analysis for the Aqara FP2 firmware. They are intentionally conservative: fields marked "candidate" still need function-level confirmation in the ESP32 and TI radar binaries.

## Dump

- Source: ESP32 flash dump from a live FP2 over UART bootloader.
- Size: 16 MiB.
- SHA-256: `6b42813080a437d8c15511065a313349b025d430f76b27d1d6fd0a8c0c41899d`.
- The ESP32 image contains an `mcu_ota` partition with TI mmWave radar appimages in TI `MSTR` / `RPRC` containers.

## Radar Firmware Target

The strongest radar-side target is appimage 4 MSS:

- RPRC core: MSS ARM.
- Load region of interest: `0x00000100`, size `0x30104`.
- Candidate ARM entry window starts near file offset `0x2879c` and branches into Thumb code near `0x287cc`.
- Useful strings in this appimage include sleep, presence, area, detection-zone, and boundary-box logs.

High-signal radar strings:

- `SleepData:`
- `frame = %u dynamicPnt = %d staticPnt = %d snrSum = %.0f`
- `sleep tid:%d, count:%d, motion:%d, stage:%d`
- `HR = %d,HC = %d##BR = %d,BC = %d`
- `Sleep_report_enable:%d data[4]:%d`
- `sleep_event:%d`
- `sleep_state:%d`
- `sleep_inout:%d`
- `Presence set %d points, doppler = %.2f, at (%.2f, %.2f, %.2f)`
- `AreaPresence: result=%d, energy_wave=%.0f, threshold=%.0f, X:%.2f, Y:%.2f`
- `Detection_area_type[%u]=%u`
- `Detection_area_close_away_enable[%u]=%u`
- `function_set_Detection_area_settings`
- `sensorPosition 2 0 0`
- `presenceBoundaryBox -1.5 1.5 0 2.5 -3 3`

MSS report-helper anchors:

- `tools/fp2_mss_report_call_summary.py` identifies small Thumb wrappers that call the common radar report helper at `0x0001c7c4`.
- Build-server artifact `mss_report_call_summary.tsv` and local copy `dumps/buildserver_reports/appimage4_mss_report_call_summary.tsv` summarize the current call sites.
- Confirmed simple report wrappers include `sleep_report_enable` (`0x0156`, call `0x0002c52a`), `sleep_presence` (`0x0167`, call `0x0002c9c8`), `sleep_event` (`0x0176`, call `0x0002d036`), `sleep_state` (`0x0161`, call `0x0002d074`), and `sleep_inout_state` (`0x0171`, call `0x0002dfdc`).
- The 12-byte `sleep_data` (`0x0159`) report does not appear to use that simple helper path directly. Its packer still needs tracing, likely through the larger sleep-processing/send code around the `SleepData:` and `sleep tid:%d, count:%d, motion:%d, stage:%d` strings.

## ESP32 Cloud Resource Mapping

The ESP32 app has a direct dispatch table that maps Aqara cloud/app resource ids to radar UART SubIDs. This table is more reliable than the earlier ACK/resource literal adjacency because it is the table used by the cloud write dispatcher.

Extractor:

```sh
python tools/fp2_extract_cloud_tables.py dumps/extracted/aqara_fw2_0x220000_0x200000.bin
python tools/fp2_extract_cloud_tables.py dumps/extracted/aqara_fw2_0x220000_0x200000.bin --all-descriptors
python tools/fp2_analyze_write_handlers.py dumps/extracted/aqara_fw2_0x220000_0x200000.bin dumps/buildserver_reports/aqara_fw2_seg3_irom_objdump.txt
```

Direct write-dispatch table:

| Resource | Radar SubID | Firmware handler/log name | Type | Notes |
| --- | ---: | --- | --- | --- |
| `14.55.85` | `0x0105` | `monitor_mode` | `UINT8` | Not `14.47.85`; the older ACK-derived table was shifted here. |
| `14.51.85` | `0x0122` | `left_right_reverse` | `UINT8` | App/firmware left-right reverse setting. |
| `14.1.85` | `0x0111` | `presence_detection_sensitivity` | `UINT8` | The app view reuses this in sleep-mode UI as sleep monitoring sensitivity. |
| `14.47.85` | `0x0106` | `closing_setting` | `UINT8` | Proximity sensing distance/closing setting. |
| `4.210.85` | `0x0153` | `detect_zone_close_away_enable` | `UINT16` | Packs zone id and value. |
| `14.30.85` | `0x0123` | `fall_sensitivity` | `UINT8` | Confirmed by dispatch table; this resolves the app-label conflict. |
| `4.68.85` | `0x0156` | `sleep_report_enable` | `BOOL` | |
| `4.69.85` | `0x0157` | `posture_report_enable` | `BOOL` | |
| `4.70.85` | `0x0158` | `people_counting_report_enable` | `BOOL` | |
| `4.71.85` | `0x0162` | `people_number_enable` | `BOOL` | |
| `4.72.85` | `0x0163` | `target_type_enable` | `BOOL` | App label: AI Person Detection. |
| `14.58.85` | `0x0168` | `sleep_zone_mount_position` | `UINT8` | |
| `14.58.700` | `0x0169` | `sleep_zone_size` | `UINT32` | High 16 bits = width, low 16 bits = length. |
| `14.57.85` | `0x0170` | `wall_corner_mount_position` | `UINT8` | |
| `4.74.85` | `0x0172` | `dwell_time_enable` | `UINT8` | Direct dispatcher uses a byte path; descriptor-table type is `BOOL`. |
| `4.75.85` | `0x0173` | `walking_distance_enable` | `UINT8` | Direct dispatcher uses a byte path; descriptor-table type is `BOOL`. |
| `14.49.85` | `0x0116` | `work_mode` | `UINT8` | App label: Detection Mode. The write handler accepts mode values `3`, `5`, `8`, and `9`. |

Secondary descriptor-table rows around the newer height/delay settings:

| Resource | Radar SubID | Descriptor type | Write handler/log name | Notes |
| --- | ---: | --- | --- | --- |
| `0.121.85` | `0x0175` | `UINT16` | handler-string lead: `sleep_inout_state` | Descriptor-only lead. The handler summary sees a 1-byte radar write (`a10=1`), but adjacent older descriptor rows show callback/log-name shifts, so the semantic role is still open. |
| `13.3.85` | `0x0176` | `UINT8` | sleep_event | This is the older known sleep-event resource/SubID. |
| `1.10.85` | `0x0177` | `UINT16` | `cloud_sleep_event` | Handler logs `sleep_event` and calls the common radar write helper with `a10=1`; live capture should determine whether this is a cloud-side selector or a second sleep-event attribute. |
| `1.11.85` | `0x0178` | `UINT16` | `cloud_sleep_bed_height` | Handler logs `sleep_bed_height`, stores a 16-bit value, and calls the radar write helper with `a10=2` on the value path. |
| `14.59.85` | `0x0179` | `UINT16` | `cloud_overhead_height` | Handler logs `overhead_height`, stores a 16-bit value, and calls the radar write helper with `a10=2`. The cached app view formats this resource as fall detection delay (`0` = at once, nonzero = seconds), so semantic naming still needs live capture. |
| `4.41.705` | `0x0180` | `BLOB2` | `cloud_fall_delay_time` | Handler extracts/logs a fall-delay value, stores a 16-bit value, and calls the radar write helper with `a10=2`; the descriptor `BLOB2` is cloud-side shape, not necessarily final radar UART payload type. |

Practical corrections:

- The old ACK/resource table is useful for finding nearby literals, but it should not be used as the authoritative incoming cloud write map.
- The descriptor `packed_high16` type appears to describe the cloud/resource value shape. Some handlers parse a richer cloud value and then send a simpler radar UART value, so do not blindly copy descriptor types into the UART decoder without a capture.
- Descriptor write-handler strings are heuristic evidence. Many older descriptor rows show callback/log-name adjacency shifts, while the tail rows for `1.10.85`, `1.11.85`, `14.59.85`, and `4.41.705` line up cleanly with their static handler strings and common radar-write calls.

## ESP32 Handler Names

The ESP32 firmware contains cloud handler names that line up with the UART protocol table:

- `cloud_fall_delay_time`
- `cloud_overhead_height`
- `cloud_sleep_bed_height`
- `cloud_walking_distance_enable`
- `cloud_dwell_time_enable`
- `cloud_wall_corner_mount_position`
- `cloud_sleep_zone_size`
- `cloud_sleep_zone_mount_position`
- `cloud_target_type_enable`
- `cloud_people_number_enable`
- `cloud_people_counting_report_enable`
- `cloud_sleep_report_enable`
- `cloud_thermodynamic_chart_enable`
- `cloud_fall_detection_sensitivity`
- `cloud_presence_detection_sensitivity`
- `cloud_monitor_mode`
- `radar_sleep_presence`
- `radar_fall_detection`

## Stock ESP32 Debug Patch Workbench

`tools/fp2_stock_patch_workbench.py` parses the stock ESP32 app image, validates the ESP image checksum/appended validation hash, applies named byte patches, and rebuilds both integrity fields.

Validated active app:

- Partition image: `aqara_fw2_0x220000_0x200000.bin`.
- Original SHA-256: `3cbd1c1b6fb5b3f53a84b762013460f26f8a1533ff8d4ed5d61c96ad9a80a8eb`.
- Patched `relax-log-gates` SHA-256: `c3cf6f64c63b59a828fd468f65578a2537092dad22d4be2332d06e3359136dc6`.
- ESP checksum after patch: `0x8a` at app offset `0x18785f`.
- ESP appended validation hash after patch: `c8e5a9a24c42144e06173d6ad91fa1569fb5a4a4fd2ef9270eb6a092a22ceefd`.
- Independent `esptool image_info` validation passes for both checksum and validation hash.
- Current device state after UART experiments: the active `fw2` partition has been restored to this cleaner `relax-log-gates` image for app pairing.

The global ESP log-level byte is initialized to `0x07` at vaddr `0x3ffb2b58` / app offset `0x4bc24`. That means the stock image already satisfies the `>= 7` verbose checks at boot. Simply raising the boot-time log level is not a useful patch.

The `relax-log-gates` variant keeps the original branch layout but changes selected `bltui a10, 7, skip` checks to `bltui a10, 2, skip`. This makes these stock log/report paths survive runtime log-level downgrades while leaving a hard-off state for levels 0/1:

| Handler path | VAddr | App offset | Before | After |
| --- | ---: | ---: | --- | --- |
| `sleep_data` cloud log gate | `0x400df3de` | `0x5f3de` | `b6 7a 32` | `b6 2a 32` |
| `people_counting` cloud log gate | `0x400df44e` | `0x5f44e` | `b6 7a 32` | `b6 2a 32` |
| `thermodynamic_chart_data` cloud log gate | `0x400df64e` | `0x5f64e` | `b6 7a 32` | `b6 2a 32` |
| `radar_debug_log_report` gate | `0x400df6ad` | `0x5f6ad` | `b6 7a 30` | `b6 2a 30` |
| `radar_sleep_data` gate | `0x400e490d` | `0x6490d` | `b6 7a 2f` | `b6 2a 2f` |
| `radar_thermodynamic_chart_data` gate | `0x400e4a09` | `0x64a09` | `b6 7a 2f` | `b6 2a 2f` |

The patched active app was written only to the `fw2` app partition at flash offset `0x220000`; bootloader, NVS, `fw1`, `mcu_ota`, factory, and PHY partitions were not modified. A normal power-cycle boot capture at 115200 produced no UART bytes, so the board/stock app appears to suppress UART output or route these logs away from the exposed UART despite the internal log sites.

Operational note, 2026-06-05: do not rely on DTR-driven bootstrapping for this bench setup. The download strap must be handled manually from now on; automation should treat COM5 as data/flash only and use outlet 3 only for power cycling after the user has physically selected normal boot or download mode.

Additional UART-console experiments:

- The ESP32 ROM map in ESP-IDF identifies `ets_printf` at `0x40007d54`, `uart_tx_one_char` at `0x40009200`, and `uart_tx_switch` at `0x40009028`.
- `rom-printf-radar` redirects the radar/resource-handler `printf` literal pool at vaddr `0x400d077c` / app offset `0x5077c` from `0x401c6af4` to ROM `ets_printf`. SHA-256: `95a5bacc4ed10f9be455810d892ca6d7180d3b84bcf5aa81cf458927047d28b9`. The image validates, flashes, and boots, but boot captures at 115200/890000/921600 do not produce readable text.
- `rom-printf-all` additionally redirects the late `printf` pool at `0x400d413c` and the broad ESP log pool at `0x4010f998`. SHA-256: `2558dffc2b2e2dfb5635988e4bc57f4c46bce2c7458f7825160476d8a15626a7`. This image validates but was not flashed because the narrower ROM printf probe did not expose text.
- `uart-boot-beacon` redirects the CPU-start boot-log function pointer at `0x40080470` from ROM `ets_printf` to ROM `uart_tx_one_char` and replaces five boot-log format pointer loads with direct low-byte beacon values (`B`, `I`, `R`, `D`, newline). SHA-256: `80aa92c52ef4ff633a618e7535f4767f91b4ceb904b51dcb7d4efda11309f013`. The image validates, flashes, and boots, but a baud sweep at 74880, 115200, 230400, 460800, 890000, and 921600 produced only short non-text byte bursts.
- The app entrypoint already contains ROM `ets_printf` boot logs gated by a variable initialized to `3` at vaddr `0x3ffb016c`, including strings such as `Unicore app`, `Pro cpu up.`, and `Single core mode`. Because those stock boot logs are already eligible to run yet remain invisible, UART0 console output appears disabled by output routing/strapping or by the exposed wiring, not merely by log-level gates.
- Practical implication: for stock-firmware reverse engineering, the exposed COM5 UART0 path is reliable for ROM download/flashing but is not currently a useful runtime text console. The next useful runtime visibility paths are app/cloud pairing, HomeKit/Aqara traffic, or attaching a second sniffer to the radar UART pins (`GPIO19` TX, `GPIO18` RX, `890000` baud).

## Current Decoder Implications

- `sleep_data` (`0x0159`) records are 12 bytes in observed captures.
- The decoder now names stock-firmware descriptor leads `0x0175` through `0x0180`, but `0x0175`, `0x0177`, and `0x0180` still need live UART/app validation before treating their payload formats as final.
- Build-server artifact `write_handler_summary.tsv` and local copy `dumps/buildserver_reports/active_esp_write_handler_summary.tsv` summarize the current descriptor-handler evidence.
- The radar MSS strings and Thumb windows confirm internal sleep-processing fields for target id, count, motion, and stage. The adjacent packet packer is not yet fully traced, so current decoder output still maps `target_id = byte 0` and candidate `count/motion/stage = bytes 9/10/11`, while preserving bytes 1-8 as unknown.
- `people_counting` (`0x0155`) is still a candidate 7-byte record. The decoder exposes it as `id`, `value_a`, `value_b`, and `value_c` until the handler is confirmed.
- `debug_log` (`0x0201`) BLOB1 strings are useful and should be kept enabled in test firmware builds when possible.

## Next RE Tasks

- Load appimage 4 MSS into Ghidra/IDA as little-endian ARM/Thumb and anchor analysis on the strings above.
- Trace callers of `SleepData:` and `sleep tid:%d, count:%d, motion:%d, stage:%d` through the non-`0x1c7c4` send path to confirm the 12-byte sleep record layout.
- Treat the exposed ESP UART0 as a flashing/recovery interface unless new wiring proves otherwise. Direct ROM `ets_printf` and `uart_tx_one_char` patches did not produce readable runtime logs on COM5.
- The patched-stock sensor is now paired to the Aqara app. Use live app mode/settings changes to watch which resources cause writes to `sleep_report_enable`, `people_counting_report_enable`, `target_type_enable`, `dwell_time_enable`, and `walking_distance_enable`.
- Aqara Home logcat now confirms app/cloud resource `4.22.700` as the live FP2 target-position stream. Use this as the app-side correlation point while sniffing radar UART `0x0117 location_track_data`.
- Router capture now identifies FP2 cloud TCP topics on `43.157.55.49:11111`, including cloud-to-device `lumi/gw/res/write` and device-to-cloud `lumi/res/report/attr`. Use these topic frames as the network-side correlation point for app toggles.
- Prioritize `14.49.85` mode-change captures. The app uses it for Detection Mode and derives the active dynamic endpoint array from it.
- `14.30.85` is resolved as `fall_sensitivity` / `0x0123`; keep the app label and decoder naming aligned with that direct dispatch table.
- Resolve the remaining `14.59.85` semantic conflict with a live app-toggle/radar-UART capture. Firmware maps it to `cloud_overhead_height` / `0x0179`, while the cached app view formats it as fall detection delay.
- Trace or capture `4.41.705` writes before renaming it publicly; the descriptor table maps it to `cloud_fall_delay_time` / `0x0180`, but the same resource id appears in zone-label contexts.
- Capture `1.10.85` / `0x0177` and `0.121.85` / `0x0175` writes if the app exposes controls that touch them; static analysis suggests 1-byte radar writes even where descriptor types say `UINT16`.
- Use the decoder XMODEM extraction (`decoder decode --xmodem-out`) on firmware-update UART captures to compare OTA appimages against the dumped `mcu_ota` partition.
