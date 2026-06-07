# IWR6843AOP TI Research Notes - 2026-06-07

These notes connect TI's public IWR6843AOP documentation to the Aqara FP2 reverse-engineering work. The useful mental model is that the ESP32 is mostly a bridge/configuration host, while the IWR6843AOP runs the radar signal processing, tracking, sleep/fall/presence state logic, and any heart/breath extraction that Aqara exposes.

## Primary TI Sources

- Product page: <https://www.ti.com/product/IWR6843AOP>
- Datasheet: <https://www.ti.com/document-viewer/IWR6843AOP/datasheet>
- Industrial radar family technical reference manual: <https://www.ti.com/lit/ug/swru522e/swru522e.pdf>
- People counting/tracking reference design: <https://www.ti.com/tool/TIDEP-01000>
- TIDEP-01000 design guide: <https://www.ti.com/lit/ug/tidue71d/tidue71d.pdf>
- mmWave SDK: <https://www.ti.com/tool/MMWAVE-SDK>
- Radar Toolbox: <https://www.ti.com/tool/download/RADAR-TOOLBOX>
- IWR6843AOPEVM: <https://www.ti.com/tool/IWR6843AOPEVM>
- Flash support note: <https://www.ti.com/lit/an/sprach9g/sprach9g.pdf>
- DSP subsystem note: <https://www.ti.com/lit/an/swra621/swra621.pdf>
- ADC raw data capture note: <https://www.ti.com/lit/an/swra581b/swra581b.pdf>
- Smart-home radar overview: <https://www.ti.com/lit/wp/swra807/swra807.pdf>

## Chip Capabilities That Matter For FP2

- The IWR6843AOP is a 60-64 GHz FMCW radar SoC with 3 TX and 4 RX channels, antenna-on-package, an Arm Cortex-R4F at 200 MHz, a C674x DSP at 600 MHz, radar HWA, and about 1.75 MB on-chip RAM.
- TI describes the R4F as the object-detection/interface-control side and the C674x/HWA path as the heavy signal-processing side. This matches the FP2 dump: the most interesting stock image is the radar MSS/R4F appimage with sleep, presence, zone, and report strings.
- TI's autonomous mode loads the user application from external QSPI flash. The FP2 board exposes a QSPI test connector, and the ESP32 dump also contains `mcu_ota` TI `MSTR`/`RPRC` radar appimages. Direct radar-flash extraction/programming remains a strong path if ESP-mediated OTA becomes limiting.
- The device exposes two UARTs in TI demos. The TIDEP people-counting chain uses one UART for input configuration and a second UART for output/results. The FP2 stock integration instead uses a custom framed ESP32-to-radar UART at 890000 baud, but the same logical split still appears: host writes config SubIDs, radar reports tracking/sleep/fall data.
- The chip has a two-lane LVDS/HSI raw-data/debug path. The FP2's unpopulated edge FFC exposes two LVDS lanes plus clock/frame-clock lines, which lines up with TI's xWR16xx/IWR6843 raw ADC capture documentation and the DCA1000-style capture path.

## TI People-Counting Chain vs FP2

TI's people-counting reference design is directly relevant:

- Low-level processing produces point clouds from range/azimuth/elevation/Doppler/SNR.
- The DSP/HWA path does range processing, static clutter removal, Capon beamforming, CFAR, elevation estimation, and Doppler estimation.
- The R4F runs `gtrack` in the Data Path Manager model. The tracker consumes point cloud measurements and produces tracked objects with 3D position, velocity, and acceleration.
- TI's output model is TLV-like data over UART for point cloud, target list, and target index/metadata. FP2's protocol is not TI's standard TLV frame, but `0x0117 location_track_data`, `0x0155 people_counting`, `0x0159 sleep_data`, posture, and people-count reports are the Aqara-wrapped equivalents to target/tracker outputs.

Practical implication: when ESPHome sees no live map or people count, the failure is usually not "radar cannot see"; it is more likely one of these:

- wrong `work_mode`/configuration profile,
- `location_report_enable` not enabled,
- target classification/filter mode suppressing output,
- static clutter/sleep/static-target state machine holding or dropping tracks,
- radar app waiting for a calibration/config stage.

The 2026-06-07 ESPHome test matched this model: `work_mode=3`, `location_report_enable=true`, and `target_type_enable=false` restored `0x0117` target streaming and Home Assistant presence/people/posture updates.

## Sleep And Static Presence Clues

The TIDEP people-counting design guide gives a very useful term: `sleep2freeThre`. TI uses it when a target is in a static zone and associated only with static/zero-Doppler points; the threshold controls how many missed frames are required before the tracker frees the target.

This maps well to Aqara's sleep feature set:

- Stock radar strings already include `SleepData:`, `sleep tid:%d, count:%d, motion:%d, stage:%d`, `HR = %d,HC = %d##BR = %d,BC = %d`, `sleep_state:%d`, `sleep_event:%d`, and `sleep_inout:%d`.
- FP2 SubIDs around sleep include `0x0156 sleep_report_enable`, `0x0159 sleep_data`, `0x0161 sleep_state`, `0x0167 sleep_presence`, `0x0168 sleep_zone_mount_position`, `0x0169 sleep_zone_size`, `0x0171 sleep_inout_state`, `0x0176 sleep_event`, `0x0178 sleep_bed_height`, and probably mode-dependent values around `0x0175`/`0x0177`.
- TI's tracker model explains why sleep mode can preserve a person that becomes nearly static, while generic presence mode may drop or classify those points differently.

Reverse-engineering lead: search the radar MSS binary for constants near `600`, `100`, `10`, and `5` around the `SleepData:`/tracker-state code, and for code paths that classify zero-Doppler/static zones. Even if Aqara renamed the variables, the state machine should resemble TI's `det2active`, `det2free`, `active2free`, `static2free`, `exit2free`, and `sleep2free` behavior.

## Zones And Scene Geometry

TI's `gtrack` configuration uses sensor/scenery/behavior parameters: scene boundaries, static zones, allocation thresholds, state transition thresholds, and gating limits. The FP2's zone protocol should be treated as an Aqara-specific wrapper around the same class of geometry inputs.

Current FP2 zone-related SubIDs already line up with this:

- `0x0107/0x0109/0x0110/0x0114` for primary zone/edge/entry maps.
- `0x0151/0x0152/0x0153` for detection area settings and close/away behavior.
- `0x0202` edge state.
- `0x0168/0x0169/0x0170/0x0178/0x0179` for sleep/fall mounting geometry, bed height, overhead height, and wall/corner mounting.

ESPHome should eventually expose zones as structured geometry rather than raw bytes only:

- a room coordinate transform,
- zone rectangles/polygons or Aqara grid masks,
- edge/entrance zones,
- close/away zones,
- sleep bed rectangle plus mount position/bed height,
- fall overhead height and delay/sensitivity settings.

Do not assume all 40-byte maps are the final geometry source. TI's tracker may also receive compact bounds or profile-specific state parameters from separate SubIDs.

## Vital Signs And Heart/Breath Data

TI's Radar Toolbox includes vital-sign example material, and TI's public smart-home material explicitly points to "Vital Signs With People Tracking" for the radar toolbox. Treat source availability, prebuilt binaries, and visualizer/user-guide details as version-specific until we pull the exact toolbox package we want to compare against.

This matters for the FP2 because the stock radar firmware already contains heart/breath strings:

- `HR = %d,HC = %d##BR = %d,BC = %d`
- `SleepData:`
- `sleep tid:%d, count:%d, motion:%d, stage:%d`

Working hypothesis:

- heart/breath estimates are generated on the IWR6843AOP, not on the ESP32;
- Aqara reports a compact subset through `0x0159 sleep_data` and nearby sleep-state/event reports;
- `HR/HC/BR/BC` likely means heart rate/count and breath rate/count or confidence/counter fields;
- the 12-byte `0x0159` payload should be traced from the radar sleep packer before ESPHome exposes named vitals.

The current decoder should continue preserving unknown bytes in `0x0159` until the packer is proven.

## Calibration And Empty-Room Setup

TI devices have built-in calibration/self-test, but Aqara's user-facing "empty room calibration" is likely an application-level baseline/scene-reset operation layered on top of normal RF calibration.

Known FP2 leads:

- `0x0113 reset_absent_status` is still the best empty-room calibration/reset candidate.
- `0x0305 radar_calibration_result` is backed by the MSS string `query radar calibration status:%d`, but host READ attempts timed out in the ESPHome test.
- The app's setup flow should be captured while selecting Presence/Fall/Sleep mode and while pressing the empty-room calibration action.

TI documentation suggests there may be several independent "calibration" concepts:

- RF/front-end self calibration across process/frequency/temperature.
- Tracker/static-clutter baseline or scene model reset.
- App-level room geometry and mode profile setup.

ESPHome should label `0x0113` conservatively as "Calibrate Empty Room / Reset Absent Baseline" until the app setup capture proves exact semantics.

## Raw Capture And Hardware Access Plan

The FP2 board exposes two valuable radar-side debug surfaces:

- QSPI connector: direct access to radar external flash signals.
- LVDS edge FFC: likely raw ADC/debug stream from the IWR6843AOP HSI/LVDS interface.

Recommended experiments:

1. Use the existing ESP32 dump and `mcu_ota` carving as the safest radar-appimage source of truth.
2. If deeper firmware work is blocked by ESP-mediated updates, dump the radar QSPI flash directly and compare it against `mcu_ota` appimages.
3. Sniff the ESP32/radar UART at 890000 baud while changing Aqara modes and calibration settings.
4. If we want raw radar data, adapt the LVDS FFC to a DCA1000-compatible capture setup or equivalent logic analyzer/front-end. Confirm voltage levels first; README currently has the FFC supply as "some voltage, 3.3V?" while the radar LVDS domain may not be 3.3 V.
5. Do not expect the exposed ESP32 COM5 UART0 to show runtime logs; prior ROM `ets_printf`/beacon patches did not produce readable runtime text.

## Next Firmware RE Tasks

- Load the radar MSS RPRC into Ghidra/IDA with the TI docs beside it, and name functions around DPM/tracker/sleep strings instead of treating them as opaque handlers.
- Trace `SleepData:` to the final `0x0159` report packer.
- Search for TI tracker-style state parameters near the sleep code: `det2active`, `det2free`, `active2free`, `static2free`, `exit2free`, `sleep2free`, allocation SNR/point thresholds, gating limits, and scene bounds.
- Capture app-driven mode values for `0x0116`: current evidence proves `3 = presence/live map`; the remaining accepted values `5`, `8`, and `9` need mode mapping.
- Capture fall-mode setup, especially `0x0123 fall_sensitivity`, `0x0179`/`0x0180` height or delay semantics, and any calibration writes.
- Capture sleep-mode setup, especially `0x0168`, `0x0169`, `0x0178`, `0x0175`, `0x0176`, and `0x0177`.
- Compare TI Radar Toolbox vital-sign UART frames with FP2 `0x0159` records to identify whether Aqara reused field order, units, or confidence counters.
- If testing patched stock radar firmware, sniff radar UART for `0x0201 debug_log`; COM5 should remain recovery/flashing only.
