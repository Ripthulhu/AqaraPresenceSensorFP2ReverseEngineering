# Aqara App Live-Pairing Findings - 2026-06-05

These notes summarize the first useful live capture with the FP2 paired to the Aqara Home app on the lab router. They intentionally avoid account tokens, app keys, and full local database dumps; those artifacts are useful for local RE but should not be committed.

## Capture Scope

- App package: `com.lumiunited.aqarahome.play`
- App version: `6.1.6` (`versionCode` `6553`)
- Target model: `lumi.motion.agl001`
- Target firmware version reported by the app: `1.3.3_0002.0099`
- Local network observation: the living-room FP2 was present at `192.168.50.100`; the MAC suffix matched the app/device-id suffix. Other paired FP2s were also visible on the subnet, but exact local identifiers are intentionally omitted here.
- Main cloud/API hosts observed:
  - `rpc-ger.aqara.com`
  - `track-ger.aqara.com`
  - `cdn.aqara.com`
  - `coap-ger.aqara.com` appears in local app configuration
- Useful local app tables:
  - `base_database.device_table`
  - `base_database.view_config_info`
  - `alink.device_card_trait`
  - `home.panel_card`

The phone-side packet capture was mostly phone-to-cloud TLS. The live track path appears to be app/cloud mediated: logcat shows `Fp2TrackSocketManager: subscribe success`, followed later by unsubscribe/close stacks in OkHttp `RealWebSocket`. This capture did not reveal a local LAN plaintext channel from the phone to the FP2.

The living-room FP2 did not answer conservative TCP reachability checks on ports `80`, `443`, `1883`, `5353`, `7788`, `8080`, `8443`, `8883`, or `9999` from the workstation. Router-side traffic capture is a better next step than local HTTP probing.

## Router-Side Capture - 2026-06-05 18:19

After the sensor came back online, a bounded 180-second router capture was taken from the lab router bridge while the paired Note 8 had the FP2 page open.

Artifacts:

- Build-server bundle: `/srv/ai-agent/artifacts/fp2-firmware-research/live-capture-20260605-111739`
- Router PCAP: `br0-20260605-181906-180s.pcap`
- PCAP SHA-256: `c349173671b15524b74289241fd33454ac29421c88d247401780d840f7009158`
- FP2 TCP payload table: `fp2_tcp_payloads.tsv`
- FP2 cloud-topic summary: `fp2_tcp_lumi_topics.tsv`
- FP2 payload-shape summary: `fp2_tcp_payload_shape_summary.txt`
- Local decoded app-push summaries:
  - `artifacts/live-capture-20260605-111739/app_position_push_events.tsv`
  - `artifacts/live-capture-20260605-111739/app_position_push_summary.fixed.tsv`

Network observations:

- Lab-router FP2 lease during this capture: `10.88.0.162`, MAC `54:ef:44:62:de:8c`.
- Router ARP and `arp-scan` both saw the device, and ICMP ping worked from both Kali/build-server and the router.
- HTTP/HTTPS/8080 checks against `10.88.0.162` returned the ASUS router login page, not an FP2 service. Treat those responses as gateway behavior until proven otherwise.
- The FP2 maintained cloud TCP sessions to `43.157.55.49:11111`.
- The Aqara Hub M100 at `10.88.0.206` talked to `43.157.55.49:11121` and queried `_aqara-setup._tcp.local`.
- The Note 8 exposed TLS SNI for `rpc-ger.aqara.com` and `cdn.aqara.com`; DNS also included `track-ger.aqara.com`.

Conversation summary from the PCAP:

| Endpoint pair | Frames / bytes | Notes |
| --- | ---: | --- |
| `10.88.0.162` <-> `43.157.55.49` | 441 / 79 kB | FP2 cloud session, mostly port `11111`. |
| `10.88.0.50` <-> `162.62.215.19` | 584 / 200 kB | Note 8 to `rpc-ger.aqara.com`. |
| `10.88.0.50` <-> `43.152.42.241` | 533 / 293 kB | Note 8 to `cdn.aqara.com`. |
| `10.88.0.206` <-> `43.157.55.49` | 20 / 4 kB | Aqara Hub M100 cloud session, port `11121`. |

## FP2 Cloud TCP Protocol Leads

The FP2-owned `43.157.55.49:11111` traffic is not ordinary TLS. Payloads are mostly binary, but topic strings are visible enough to classify report/read/write direction.

`tools/fp2_extract_cloud_topics.py` summarizes payload TSV exported by tshark. Current topic counts:

| Topic | Total | FP2 -> cloud | Cloud -> FP2 |
| --- | ---: | ---: | ---: |
| `lumi/func/res/report` | 68 | 68 | 0 |
| `lumi/res/report/attr` | 27 | 27 | 0 |
| `lumi/gw/res/write` | 6 | 0 | 6 |
| `lumi/res/report/examination` | 3 | 3 | 0 |
| `lumi/central/active/inquiry` | 2 | 2 | 0 |
| `lumi/dev/heartbeat` | 1 | 1 | 0 |
| `lumi/gw/res/read` | 1 | 0 | 1 |

Outer payload shape lead:

| Field | Observation |
| --- | ---: |
| TCP payload rows with data | 178 |
| First two payload bytes equal big-endian `tcp.len - 2` | 175 |
| Common header bytes after length | `48 01 00 00` (100 frames), `68 45 00 00` (67 frames), `48 02 ff ff` (7 frames), `68 45 ff ff` (3 frames) |

Interpretation:

- The first two bytes are probably a big-endian payload length excluding the length field.
- `48 01 00 00` and `48 02 ff ff` appear on topic-bearing command/report payloads; `68 45 ...` appears on short response/ack-like frames.
- FP2-to-cloud topics are slash strings such as `lumi/res/report/attr`.
- Cloud-to-FP2 `lumi/gw/res/write` / `read` appears in a compact segmented form (`lumi`, then length-prefixed path parts like `gw`, `res`, `write`), which the extractor normalizes to slash paths.
- Targeted app toggles should now be captured with router PCAP plus app logcat; cloud `lumi/gw/res/write` frames are the best place to correlate app setting writes before they become ESP32 cloud-resource handlers and radar UART writes.

## Live Position Pushes - `4.22.700`

`tools/fp2_extract_app_position_pushes.py` decodes Aqara Home logcat lines containing `H5Invoke("handleWSPushPositionData", ...)`. The app logs the nested `result.value` field as a double-escaped JavaScript string, so a plain regex/outer-JSON parser will undercount these events.

Decoded from `note8-logcat-fp2-filtered.txt`:

| Field | Observation |
| --- | --- |
| Decoded H5 position events | 58 |
| `4.22.700` events | 56 |
| `13.27.85` events | 2 scalar events, values `6` and `7`; role still unclassified. |
| Model | `lumi.motion.agl001` |
| Subject | `lumi1.54ef4462de8c` |
| Push type | `view_subscribe` |
| `4.22.700` value shape | JSON array of 20 target slots. |
| Active-target field set | `rangeId`, `x`, `y`, `targetType`, `id`, `state`. |
| Inactive-target shape | `rangeId` empty, `x=0`, `y=0`, `targetType=0`, `state="0"`. |

Active target summary:

| Target id | Active frames | App `x` range | App `y` range | `rangeId` values | `targetType` values |
| ---: | ---: | --- | --- | --- | --- |
| `0` | 56 | `165..297` | `129..143` | `0` | `0` |
| `3` | 28 | `120..286` | `123..157` | `0` mostly, one `1` | `0` |

Frame activity histogram:

| Active targets | Frames |
| ---: | ---: |
| 0 | 2 |
| 1 | 28 |
| 2 | 28 |

Interpretation:

- `4.22.700` is the app/cloud live-position stream feeding the FP2 H5 view.
- The app view receives a fixed 20-slot target array even when only one or two targets are active.
- App coordinates are not yet proven to be raw radar UART coordinates. They need to be correlated against simultaneous `0x0117 location_track_data` UART sniffing.
- `targetType` is always `0` in this capture, so AI target classification still needs a capture with the app's AI/person-detection feature toggled and a suitable moving object.

## Live Capture Refresh - 2026-06-07

The paired "Living Room Sensor" was reachable again at `10.88.0.162` / `54:ef:44:62:de:8c`, subject `lumi1.54ef4462de8c`. The Note 8 app was on `10.88.0.50:5555`.

Artifacts:

- `artifacts/live-capture-20260607-fresh-idle`
- `artifacts/live-capture-20260607-living-room-liveview`
- `artifacts/live-capture-20260607-zone-management`

Idle capture:

| Field | Observation |
| --- | --- |
| Router PCAP | `br0-20260607-012856-120s.pcap`, SHA256 `a27eff87b2dc2180e21d2105883f4edfadbc6c0b484f76d467274148f50f418f` |
| TCP payload rows | 12 |
| Length check | 12/12 rows had first two bytes equal to `tcp.len - 2`. |
| Topics | `lumi/dev/heartbeat` 4, `lumi/res/report/attr` 2. |
| H5 position pushes | 0 decoded events. |

Living-room live-view capture:

| Field | Observation |
| --- | --- |
| Router PCAP | `br0-20260607-013633-120s.pcap`, SHA256 `f43856df4e4f21bcc59b44598f3d1255f6e54d17995a957130805698f21710bd` |
| TCP payload rows | 402 |
| Length check | 402/402 rows had first two bytes equal to `tcp.len - 2`. |
| Header counts | `48 01 00 00`: 199, `68 45 00 00`: 199, `48 02 ff ff`: 2, `68 45 ff ff`: 2. |
| Cloud topics | `lumi/func/res/report` 159, `lumi/res/report/attr` 36, `lumi/dev/heartbeat` 4, `lumi/gw/res/write` 2. |
| H5 position events | 197 decoded events, 0 parse errors. |
| H5 attrs | `4.22.700`: 195 events, `13.27.85`: 2 scalar events. |

Live-view `4.22.700` target summary:

| Target id | Active frames | App `x` range | App `y` range | `rangeId` values | `targetType` values |
| ---: | ---: | --- | --- | --- | --- |
| `1` | 195 | `86..299` | `52..217` | `0`: 191, `1`: 4 | `0` |
| `3` | 195 | `106..347` | `38..320` | `0`: 194, `1`: 1 | `0` |
| `5` | 125 | `285..349` | `250..342` | `0`: 125 | `0` |
| `9` | 19 | `286..335` | `295..369` | `0`: 19 | `0` |

The active-target histogram was 2 targets for 51 frames and 3 targets for 144 frames. The scalar `13.27.85` events were:

| App time | Resource | Source | Value |
| --- | --- | --- | --- |
| `06-07 01:36:25.747` | `13.27.85` | `10,,1780788986220,0.trg=0,,` | `6` |
| `06-07 01:37:04.693` | `13.27.85` | `10,,1780789025078,0.trg=0,,` | `7` |

The live-view H5 page also polled `/res/statistics/log` about every 10 seconds with `resourceIds` `["0.62.85","0.63.85"]` and `aggrTypes` `[6]`. These likely back the visible cards such as presence duration / visits / distance, but exact card-to-resource mapping still needs response correlation.

Zone-management capture:

| Field | Observation |
| --- | --- |
| Router PCAP | `br0-20260607-014225-90s.pcap`, SHA256 `e6084e7da4348bdb50c1510a7bdf369ea515e8cdb2a87c7df9905177b42e4c98` |
| Screen | `note8_zone_screen.png` showed Zone Management with `Detection Zone 1`, `Detection Zone 2`, `Edge`, and several `exits and entrances` stickers. |
| TCP payload rows | 264 |
| Length check | 264/264 rows had first two bytes equal to `tcp.len - 2`. |
| Header counts | `48 01 00 00`: 130, `68 45 00 00`: 130, `48 02 ff ff`: 2, `68 45 ff ff`: 2. |
| Cloud topics | `lumi/func/res/report` 119, `lumi/res/report/attr` 8, `lumi/dev/heartbeat` 3, `lumi/gw/res/write` 2. |
| H5 position events | 152 decoded `4.22.700` events, all with 4 active targets. |

The Zone Management page did these app-side reads/writes when opened:

| App bridge call | Resource / endpoint | Notes |
| --- | --- | --- |
| `queryTransfer` GET | `/devex/radar/range/background/query` | Likely background/floorplan/radar range data for the editable zone map. |
| `queryTransfer` POST | `/res/query/by/resourceId`, option `13.35.85` | Zone-page resource read; M100 `ha_master` also contains `13.35.85` near the coordinate-data run. |
| `subscribeSubDevices` | prop `14.49.85` | Work-mode subscription; failed locally with `Client id is empty`, then the page issued a direct query. |
| `queryTransfer` POST | `/res/query/by/resourceId`, option `14.49.85` | Work mode / detection mode. |
| `queryTransfer` POST | `/res/query/by/resourceId`, option `3.51.85` | Whole-device occupancy; M100 maps this FP2 resource to `2.160.33000.1`. |
| `queryTransfer` POST | `/res/write` x2 | Page-open writes were observed in logcat, but the compact cloud write body is not decoded yet. |

Zone edit-mode long-press capture:

| Field | Observation |
| --- | --- |
| Artifact path | `artifacts/live-capture-20260607-zone-edit-longpress-router` |
| Router PCAP | `br0-20260607-zone-edit-longpress-90s.pcap`, SHA256 `6cce4742f886298571e8fe3f0b0758caaba5a3624a81a95debb9ab6c956c2235` |
| Screen state | The app was in `Detection Zone 2` edit mode. The accidental shape edit was discarded with the app's unsaved-change `Exit` prompt; final screenshot returned to Zone Management. |
| TCP payload rows | 260 |
| Length check | 260/260 rows had first two bytes equal to `tcp.len - 2`. |
| Header counts | `48 01 00 00`: 128, `68 45 00 00`: 128, `48 02 ff ff`: 2, `68 45 ff ff`: 2. |
| Cloud topics | `lumi/func/res/report` 119, `lumi/res/report/attr` 6, `lumi/dev/heartbeat` 3, `lumi/gw/res/write` 2. |
| H5 position events | 126 decoded `4.22.700` events, all with 4 active targets. |
| Edit-mode writes | `/res/write` wrote `{"4.22.85":1}` twice, at `06-07 01:56:50.890` and `06-07 01:57:50.893`. |

Edit-mode `4.22.700` target summary:

| Target id | Active frames | App `x` | App `y` | `rangeId` values | `targetType` values |
| ---: | ---: | ---: | ---: | --- | --- |
| `1` | 126 | `294` | `106` | `0`: 126 | `0` |
| `3` | 126 | `279` | `254` | `0`: 126 | `0` |
| `4` | 126 | `293` | `180` | `0`: 126 | `0` |
| `5` | 126 | `276` | `295` | `0`: 126 | `0` |

Interpretation:

- `4.22.700` is now confirmed across normal live view and Zone Management as the live app/cloud target stream.
- `13.27.85` behaves like an event/trigger scalar, not a coordinate stream. The M100 bridge maps it to `3.161.33002.1`, so it is likely a motion/event trait.
- `3.51.85` is reinforced as whole-device occupancy by both app cache and M100 bridge mapping.
- `13.35.85` is a new zone-page lead. It sits near `4.22.700` in the M100 advanced motion resource run and should be probed while opening/editing zone background/range state.
- `4.22.85` is a new FP2 app-side zone-edit lead. It is written with value `1` while `Detection Zone 2` is in edit mode, likely as an edit/session/operation flag or zone-related state. M100 `bc2al.conf` contains `4.22.85` mappings in other model blocks and `ha_master` contains the string in motion/occupancy areas, but the direct `lumi.motion.agl001` M100 block does not map it. Keep this as live-app evidence until a save/cancel/write capture resolves the semantics.

## Packed App Notes

The Play Store app is SecNeo packed. Static JADX output primarily shows the wrapper (`com.secneo.apkwrapper`) and bootstrap/route metadata, while live stack traces mention real classes that are missing from static decompilation, including:

- `Fp2TrackSocketManager`
- `CommonWebActionHelper`
- `ThreadSyncUtils`

Native libraries in the split APK include `libDexHelper.so`, `libdexjni.so`, `liblumidevsdk.so`, and a large `libdatajar.so`. Strings in `libDexHelper.so` reference anti-debug/dynamic dex loading paths such as `InMemoryDexClassLoader`, `DexFile::OpenMemory`, `/proc/self/maps`, and `ptrace`.

Runtime dex dumping while the FP2 page was open recovered only small bootstrap/router dex material, not the hidden implementation classes. Future app RE should target runtime class loading and OkHttp/WebSocket instrumentation instead of relying on plain static JADX.

## App View Routes

`base_database.view_config_info` exposes H5 routes for `lumi.motion.agl001`.

Control view:

- `/human-exist-sensor-fp2/home`

Detail/settings view:

- `/human-exist-sensor-fp2/more-setting/work-mode-set`
- `/human-exist-sensor-fp2/more-setting/flow-setting`
- `/human-exist-sensor-fp2/more-setting/side-work-mode-set`
- `/human-exist-sensor-fp2/falldown-detect/setting`
- `/human-exist-sensor-fp2/edit`
- `/human-exist-sensor-fp2/sleep-guide?step=2`
- `/human-exist-sensor-fp2/more-setting/view-set`
- `/human-exist-sensor-fp2/more-setting/reset-nopeople?isSleepMode=0`
- `/human-exist-sensor-fp2/more-setting/reset-nopeople?isSleepMode=1`

## Matter-Like Endpoint Cache

`alink.device_card_trait` uses paths shaped like:

```text
<endpoint>.<functionId>.<traitId>
```

For example, whole-device occupancy is stored as `2.160.33000`, where function `160` is `OccupancySensing` and trait `33000` is `Occupancy`.

Observed endpoint cache for the paired FP2:

| Endpoint | App name | Function/trait paths | Aqara resource ids | Notes |
| ---: | --- | --- | --- | --- |
| `0` | Root device | `0.128.32901`, `0.129.33013`, `0.130.32913` | `8.0.2045`, `14.49.85`, `8.0.8101`, `8.0.8108`, `8.0.8102` | Root descriptor and labels. `EndpointArrayDynamic` was `[2,4,102,202,101,203]`. |
| `2` | Occupancy Sensor | `2.160.33000`, `2.160.33044` | `3.51.85` | Whole-device occupancy and occupied duration. |
| `4` | Illuminance | `4.154.32989` | `0.4.85` | Current illuminance in lux. |
| `101` | Detection Zone 1 | `101.160.33000`, `101.160.33044` | `3.1.85` | Zone occupancy and occupied duration. |
| `102` | Detection Zone 2 | `102.160.33000`, `102.160.33044` | `3.2.85` | Zone occupancy and occupied duration. |
| `103` | Detection Zone 3 | `103.160.33000` | `3.3.85` | Present in the trait cache but not in the active dynamic endpoint array during this capture. |

Open point: endpoints `202` and `203` appeared in `EndpointArrayDynamic` but had no rows in `device_card_trait` during this capture. Given the zone-management UI text (`Edge`, `exits and entrances`) and the known UART attributes for edge/enter-exit maps, these are strong candidates for dynamic virtual endpoints related to edge or entrance/exit zones. They need a mode/zone-change capture to confirm.

## M100 Firmware Cross-Check

The completed Aqara Hub M100 dump adds an independent bridge/cloud reference for FP2 resource naming. Both active and backup rootfs images contain a `lumi.motion.agl001` block in `etc/bc2al.conf`.

Direct FP2 mappings from M100 `bc2al.conf`:

| FP2 resource | M100 mapped id | Current interpretation |
| --- | --- | --- |
| `0.4.85` | `4.154.32989.1` | Illuminance. |
| `3.51.85` | `2.160.33000.1` | Whole-device occupancy. |
| `13.27.85` | `3.161.33002.1` | Motion/event scalar; observed as live H5 values `6` and `7`. |
| `4.31.85` | `5.167.33018.1` | Still needs FP2 app/firmware correlation. |
| `8.0.2045` | `0.128.32901.1` | Root descriptor. |
| `8.0.8101` | `0.130.32913.1` | Root metadata/name trait. |
| `8.0.8102` | `0.130.33016.1` | Root metadata/name trait. |
| `8.0.8108` | `0.130.32914.1` | Root metadata/name trait. |

Important non-direct M100 clue:

- M100 active/backup `ha_master` also contains `4.22.85` in motion/occupancy string areas, and `bc2al.conf` maps `4.22.85` in other device/model blocks. The `lumi.motion.agl001` block itself does not include `4.22.85`, so the 2026-06-07 FP2 edit-mode app write should be treated as the primary evidence for this resource.

The newer M100 backup `ha_master` contains an advanced motion descriptor block with FP2-relevant resources including `4.22.700`, `4.41.705`, `13.27.85`, and `3.51.85`, plus descriptors such as `char_MotionReportCoordinateData`, `char_MotionRegionConfigBlock`, `char_MotionHumanDetectZone`, `char_MotionDetectZoneSetting`, `char_MotionMonitorWalkingDistance`, and fall/posture descriptors.

High-confidence M100 zone-base map from the zone-indexing function at VA `0xb9704`:

| Resource | Candidate characteristic | Evidence |
| --- | --- | --- |
| `1.162.85` | `char_MotionZoneMoveDetected` | Resource run aligns with an 8-entry characteristic pointer array consumed by the zone-indexing function. |
| `4.41.705` | `char_OccupancyDetectedZone` | Same zone-indexing function. |
| `13.1.700` | `char_MotionDetectZoneType` | Same zone-indexing function. |
| `8.0.2207` | `char_MotionDetectZoneApproachEnable` | Same zone-indexing function. |
| `4.211.85` | `char_MotionDetectZoneHumanDetectDelay` | Same zone-indexing function. |
| `4.58.701` | `char_MotionMonitorSchedulePeopleZone` | Same zone-indexing function. |
| `13.21.703` | `char_MotionMonitorScheduleCountingZone` | Same zone-indexing function. |
| `13.117.85` | `char_MotionMonitorWonderingTimeCountZone` | Same zone-indexing function. |

Bounded but useful candidate:

- `4.22.700` is still the best app/cloud candidate for `char_MotionReportCoordinateData (char_str)`: FP2 app logs prove it is the live target-coordinate stream, and M100 contains the matching descriptor in the same advanced motion block. The M100 binary does not contain a direct pointer from `4.22.700` to that descriptor, so keep this as bounded rather than proven.

## FP2 Settings Resources From The App View

The app detail view labels several Aqara resource ids directly:

| Resource id | App label / role | Notes |
| --- | --- | --- |
| `14.49.85` | Detection Mode | Central mode value used by many show/hide rules. The ESP32 direct dispatch table maps this resource to radar SubID `0x0116` (`work_mode`), and the handler accepts modes `3`, `5`, `8`, and `9`. |
| `14.30.85` | Fall Detection Sensitivity | Confirmed by ESP32 direct dispatch: resource `14.30.85` maps to radar SubID `0x0123` (`fall_sensitivity`). |
| `14.1.85` | Sleep Monitoring Sensitivity | Visible only when detection mode is `9`. ESP32 dispatch maps the same resource to SubID `0x0111` (`presence_detection_sensitivity`), so this appears to be mode-contextual naming. |
| `4.73.85` | Homepage View Display | Visible in modes `1`, `3`, and `8`. |
| `4.72.85` | AI Person Detection | ESP32 dispatch maps this to SubID `0x0163` (`target_type_enable`). Gated by firmware `>= 1.2.4` and disabled in modes `5`, `8`, and `9`. |
| `14.59.85` | Fall detection delay | The cached H5 unpacking code formats `0` as "at once" and nonzero values as seconds, but the ESP32 descriptor table maps this resource to SubID `0x0179` / `cloud_overhead_height`. The neighboring descriptor maps `4.41.705` to `0x0180` / `cloud_fall_delay_time`; handler analysis shows that `4.41.705` is cloud-side `BLOB2` but is reduced to a 16-bit radar write. A targeted app-toggle/radar-UART capture should determine whether Aqara mislabeled the UI binding, remaps at cloud level, or uses a mode-specific semantic for the same resource. |
| `4.23.85` | Turn Off Indicator Light | Enables a schedule row. |
| `8.0.2207` | Indicator-light time period | Shown only when `4.23.85` is enabled. |
| `8.0.2096` | Identify / Find device | App-side identify action. |

Version/mode feature gates in the same view:

| Gate | Meaning inferred from app JS |
| --- | --- |
| `1.2.1` | Enables monitor-mode selection unless mode is `5` or `9`; mode `8` gets a special state. |
| `1.2.4` | Enables AI-related mode support. |
| `1.2.5` | Enables newer area/zone flow for mode `9`. |
| `1.3.0_0002.0095` | Enables the fall-down model UI in modes `5` and `8`. |
| `3.2.5` | Minimum app version for a device-info feature. |
| `4.0.5` | Minimum app version for a newer function settings path. |
| `9.9.9` | Future/support gate that evaluates false for current public firmware. |

## UI Observations

The live FP2 page exposed these user-facing values and pages:

- Main page: current count, presence duration, visits today, distance traveled today, illuminance.
- Zone Management: `Detection Zone 1`, `Detection Zone 2`, `Edge`, and `exits and entrances`.
- Installation mode dialog: mount height guidance `1.4m~1.8m`.

## Next Experiments

- Change detection modes in the app while capturing logcat, pcap, and before/after app databases. The highest-value resource is `14.49.85`; mode changes should explain endpoint `202` and `203`.
- Long-press/edit an existing zone and create/cancel/save a new zone while capturing logcat and PCAP. Target the zone-page reads `13.35.85`, `3.51.85`, edit-mode writes to `4.22.85`, the background endpoint `/devex/radar/range/background/query`, and any `/res/write` payloads.
- Open `flow-setting`, `view-set`, `reset-nopeople`, and fall/sleep settings while capturing app logs. These paths should exercise `CommonWebActionHelper.subscribeProps` and the hidden WebSocket layer.
- Specifically change the fall detection delay UI and compare before/after values for `14.59.85`, `4.41.705`, `0x0179`, and `0x0180`.
- If hidden sleep/fall controls expose `0.121.85` or `1.10.85`, capture those too; static handler summaries suggest 1-byte radar writes despite cloud descriptor rows marked `UINT16`.
- Instrument OkHttp `RealWebSocket` and the Aqara JS bridge at runtime. Static JADX is not enough because the app implementation is packed and loaded dynamically.
- Continue router-side capture for FP2-owned cloud sessions. The first bridge capture identified the FP2 cloud endpoint but not plaintext LAN control traffic.
- Sniff the radar UART directly on ESP32 GPIO19/GPIO18 at `890000` baud for ground truth while using the app to toggle resources and while watching `4.22.700` app position pushes.
