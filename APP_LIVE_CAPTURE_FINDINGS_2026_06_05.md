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
- Open `flow-setting`, `view-set`, `reset-nopeople`, and fall/sleep settings while capturing app logs. These paths should exercise `CommonWebActionHelper.subscribeProps` and the hidden WebSocket layer.
- Specifically change the fall detection delay UI and compare before/after values for `14.59.85`, `4.41.705`, `0x0179`, and `0x0180`.
- If hidden sleep/fall controls expose `0.121.85` or `1.10.85`, capture those too; static handler summaries suggest 1-byte radar writes despite cloud descriptor rows marked `UINT16`.
- Instrument OkHttp `RealWebSocket` and the Aqara JS bridge at runtime. Static JADX is not enough because the app implementation is packed and loaded dynamically.
- Continue router-side capture for FP2-owned cloud sessions. The first bridge capture identified the FP2 cloud endpoint but not plaintext LAN control traffic.
- Sniff the radar UART directly on ESP32 GPIO19/GPIO18 at `890000` baud for ground truth while using the app to toggle resources and while watching `4.22.700` app position pushes.
