# Recorded demonstration and verification

**[Watch the demo](evidence/demo.mp4)** — 44 seconds, 1920×1080, 30 fps, silent. The iPhone and full Jetson desktop are shown together at original speed, with no cuts inside the provisioning attempt.

## What to watch

| Approximate time | Recorded observation |
| --- | --- |
| 00:00–00:04 | Device Wi-Fi is disconnected; setup advertising is open. The phone scans the setup card with the entire camera view covered in the published edit. |
| 00:05–00:18 | The phone finds the device, authenticates it against the card and receives the device-side Wi-Fi list. |
| 00:19–00:24 | The technician reviews the remembered network and explicitly submits Join. The password area is covered. |
| 00:31–00:34 | Linux shows the real Wi-Fi “Connection Established” notification. The Wi-Fi interface reaches connected state and obtains an address; the phone shows authenticated confirmation. |
| 00:35–00:44 | The daemon remains active and setup advertisements change to zero. |

The actual joined SSID is replaced consistently with **Target Network**, explicitly labelled as a privacy alias. Nearby network names, the QR and password area are covered. The translucent phone navigation header is replaced by an opaque cover so scrolled network names cannot show through it. Opaque blocks also cover the Jetson's Ethernet MAC address and the Wi-Fi access point's hardware address (BSSID) wherever they appear. The Wi-Fi interface state, assigned IP address and connection confirmation remain visible. These are visual redactions, not a renamed AP or synthetic connection result.

The desktop's already-open Ethernet **Connection Information** dialog did not refresh and is labelled as a stale snapshot. Use the changing tray indicator, Wi-Fi notification and live `wlP1p1s0` output as evidence instead. The operator unplugged Ethernet before provisioning; OBS recorded locally on the Jetson while the remote desktop connection was unavailable. The phone's Wi-Fi icon remains visible, so this is not presented as a strict all-radios-disabled recording or a measurement of internet availability.

## Reference hardware and software

| Component | Recorded baseline |
| --- | --- |
| Device | Jetson Orin Nano, logical demo ID `jetson-demo-01`; physical serial not published |
| OS / bootloader | Ubuntu 22.04, Jetson Linux / L4T 36.5.2 |
| Kernel | 5.15.199-tegra |
| Bluetooth | BlueZ 5.64; Realtek driver 3.1.65ab490.20240531-141726; `ReverseServiceDiscovery=false` |
| Wi-Fi | NetworkManager 1.36.6; interface `wlP1p1s0` |
| Python / app | Python 3.10.12; Kauth 3.0/build 5, package 3.0.0, protocol v3 |
| Capture | Local OBS 27.2.3, 1280×800 at 15 fps; separate iPhone screen recording; final composition at 30 fps |

The two source recordings were aligned by their recorded timestamps, cross-checked against visible minute transitions. Terminal refresh is approximately one second; the edit is not a subsecond latency measurement. Original recordings and active setup credentials are not distributed.

## Evidence ledger

- **Recorded post-reset join — 2026-10-12:** the installed IT reset rotated device keys/setup secret and removed the tracked Wi-Fi profile. The operator scanned the new card and completed the real iPhone-to-Jetson join shown above. Wi-Fi received a usable address, the phone confirmed success and advertising closed.
- **Earlier physical observation — 2026-10-11:** an independent D-Bus inspection after a successful join found the profile saved (`Unsaved=false`), autoconnect enabled, trial ACL cleared and advertising stopped. Ethernet was retained for that observation. This is separate from what can be read directly from the video.
- **Installer and reset:** actual adoption/update and reset ran on the existing Jetson installation. This is not a blank-host installation or live uninstall test.
- **Automated Python verification:** the final pre-release check and exact result are recorded in [checks.json](evidence/checks.json). NetworkManager/systemd failure boundaries in these tests are modeled, not real radios.
- **Fresh Swift verification — 2026-10-12:** 19 tests passed after the project/module rename to **Kauth**, using Xcode 15.2 and the iOS 17.2 simulator with normal simulator signing. They cover crypto/vector cases and the actual simulator Keychain. The built app's `CFBundleIdentifier` resolves to `com.ozankaraali.Kauth`, and that app was launched in the simulator. The recording predates this identifier rename; wire v3 and QR schema 1 are unchanged. Physical Bluetooth/camera behavior is demonstrated by the real phone recording, not the simulator.

The design goals are a real connection and no plaintext credential transmission. The video establishes the user-visible join; the source, protocol and negative cryptographic tests address properties that an on-screen animation alone cannot establish. Source inspection found BLE and local D-Bus as the provisioning path, without an HTTP, cloud or shared-LAN provisioning transport. It does not claim that the entire operating systems emit no other network traffic.

## Reproduction and remaining qualification

Follow [README.md](README.md) for Ubuntu setup and either configurator. For a deliberately isolated rerun, disable phone Wi-Fi/cellular while retaining Bluetooth, start the device without a network connection, and observe it locally rather than through a network link being disconnected. Preinstall dependencies and prepare the private card first.

Physical reboot persistence, wrong-password recovery, handover from another AP, crash/power-loss qualification, fresh blank-host installation and live uninstall have not been established by this recording. The implementation and automated boundary tests are not substitutes for those hardware acceptance runs. No enterprise enrollment, large-fleet throughput, internet or fleet-service reachability result is claimed.
