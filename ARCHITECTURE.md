# Kauth — architecture

**Ozan Karaali**

Kauth provisions a headless Linux device from an iPhone or a second computer. A technician scans a private setup card, verifies the nearby device, selects the site Wi-Fi and receives an authenticated result. Setup needs no internet connection, cloud service or existing network. Installing dependencies is a separate preparation step.

## 1. Transport: BLE for setup, Wi-Fi for the network

**BLE carries setup; Wi-Fi joins the network.** Separate radio roles preserve a local progress channel while Wi-Fi changes. iOS uses CoreBluetooth and CryptoKit; Linux uses Bless/BlueZ GATT and NetworkManager's system D-Bus API for Wi-Fi. A Python/Bleak configurator is an alternative to building the iPhone app.

```text
iPhone / Python configurator
    │ QR-bound HPKE requests; authenticated encrypted replies
    │ BLE GATT — no IP connection between these devices
Linux provisioning service
    │ local system D-Bus
NetworkManager → Wi-Fi association → IP configuration → saved profile
```

| Alternative | Tradeoff against the selected BLE channel |
| --- | --- |
| Device hotspot / SoftAP | Also works offline, but requires phone network switching and a result-recovery path when a single Wi-Fi radio leaves AP mode to join the target. |
| Wi-Fi Easy Connect / DPP | Standardized public-key onboarding; attractive with qualified hardware and configurator APIs, but not uniformly available on the chosen iPhone/Linux endpoints. |
| BLE + application encryption | Native iPhone support and independent Wi-Fi transition; costs an app, peripheral-capable Bluetooth hardware, limited bandwidth and radio-stack qualification. |

BLE is not interference-free, and a successful adapter on one machine does not qualify every Linux radio. The demonstrated Jetson uses Ubuntu 22.04 / L4T 36.5.2 with BlueZ's reverse service discovery disabled. The installer applies and records ownership of that one policy setting; it does not patch drivers, change event masks or require OS Bluetooth pairing.

## 2. Trust model and encryption

A Bluetooth name is **discovery, not identity**. The trusted QR contains a device ID, its X25519 public key and a random 32-byte setup secret. The device retains the private key. The app verifies an encrypted device-side scan before enabling credential entry. A second peripheral with the same advertised name cannot substitute its own key and receive the password.

Requests use [RFC 9180 HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) **PSK mode** with X25519, HKDF-SHA256 and ChaCha20Poly1305. The recipient key binds the request to the device; possession of the setup secret authorizes the configurator. A fresh, 60-second device challenge is bound into the context and consumed on the first matching attempt, including failed decryption. Randomness alone would not prevent replay; this single-use state does.

Replies use a separate exporter-derived key, authenticated context and ordered counters. The configurator accepts only an authenticated final result bound to its request. Credentials are encrypted before BLE transmission, independently of link pairing. They necessarily exist at the endpoints and in local NetworkManager calls; passwords are not passed as subprocess arguments or written to application logs. NetworkManager deliberately saves the secret for autoconnect. Optional phone reuse stores one successfully provisioned profile in an app-scoped, non-synchronizing, device-only Keychain item.

A copied QR copies setup authorization while setup is open; a sealed in-box card and IT custody reduce exposure but are not revocation. IT reset rotates the keypair and secret, invalidating old cards. The protocol does not prevent relays, jamming, compromised endpoints or later decryption after compromise of both device private key and setup secret. Exact framing and security boundaries are in [PROTOCOL.md](PROTOCOL.md).

## 3. Joining is a transaction, not “credentials sent”

The device checkpoints only the selected Wi-Fi interface, creates an in-memory candidate and observes activation events belonging to that attempt. It verifies the requested SSID and a usable address on **that Wi-Fi interface**, not an Ethernet address or a global connectivity flag. It then persists the autoconnect profile, commits the checkpoint, durably records provisioning state and returns authenticated success. Advertising closes; the daemon stays available for local administration.

On failure, the service attempts checkpoint rollback and deletes only its own trial profile. It distinguishes supported failure reasons from generic timeouts and reports restoration failure rather than inventing success. A lost final reply is an unknown outcome. A five-minute local reopen preserves identity and existing Wi-Fi; ordinary Wi-Fi loss does not reopen setup. Reset, unlike reopen, revokes the old QR and removes only the validated tracked profile.

Checkpoints are memory-only. Power loss before profile persistence loses the trial, not existing saved networks. Profile and application-state saves are separate commits, so interruption between them can leave a saved network without confirmed setup. This is not whole-system crash atomicity. The root POC service has systemd filesystem restrictions and no Linux capabilities, but holds powerful D-Bus authority; production should separate radio parsing from a narrowly authorized networking helper.

## 4. Scaling to large deployments

The implemented **Save for the next device** option eliminates repeated password entry on one phone. Scaling the deployment is a separate operational design, not opening hundreds of GATT sessions from one phone:

1. **Prepare with IT once.** Validate the approved network profile, coverage, VLAN/address capacity, MAC registration and fleet access. Preprovision at the warehouse where policy permits.
2. **Distribute authorized site profiles.** Managed configurators receive encrypted, offline-capable profiles and scoped technician authorization. Define expiry and revocation behavior without requiring a cloud check during each local setup.
3. **Separate identity from placement.** Scan the device, verify it, assign room/asset and apply the site profile. Handle duplicate scans and assignment conflicts; never share a sheet of setup secrets.
4. **Work in bounded zones.** Multiple technicians handle batches; stagger advertising and cap concurrent joins per area/AP. Measure contention and completion rates on the actual hardware rather than claiming a fleet-wide throughput figure.
5. **Track distinct outcomes.** Keep minimal offline receipts for identity, assignment, profile version and outcome. Reconcile with the fleet-management system later; “Wi-Fi joined” and “fleet service reachable” are separate stages. Rotate credentials while devices are reachable, with rollback and authorized local recovery.

Enterprise Wi-Fi needs EAP identities, validated CA/server names, certificates and renewal/revocation—not just extra password fields. The POC deliberately supports WPA2-Personal, including compatible transition networks, rather than pretending to implement enterprise enrollment.

## 5. Evidence and scope

The [recorded run](evidence/demo.mp4) shows the real iPhone app provisioning a Jetson after IT reset, with the device initially disconnected and then receiving a Wi-Fi address and authenticated confirmation. The OS Wi-Fi notification appears and setup advertising closes. Network names are privacy aliases; the open Ethernet details pane is explicitly identified as a stale snapshot. Phone Wi-Fi remains visible, so the clip is not presented as a strict all-radios-disabled test. Source inspection confirms the provisioning path uses BLE and local D-Bus, not a cloud/LAN transport.

The [evidence ledger](DEMO.md) separates this hardware result from automated crypto/transaction tests and simulator results. Physical reboot, wrong-password/handover/crash qualification, fresh blank-host installation and live uninstall are not claimed. These are production acceptance priorities, not substitutions for the successful real-network demonstration.
