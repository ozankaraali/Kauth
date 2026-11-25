# Kauth provisioning protocol v3

## Scope and trust

BLE GATT carries device-side Wi-Fi scans, WPA2-Personal configuration, current status, and a diagnostic echo. Application security does not depend on Bluetooth pairing or bonding. The native iPhone app and Python configurator implement the same protocol.

Preparation generates a unique X25519 key pair and a random 32-byte setup secret. The private key remains on the device. A trusted QR supplies the public key, setup secret, and device ID. Possession of the QR authorizes setup while the device's setup window is open; public-key knowledge alone is insufficient. A copied or replaced QR compromises that physical trust boundary. BLE names, addresses, advertisements, challenge announcements, and plaintext errors are untrusted.

Release 3.0 is a clean wire-v3 cutover, including the `karaali-provision/v3` domain-separation labels. **Update both app and server; v1/v2 clients and servers are not compatible.** Existing per-device keys and QR artifacts remain valid because the QR schema is still version 1. The package is `device-provisioning`, the Python import is `device_provision`, and the executable is `device-provision`; there are no legacy aliases. `echo` remains a diagnostic operation.

## Encoding and limits

- Outer messages: UTF-8 JSON objects, at most 8192 bytes; member order is irrelevant.
- Binary fields: canonical padded standard Base64, not URL-safe Base64.
- Device IDs: 1–32 ASCII characters matching `[a-z0-9-]+`.
- Encrypted requests: JSON objects, at most 4096 plaintext bytes.
- Encrypted reply events: JSON objects, at most 5600 plaintext bytes.
- Echo text: exact UTF-8, 1–512 bytes, without trimming or normalization.
- SSIDs: exact UTF-8, 1–32 bytes. Non-UTF-8 SSIDs are outside this POC.
- WPA2 credentials: an 8–63-character printable ASCII passphrase (bytes `0x20`–`0x7e`), or 64 hexadecimal digits representing a PSK. Spaces are preserved.
- Counters and binary lengths: unsigned, big-endian. Boolean JSON values are not integer counters.

QR schema:

```text
version:      integer 1
device_id:    device identifier
public_key:   Base64(raw X25519 public key, 32 bytes)
setup_secret: Base64(random 32 bytes)
```

Device identity JSON adds `private_key`, Base64 of the raw 32-byte X25519 private key. Identity and QR output files are created exclusively with owner-only permissions. Fixture secrets are public synthetic test data and must never initialize a real device.

## BLE framing and negotiation

| Role | UUID | Properties |
| --- | --- | --- |
| Service | `8a46a1b0-5f14-4ad9-a7a8-21fc87a08001` | Primary |
| RX: configurator → device | `8a46a1b0-5f14-4ad9-a7a8-21fc87a08002` | Write with response |
| TX: device → configurator | `8a46a1b0-5f14-4ad9-a7a8-21fc87a08003` | Notify |

Subscribe to TX before sending. With packet size `N`:

```text
Start:        01 || uint16(total JSON byte length) || first ≤N−3 bytes
Continuation: 00 || next ≤N−1 bytes
```

The challenge request always uses 20-byte packets. It proposes an integer `packet_size` between 20 and 185 (default 20). The response and subsequent packets use the selected size, no larger than requested. iOS derives its request from the peripheral's maximum write-without-response length, capped at 185; this is a payload-size bound, even though actual writes use responses. The Python client uses the negotiated ATT MTU minus three bytes, capped at 185. Twenty-byte packets remain valid when the adapter cannot report a larger MTU.

Only one ordered frame is emitted at a time. A new start replaces an interrupted partial frame. Invalid flags, lengths, overflow, and continuation without a start fail the attempt. Writable/notifying characteristics have no cached initial value. Device notifications are serialized and paced with backend backpressure handling.

The Linux advertisement uses the device ID, limited to its first 29 ASCII bytes; BlueZ 5.83 places its local name in the legacy scan response (31 bytes including the two-byte name header). A normal ID such as `demodevice1` is shown in full. macOS diagnostic peripherals use the first ten characters to stay within CoreBluetooth's local-name budget and avoid the pinned Bless fallback dropping the service UUID. Radio names are best-effort selection hints; truncated prefixes can collide. The full QR/device ID remains unchanged and is authenticated by the protocol. See [BlueZ advertising implementation](https://github.com/bluez/bluez/blob/5.83/src/advertising.c) and [CoreBluetooth advertising limits](https://developer.apple.com/documentation/corebluetooth/cbperipheralmanager/startadvertising(_:)).

Bless does not expose a portable per-central identity here, so the device has one shared serialized setup slot. Another central can disrupt availability by replacing challenges or interleaving traffic; multi-client arbitration is not implemented.

## Challenge and HPKE request

Request:

```json
{"type":"challenge_request","version":3,"packet_size":185}
```

Response:

```text
type:        "challenge"
version:     integer 3
device_id:   device identifier
challenge:   Base64(32 random bytes)
packet_size: selected integer 20..185
```

There is one current challenge with a 60-second monotonic deadline. A fresh challenge replaces the previous one. Challenges are memory-only. The client checks the version, ID, size and challenge length, but the announcement itself is not proof of identity.

HPKE suite: PSK mode `0x01`, DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`, ChaCha20Poly1305 `0x0003`. Notation below uses ASCII literals, byte concatenation `||`, and `00` for a single zero byte:

```text
psk    = decoded QR setup_secret
psk_id = "karaali-provision/v3/setup/" || device_id
info   = "karaali-provision/v3" || 00 || device_id || 00 || challenge32 || uint16(packet_size)
AAD    = "karaali-provision/v3/request"
```

Create a PSK-mode HPKE sender context using the QR public key and seal the command JSON with this AAD. The request envelope is:

```text
type:       "request"
challenge:  original Base64 challenge
enc:        Base64(32-byte encapsulated key)
ciphertext: Base64(HPKE ciphertext including tag)
```

The device compares the supplied challenge to its current unexpired challenge, then consumes a matching challenge **before** parsing the encapsulated key or decrypting. A failed matching attempt also burns it. An unrelated old challenge is rejected without consuming a different current challenge. Including randomness in `info` is not replay protection by itself; this state transition supplies the single-use property.

### Commands

```json
{"op":"echo","text":"hello world"}
{"op":"scan"}
{"op":"status"}
{"op":"configure","ssid":"Site-IoT","password":"example-only-passphrase","hidden":false}
```

The example passphrase is not a device default. `hidden` defaults to false. Configure supports WPA2-Personal and transition APs advertising WPA2-PSK, not enterprise, open, WEP, or WPA3-only networks. A hidden-network request permits directed discovery; it does not weaken authentication.

## Authenticated reply stream

Both HPKE endpoints export a separate reply key:

```text
reply_key = HPKE.Export("karaali-provision/v3/device-to-phone", 32)
counter8  = uint64(counter)
nonce     = 00 00 00 01 || counter8
replyAAD  = info || 00 || "reply" || 00 || counter8
```

ChaCha20-Poly1305 seals each reply-event JSON. Counters begin at zero and increase by one; a fresh key is derived for each request. Outer envelope:

```text
type:       "reply"
challenge:  original Base64 challenge
counter:    expected integer 0, 1, ...
ciphertext: Base64(ChaCha ciphertext || 16-byte tag)
```

Every decrypted event includes `device_id`, the exact request `op`, `event`, and a Boolean `final`. The client checks envelope challenge, expected counter, AEAD, identity, operation and event shape before advancing its counter. A final event closes the stream; duplicate, skipped, out-of-order and post-final messages are rejected. Exact SSID/echo comparisons use UTF-8 bytes rather than normalized display-string equality.

| Operation | Progress events (`final:false`) | Terminal event (`final:true`) |
| --- | --- | --- |
| `echo` | None | `echo`, with the exact `echo` text |
| `scan` | `scanning` | `networks`, with `interface`, `networks`, `truncated` |
| `status` | None | `status`, with `provisioned`, `setup_allowed`, current `network` or null |
| `configure` | `connecting`, `obtaining_ip`, `saving`, each with `ssid` | `connected`, with `ssid`, `interface`, `addresses`, `profile_uuid`, `provisioned:true` |
| Any authenticated operation | — | `error`, with a safe `code` and `message` |

Scan rows contain `ssid`, signal `strength` (0–100), `security`, and `supported`. Security values are `wpa2-psk`, `wpa3-sae`, `enterprise`, `open`, or `unsupported`. The device returns the strongest 16 unique `(SSID, security)` rows, with deterministic ordering and a truncation flag. Manual SSID entry covers networks outside that list. Unsupported rows are visible but not selectable for provisioning.

A network result contains `ssid`, `interface`, `addresses` and `profile_uuid`. Configure success requires the requested SSID and usable unicast IP configuration, not loopback, link-local, multicast, or unspecified addresses. The Linux backend checks the selected device, candidate active connection, actual AP SSID, and that device's IP configuration. An Ethernet/VPN address or global “online” state is not evidence of a successful Wi-Fi join. Status is a separate current-state observation; a prior durable provisioning record alone does not prove current connectivity.

Operational errors such as `backend_unavailable`, `permission_denied`, `setup_closed`, `network_not_found`, `authentication_failed`, `ip_failed`, `timeout`, `rollback_failed`, or `state_write_failed` are encrypted after request authentication. Raw D-Bus exception bodies are not forwarded. A timeout is not automatically described as a wrong password.

Authentication/framing failure can produce only a generic untrusted rejection:

```json
{"type":"error","code":"rejected"}
```

An attacker can forge this rejection or disconnect the link. Neither proves the device's identity or means a connection succeeded. No plaintext credential or success fallback exists.

## Network transaction and setup lifecycle

The device uses NetworkManager's system D-Bus API, not `nmcli` password arguments or direct supplicant configuration. It checkpoints only the selected Wi-Fi device before creating an in-memory candidate with autoconnect disabled. Existing profiles remain untouched. A bounded trial verifies requested association and usable IP, persists the candidate including its secret, then commits the checkpoint. Failure/cancellation waits for an already-dispatched activation call to settle, rolls back its checkpoint and deletes only its own candidate, including recovery by a randomly generated profile UUID if a reply was interrupted. Failed restoration or an activation RPC whose outcome remains unsettled returns `rollback_failed`, not a claim that cleanup completed.

Before activation, an attempt-local subscription pins NetworkManager's bus owner and the selected device. It correlates `Device.StateChanged` reasons with the ordered `ActiveConnection` property notifications and the candidate's returned active path, including signals arriving before the activation method returns. It never classifies failure from a polled `StateReason` snapshot. An old connection's `NEW_ACTIVATION` handover is not a failure of the new candidate; `CARRIER` is not treated as `NEW_ACTIVATION`.

`NEED_AUTH` (60), including reason `NO_SECRETS` (7), is intermediate: NetworkManager may retrieve the supplied secret and resume `CONFIG` without rejecting the password. Only a terminal transition makes its reason an activation failure. An unresolved secret request remains subject to the attempt deadline; it is not automatically `authentication_failed`.

The trial profile has `connection.permissions=["user:root:"]`, removed when the verified profile is saved. This excludes ordinary non-root desktop secret agents without disabling or changing those agents or existing profiles. NetworkManager's explicit root activation is not bound to a logged-in root desktop session. Privileged/custom agents remain outside this guarantee, and SteamOS/iwd needs separate qualification. See the upstream [agent ACL filter](https://github.com/NetworkManager/NetworkManager/blob/1.46.0/src/core/settings/nm-agent-manager.c#L725-L764) and [root activation exception](https://github.com/NetworkManager/NetworkManager/blob/1.46.0/src/core/nm-manager.c#L5535-L5542). Authentication retry count is not a no-prompt mechanism.

Joining does not demand another explicit scan immediately after the user selected a scan result: NetworkManager can rate-limit that request. The service uses available AP observations as a selection hint and lets NetworkManager discover the target during activation if needed. Cached discovery alone never proves success; the active connection, actual SSID and interface IP checks still apply.

After network commit, owner-only atomic state records the successful profile metadata, never the password. Only then is final success sent. Failure to save this separate record returns `state_write_failed` and preserves the working network. The service drains the final reply before closing BLE advertising. If the phone disconnects, the operation may have completed: absence of a verified final event is not proof of rollback. Local authorized reopen and current status resolve that ambiguity.

Missing state means initial setup is allowed. A valid provisioned record keeps setup closed across ordinary network outages and daemon restarts. The local `reopen` command grants a five-minute window without deleting profiles or identity. Corrupt, shared, or unowned state is an error, not permission to fall back to first-time setup. Saved NetworkManager profiles and root access remain part of the trusted endpoint boundary.

Checkpoints exist in NetworkManager memory. If only the provisioning process dies, the still-running NetworkManager can apply its checkpoint timeout. Power loss, reboot or a NetworkManager restart destroys that checkpoint; none implies a delayed rollback after boot. Existing saved profiles are not deleted, but candidate persistence and the provisioning-state write are separate commits. A crash between them can leave a saved candidate without a provisioned record. Qualify that recovery boundary separately rather than claim a power-loss-atomic transaction.

## Limits and evidence

This protects application credential confidentiality, integrity and QR-bound authentication under uncompromised endpoints and keys. It does not hide BLE presence, sizes or timing; prevent radio jamming or active relay; provide a factory/manufacturer attestation chain; or implement secure boot/hardware key storage. Compromise of both the recipient private key and setup PSK permits decryption of recorded sessions. Python/Swift managed memory is not claimed to provide guaranteed secret zeroization.

The root Linux service is a POC privilege boundary. PyHPKE states it has not been formally audited. Passing vectors and negative tests is not a security audit. Neither a host-side `btmon` trace nor unreadable ciphertext alone proves radio security. [DEMO.md](DEMO.md) separates the recorded iPhone/Jetson join, automated checks and remaining physical qualification.

`fixtures/rfc9180-psk.json` retains the complete mode1/KEM32/KDF1/AEAD3 object from the [official vectors at commit `5f503c564da00b0687b3de75f1dfbdfc4079ad31`](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json): 257 encryption sequences and three exports.

`fixtures/interop.json` is an independent PyHPKE 0.6.3 / cryptography 46.0.3 v3 known-answer fixture, generated without project imports: packet size 20, device ID `fixture-device-01`, PSK bytes 0–31, challenge bytes 32–63, and echo `hello world — merhaba`. HPKE derives its recipient pair from `karaali-provision fixture device key; NEVER production` and deterministic ephemeral pair from `karaali-provision fixture ephemeral; NEVER production`. JSON uses UTF-8, `ensure_ascii=False`, separators `(',', ':')`, request insertion order `op,text` and reply insertion order `device_id,op,event,final,echo`. The fixture records both plaintexts and ciphertexts. Tests compare decoded command/event content because Foundation JSON escaping/order is not a cross-language contract. Deterministic keys are synthetic fixtures only, never device defaults.

References: [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), [CryptoKit HPKE](https://developer.apple.com/documentation/cryptokit/hpke), [PyHPKE security notice](https://github.com/dajiaji/pyhpke#security), [NetworkManager D-Bus](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html).
