# Operations and recovery

These commands are for an administrator, not part of the technician's normal scan → verify → join flow. Work from Ethernet or a local console when changing Wi-Fi. Run commands from the trusted source checkout unless an installed path is shown.

## Ubuntu installation and updates

```sh
sudo sh deploy/install.sh --device-id demodevice1
```

Ubuntu 22.04/24.04, systemd and already-active NetworkManager managing the selected Wi-Fi interface are prerequisites. The installer installs missing Python/BlueZ dependencies but does not replace another network manager or upgrade firmware/the OS. It refuses ambiguous radio selection; use `--interface ACTUAL_WIFI_INTERFACE --adapter hci0` if needed. Wi-Fi/Bluetooth must be enabled and the Bluetooth controller must support peripheral advertising.

On first install, `--output-dir "$HOME/new-private-directory"` chooses an unused card directory with an existing parent. Otherwise the default is `~/kauth-setup-DEVICE-ID/` for the sudo invoker. Do not give `--output-dir` when updating an existing identity. A supplied ID must match that identity. Rerunning the installer preserves keys, setup state and saved networks.

Runtime/service paths are root-owned and must not be group/world-writable or symlinked. If the ownership preflight rejects a path, have the administrator inspect and restore its expected OS metadata. Do not bypass the check or recursively chmod/chown system directories.

The installer changes only BlueZ's `[General] ReverseServiceDiscovery=false`, preventing this peripheral-only device from probing the connecting phone's GATT services. It records ownership of the change for uninstall. Restarting Bluetooth can disconnect Bluetooth peripherals. It does not delete bonds, enable blind pairing, issue HCI event-mask commands or change the Wi-Fi backend.

## Observe without exposing secrets

```sh
systemctl is-active karaali-provisioning.service bluetooth.service
sudo journalctl -u karaali-provisioning.service -n 60 --no-pager
nmcli device status
```

Inspect the selected Wi-Fi interface for association and an IP, rather than relying on an old desktop dialog or an Ethernet address. Never publish identity JSON, active QR/card files, `nmcli --show-secrets`, or raw Bluetooth/phone captures. The QR contains authorization material, even though its recipient key is public.

The service runs from `/opt/karaali-provisioning/.venv`, with identity/state in `/var/lib/karaali-provisioning`. That directory is private. The systemd unit applies `ProtectSystem=strict`, a writable state-directory exception, `PrivateTmp=yes`, `NoNewPrivileges=yes` and an empty capability bounding set. NetworkManager/BlueZ perform their own writes in separate services. Root's D-Bus authority remains a production privilege-separation concern.

## Reopen without erasing anything

```sh
sudo /opt/karaali-provisioning/.venv/bin/device-provision reopen \
  --identity /var/lib/karaali-provisioning/identity.json
```

This opens setup for five minutes. Existing profiles, identity and QR remain valid; the same secret is still required. The running service notices the state change without restarting. After successful provisioning, BLE status/scan commands require reopen because advertising has closed.

Stopping the app's observation does not undo an accepted join. If the final reply was lost, inspect locally or reopen and request authenticated status before deciding whether to retry:

```sh
# On the separate configurator, after the administrator reopens the device:
.venv/bin/device-provision status --qr /path/to/private/qr.json
```

## IT reset and key/card reissue

```sh
sudo /opt/karaali-provisioning/bin/reset.sh \
  --output-dir "$HOME/kauth-reset-01"
```

Use a **new output directory each time**. Reset stops setup, validates the recorded Wi-Fi profile's UUID/type/interface/SSID/label and removes only that profile. It retains the logical device ID, rotates the X25519 keypair and setup secret, clears provisioned state and exports a fresh private card. Setup returns to first-install readiness without the five-minute limit. Every older QR is invalid.

Reset revokes Kauth application trust; it does not clear OS Bluetooth bonds. Untracked Wi-Fi, Ethernet, VPNs, bridges and firmware are retained. An unrelated saved Wi-Fi profile can still autoconnect. Destroy obsolete external cards separately; logical deletion is not secure flash erasure.

If reset stops partway, some deletion/rotation may already have occurred. Leave setup stopped/disabled, resolve the reported error and retry with another unused output directory. Do not distribute a card from an incomplete attempt.

## Uninstall

Choose one operation, not both in sequence:

```sh
# Remove owned runtime/service, retain identity/state/Wi-Fi for reinstall.
sudo /opt/karaali-provisioning/bin/uninstall.sh

# Alternative: also remove private app data and the validated tracked Wi-Fi profile.
sudo /opt/karaali-provisioning/bin/uninstall.sh --purge
```

If the installed runtime is unavailable, the standard-library maintenance entry point is `sudo /usr/bin/python3 deploy/manage.py uninstall`, optionally with `--purge`. It needs the installer ownership record; an older unmanaged deployment must first be adopted by the installer.

Uninstall restores the BlueZ setting only if it was changed by Kauth and still matches the owned value. Pre-existing/later administrator settings, unrelated unit drop-ins, untracked content, shared packages and Bluetooth bonds are retained. External QR copies are not removed.

## Failure boundaries

| Observation | Interpretation / action |
| --- | --- |
| No peripheral or services found | Check that setup is open, radios are powered, no competing peripheral owns the adapter, and the controller supports the role. A running process alone does not establish working GATT. |
| Authentication rejected | Use the newest card for that exact device, especially after reset. A friendly-name match is insufficient. |
| Network not found / authentication failure | Check the requested SSID and WPA2 support; retry with correct credentials when the reported reason supports it. A generic timeout is not automatically a bad password. |
| Rollback failed | Inspect the selected interface and profiles locally. Do not assume the old connection was restored. |
| Wi-Fi joined but app timed out | Result is unknown to the app; local observation or authenticated status can establish it. Do not show success from a timeout. |
| Power loss during setup | Trials are memory-only; checkpoints do not survive NetworkManager restart. Profile persistence and application-state persistence are separate commits. Inspect both on recovery. |

## Jetson reference

The demonstrated Orin Nano uses Ubuntu 22.04 / L4T and bootloader 36.5.2, kernel 5.15.199-tegra, Realtek Bluetooth driver 3.1.65ab490.20240531-141726, BlueZ 5.64 and NetworkManager 1.36.6. Earlier GATT failures were resolved on this bench after the OS/driver upgrade and peripheral-role policy. Do not infer a universal driver fix or reproduce historical HCI experiments. A display is not required for Kauth; the recorded desktop was a locally recorded virtual Xfce session.

The installer does not upgrade JetPack/L4T. Follow NVIDIA's supported update procedure separately when needed, with backups. SteamOS and its read-only system are not targets of this Ubuntu installer.
