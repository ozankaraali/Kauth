#!/usr/bin/env python3
"""Root-only, deliberately scoped Kauth maintenance; uninstall needs only stdlib."""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

RUNTIME = Path("/opt/karaali-provisioning")
DATA = Path("/var/lib/karaali-provisioning")
UNIT = Path("/etc/systemd/system/karaali-provisioning.service")
DROPIN = Path(str(UNIT) + ".d") / "10-kauth.conf"
SERVICE = "karaali-provisioning.service"
BLUEZ_CONFIG = Path("/etc/bluetooth/main.conf")
TOOLS = ("manage.py", "reset.sh", "uninstall.sh", "bluetooth_policy.py", "make_setup_card.py", "k-glyph-final.svg")
QR_ARTIFACTS = ("qr.json", "qr.png", "setup-card.html")
FIRST_INSTALL = {"version": 1, "provisioned": False, "reopen_until": 0, "network": None}
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
LIFECYCLE_LOCK = Path("/run/lock/karaali-provisioning-maintenance.lock")


class MaintenanceError(RuntimeError):
    """Messages contain instructions, never subprocess output or credential data."""


def root_directory(path: Path, *, private=False, missing=False):
    """Reject symlink ancestors and writable/unowned service-data paths."""
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if missing and part == path:
                return False
            raise MaintenanceError("A required directory is missing; repair the installation first.") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or (private and part == path and info.st_mode & 0o077)):
            raise MaintenanceError("Refusing a symlink, unowned or shared installation/data directory.")
    return True


def read_file(path: Path, *, private=True, missing=False, maximum=65536):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing:
            return None
        raise MaintenanceError("A required maintenance file is missing; repair the installation first.") from None
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & (0o077 if private else 0o022) or info.st_nlink != 1):
            raise MaintenanceError("Refusing a symlink, unowned, shared or multiply linked maintenance file.")
        content = source.read(maximum + 1)
    if len(content) > maximum:
        raise MaintenanceError("A maintenance file is oversized; repair it locally before retrying.")
    return content


def load_json(path: Path, *, missing=False):
    content = read_file(path, missing=missing)
    if content is None:
        return None
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    try:
        value = json.loads(content, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise MaintenanceError("A maintenance JSON file is invalid; repair it locally before retrying.") from None


def run_command(args, label):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=COMMAND_ENV, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise MaintenanceError(label + " could not run; inspect the host locally.") from None
    if result.returncode:
        raise MaintenanceError(label + " failed; inspect the host locally (command output withheld).")
    try:
        return result.stdout.decode("utf-8")
    except UnicodeError:
        raise MaintenanceError(label + " returned invalid text; no profile will be guessed.") from None


def systemctl(*args):
    return run_command(["systemctl", *args], "systemctl " + args[0])


def stop_service():
    # Disable before mutation so a failed reset also stays closed across a reboot.
    systemctl("disable", SERVICE)
    systemctl("stop", SERVICE)
    if (systemctl("show", "--property=ActiveState", "--value", SERVICE).strip()
            not in ("inactive", "failed")
            or systemctl("show", "--property=MainPID", "--value", SERVICE).strip() != "0"):
        raise MaintenanceError("Service did not quiesce; no identity or profile changes are permitted.")


@contextlib.contextmanager
def lifecycle_lock():
    # Shared with the installer; it lives outside directories uninstall may remove.
    fd = os.open(LIFECYCLE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise MaintenanceError("Lifecycle lock must be a root-owned private regular file.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MaintenanceError("Another installation or maintenance operation is active; wait for it to finish.") from None
        yield
    finally:
        os.close(fd)


@contextlib.contextmanager
def state_lock():
    path = DATA / "provisioning-state.json.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise MaintenanceError("Provisioning lock must be a root-owned private regular file.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def read_state():
    """Validate without importing crypto, including on a broken-venv uninstall."""
    value = load_json(DATA / "provisioning-state.json", missing=True)
    if value is None:
        return dict(FIRST_INSTALL)
    try:
        if (type(value.get("version")) is not int or value["version"] != 1
                or type(value.get("provisioned")) is not bool
                or type(value.get("reopen_until")) not in (int, float)
                or not math.isfinite(value["reopen_until"]) or value["reopen_until"] < 0
                or "network" not in value):
            raise ValueError()
        network = value.get("network")
        if network is None:
            if value["provisioned"]:
                raise ValueError()
        else:
            if not isinstance(network, dict):
                raise ValueError()
            for field, limit in (("ssid", 32), ("interface", 128), ("profile_uuid", 64)):
                text = network.get(field)
                if not isinstance(text, str) or not 1 <= len(text.encode("utf-8")) <= limit or "\0" in text:
                    raise ValueError()
            identifier = network["profile_uuid"]
            if str(uuid.UUID(identifier)) != identifier:
                raise ValueError()
            addresses = network.get("addresses")
            if not isinstance(addresses, list) or not addresses:
                raise ValueError()
            for address in addresses:
                if not isinstance(address, str):
                    raise ValueError()
                parsed = ipaddress.ip_address(address)
                if parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast:
                    raise ValueError()
        return value
    except (KeyError, ValueError, TypeError, UnicodeError):
        raise MaintenanceError("Invalid provisioning state; refusing to guess which Wi-Fi profile to remove.") from None


def tracked_profile(network):
    """Match the exact UUID AND all ownership fields used by network.py."""
    if network is None:
        return None
    identifier = network["profile_uuid"]
    known = run_command(["nmcli", "--get-values", "UUID", "connection", "show"],
                        "NetworkManager profile inventory").splitlines()
    if identifier not in known:
        return None  # Already removed is recoverable, including after a partial reset.
    expected = {"connection.uuid": identifier, "connection.type": "802-11-wireless",
                "connection.id": "Karaali - " + network["ssid"],
                "connection.interface-name": network["interface"],
                "802-11-wireless.ssid": network["ssid"]}
    for field, value in expected.items():
        actual = run_command(["nmcli", "--escape", "no", "--get-values", field,
                              "connection", "show", "uuid", identifier],
                             "NetworkManager profile ownership check")
        if actual.removesuffix("\n") != value:
            raise MaintenanceError("Tracked UUID no longer matches this app's Wi-Fi profile; nothing will be guessed or bulk-deleted.")
    return identifier


def delete_tracked(network):
    identifier = tracked_profile(network)  # Revalidate immediately before the destructive call.
    if identifier is not None:
        run_command(["nmcli", "--wait", "30", "connection", "delete", "uuid", identifier],
                    "Tracked Wi-Fi profile deletion")
    return identifier is not None


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def invoking_owner():
    uid_text = os.environ.get("SUDO_UID")
    if uid_text is None:
        return 0, 0
    try:
        uid = int(uid_text)
        user = pwd.getpwuid(uid)
        if uid < 0:
            raise ValueError()
        return uid, user.pw_gid
    except (ValueError, KeyError):
        raise MaintenanceError("Invalid sudo invoking-user information; run from a normal sudo session.") from None


@contextlib.contextmanager
def new_output(path, owner):
    path = Path(path).absolute()
    parent = path.parent.resolve(strict=True)
    path = parent / path.name
    if path == DATA or DATA in path.parents or path == RUNTIME or RUNTIME in path.parents:
        raise MaintenanceError("Choose a new private QR directory outside runtime and application data.")
    info = parent.stat()
    if info.st_uid not in (0, owner[0]) or info.st_mode & 0o022:
        raise MaintenanceError("QR parent directory must belong to root or the invoking administrator and not be shared-writable.")
    if owner[0] != 0:
        account = pwd.getpwuid(owner[0])
        groups = set(os.getgrouplist(account.pw_name, owner[1]))
        for ancestor in (parent, *parent.parents):
            access = ancestor.stat()
            execute = (stat.S_IXUSR if access.st_uid == owner[0] else
                       stat.S_IXGRP if access.st_gid in groups else stat.S_IXOTH)
            if not access.st_mode & execute:
                raise MaintenanceError("The sudo invoker cannot traverse the QR destination; choose a new directory under their home.")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            raise MaintenanceError("QR output directory already exists; choose a NEW directory (nothing was overwritten).") from None
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        created = os.fstat(fd)
        if created.st_uid != 0 or stat.S_IMODE(created.st_mode) != 0o700:
            raise MaintenanceError("QR output directory changed during creation; refusing to write artifacts.")
        yield path, fd
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (created.st_dev, created.st_ino):
            raise MaintenanceError("QR output directory moved during reset; keep service stopped and retry with a new directory.")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def copy_qr(stage, fd):
    for name in QR_ARTIFACTS:
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(out, "wb") as target:
            target.write((stage / name).read_bytes())
            target.flush()
            os.fsync(target.fileno())
    os.fsync(fd)


def release_qr(fd, owner):
    for name in QR_ARTIFACTS:
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            os.fchown(child, *owner)
        finally:
            os.close(child)
    os.fchown(fd, *owner)


def reset(output_dir):
    # Imports are intentionally here: system Python can always execute uninstall.
    from device_provision.identity import DeviceIdentity, create_identity
    from device_provision.state import ProvisioningState
    from make_setup_card import render

    root_directory(DATA, private=True)
    owner = invoking_owner()
    print("RESET disconnects this app's tracked Wi-Fi and invalidates every previous setup QR. Use Ethernet or a local console.")
    print("Unmanaged and previous untracked network profiles and all Bluetooth bonds are retained.")
    mutation_started = False
    try:
        with new_output(output_dir, owner) as (output, output_fd):
            # Validation before disruption; repeat after quiescing under the state lock.
            read_file(DATA / "identity.json", maximum=4096)
            DeviceIdentity.load(DATA / "identity.json")
            read_state()
            mutation_started = True
            stop_service()
            with state_lock():
                read_file(DATA / "identity.json", maximum=4096)
                identity = DeviceIdentity.load(DATA / "identity.json")
                state = read_state()
                tracked_profile(state["network"])
                with tempfile.TemporaryDirectory(prefix=".reset-", dir=DATA) as temporary:
                    stage = Path(temporary)
                    fresh = create_identity(identity.device_id, stage / "identity.json", stage / "qr.json", stage / "qr.png")
                    card_fd = os.open(stage / "setup-card.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(card_fd, "w", encoding="utf-8") as card:
                        card.write(render(fresh.qr, serial=None, inset=True, preview=False))
                    copy_qr(stage, output_fd)
                    delete_tracked(state["network"])
                    os.replace(stage / "identity.json", DATA / "identity.json")
                    fsync_directory(DATA)
                    # FIRST-INSTALL, deliberately NOT reopen(): there is no five-minute deadline.
                    ProvisioningState(DATA / "provisioning-state.json")._write(dict(FIRST_INSTALL))
                # Start before enabling: a failed start must not make reboot resume a partial reset.
                systemctl("start", SERVICE)
                if systemctl("show", "--property=ActiveState", "--value", SERVICE).strip() != "active":
                    raise MaintenanceError("Provisioning service did not become active after reset.")
                systemctl("enable", SERVICE)
                release_qr(output_fd, owner)
        print("Reset complete: logical device ID retained; X25519 keypair and setup secret replaced.")
        print("First-install readiness restored without a time limit; service started (radio/phone proof not performed).")
        print("Private QR JSON: " + str(output / "qr.json"))
        print("Private QR PNG:  " + str(output / "qr.png"))
        print("Private brochure: " + str(output / "setup-card.html"))
        print("Destroy obsolete external QR copies separately; this is logical deletion, not secure flash erasure.")
    except BaseException:
        if mutation_started:
            safely_stopped = True
            for action in ("disable", "stop"):
                try:
                    systemctl(action, SERVICE)
                except Exception:
                    safely_stopped = False
            print("RESET FAILED: " + ("service left stopped and disabled." if safely_stopped else
                  "could not confirm service stopped; stop it locally immediately."), file=sys.stderr)
            print("Identity/network may already have changed. Do not distribute this attempt's QR; rerun reset with a NEW output directory to recover.", file=sys.stderr)
        raise


def installation_record():
    record = load_json(DATA / "install-record.json", missing=True)
    if record is None:
        if os.path.lexists(RUNTIME) or os.path.lexists(UNIT) or os.path.lexists(DROPIN):
            raise MaintenanceError("Installation ownership record is missing; rerun the trusted installer before removing existing runtime/unit paths.")
        return None
    if type(record.get("version")) is not int or record["version"] != 1 or record.get("runtime") != str(RUNTIME):
        raise MaintenanceError("Invalid installation ownership record; no runtime paths will be guessed.")
    for key, expected in (("unit", UNIT), ("dropin", DROPIN)):
        item = record.get(key)
        if (not isinstance(item, dict) or item.get("path") != str(expected)
                or not isinstance(item.get("sha256"), str) or len(item["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in item["sha256"])):
            raise MaintenanceError("Invalid installed-unit ownership record; repair it locally.")
        if expected.parent.exists():
            root_directory(expected.parent)
        content = read_file(expected, private=False, missing=True)
        if content is not None and hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise MaintenanceError("An installer-owned unit artifact was edited later; preserve/reconcile that edit before uninstalling.")
    return record


def safe_tree(path):
    """Recursive deletion never crosses mounts or follows links; foreign owners stop it."""
    if not os.path.lexists(path):
        return
    root_directory(path)
    device = path.stat().st_dev
    if os.path.ismount(path):
        raise MaintenanceError("Refusing to delete a mounted application directory.")
    for directory, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            child = Path(directory) / name
            info = child.lstat()
            if info.st_uid != 0 or info.st_dev != device or os.path.ismount(child):
                raise MaintenanceError("Unowned files or mount points exist in an application directory; inspect locally before deletion.")
            if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022:
                raise MaintenanceError("Shared-writable application files prevent safe recursive deletion.")


def remove_if_empty(path):
    try:
        path.rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        print("Retained directory containing untracked files: " + str(path))


def remove_runtime():
    if not RUNTIME.exists():
        return
    venv = RUNTIME / ".venv"
    if venv.exists():
        shutil.rmtree(venv)
    tools = RUNTIME / "bin"
    if tools.exists():
        for name in TOOLS:
            (tools / name).unlink(missing_ok=True)
        remove_if_empty(tools)
    remove_if_empty(RUNTIME)


def uninstall(purge=False):
    data_exists = root_directory(DATA, private=True, missing=True)
    record = installation_record() if data_exists else None
    if record is None and any(os.path.lexists(path) for path in (RUNTIME, UNIT, DROPIN)):
        raise MaintenanceError("No installation ownership record; rerun the trusted installer before removing existing runtime/unit paths.")
    if RUNTIME.exists():
        root_directory(RUNTIME)
        safe_tree(RUNTIME / ".venv")
        tools = RUNTIME / "bin"
        if tools.exists():
            root_directory(tools)
            for name in TOOLS:
                read_file(tools / name, private=False, missing=True, maximum=1024 * 1024)
    if purge and data_exists:
        safe_tree(DATA)
        read_file(DATA / "identity.json", missing=True, maximum=4096)
        read_state()
    policy_record = DATA / "bluetooth-policy.json"
    restore = None
    if os.path.lexists(policy_record):
        # Resolve before deleting runtime, and fail closed if the helper is missing.
        from bluetooth_policy import restore_policy
        restore = restore_policy
    print("UNINSTALL " + ("--purge deletes private app data and disconnects only its validated tracked Wi-Fi." if purge else
                          "retains identity, provisioning state and all Wi-Fi profiles for safe reinstall."))
    print("Untracked networks, Bluetooth bonds and shared system packages are never removed.")
    try:
        loaded = systemctl("show", "--property=LoadState", "--value", SERVICE).strip() != "not-found"
        if loaded:
            if record is None:
                raise MaintenanceError("A service exists without our installation record; refusing to stop an unowned service.")
            stop_service()
        if purge and data_exists:
            with state_lock():
                delete_tracked(read_state()["network"])
        if restore is not None:
            changed = restore(BLUEZ_CONFIG, policy_record)
            restored = load_json(policy_record, missing=True)
            # A previous uninstall may have restored policy but failed its restart.
            if changed or (restored is not None and restored.get("status") == "restored"
                           and restored.get("restored_changed") is True):
                systemctl("restart", "bluetooth.service")
        if record is not None:
            for path in (DROPIN, UNIT):
                path.unlink(missing_ok=True)
            remove_if_empty(DROPIN.parent)
            systemctl("daemon-reload")
            remove_runtime()
        if purge and data_exists:
            # Keep the record until all earlier steps succeeded so reruns can recover.
            shutil.rmtree(DATA)
        print("Uninstall complete. " + ("Private app data removed." if purge else "Private app data and network retained."))
        print("External QR copies are not removed. Purge is logical deletion, not secure flash erasure.")
    except BaseException:
        print("UNINSTALL FAILED: removal may be partial; service is not restarted. Repair the reported prerequisite, then rerun from a trusted checkout if installed tools are gone.", file=sys.stderr)
        raise


def parser():
    result = argparse.ArgumentParser(description="Root-only Kauth IT lifecycle tools. Use Ethernet or a local console.")
    commands = result.add_subparsers(dest="command", required=True)
    reset_parser = commands.add_parser("reset", help="disconnect tracked Wi-Fi, rotate ALL setup keys and restore first-install readiness",
                                      description="Invalidates old QRs, keeps the logical device ID, and rotates X25519 keys plus setup secret. Failures leave setup stopped/disabled; recover by rerunning with a new output directory.")
    reset_parser.add_argument("--output-dir", type=Path, required=True,
                              help="NEW private directory for qr.json, qr.png and setup-card.html; parent must already exist; ownership passes to sudo invoker")
    uninstall_parser = commands.add_parser("uninstall", help="remove owned service/runtime; retain data and Wi-Fi unless --purge",
                                          description="Restore only installer-owned Bluetooth policy. Never remove Bluetooth bonds, unrelated profiles or shared system packages. External QR copies remain; deletion is not secure flash erasure.")
    uninstall_parser.add_argument("--purge", action="store_true", help="also delete private app data and ONLY the validated tracked Wi-Fi profile (disconnects it)")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    if os.geteuid() != 0:
        print("Maintenance must run as root (use sudo).", file=sys.stderr)
        return 1
    os.umask(0o077)
    try:
        with lifecycle_lock():
            if args.command == "reset":
                reset(args.output_dir)
            else:
                uninstall(args.purge)
        return 0
    except MaintenanceError as error:
        print("ERROR: " + str(error), file=sys.stderr)
    except KeyboardInterrupt:
        print("ERROR: interrupted; inspect the maintenance status above before resuming setup.", file=sys.stderr)
    except Exception:
        # Never print arbitrary exceptions: dependencies and child processes may include secrets.
        print("ERROR: maintenance could not finish; check private file integrity/permissions, disk space and installed prerequisites locally. No credential data or command output was printed.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
