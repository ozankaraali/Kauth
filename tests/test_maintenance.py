import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

import pytest

from device_provision.identity import DeviceIdentity, QRIdentity, b64, create_identity
from device_provision.protocol import ClientSession, DeviceSession, ProtocolError
from device_provision.state import ProvisioningState

SPEC = importlib.util.spec_from_file_location("kauth_manage", Path(__file__).resolve().parents[1] / "deploy" / "manage.py")
manage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage)

UUID = "78ce681c-2b2a-4e64-8142-08f8a8446f4d"
NETWORK = {"ssid": "café lab", "interface": "wlan0", "addresses": ["192.168.50.8"], "profile_uuid": UUID}


class Host:
    """Only the system boundary is simulated; identities/state/QRs are real files."""
    def __init__(self):
        self.active = True
        self.enabled = True
        self.start_failure = False
        self.commands = []
        self.profiles = {
            UUID: {"connection.uuid": UUID, "connection.type": "802-11-wireless",
                   "connection.id": "Karaali - " + NETWORK["ssid"],
                   "connection.interface-name": NETWORK["interface"],
                   "802-11-wireless.ssid": NETWORK["ssid"]},
            "unrelated-ethernet": {"connection.type": "802-3-ethernet"},
            "previous-untracked-wifi": {"connection.type": "802-11-wireless"},
        }

    def command(self, args, label):
        self.commands.append(args)
        if args[0] == "systemctl":
            action = args[1]
            if action == "stop":
                self.active = False
            elif action == "disable":
                self.enabled = False
            elif action == "enable":
                self.enabled = True
            elif action == "start":
                if self.start_failure:
                    raise manage.MaintenanceError("Service start failed.")
                self.active = True
            elif action == "show":
                if "--property=ActiveState" in args:
                    return "active\n" if self.active else "inactive\n"
                if "--property=MainPID" in args:
                    return "30\n" if self.active else "0\n"
                if "--property=LoadState" in args:
                    return "loaded\n"
            return ""
        assert args[0] == "nmcli"
        if "delete" in args:
            del self.profiles[args[-1]]
            return ""
        field = args[args.index("--get-values") + 1]
        if field == "UUID":
            return "\n".join(self.profiles) + "\n"
        return self.profiles[args[-1]][field] + "\n"


@pytest.fixture
def installed(tmp_path, monkeypatch):
    # Temporary files model root-owned installation files without requiring pytest
    # itself to be root. Ancestors of pytest's temporary directory are not /var/lib.
    owner = os.geteuid(), os.getegid()
    original_fstat, original_lstat = os.fstat, Path.lstat

    def as_root(info):
        fields = list(info)
        fields[4] = 0
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", lambda fd: as_root(original_fstat(fd)))
    monkeypatch.setattr(Path, "lstat", lambda path: as_root(original_lstat(path)))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(manage, "invoking_owner", lambda: owner)
    monkeypatch.setattr(manage, "root_directory", lambda path, **options: path.exists())
    for name, path in (("DATA", tmp_path / "data"), ("RUNTIME", tmp_path / "runtime"),
                       ("UNIT", tmp_path / "units" / manage.SERVICE)):
        monkeypatch.setattr(manage, name, path)
    monkeypatch.setattr(manage, "DROPIN", Path(str(manage.UNIT) + ".d") / "10-kauth.conf")
    manage.DATA.mkdir(mode=0o700)
    manage.RUNTIME.mkdir()
    manage.UNIT.parent.mkdir()
    manage.DROPIN.parent.mkdir()
    manage.UNIT.write_text("owned service")
    manage.DROPIN.write_text("owned selection")
    (manage.RUNTIME / ".venv").mkdir()
    (manage.RUNTIME / ".venv" / "package").write_text("runtime")
    (manage.RUNTIME / "bin").mkdir()
    for name in manage.TOOLS:
        (manage.RUNTIME / "bin" / name).write_text("owned tool")
    record = {"version": 1, "runtime": str(manage.RUNTIME)}
    for key, path in (("unit", manage.UNIT), ("dropin", manage.DROPIN)):
        record[key] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    record_path = manage.DATA / "install-record.json"
    record_path.write_text(json.dumps(record))
    record_path.chmod(0o600)
    identity = create_identity("test-device", manage.DATA / "identity.json",
                               manage.DATA / "initial-qr.json", manage.DATA / "initial-qr.png")
    ProvisioningState(manage.DATA / "provisioning-state.json").provisioned(NETWORK)
    host = Host()
    monkeypatch.setattr(manage, "run_command", host.command)
    return host, identity


def authenticate(identity, qr):
    device = DeviceSession(identity)
    client = ClientSession(qr, {"op": "status"})
    challenge = device.challenge({"type": "challenge_request", "version": 3})
    return device.authenticate(client.create_request(challenge))


def test_reset_rotates_all_keys_exports_only_qr_and_restores_unlimited_readiness(installed, tmp_path, capsys):
    host, old = installed
    output = tmp_path / "new-card"
    manage.reset(output)
    new = DeviceIdentity.load(manage.DATA / "identity.json")
    qr = QRIdentity.load(output / "qr.json")
    assert new.device_id == old.device_id
    assert new.private_key != old.private_key and new.public_key != old.public_key
    assert new.setup_secret != old.setup_secret
    assert qr == new.qr
    assert "private_key" not in json.loads((output / "qr.json").read_text())
    assert {path.name for path in output.iterdir()} == {"qr.json", "qr.png", "setup-card.html"}
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for path in (output / "qr.json", output / "qr.png", output / "setup-card.html", manage.DATA / "identity.json"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert authenticate(new, qr).command == {"op": "status"}
    with pytest.raises(ProtocolError):
        authenticate(new, old.qr)
    state = ProvisioningState(manage.DATA / "provisioning-state.json", clock=lambda: 10**12)
    assert state.read() == manage.FIRST_INSTALL
    assert state.allowed()
    assert host.active and host.enabled
    assert set(host.profiles) == {"unrelated-ethernet", "previous-untracked-wifi"}
    logged = capsys.readouterr()
    for secret in (old.private_key, old.setup_secret, new.private_key, new.setup_secret):
        assert b64(secret) not in logged.out + logged.err


@pytest.mark.parametrize("field,value", [("connection.id", "foreign network"),
                                        ("connection.type", "802-3-ethernet"),
                                        ("connection.interface-name", "other0"),
                                        ("802-11-wireless.ssid", "other SSID")])
def test_reset_refuses_unowned_tracked_profile(installed, tmp_path, field, value):
    host, old = installed
    host.profiles[UUID][field] = value
    with pytest.raises(manage.MaintenanceError):
        manage.reset(tmp_path / "rejected")
    assert DeviceIdentity.load(manage.DATA / "identity.json") == old
    assert UUID in host.profiles
    assert not host.active and not host.enabled
    assert ProvisioningState(manage.DATA / "provisioning-state.json").read()["provisioned"]


@pytest.mark.parametrize("failure", ["state-write", "start"])
def test_partial_reset_stays_stopped_and_can_recover_with_new_output(installed, tmp_path, monkeypatch, failure):
    host, old = installed
    write_state = ProvisioningState._write
    if failure == "state-write":
        def fail(self, value):
            raise OSError("disk full")
        monkeypatch.setattr(ProvisioningState, "_write", fail)
    else:
        host.start_failure = True
    with pytest.raises((OSError, manage.MaintenanceError)):
        manage.reset(tmp_path / "failed-attempt")
    assert not host.active and not host.enabled
    assert UUID not in host.profiles
    assert DeviceIdentity.load(manage.DATA / "identity.json").private_key != old.private_key
    monkeypatch.setattr(ProvisioningState, "_write", write_state)
    host.start_failure = False
    manage.reset(tmp_path / "recovered")
    recovered = DeviceIdentity.load(manage.DATA / "identity.json")
    assert authenticate(recovered, QRIdentity.load(tmp_path / "recovered" / "qr.json")).command == {"op": "status"}
    with pytest.raises(ProtocolError):
        authenticate(recovered, QRIdentity.load(tmp_path / "failed-attempt" / "qr.json"))
    assert host.active and host.enabled
    assert ProvisioningState(manage.DATA / "provisioning-state.json").read() == manage.FIRST_INSTALL


def test_reset_never_overwrites_output_or_disrupts_service_on_collision(installed, tmp_path):
    host, old = installed
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "qr.json").write_text("keep me")
    with pytest.raises(manage.MaintenanceError):
        manage.reset(existing)
    assert (existing / "qr.json").read_text() == "keep me"
    assert DeviceIdentity.load(manage.DATA / "identity.json") == old
    assert host.active and host.enabled and not host.commands


@pytest.mark.parametrize("purge", [False, True])
def test_uninstall_scopes_runtime_data_and_network_deletion(installed, purge):
    host, identity = installed
    untracked = manage.RUNTIME / "administrator-note"
    untracked.write_text("keep me")
    foreign_dropin = manage.DROPIN.parent / "90-local.conf"
    foreign_dropin.write_text("local policy")
    manage.uninstall(purge)
    assert not host.active and not host.enabled
    assert not manage.UNIT.exists() and not manage.DROPIN.exists()
    assert foreign_dropin.read_text() == "local policy"
    assert not (manage.RUNTIME / ".venv").exists()
    assert not (manage.RUNTIME / "bin").exists()
    assert untracked.read_text() == "keep me"
    assert {"unrelated-ethernet", "previous-untracked-wifi"} <= host.profiles.keys()
    if purge:
        assert UUID not in host.profiles and not manage.DATA.exists()
    else:
        assert UUID in host.profiles
        assert DeviceIdentity.load(manage.DATA / "identity.json") == identity
        assert ProvisioningState(manage.DATA / "provisioning-state.json").read()["network"] == NETWORK


def test_uninstall_refuses_later_unit_edits_before_disruption(installed):
    host, _ = installed
    manage.UNIT.write_text("administrator changed this")
    with pytest.raises(manage.MaintenanceError):
        manage.uninstall(True)
    assert host.active and host.enabled and not host.commands
    assert UUID in host.profiles and manage.DATA.exists()
    assert manage.UNIT.read_text() == "administrator changed this"


@pytest.mark.parametrize("content", ["{broken", '{"version":1,"version":1}',
                                    '{"version":1,"provisioned":false,"reopen_until":1e999,"network":null}'])
def test_purge_refuses_corrupt_state_without_network_changes(installed, content):
    host, _ = installed
    (manage.DATA / "provisioning-state.json").write_text(content)
    with pytest.raises(manage.MaintenanceError):
        manage.uninstall(True)
    assert host.active and host.enabled and not host.commands
    assert UUID in host.profiles


def test_private_file_checks_reject_shared_files_and_symlinks(installed):
    path = manage.DATA / "identity.json"
    path.chmod(0o644)
    with pytest.raises(manage.MaintenanceError):
        manage.read_file(path)
    path.chmod(0o600)
    link = manage.DATA / "identity-link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        manage.read_file(link)


def test_root_requirement_precedes_any_mutation(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert manage.main(["reset", "--output-dir", str(tmp_path / "unused")]) == 1
    assert not (tmp_path / "unused").exists()


def test_uninstall_does_not_follow_runtime_symlinks(installed, tmp_path):
    outside = tmp_path / "external-data"
    outside.mkdir()
    sentinel = outside / "keep"
    sentinel.write_text("unrelated")
    (manage.RUNTIME / ".venv" / "external-link").symlink_to(outside, target_is_directory=True)
    manage.uninstall()
    assert sentinel.read_text() == "unrelated"


def test_missing_ownership_record_never_guesses_runtime_removal(installed):
    host, _ = installed
    (manage.DATA / "install-record.json").unlink()
    with pytest.raises(manage.MaintenanceError):
        manage.uninstall(True)
    assert host.active and not host.commands
    assert manage.UNIT.exists() and (manage.RUNTIME / ".venv").exists()
    assert UUID in host.profiles


def test_purge_refuses_changed_profile_without_removing_data_or_runtime(installed):
    host, _ = installed
    host.profiles[UUID]["connection.id"] = "adopted by administrator"
    with pytest.raises(manage.MaintenanceError):
        manage.uninstall(True)
    assert not host.active and not host.enabled
    assert manage.DATA.exists() and manage.UNIT.exists()
    assert (manage.RUNTIME / ".venv").exists() and UUID in host.profiles


def test_lifecycle_lock_excludes_concurrent_maintenance(installed, monkeypatch, tmp_path):
    monkeypatch.setattr(manage, "LIFECYCLE_LOCK", tmp_path / "lifecycle.lock")
    with manage.lifecycle_lock():
        with pytest.raises(manage.MaintenanceError):
            with manage.lifecycle_lock():
                pytest.fail("concurrent maintenance must not acquire the lock")


def test_uninstall_tolerates_partly_missing_runtime(installed):
    host, identity = installed
    (manage.RUNTIME / ".venv" / "package").unlink()
    (manage.RUNTIME / ".venv").rmdir()
    (manage.RUNTIME / "bin" / "reset.sh").unlink()
    manage.uninstall()
    assert not manage.RUNTIME.exists() and not manage.UNIT.exists()
    assert DeviceIdentity.load(manage.DATA / "identity.json") == identity
    assert UUID in host.profiles and not host.active
