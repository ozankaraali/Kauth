import json
import os
import stat

import pytest

from device_provision.cli import main, parser
from device_provision.identity import create_identity
from device_provision.state import ProvisioningState, StateError

NETWORK = {"ssid": "old network", "interface": "wlan0", "addresses": ["192.168.1.9"], "profile_uuid": "old-uuid"}


def test_factory_open_success_closed_and_restart_stays_closed(tmp_path):
    path = tmp_path / "state.json"
    store = ProvisioningState(path)
    assert store.allowed() and not store.read()["provisioned"]
    store.provisioned(NETWORK)
    restarted = ProvisioningState(path)
    assert restarted.read()["provisioned"] and not restarted.allowed()
    assert restarted.read()["network"] == NETWORK
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "password" not in path.read_text()


def test_local_reopen_expiry_and_failed_join_preserve_prior_state(tmp_path):
    now = [1000.0]
    path = tmp_path / "state.json"
    store = ProvisioningState(path, clock=lambda: now[0])
    store.provisioned(NETWORK)
    assert store.reopen() == 1300
    assert store.allowed()
    assert store.read()["network"] == NETWORK
    # A failed transaction never calls provisioned(); reopen remains valid until expiry.
    now[0] = 1299.9
    assert ProvisioningState(path, clock=lambda: now[0]).allowed()
    now[0] = 1300
    assert not store.allowed()
    assert store.read()["provisioned"]
    assert store.read()["network"] == NETWORK


def test_success_during_reopen_closes_window(tmp_path):
    store = ProvisioningState(tmp_path / "state.json")
    store.provisioned(NETWORK)
    store.reopen()
    store.provisioned({**NETWORK, "ssid": "new network", "profile_uuid": "new-uuid"})
    assert not store.allowed()
    assert store.read()["reopen_until"] == 0
    assert store.read()["network"]["ssid"] == "new network"


def test_atomic_replace_failure_preserves_previous_record(tmp_path, monkeypatch):
    store = ProvisioningState(tmp_path / "state.json")
    store.provisioned(NETWORK)
    original = store.path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("disk failure")

    monkeypatch.setattr("device_provision.state.os.replace", fail_replace)
    with pytest.raises(OSError):
        store.provisioned({**NETWORK, "ssid": "new network"})
    assert store.path.read_bytes() == original
    assert not list(tmp_path.glob(".provisioning-state-*"))


def test_corrupt_shared_and_symlink_states_do_not_reopen(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("not JSON")
    path.chmod(0o600)
    with pytest.raises(StateError):
        ProvisioningState(path).allowed()
    path.write_text(json.dumps({"version": 1, "provisioned": True, "reopen_until": 0, "network": NETWORK}))
    path.chmod(0o644)
    with pytest.raises(StateError):
        ProvisioningState(path).allowed()
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        ProvisioningState(link).allowed()


def test_cli_local_reopen_retains_identity_and_network(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("device_provision.cli.sys.platform", "darwin")
    identity_path, qr_path, png_path = [tmp_path / name for name in ("identity.json", "qr.json", "qr.png")]
    create_identity("test", identity_path, qr_path, png_path)
    state = ProvisioningState(tmp_path / "state.json")
    state.provisioned(NETWORK)
    before = identity_path.read_bytes()
    assert main(["reopen", "--identity", str(identity_path), "--state", str(state.path)]) == 0
    assert state.allowed() and state.read()["network"] == NETWORK
    assert identity_path.read_bytes() == before
    assert "five minutes" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [["send", "--qr", "qr.json"],
                                   ["configure", "--qr", "qr.json", "--ssid", "test", "--password", "private"]])
def test_cli_rejects_obsolete_command_and_password_in_argv(argv, capsys):
    with pytest.raises(SystemExit) as error:
        parser().parse_args(argv)
    assert error.value.code == 2
    capsys.readouterr()


def test_linux_service_requires_root_without_loading_files(monkeypatch, capsys):
    monkeypatch.setattr("device_provision.cli.sys.platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert main(["serve", "--identity", "does-not-exist.json"]) == 1
    assert "must run as root" in capsys.readouterr().err
