"""Real-file tests for ownership-scoped BlueZ policy changes."""
import importlib.util
import json
from pathlib import Path
import stat

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "bluetooth_policy", Path(__file__).resolve().parents[1] / "deploy/bluetooth_policy.py")
policy = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(policy)


@pytest.mark.parametrize("original", [
    "# preserve comments\n[General]\nName = Demo\nReverseServiceDiscovery = true\n[Policy]\nAutoEnable=true\n",
    "[General]\n# ReverseServiceDiscovery = true\n[Policy]\nAutoEnable=true\n",
    "[Policy]\nAutoEnable=true\n",
    "# no final newline",
    "[General]",
    "[General]\r\nReverseServiceDiscovery=true\r\n[Policy]\r\nAutoEnable=true\r\n",
    "",
])
def test_roundtrip_and_rerun_preserve_original(tmp_path, original):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    config.write_bytes(original.encode())
    config.chmod(0o640)
    assert policy.apply_policy(config, record)
    applied = config.read_bytes()
    history = record.read_bytes()
    assert not policy.apply_policy(config, record)
    assert config.read_bytes() == applied
    assert record.read_bytes() == history
    assert stat.S_IMODE(record.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.stat().st_mode) == 0o640
    assert policy.restore_policy(config, record)
    assert config.read_bytes() == original.encode()
    assert json.loads(record.read_text())["restored_changed"] is True
    assert not policy.restore_policy(config, record)
    assert config.read_bytes() == original.encode()


def test_preexisting_false_is_not_claimed(tmp_path):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    original = "[General]\n ReverseServiceDiscovery = false\nName=Keep\n"
    config.write_text(original)
    assert not policy.apply_policy(config, record)
    assert not policy.restore_policy(config, record)
    assert config.read_text() == original
    assert json.loads(record.read_text())["restored_changed"] is False


def test_restoration_preserves_unrelated_later_edits(tmp_path):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    config.write_text("[General]\nReverseServiceDiscovery=true\nName=Before\n")
    policy.apply_policy(config, record)
    config.write_text(config.read_text().replace("Name=Before", "Name=After") + "[Policy]\nAutoEnable=false\n")
    assert policy.restore_policy(config, record)
    assert config.read_text() == "[General]\nReverseServiceDiscovery=true\nName=After\n[Policy]\nAutoEnable=false\n"


@pytest.mark.parametrize("later", ["ReverseServiceDiscovery=true\n", "ReverseServiceDiscovery = false\n", ""])
def test_later_owned_key_edits_are_never_overwritten(tmp_path, later):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    config.write_text("[General]\nName=Keep\n")
    policy.apply_policy(config, record)
    config.write_text("[General]\n" + later + "Name=Keep\n")
    before = config.read_bytes()
    with pytest.raises(ValueError, match="changed outside"):
        policy.apply_policy(config, record)
    assert not policy.restore_policy(config, record)
    assert config.read_bytes() == before


def test_added_section_keeps_later_settings(tmp_path):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    config.write_text("[Policy]\nAutoEnable=true\n")
    policy.apply_policy(config, record)
    config.write_text(config.read_text() + "Name=Added\n")
    assert policy.restore_policy(config, record)
    assert config.read_text() == "[Policy]\nAutoEnable=true\n[General]\nName=Added\n"


@pytest.mark.parametrize("text", [
    "[General]\nReverseServiceDiscovery=true\nReverseServiceDiscovery=false\n",
    "[General]\n[General]\n", "[General]\nReverseServiceDiscovery=maybe\n",
    "ReverseServiceDiscovery=true\n", "[General]\nunparseable\n",
])
def test_invalid_config_is_not_touched(tmp_path, text):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    config.write_text(text)
    with pytest.raises(ValueError):
        policy.apply_policy(config, record)
    assert config.read_text() == text
    assert not record.exists()


def test_corrupt_record_does_not_change_config(tmp_path):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    config.write_text("[General]\n")
    record.write_text('{"version": 1}')
    record.chmod(0o600)
    for operation in (policy.apply_policy, policy.restore_policy):
        with pytest.raises(ValueError):
            operation(config, record)
        assert config.read_text() == "[General]\n"
        assert record.read_text() == '{"version": 1}'


def test_symlink_and_shared_records_are_rejected(tmp_path):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    config.write_text("[General]\n")
    policy.apply_policy(config, record)
    before = config.read_bytes()
    record.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        policy.restore_policy(config, record)
    record.chmod(0o600)
    linked = tmp_path / "linked.json"
    linked.symlink_to(record)
    with pytest.raises(OSError):
        policy.restore_policy(config, linked)
    assert config.read_bytes() == before


def test_reinstall_starts_new_ownership_epoch(tmp_path):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    config.write_text("[General]\nReverseServiceDiscovery=true\n")
    assert policy.apply_policy(config, record)
    assert policy.restore_policy(config, record)
    config.write_text("[General]\nReverseServiceDiscovery = true\nName=New\n")
    original = config.read_bytes()
    assert policy.apply_policy(config, record)
    assert policy.restore_policy(config, record)
    assert config.read_bytes() == original


def test_record_cannot_be_used_for_another_config(tmp_path):
    config, other, record = tmp_path / "main.conf", tmp_path / "other.conf", tmp_path / "policy.json"
    config.write_text("[General]\n")
    other.write_text("[General]\nReverseServiceDiscovery=true\n")
    policy.apply_policy(config, record)
    with pytest.raises(ValueError):
        policy.restore_policy(other, record)
    assert other.read_text() == "[General]\nReverseServiceDiscovery=true\n"


@pytest.mark.parametrize("config_was_written", [False, True])
def test_pending_install_recovers_without_losing_original(tmp_path, config_was_written):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    original = "[General]\nReverseServiceDiscovery = true\nName=Keep\n"
    config.write_text(original)
    policy.apply_policy(config, record)
    data = json.loads(record.read_text())
    data["status"] = "pending"
    record.write_text(json.dumps(data))
    if not config_was_written:
        config.write_text(original)
    assert policy.apply_policy(config, record) is not config_was_written
    assert json.loads(record.read_text())["status"] == "active"
    assert policy.restore_policy(config, record)
    assert config.read_text() == original


def test_invalid_later_config_preserves_active_record(tmp_path):
    config, record = tmp_path / "main.conf", tmp_path / "policy.json"
    config.write_text("[General]\n")
    policy.apply_policy(config, record)
    history = record.read_bytes()
    config.write_text("[General]\nReverseServiceDiscovery=false\nReverseServiceDiscovery=true\n")
    before = config.read_bytes()
    with pytest.raises(ValueError):
        policy.restore_policy(config, record)
    assert config.read_bytes() == before
    assert record.read_bytes() == history
