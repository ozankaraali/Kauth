import json
import os
import stat

import pytest

from device_provision.identity import DeviceIdentity, IdentityError, QRIdentity, create_identity, unb64


def test_exclusive_owner_only_identity_and_qr(tmp_path):
    private, qr_json, qr_png = (tmp_path / name for name in ("identity.json", "qr.json", "qr.png"))
    identity = create_identity("deck-demo-01", private, qr_json, qr_png)
    assert DeviceIdentity.load(private) == identity
    assert QRIdentity.load(qr_json) == identity.qr
    assert "private_key" not in json.loads(qr_json.read_text())
    assert qr_png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    for path in (private, qr_json, qr_png):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    original = private.read_bytes()
    with pytest.raises(FileExistsError):
        create_identity("deck-demo-01", private, qr_json, qr_png)
    assert private.read_bytes() == original
    assert identity.private_key != DeviceIdentity.generate(identity.device_id).private_key
    assert identity.setup_secret != DeviceIdentity.generate(identity.device_id).setup_secret
    assert identity.setup_secret.hex() not in repr(identity)


def test_creation_rolls_back_only_own_artifacts(tmp_path):
    private, qr_json, qr_png = (tmp_path / name for name in ("identity.json", "qr.json", "qr.png"))
    qr_json.write_text("preexisting")
    with pytest.raises(FileExistsError):
        create_identity("test", private, qr_json, qr_png)
    assert not private.exists()
    assert qr_json.read_text() == "preexisting"
    assert not qr_png.exists()


def test_load_refuses_shared_private_file(tmp_path):
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(DeviceIdentity.generate("test").to_dict()))
    path.chmod(0o644)
    with pytest.raises(IdentityError):
        DeviceIdentity.load(path)
    path.chmod(0o600)
    assert DeviceIdentity.load(path).device_id == "test"
    link = tmp_path / "link"
    link.symlink_to(path)
    if hasattr(os, "O_NOFOLLOW"):
        with pytest.raises(OSError):
            DeviceIdentity.load(link)


@pytest.mark.parametrize("device_id", ["", "X", "two words", "é", "a" * 33, "a\n"])
def test_invalid_ids(device_id):
    with pytest.raises(IdentityError):
        DeviceIdentity.generate(device_id)


def test_reject_invalid_and_mismatched_keys():
    value = DeviceIdentity.generate("test").to_dict()
    value["private_key"] = DeviceIdentity.generate("test").to_dict()["private_key"]
    with pytest.raises(IdentityError):
        DeviceIdentity.from_dict(value)
    value["version"] = True
    with pytest.raises(IdentityError):
        QRIdentity.from_dict(value)
    for bad in ("AAAA====", "not base64", "AA", 123, None):
        with pytest.raises(ValueError):
            unb64(bad, 32)
