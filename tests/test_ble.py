"""Advertising policy tests, not evidence of actual controller packet placement."""
import pytest

from device_provision.ble import advertised_name
from device_provision.identity import DeviceIdentity


@pytest.mark.parametrize("platform,maximum", [("linux", 29), ("darwin", 10)])
@pytest.mark.parametrize("device_id", ["a", "demodevice1", "deck-demo-01", "a" * 29, "a" * 32])
def test_advertised_prefix_fits_name_budget_without_changing_identity(monkeypatch, platform, maximum, device_id):
    monkeypatch.setattr("device_provision.ble.sys.platform", platform)
    identity = DeviceIdentity.generate(device_id)
    name = advertised_name(identity.device_id)
    assert name == device_id[:maximum]
    assert len(name.encode("ascii")) <= maximum
    assert identity.device_id == device_id
    assert identity.qr.device_id == device_id
    if platform == "linux":
        # Local-name AD length/type plus payload fits the legacy scan response;
        # the separate advertising packet retains the 128-bit service UUID.
        assert len(name.encode("ascii")) + 2 <= 31


def test_colliding_advertised_prefixes_are_not_identity(monkeypatch):
    monkeypatch.setattr("device_provision.ble.sys.platform", "linux")
    first = DeviceIdentity.generate("a" * 29 + "-01")
    second = DeviceIdentity.generate("a" * 29 + "-02")
    assert advertised_name(first.device_id) == advertised_name(second.device_id)
    assert first.qr.device_id != second.qr.device_id
    assert first.qr.public_key != second.qr.public_key
