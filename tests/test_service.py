"""Crypto/controller tests; simulated NM scenarios are not hardware evidence."""
import asyncio

import pytest

from device_provision.identity import DeviceIdentity
from device_provision.protocol import ClientSession, DeviceSession, ProtocolError
from device_provision.service import ProvisioningService
from device_provision.state import ProvisioningState
from test_network import COMMAND, SimulatedNM


async def exchange(service, identity, command):
    client = ClientSession(identity.qr, command)
    challenge = service.session.challenge({"type": "challenge_request", "version": 3, "packet_size": 20})
    request = client.create_request(challenge)
    events = []

    async def emit(envelope):
        events.append(client.accept_reply(envelope))

    await service.handle(request, emit)
    return events


def test_encrypted_connection_success_commits_state_before_final(tmp_path):
    async def run():
        identity = DeviceIdentity.generate("test")
        state = ProvisioningState(tmp_path / "state.json")
        backend = SimulatedNM()
        service = ProvisioningService(DeviceSession(identity), state, backend)
        events = await exchange(service, identity, dict(COMMAND))
        assert [event["event"] for event in events] == ["connecting", "obtaining_ip", "saving", "connected"]
        assert events[-1]["final"] and events[-1]["provisioned"]
        assert state.read()["network"]["profile_uuid"] == events[-1]["profile_uuid"]
        assert not state.allowed()
        # A subsequent authenticated request is rejected even on a still-open BLE connection.
        denied = await exchange(service, identity, {"op": "scan"})
        assert denied[-1]["code"] == "setup_closed"
    asyncio.run(run())


def test_state_write_failure_never_reports_success_or_undoes_working_network(tmp_path, monkeypatch):
    async def run():
        identity = DeviceIdentity.generate("test")
        state = ProvisioningState(tmp_path / "state.json")
        backend = SimulatedNM()
        service = ProvisioningService(DeviceSession(identity), state, backend)

        def fail_write(value):
            raise OSError("private failure detail must not cross BLE")

        monkeypatch.setattr(state, "provisioned", fail_write)
        events = await exchange(service, identity, dict(COMMAND))
        assert events[-1]["event"] == "error" and events[-1]["code"] == "state_write_failed"
        assert "private failure" not in events[-1]["message"]
        assert all(event["event"] != "connected" for event in events)
        assert backend.saved and backend.active == "/candidate_active"
        assert backend.checkpoint is None
        assert not state.read()["provisioned"]
    asyncio.run(run())


def test_failed_reopen_join_keeps_prior_profile_and_window(tmp_path):
    async def run():
        identity = DeviceIdentity.generate("test")
        state = ProvisioningState(tmp_path / "state.json")
        prior = {"ssid": "old", "interface": "wlan0", "addresses": ["10.0.0.2"], "profile_uuid": "old-uuid"}
        state.provisioned(prior)
        state.reopen()
        backend = SimulatedNM(fail_save=True)
        events = await exchange(ProvisioningService(DeviceSession(identity), state, backend), identity, dict(COMMAND))
        assert events[-1]["event"] == "error"
        assert state.allowed() and state.read()["network"] == prior
        assert backend.profiles == backend.original
    asyncio.run(run())


def test_mac_actual_backend_reports_authenticated_unsupported(tmp_path, monkeypatch):
    monkeypatch.setattr("device_provision.service.sys.platform", "darwin")

    async def run():
        identity = DeviceIdentity.generate("test")
        service = ProvisioningService(DeviceSession(identity), ProvisioningState(tmp_path / "state.json"))
        for command in ({"op": "scan"}, dict(COMMAND)):
            events = await exchange(service, identity, command)
            assert events[-1]["event"] == "error"
            assert events[-1]["code"] == "backend_unavailable"
            assert events[-1]["final"]
        echo = await exchange(service, identity, {"op": "echo", "text": " merhaba "})
        assert echo[-1]["echo"] == " merhaba "
        status = await exchange(service, identity, {"op": "status"})
        assert status[-1]["network"] is None and not status[-1]["provisioned"]
    asyncio.run(run())


@pytest.mark.parametrize("reason,code", [(7, "authentication_failed"), (53, "network_not_found"),
                                        (11, "timeout"), (40, "network_error")])
def test_early_candidate_failure_is_authenticated_consumer_error(tmp_path, reason, code):
    async def run():
        identity = DeviceIdentity.generate("test")
        state = ProvisioningState(tmp_path / "state.json")
        backend = SimulatedNM(states=(40, 120), early=True, handover=True, stale_reason=7)
        backend.failure_reason = reason
        service = ProvisioningService(DeviceSession(identity), state, backend)
        events = await exchange(service, identity, dict(COMMAND))
        assert events[-1]["event"] == "error" and events[-1]["code"] == code
        assert events[-1]["final"]
        assert not any(event["event"] in ("saving", "connected") for event in events)
        assert COMMAND["password"] not in str(events)
        assert state.allowed() and not state.read()["provisioned"]
        assert backend.profiles == backend.original
        assert not backend.signal_bus.handlers and not backend.signal_bus.matches
    asyncio.run(run())


def test_encrypted_wrong_password_then_correct_retry_without_reopening(tmp_path):
    async def run():
        identity = DeviceIdentity.generate("test")
        state = ProvisioningState(tmp_path / "state.json")
        backend = SimulatedNM(states=(40, 120), early=True, handover=True)
        backend.failure_reason = 7
        service = ProvisioningService(DeviceSession(identity), state, backend)
        failed = await exchange(service, identity, {**COMMAND, "password": "wrong password"})
        assert failed[-1]["code"] == "authentication_failed"
        assert state.allowed() and backend.profiles == backend.original
        backend.states, backend.failure_reason, backend.stale_reason = [40, 70, 100], 0, 7
        succeeded = await exchange(service, identity, dict(COMMAND))
        assert succeeded[-1]["event"] == "connected" and succeeded[-1]["provisioned"]
        assert succeeded[-1]["ssid"] == COMMAND["ssid"]
        assert state.read()["network"]["profile_uuid"] == succeeded[-1]["profile_uuid"]
        assert backend.profiles["/old_profile"] == backend.original["/old_profile"]
    asyncio.run(run())


@pytest.mark.parametrize("addresses", [[], ["127.0.0.1"], ["169.254.1.2"], ["fe80::1"], ["ff02::1"]])
def test_authenticated_connected_event_still_requires_usable_address(addresses):
    identity = DeviceIdentity.generate("test")
    device = DeviceSession(identity)
    client = ClientSession(identity.qr, dict(COMMAND))
    context = device.authenticate(client.create_request(device.challenge({"type": "challenge_request", "version": 3})))
    reply = context.reply({"event": "connected", "final": True, "ssid": COMMAND["ssid"],
                           "interface": "wlan0", "addresses": addresses,
                           "profile_uuid": "candidate-uuid", "provisioned": True})
    with pytest.raises(ProtocolError):
        client.accept_reply(reply)
