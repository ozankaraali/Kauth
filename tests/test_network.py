"""Deterministic NM state-machine simulation only; these are NOT hardware join evidence."""
import asyncio
import copy

import pytest
from dbus_next import Message, MessageType, Variant

from device_provision.network import (
    ACTIVE, AP, CONNECTION, DBUS, DEVICE, NM, PROPERTIES, ROOT, SETTINGS, WIRELESS,
    BusFailure, NetworkError, NetworkManager, scan_rows, security, unwrap,
)
from device_provision.protocol import usable_address


COMMAND = {"op": "configure", "ssid": "  café ", "password": "correct horse", "hidden": False}


class SignalBus:
    """In-process bus delivery, including unsolicited signals (not trusted NM)."""
    def __init__(self):
        self.handlers = []
        self.matches = set()
        self.disconnected = False
        self.fail_remove = False

    def add_message_handler(self, handler):
        self.handlers.append(handler)

    def remove_message_handler(self, handler):
        self.handlers.remove(handler)

    def disconnect(self):
        self.disconnected = True
        self.matches.clear()

    async def call(self, message):
        if message.member == "AddMatch":
            self.matches.add(message.body[0])
        elif message.member == "RemoveMatch":
            if self.fail_remove:
                raise OSError("bus unavailable")
            self.matches.remove(message.body[0])
        else:
            raise AssertionError("Unexpected simulated bus operation")
        return Message(message_type=MessageType.METHOD_RETURN, reply_serial=1, sender=DBUS)

    def emit(self, interface, member, signature, body, *, sender=":1.42", path="/wifi",
             unsolicited=False):
        if not unsolicited and "type='signal',sender='%s',path='%s'" % (sender, path) not in self.matches:
            return
        message = Message(message_type=MessageType.SIGNAL, sender=sender, path=path,
                          interface=interface, member=member, signature=signature, body=body)
        for handler in list(self.handlers):
            handler(message)


class SimulatedNM(NetworkManager):
    """Models stored profiles, checkpoint restoration, association and IP acquisition."""
    def __init__(self, *, states=(40, 70, 100), addresses=("192.168.20.42",), actual_ssid=None,
                 fail_save=False, fail_rollback=False, deny_checkpoint=False, old_active=False,
                 early=False, handover=False, stale_reason=0):
        super().__init__(timeout=0.16, poll_interval=0.001)
        self.bus, self.owner = SignalBus(), ":1.42"
        self.signal_bus = self.bus
        self.early, self.handover, self.stale_reason = early, handover, stale_reason
        self.device_state = 100
        self.activation_entered = asyncio.Event()
        self.hold_reply = None
        self.prompted_agents = []
        self.desktop_agents = ["desktop"]
        self.states, self.step = list(states), 0
        self.addresses = list(addresses)
        self.actual_ssid = COMMAND["ssid"] if actual_ssid is None else actual_ssid
        self.fail_save, self.fail_rollback = fail_save, fail_rollback
        self.deny_checkpoint, self.old_active = deny_checkpoint, old_active
        self.profiles = {"/old_profile": {"connection": {"uuid": "old-uuid", "autoconnect": True},
                                         "marker": "existing user profile"}}
        self.original = copy.deepcopy(self.profiles)
        self.active = "/old_active"
        self.candidate = None
        self.candidate_active = None
        self.attempt_number = 0
        self.checkpoint = None
        self.scanned = 1
        self.saved = False
        self.checkpoint_snapshot = None
        self.failure_reason = 0
        self.persist_evidence = None

    async def connect(self):
        pass  # Only the physical transport/platform check is replaced.

    def publish_active(self, active):
        self.active = active
        self.bus.emit(PROPERTIES, "PropertiesChanged", "sa{sv}as",
                      [DEVICE, {"ActiveConnection": Variant("o", active)}, []])

    def transition(self, state, reason=0):
        old_state, self.device_state = self.device_state, state
        self.bus.emit(DEVICE, "StateChanged", "uuu", [state, old_state, reason])

    def advance(self):
        if self.step < len(self.states):
            state = self.states[self.step]
            self.step += 1
            reason = 7 if state == 60 else self.failure_reason if state in (110, 120, 30) else 0
            self.transition(state, reason)

    def request_new_secret(self, path, requester="root"):
        # Model the documented/source ACL + UID filters before any agent is
        # asked. This models policy, not an actual KDE/GNOME/iwd/wpa_supplicant.
        permissions = self.profiles[path]["connection"].get("permissions", [])
        for user in self.desktop_agents:
            if permissions and "user:%s:" % user not in permissions:
                continue
            if requester is not None and requester != user:
                continue
            self.prompted_agents.append((path, user))

    async def properties(self, path, interface):
        if path == ROOT and interface == NM:
            return {"NetworkingEnabled": True, "WirelessEnabled": True, "WirelessHardwareEnabled": True}
        if path == "/wifi" and interface == DEVICE:
            if self.candidate:
                self.advance()
            state = self.device_state
            return {"DeviceType": 2, "Managed": True, "State": state,
                    "StateReason": [state, self.stale_reason], "Interface": "wlan0",
                    "ActiveConnection": "/old_active" if self.old_active else self.active,
                    "Ip4Config": "/wifi_ip4", "Ip6Config": "/"}
        if path == "/ethernet" and interface == DEVICE:
            return {"DeviceType": 1, "Managed": True, "State": 100, "Interface": "eth0",
                    "ActiveConnection": "/ethernet_active", "Ip4Config": "/ethernet_ip4"}
        if interface == WIRELESS:
            return {"LastScan": self.scanned, "ActiveAccessPoint": "/ap"}
        if interface == AP:
            return {"Ssid": self.actual_ssid.encode(), "Strength": 80, "RsnFlags": 0x100,
                    "WpaFlags": 0, "Flags": 1}
        if interface == ACTIVE:
            candidate = path == self.candidate_active
            return {"State": 2, "Devices": ["/wifi"],
                    "Connection": self.candidate if candidate else "/old_profile",
                    "Uuid": self.profiles[self.candidate]["connection"]["uuid"] if candidate else "old-uuid"}
        if path == "/wifi_ip4":
            return {"AddressData": [{"address": value} for value in self.addresses]}
        if path == "/ethernet_ip4":
            return {"AddressData": [{"address": "10.0.0.50"}]}
        raise AssertionError("Unexpected simulated property path")

    async def call(self, path, interface, member, signature="", body=None):
        if member == "GetDevices":
            return [["/wifi", "/ethernet"]]
        if member == "RequestScan":
            self.scanned += 1
            return []
        if member == "GetAllAccessPoints":
            # Discovery sees the requested AP; actual association can intentionally be wrong.
            return [([] if self.actual_ssid != COMMAND["ssid"] else ["/ap"])]
        if member == "CheckpointCreate":
            if self.deny_checkpoint:
                raise BusFailure(NM + ".PermissionDenied")
            self.checkpoint = "/checkpoint"
            self.checkpoint_snapshot = (copy.deepcopy(self.profiles), self.active)
            return [self.checkpoint]
        if member == "AddAndActivateConnection2":
            assert self.checkpoint is not None
            settings, _, _, options = body
            assert unwrap(options)["persist"] == "memory"
            assert unwrap(options)["bind-activation"] == "none"
            self.attempt_number += 1
            suffix = "" if self.attempt_number == 1 else "_%d" % self.attempt_number
            self.candidate, self.candidate_active = "/candidate" + suffix, "/candidate_active" + suffix
            self.profiles[self.candidate] = unwrap(settings)
            assert not self.profiles[self.candidate]["connection"]["autoconnect"]
            self.step = 0
            if self.handover:
                self.publish_active("/old_active")
                self.transition(110, 60)  # NEW_ACTIVATION, not CARRIER (40).
                self.transition(30, 60)
                self.publish_active("/")
            self.publish_active(self.candidate_active)
            if self.early:
                while self.step < len(self.states):
                    self.advance()
            self.activation_entered.set()
            if self.hold_reply is not None:
                await self.hold_reply.wait()
            return [self.candidate, self.active, {}]
        if member == "Update2":
            assert self.step >= len(self.states)
            assert any(usable_address(value) for value in self.addresses)
            assert not self.old_active
            assert self.actual_ssid == COMMAND["ssid"]
            assert "permissions" not in unwrap(body[0])["connection"]
            self.persist_evidence = (self.active, self.actual_ssid, list(self.addresses))
            if self.fail_save:
                raise BusFailure(NM + ".Settings.PermissionDenied")
            self.profiles[path] = unwrap(body[0])
            self.saved = True
            return [{}]
        if member == "CheckpointDestroy":
            self.checkpoint = None
            return []
        if member == "CheckpointRollback":
            if self.fail_rollback:
                return [{"/wifi": 3}]
            old_profiles, self.active = self.checkpoint_snapshot
            # NM checkpoint restores the device; client must separately delete its new profile.
            self.profiles.update(old_profiles)
            self.checkpoint = None
            return [{"/wifi": 0}]
        if member == "GetConnectionByUuid":
            for key, profile in self.profiles.items():
                if profile["connection"]["uuid"] == body[0]:
                    return [key]
            raise BusFailure(NM + ".Settings.InvalidConnection")
        if member == "GetSettings":
            return [self.profiles[path]]
        if member == "Delete":
            del self.profiles[path]
            self.candidate = None
            return []
        raise AssertionError("Unexpected simulated D-Bus operation")


async def run_join(backend, command=None):
    events = []

    async def progress(event):
        events.append(event)

    result = await backend.configure(dict(command or COMMAND), progress)
    return result, events


def test_association_then_ip_then_persistence_preserves_existing_profile():
    backend = SimulatedNM()
    result, events = asyncio.run(run_join(backend))
    assert result["ssid"] == COMMAND["ssid"]
    assert result["addresses"] == ["192.168.20.42"]
    assert events == ["connecting", "obtaining_ip", "saving"]
    assert backend.persist_evidence == ("/candidate_active", COMMAND["ssid"], ["192.168.20.42"])
    assert backend.saved and backend.checkpoint is None
    assert backend.profiles["/old_profile"] == backend.original["/old_profile"]
    saved = backend.profiles["/candidate"]
    assert saved["connection"]["autoconnect"]
    assert saved["connection"]["id"] == "Karaali - " + COMMAND["ssid"]
    assert saved["connection"]["uuid"] == result["profile_uuid"]
    assert saved["connection"]["uuid"] != saved["connection"]["id"]
    assert saved["802-11-wireless-security"]["psk"] == COMMAND["password"]
    assert saved["802-11-wireless-security"]["wps-method"] == 1


@pytest.mark.parametrize("early", [False, True])
def test_need_auth_secret_lookup_can_resume_configuration_and_succeed(early):
    # Observed on iwd: CONFIG -> NEED_AUTH/NO_SECRETS -> CONFIG, not rejection.
    backend = SimulatedNM(states=(40, 50, 60, 50, 70, 100), early=early)
    result, _ = asyncio.run(run_join(backend))
    assert result["ssid"] == COMMAND["ssid"]
    assert result["addresses"] == ["192.168.20.42"]
    assert backend.saved and backend.checkpoint is None
    assert backend.profiles["/old_profile"] == backend.original["/old_profile"]


def test_unresolved_need_auth_times_out_without_inventing_bad_password():
    backend = SimulatedNM(states=(40, 60))
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "timeout"
    assert backend.profiles == backend.original and not backend.saved


def test_join_after_scan_does_not_depend_on_another_scan_being_allowed():
    class RateLimitedNM(SimulatedNM):
        async def call(self, path, interface, member, signature="", body=None):
            if member == "RequestScan" and self.scanned > 1:
                raise BusFailure(NM + ".Device.NotAllowed")
            return await super().call(path, interface, member, signature, body)

    backend = RateLimitedNM()

    async def scan_then_join():
        result = await backend.scan()
        assert result["networks"][0]["ssid"] == COMMAND["ssid"]
        return await run_join(backend)

    result, _ = asyncio.run(scan_then_join())
    assert result["ssid"] == COMMAND["ssid"]
    assert result["addresses"] == ["192.168.20.42"]
    assert backend.saved and backend.checkpoint is None
    assert backend.profiles["/old_profile"] == backend.original["/old_profile"]


@pytest.mark.parametrize("addresses", [[], ["0.0.0.0"], ["127.0.0.1"], ["169.254.2.4"],
                                        ["fe80::1"], ["::"], ["ff02::1"], ["255.255.255.255"]])
def test_nm_activated_without_usable_wifi_ip_rolls_back(addresses):
    backend = SimulatedNM(addresses=addresses)
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "timeout"
    assert not backend.saved
    assert backend.profiles == backend.original
    assert backend.active == "/old_active"  # Ethernet's usable address was not accepted.


def test_existing_active_connection_is_not_candidate_success():
    backend = SimulatedNM(old_active=True)
    with pytest.raises(NetworkError):
        asyncio.run(run_join(backend))
    assert not backend.saved and backend.profiles == backend.original


def test_wrong_actual_ssid_never_reports_success():
    backend = SimulatedNM(actual_ssid="other")
    with pytest.raises(NetworkError):
        asyncio.run(run_join(backend, {**COMMAND, "hidden": True}))
    assert not backend.saved and backend.profiles == backend.original


def test_checkpoint_denial_prevents_all_mutation():
    backend = SimulatedNM(deny_checkpoint=True)
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "permission_denied"
    assert backend.candidate is None and backend.profiles == backend.original


def test_save_failure_restores_prior_network_and_only_deletes_candidate():
    backend = SimulatedNM(fail_save=True)
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "permission_denied"
    assert backend.profiles == backend.original and backend.active == "/old_active"


def test_rollback_failure_is_explicit_not_original_error():
    backend = SimulatedNM(fail_save=True, fail_rollback=True)
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "rollback_failed"
    assert "/candidate" not in backend.profiles
    assert backend.profiles["/old_profile"] == backend.original["/old_profile"]


@pytest.mark.parametrize("cancel_before_reply", [False, True])
def test_cancelled_transaction_restores_only_owned_candidate(cancel_before_reply):
    async def run():
        backend = SimulatedNM(states=(40,))
        if cancel_before_reply:
            backend.hold_reply = asyncio.Event()
        task = asyncio.create_task(run_join(backend))
        await backend.activation_entered.wait()
        task.cancel()
        if cancel_before_reply:
            # The daemon must let an already-dispatched NM method settle before
            # restoring, not "cancel" the local await and leave a late candidate.
            await asyncio.sleep(0)
            backend.hold_reply.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert backend.profiles == backend.original
        assert backend.active == "/old_active"
        assert not backend.signal_bus.handlers and not backend.signal_bus.matches
    asyncio.run(run())


@pytest.mark.parametrize("reason,code", [(7, "authentication_failed"), (11, "timeout"),
                                        (5, "ip_failed"), (53, "network_not_found"), (10, "network_error")])
def test_nm_failure_reasons_not_all_wrong_password(reason, code):
    # The intermediate NO_SECRETS must not mask the actual terminal reason.
    backend = SimulatedNM(states=(40, 60, 120))
    backend.failure_reason = reason
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == code
    assert backend.profiles == backend.original


@pytest.mark.parametrize("stale_reason", [7, 11, 40, 53, 60])
@pytest.mark.parametrize("early", [False, True])
def test_connected_handover_ignores_prior_network_reason(stale_reason, early):
    backend = SimulatedNM(handover=True, stale_reason=stale_reason, early=early)
    result, _ = asyncio.run(run_join(backend))
    assert result["ssid"] == COMMAND["ssid"] and backend.saved
    assert backend.profiles["/old_profile"] == backend.original["/old_profile"]
    assert "permissions" not in backend.profiles["/candidate"]["connection"]
    assert not backend.signal_bus.handlers and not backend.signal_bus.matches


@pytest.mark.parametrize("reason,code", [(7, "authentication_failed"), (53, "network_not_found"),
                                        (11, "timeout"), (40, "network_error")])
def test_failure_before_activation_reply_survives_later_disconnected_state(reason, code):
    class EarlyFailureNM(SimulatedNM):
        async def call(self, path, interface, member, signature="", body=None):
            reply = await super().call(path, interface, member, signature, body)
            if member == "AddAndActivateConnection2":
                self.publish_active("/")
                self.transition(30, 0)
            return reply

    backend = EarlyFailureNM(states=(40, 120), early=True, handover=True, stale_reason=0)
    backend.failure_reason = reason
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == code
    assert backend.profiles == backend.original and not backend.saved
    assert not backend.signal_bus.handlers and not backend.signal_bus.matches


@pytest.mark.parametrize("spoof", [{"sender": ":1.999"}, {"path": "/other_wifi"},
                                  {"interface": ACTIVE}, {"member": "OtherSignal"}])
def test_untrusted_signal_cannot_fail_or_claim_candidate_ownership(spoof):
    class NoisyNM(SimulatedNM):
        async def call(self, path, interface, member, signature="", body=None):
            reply = await super().call(path, interface, member, signature, body)
            if member == "AddAndActivateConnection2":
                args = {"interface": DEVICE, "member": "StateChanged", "signature": "uuu",
                        "body": [120, 50, 7], "unsolicited": True, **spoof}
                self.bus.emit(**args)
                # Spoofing ownership from a different sender/path cannot attach
                # a later genuine failure of an unrelated activation to ours.
                self.bus.emit(PROPERTIES, "PropertiesChanged", "sa{sv}as",
                              [DEVICE, {"ActiveConnection": Variant("o", "/unrelated")}, []],
                              sender=":1.999", unsolicited=True)
            return reply

    backend = NoisyNM()
    result, _ = asyncio.run(run_join(backend))
    assert result["ssid"] == COMMAND["ssid"] and backend.saved


def test_prior_activation_failure_during_handover_is_not_candidate_failure():
    class PreviousFailureNM(SimulatedNM):
        def publish_active(self, active):
            if active == self.candidate_active:
                super().publish_active("/previous_attempt")
                self.transition(120, 7)
                super().publish_active("/")
            super().publish_active(active)

    backend = PreviousFailureNM(handover=True)
    result, _ = asyncio.run(run_join(backend))
    assert result["ssid"] == COMMAND["ssid"] and backend.saved


def test_wrong_password_then_correct_retry_uses_fresh_observations():
    async def run():
        backend = SimulatedNM(states=(40, 120), early=True)
        backend.failure_reason = 7
        with pytest.raises(NetworkError) as error:
            await run_join(backend, {**COMMAND, "password": "wrong password"})
        assert error.value.code == "authentication_failed"
        assert backend.profiles == backend.original
        assert not backend.signal_bus.handlers and not backend.signal_bus.matches
        backend.states, backend.failure_reason, backend.stale_reason = [40, 70, 100], 0, 7
        result, _ = await run_join(backend)
        assert result["ssid"] == COMMAND["ssid"]
        assert backend.profiles["/candidate_2"]["802-11-wireless-security"]["psk"] == COMMAND["password"]
        assert backend.profiles["/old_profile"] == backend.original["/old_profile"]
    asyncio.run(run())


def test_candidate_replaced_by_other_activation_never_saves_unrelated_success():
    class ReplacedNM(SimulatedNM):
        async def properties(self, path, interface):
            if self.candidate and interface == ACTIVE:
                self.publish_active("/unrelated")
                self.transition(100)
            return await super().properties(path, interface)

    backend = ReplacedNM()
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "network_error"
    assert not backend.saved and backend.profiles == backend.original


def test_unpublished_candidate_terminal_state_is_failure_without_guessed_reason():
    class UnpublishedFailureNM(SimulatedNM):
        def publish_active(self, active):
            self.active = active  # Failure before NM publishes device ownership.

        async def properties(self, path, interface):
            result = await super().properties(path, interface)
            if path == self.candidate_active and interface == ACTIVE:
                result["State"] = 4
            return result

    backend = UnpublishedFailureNM(stale_reason=7)
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "network_error"  # stale NO_SECRETS is not evidence.
    assert not backend.saved and backend.profiles == backend.original


def test_unsubscribe_failure_disconnects_without_masking_authentication_error():
    backend = SimulatedNM(states=(120,), early=True)
    backend.failure_reason = 7
    backend.signal_bus.fail_remove = True
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "authentication_failed"
    assert backend.signal_bus.disconnected and not backend.signal_bus.handlers
    assert backend.profiles == backend.original


def test_repeated_cancellation_cannot_cancel_rollback():
    async def run():
        entered, release = asyncio.Event(), asyncio.Event()

        class SlowRollbackNM(SimulatedNM):
            async def call(self, path, interface, member, signature="", body=None):
                if member == "CheckpointRollback":
                    entered.set()
                    await release.wait()
                return await super().call(path, interface, member, signature, body)

        backend = SlowRollbackNM(states=(40,))
        task = asyncio.create_task(run_join(backend))
        await backend.activation_entered.wait()
        task.cancel()
        await entered.wait()
        for _ in range(3):
            task.cancel()
            await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert backend.profiles == backend.original and backend.active == "/old_active"
        assert not backend.signal_bus.handlers and not backend.signal_bus.matches
    asyncio.run(run())


def test_new_secret_request_excludes_desktop_only_for_candidate():
    class SecretRequestNM(SimulatedNM):
        async def call(self, path, interface, member, signature="", body=None):
            reply = await super().call(path, interface, member, signature, body)
            if member == "AddAndActivateConnection2":
                # Even an internal request (no UID filtering) must not offer
                # this trial to the desktop agent. Other profiles stay usable.
                self.request_new_secret(self.candidate, requester=None)
                self.request_new_secret("/old_profile", requester=None)
            return reply

    backend = SecretRequestNM(states=(120,), early=True)
    backend.failure_reason = 7
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "authentication_failed"
    assert backend.prompted_agents == [("/old_profile", "desktop")]
    assert backend.profiles == backend.original



def test_timeout_restores_network_and_removes_subscription():
    backend = SimulatedNM(states=(40,))
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "timeout"
    assert backend.profiles == backend.original and backend.active == "/old_active"
    assert not backend.signal_bus.handlers and not backend.signal_bus.matches


def test_cancelled_call_waits_for_late_candidate_creation_before_rollback():
    async def run():
        dispatched, release = asyncio.Event(), asyncio.Event()

        class LateCreateNM(SimulatedNM):
            async def call(self, path, interface, member, signature="", body=None):
                if member == "AddAndActivateConnection2":
                    dispatched.set()
                    await release.wait()
                return await super().call(path, interface, member, signature, body)

        backend = LateCreateNM(states=(40,))
        task = asyncio.create_task(run_join(backend))
        await dispatched.wait()
        task.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert backend.attempt_number == 1  # NM did create it after cancellation.
        assert backend.profiles == backend.original and backend.active == "/old_active"
        assert not backend.signal_bus.handlers and not backend.signal_bus.matches
    asyncio.run(run())


def test_lost_activation_reply_recovers_only_the_candidate_uuid():
    class LostReplyNM(SimulatedNM):
        async def call(self, path, interface, member, signature="", body=None):
            result = await super().call(path, interface, member, signature, body)
            if member == "AddAndActivateConnection2":
                raise BusFailure(NM + ".Failed")
            return result

    backend = LostReplyNM(states=(40,))
    # Duplicate human labels must never make an existing profile ours to delete.
    backend.profiles["/old_profile"]["connection"]["id"] = "Karaali - " + COMMAND["ssid"]
    backend.original = copy.deepcopy(backend.profiles)
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "network_error"
    assert backend.profiles == backend.original and backend.active == "/old_active"
    assert not backend.signal_bus.handlers and not backend.signal_bus.matches


def test_reason_arriving_while_failed_active_object_disappears_is_preserved():
    class DisappearingNM(SimulatedNM):
        async def properties(self, path, interface):
            if path == self.candidate_active and interface == ACTIVE:
                self.transition(120, 7)
                self.publish_active("/")
                raise BusFailure("org.freedesktop.DBus.Error.UnknownObject")
            return await super().properties(path, interface)

    backend = DisappearingNM()
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "authentication_failed"
    assert backend.profiles == backend.original and not backend.saved


def test_unsettled_activation_rpc_never_claims_verified_rollback():
    class ReplyTimeoutNM(SimulatedNM):
        async def call(self, path, interface, member, signature="", body=None):
            result = await super().call(path, interface, member, signature, body)
            if member == "AddAndActivateConnection2":
                raise asyncio.TimeoutError()
            return result

    backend = ReplyTimeoutNM()
    with pytest.raises(NetworkError) as error:
        asyncio.run(run_join(backend))
    assert error.value.code == "rollback_failed"
    # Best-effort cleanup still happens, but a local RPC timeout cannot prove
    # that the server has finished all pending work.
    assert backend.profiles == backend.original and backend.active == "/old_active"
    assert not backend.signal_bus.handlers and not backend.signal_bus.matches

@pytest.mark.parametrize("address", ["192.168.1.4", "10.0.0.2", "100.64.0.2", "fd00::12", "2001:db8::1", "::ffff:10.0.0.2"])
def test_real_unicast_address_validation(address):
    assert usable_address(address)


@pytest.mark.parametrize("address", ["", "not an IP", "0.0.0.0", "127.2.3.4", "169.254.2.4", "224.0.0.1",
                                    "255.255.255.255", "::", "::1", "fe80::2", "ff02::1", "::ffff:127.0.0.1",
                                    "::ffff:169.254.2.4", "::ffff:224.0.0.1", "fe80::1%wlan0"])
def test_invalid_or_nonusable_address_validation(address):
    assert not usable_address(address)


def test_scan_wpa2_rsn_bit_transition_support_and_bounded_deduplication():
    assert security({"RsnFlags": 0x500}) == "wpa2-psk"
    assert security({"RsnFlags": 0x400}) == "wpa3-sae"
    assert security({"WpaFlags": 0x100}) == "unsupported"
    assert security({"RsnFlags": 0x200}) == "enterprise"
    assert security({"Flags": 1}) == "unsupported"
    assert security({}) == "open"
    points = [(str(i), {"Ssid": ("ssid-%02d" % i).encode(), "Strength": 50, "RsnFlags": 0x100}) for i in range(20)]
    points += [("duplicate", {"Ssid": b"ssid-19", "Strength": 99, "RsnFlags": 0x100})]
    rows, truncated = scan_rows(points)
    assert truncated and len(rows) == 16
    assert rows[0]["ssid"] == "ssid-19" and rows[0]["strength"] == 99
    assert rows[1]["ssid"] == "ssid-00"
    assert len({row["ssid"] for row in rows}) == 16
