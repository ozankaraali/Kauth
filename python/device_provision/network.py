"""Real NetworkManager system-bus provisioning; no shell or credential logging."""
from __future__ import annotations

import asyncio
import math
import os
import sys
import uuid

from dbus_next import BusType, Message, MessageType, Variant
from dbus_next.aio import MessageBus

from .protocol import usable_address, utf8

NM = "org.freedesktop.NetworkManager"
ROOT = "/org/freedesktop/NetworkManager"
DEVICE = NM + ".Device"
WIRELESS = DEVICE + ".Wireless"
AP = NM + ".AccessPoint"
ACTIVE = NM + ".Connection.Active"
SETTINGS = NM + ".Settings"
CONNECTION = SETTINGS + ".Connection"
DBUS = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
PROPERTIES = DBUS + ".Properties"
MESSAGES = {
    "invalid_request": "Invalid request. Check the SSID and WPA2 passphrase requirements.",
    "setup_closed": "Setup is closed. An administrator must run the local reopen command.",
    "backend_unavailable": "Wi-Fi provisioning requires Linux with NetworkManager. macOS supports Diagnostics only.",
    "radio_disabled": "Wi-Fi is disabled or unavailable. Enable the radio and check its hardware switch locally.",
    "no_wifi_device": "No unambiguous managed Wi-Fi adapter. Check NetworkManager and serve --interface locally.",
    "network_not_found": "The requested WPA2-Personal network was not found. Check the SSID, range, and hidden setting.",
    "authentication_failed": "NetworkManager could not authenticate with the supplied credentials. Check the WPA2 passphrase.",
    "ip_failed": "Wi-Fi did not obtain a usable IP address. Check the network's address configuration.",
    "timeout": "The network operation timed out. This does not establish that the password was wrong.",
    "permission_denied": "NetworkManager access was denied. The Linux POC service must run as root.",
    "network_error": "NetworkManager could not complete the operation. Check the adapter and network locally.",
    "rollback_failed": "The connection attempt failed and restoration could not be verified. Inspect networking locally.",
    "state_write_failed": "Wi-Fi is connected, but the local provisioning record could not be saved. Check state directory permissions and disk space locally.",
}


class NetworkError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(MESSAGES[code])

    def event(self):
        return {"event": "error", "final": True, "code": self.code, "message": str(self)}


class BusFailure(Exception):
    """Only the error name survives; D-Bus error bodies can contain secrets."""
    def __init__(self, name):
        self.name = name
        super().__init__("NetworkManager D-Bus call failed")


def safe_error(error: Exception) -> NetworkError:
    if isinstance(error, NetworkError):
        return error
    if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        return NetworkError("timeout")
    if isinstance(error, PermissionError):
        return NetworkError("permission_denied")
    if isinstance(error, BusFailure):
        if error.name.endswith(("PermissionDenied", "NotAuthorized", "AccessDenied")):
            return NetworkError("permission_denied")
        if error.name.endswith(("ServiceUnknown", "NameHasNoOwner", "UnknownMethod", "UnknownInterface")):
            return NetworkError("backend_unavailable")
    return NetworkError("network_error")


def unwrap(value):
    if isinstance(value, Variant):
        return unwrap(value.value)
    if isinstance(value, dict):
        return {k: unwrap(v) for k, v in value.items()}
    if isinstance(value, list):
        return [unwrap(v) for v in value]
    return value


def security(properties):
    rsn, wpa = properties.get("RsnFlags", 0), properties.get("WpaFlags", 0)
    if rsn & 0x100:
        return "wpa2-psk"
    if rsn & 0x400:
        return "wpa3-sae"
    if (rsn | wpa) & (0x200 | 0x2000):
        return "enterprise"
    if not (rsn or wpa or properties.get("Flags", 0) & 1):
        return "open"
    return "unsupported"


def scan_rows(points):
    strongest = {}
    for _, properties in points:
        try:
            ssid = bytes(properties["Ssid"]).decode("utf-8")
        except (KeyError, UnicodeError, ValueError):
            continue  # Non-UTF8/unknown hidden SSIDs cannot be represented by this protocol.
        if not utf8(ssid, 32):
            continue
        kind = security(properties)
        row = {"ssid": ssid, "strength": min(100, max(0, properties["Strength"])),
               "security": kind, "supported": kind == "wpa2-psk"}
        key = (ssid, kind)
        if key not in strongest or row["strength"] > strongest[key]["strength"]:
            strongest[key] = row
    rows = sorted(strongest.values(), key=lambda row: (-row["strength"], row["ssid"], row["security"]))
    return rows[:16], len(rows) > 16


def failure_reason(reason):
    if reason in (7,):  # NO_SECRETS: supplied credentials were not accepted/usable.
        return NetworkError("authentication_failed")
    if reason in (5, 6, 15, 16, 17):
        return NetworkError("ip_failed")
    if reason == 53:  # SSID_NOT_FOUND
        return NetworkError("network_not_found")
    if reason == 11:  # SUPPLICANT_TIMEOUT does not prove a bad password.
        return NetworkError("timeout")
    return NetworkError("network_error")


class ActivationWatch:
    """An attempt-local, owner-pinned Device.StateChanged subscription.

    Device reasons have no activation identifier. Pair each signal with the
    ActiveConnection published by NM's ordered PropertiesChanged stream, never
    with a later GetAll/StateReason snapshot. NM publishes ActiveConnection before
    PREPARE (nm-device.c activate_stage1_device_prepare). Retain early failures
    until AddAndActivateConnection2 returns the candidate's active path.
    """
    def __init__(self, backend, device):
        self.backend, self.device = backend, device
        self.bus, self.owner = backend.bus, backend.owner
        self.match = "type='signal',sender='%s',path='%s'" % (self.owner, device)
        self.current = "/"
        self.armed = False
        self.states = {}
        self.errors = {}

    def receive(self, message):
        if (message.message_type != MessageType.SIGNAL or message.sender != self.owner
                or message.path != self.device):
            return
        if (message.interface == PROPERTIES and message.member == "PropertiesChanged"
                and message.signature == "sa{sv}as" and len(message.body) == 3
                and message.body[0] == DEVICE):
            changed, invalidated = message.body[1:]
            previous = self.current
            if "ActiveConnection" in invalidated:
                self.current = "/"
            if "ActiveConnection" in changed:
                self.current = unwrap(changed["ActiveConnection"])
            if self.armed and previous != "/" and previous != self.current:
                # Losing this activation cannot be success, even if its terminal
                # Device signal comes after NM clears ActiveConnection.
                self.errors.setdefault(previous, NetworkError("network_error"))
        elif (self.armed and message.interface == DEVICE and message.member == "StateChanged"
              and message.signature == "uuu" and len(message.body) == 3):
            state, _, reason = message.body
            if self.current == "/":
                return  # No proven activation ownership; never guess from a reason.
            self.states[self.current] = state
            # NEED_AUTH (60) can be a normal secret lookup, even with NO_SECRETS.
            # Classify its reason only if the activation actually terminates.
            if state == 120 or state <= 30 or state == 110:
                self.errors.setdefault(self.current, failure_reason(reason))

    async def start(self):
        self.bus.add_message_handler(self.receive)
        # Mark removal necessary even if cancellation races AddMatch's reply.
        await self.backend._bus_call(DBUS, DBUS_PATH, DBUS, "AddMatch", "s", [self.match])

    def check(self, active):
        if active in self.errors:
            raise self.errors[active]
        return self.states.get(active, 0)

    async def stop(self):
        self.armed = False
        self.bus.remove_message_handler(self.receive)
        try:
            await asyncio.wait_for(self.backend._bus_call(
                DBUS, DBUS_PATH, DBUS, "RemoveMatch", "s", [self.match]), 2)
        except Exception:
            # Disconnect drops matches even if RemoveMatch failed. Cleanup must
            # not replace an authentication/rollback error with a bus error.
            try:
                self.backend.close()
            except Exception:
                pass  # The local handler is already detached.


class NetworkManager:
    def __init__(self, interface=None, timeout=120.0, poll_interval=0.5):
        self.interface, self.timeout, self.poll_interval = interface, timeout, poll_interval
        self.bus = None
        self.owner = None

    async def connect(self):
        if sys.platform != "linux":
            raise NetworkError("backend_unavailable")
        if os.geteuid() != 0:
            raise NetworkError("permission_denied")
        if self.bus is None:
            try:
                self.bus = await asyncio.wait_for(MessageBus(bus_type=BusType.SYSTEM).connect(), 10)
                self.owner = (await self._bus_call(
                    DBUS, DBUS_PATH, DBUS, "GetNameOwner", "s", [NM]))[0]
                if not self.owner.startswith(":"):
                    raise NetworkError("backend_unavailable")
            except asyncio.CancelledError:
                self.close()
                raise
            except Exception as exc:
                self.close()
                raise NetworkError("backend_unavailable") from exc

    def close(self):
        if self.bus is not None:
            self.bus.disconnect()
            self.bus = None
        self.owner = None

    async def _bus_call(self, destination, path, interface, member, signature="", body=None):
        reply = await asyncio.wait_for(self.bus.call(Message(
            destination=destination, path=path, interface=interface, member=member,
            signature=signature, body=[] if body is None else body)), 10)
        if reply.sender not in (destination, DBUS):
            raise NetworkError("network_error")
        if reply.message_type == MessageType.ERROR:
            raise BusFailure(reply.error_name)
        return reply.body

    async def call(self, path, interface, member, signature="", body=None):
        await self.connect()
        return await self._bus_call(self.owner, path, interface, member, signature, body)

    async def properties(self, path, interface):
        result = await self.call(path, PROPERTIES, "GetAll", "s", [interface])
        return unwrap(result[0])

    async def select_device(self):
        manager = await self.properties(ROOT, NM)
        if not all(manager.get(key, False) for key in ("NetworkingEnabled", "WirelessEnabled", "WirelessHardwareEnabled")):
            raise NetworkError("radio_disabled")
        paths = (await self.call(ROOT, NM, "GetDevices"))[0]
        candidates = []
        for path in paths:
            properties = await self.properties(path, DEVICE)
            if (properties.get("DeviceType") == 2 and properties.get("Managed")
                    and (self.interface is None or properties.get("Interface") == self.interface)):
                candidates.append((path, properties))
        if len(candidates) != 1:
            raise NetworkError("no_wifi_device")
        path, properties = candidates[0]
        if properties.get("State", 0) < 30:
            raise NetworkError("radio_disabled")
        return path, properties["Interface"]

    async def access_points(self, device):
        before = (await self.properties(device, WIRELESS))["LastScan"]
        try:
            await self.call(device, WIRELESS, "RequestScan", "a{sv}", [{}])
        except BusFailure as exc:
            # NotAllowed can mean a scan is already running, but also rate limiting.
            # Do not guess from an error string or present old APs as a fresh scan:
            # require an observed completed scan in either case.
            if not exc.name.endswith("NotAllowed"):
                raise
        deadline = asyncio.get_running_loop().time() + 25
        while (await self.properties(device, WIRELESS))["LastScan"] == before:
            if asyncio.get_running_loop().time() >= deadline:
                raise NetworkError("timeout")
            await asyncio.sleep(self.poll_interval)
        paths = (await self.call(device, WIRELESS, "GetAllAccessPoints"))[0]
        return [(path, await self.properties(path, AP)) for path in paths]

    async def scan(self):
        async def run():
            device, interface = await self.select_device()
            rows, truncated = scan_rows(await self.access_points(device))
            return {"interface": interface, "networks": rows, "truncated": truncated}
        try:
            return await asyncio.wait_for(run(), 35)
        except Exception as exc:
            raise safe_error(exc) from exc

    async def evidence(self, device, interface, candidate=None, active=None, ssid=None):
        properties = await self.properties(device, DEVICE)
        if properties.get("State") != 100 or properties.get("Interface") != interface:
            return None
        active_path = properties.get("ActiveConnection", "/")
        if active_path == "/" or (active is not None and active_path != active):
            return None
        connection = await self.properties(active_path, ACTIVE)
        if (connection.get("State") != 2 or device not in connection.get("Devices", [])
                or (candidate is not None and connection.get("Connection") != candidate)):
            return None
        wireless = await self.properties(device, WIRELESS)
        ap_path = wireless.get("ActiveAccessPoint", "/")
        if ap_path == "/":
            return None
        point = await self.properties(ap_path, AP)
        try:
            actual_ssid = bytes(point["Ssid"]).decode("utf-8")
        except (UnicodeError, KeyError):
            return None
        if not utf8(actual_ssid, 32) or (ssid is not None and actual_ssid != ssid):
            return None
        if candidate is not None and security(point) != "wpa2-psk":
            return None
        addresses = []
        for family in (4, 6):
            path = properties.get("Ip%dConfig" % family, "/")
            # Read this DEVICE's addresses, never global connectivity or another adapter.
            if path != "/":
                configuration = await self.properties(path, NM + ".IP%dConfig" % family)
                addresses.extend(row["address"] for row in configuration.get("AddressData", [])
                                 if usable_address(row.get("address")))
        if not addresses:
            return None
        # Reject evidence collected across a device/AP transition.
        after = await self.properties(device, DEVICE)
        after_wifi = await self.properties(device, WIRELESS)
        if (after.get("State") != 100 or after.get("ActiveConnection") != active_path
                or after_wifi.get("ActiveAccessPoint") != ap_path):
            return None
        return {"ssid": actual_ssid, "interface": interface, "addresses": sorted(set(addresses))[:16],
                "profile_uuid": connection["Uuid"]}

    async def status(self):
        async def run():
            try:
                device, interface = await self.select_device()
            except NetworkError as exc:
                if exc.code == "radio_disabled":
                    return None
                raise
            return await self.evidence(device, interface)
        try:
            return await asyncio.wait_for(run(), 20)
        except Exception as exc:
            raise safe_error(exc) from exc

    async def configure(self, command, progress):
        """Bounded transaction, reserving 15s of the 120s limit for restoration."""
        checkpoint = candidate = device = watch = activation_task = None
        identifier = str(uuid.uuid4())
        attempted = False
        cleanup_time = min(15.0, self.timeout / 4)

        async def trial():
            nonlocal checkpoint, candidate, device, attempted, watch, activation_task
            device, interface = await self.select_device()
            ssid = command["ssid"]
            # Reuse NM's discovered APs; scan→join must not require a second scan
            # during NM's rate-limit window. Activation handles discovery if absent.
            paths = (await self.call(device, WIRELESS, "GetAllAccessPoints"))[0]
            points = [(path, await self.properties(path, AP)) for path in paths]
            supported = [(path, p) for path, p in points
                         if bytes(p.get("Ssid", b"")) == ssid.encode("utf-8") and security(p) == "wpa2-psk"]
            specific = max(supported, key=lambda item: item[1]["Strength"])[0] if supported else "/"
            checkpoint = (await self.call(ROOT, NM, "CheckpointCreate", "aouu",
                                          [[device], math.ceil(self.timeout), 0]))[0]
            if not checkpoint or checkpoint == "/":
                raise NetworkError("network_error")
            settings = {
                "connection": {"id": Variant("s", "Karaali - " + ssid),
                               "uuid": Variant("s", identifier), "type": Variant("s", "802-11-wireless"),
                               "interface-name": Variant("s", interface), "autoconnect": Variant("b", False),
                               # NM filters agents by the candidate's ACL as well
                               # as the root activation subject. This is NOT an
                               # auth-retries workaround: even REQUEST_NEW cannot
                               # be sent to a non-root desktop agent for this trial.
                               # Root manual activations are not session-bound.
                               "permissions": Variant("as", ["user:root:"])},
                "802-11-wireless": {"ssid": Variant("ay", ssid.encode("utf-8")),
                                    "mode": Variant("s", "infrastructure"),
                                    "hidden": Variant("b", command.get("hidden", False))},
                "802-11-wireless-security": {"key-mgmt": Variant("s", "wpa-psk"),
                                             "proto": Variant("as", ["rsn"]),
                                             "wps-method": Variant("u", 1),
                                             "psk": Variant("s", command["password"]),
                                             "psk-flags": Variant("u", 0)},
                "ipv4": {"method": Variant("s", "auto")},
                "ipv6": {"method": Variant("s", "auto")},
            }
            await progress("connecting")
            await self.connect()
            watch = ActivationWatch(self, device)
            await watch.start()
            watch.armed = True
            attempted = True
            activation_task = asyncio.create_task(self.call(
                ROOT, NM, "AddAndActivateConnection2", "a{sa{sv}}ooa{sv}",
                [settings, device, specific, {"persist": Variant("s", "memory"),
                                             "bind-activation": Variant("s", "none")}]))
            # Cancelling a local await does not cancel an NM method. Preserve
            # its reply so rollback cannot race a still-being-created candidate.
            candidate, active, _ = await asyncio.shield(activation_task)
            obtaining = False
            while True:
                observed_state = watch.check(active)
                if 70 <= observed_state <= 100 and not obtaining:
                    await progress("obtaining_ip")
                    obtaining = True
                # An activation can fail before becoming the device's public
                # ActiveConnection. Its own terminal state is failure evidence,
                # but does not establish a password/SSID-specific reason.
                try:
                    activation = await self.properties(active, ACTIVE)
                    watch.check(active)
                    if activation.get("State") in (3, 4):
                        raise NetworkError("network_error")
                    result = await self.evidence(device, interface, candidate, active, ssid)
                except BusFailure:
                    # A failed activation may disappear while GetAll is in
                    # flight. Prefer its observed reason to UnknownObject.
                    watch.check(active)
                    raise
                watch.check(active)
                if result is not None:
                    break
                await asyncio.sleep(self.poll_interval)
            await progress("saving")
            settings["connection"]["autoconnect"] = Variant("b", True)
            settings["connection"]["autoconnect-priority"] = Variant("i", 999)
            # The verified profile becomes a normal system/autoconnect profile;
            # do not retain the trial's root-only visibility restriction.
            del settings["connection"]["permissions"]
            # Keep original settings AND PSK; GetSettings deliberately omits secrets.
            await self.call(candidate, CONNECTION, "Update2", "a{sa{sv}}ua{sv}", [settings, 1, {}])
            verified = await self.evidence(device, interface, candidate, active, ssid)
            watch.check(active)
            if verified is None:
                raise NetworkError("ip_failed")
            await self.call(ROOT, NM, "CheckpointDestroy", "o", [checkpoint])
            checkpoint = None
            return verified

        async def restore():
            nonlocal candidate
            failed = False
            if activation_task is not None:
                try:
                    candidate = (await activation_task)[0]
                except BusFailure as exc:
                    # A daemon error reply settles the method; transport errors
                    # do not prove that the server stopped creating a profile.
                    failed = exc.name.endswith(("NoReply", "Disconnected", "Timeout"))
                except Exception:
                    failed = True
            if checkpoint:
                try:
                    results = (await self.call(ROOT, NM, "CheckpointRollback", "o", [checkpoint]))[0]
                    failed = failed or results.get(device) != 0 or any(code != 0 for code in results.values())
                except Exception:
                    failed = True
            if attempted:
                try:
                    # A cancelled AddAndActivate may have created a profile without returning
                    # its path. Recover ONLY our randomly generated UUID, never another profile.
                    path = candidate
                    if path is None:
                        path = (await self.call(ROOT + "/Settings", SETTINGS, "GetConnectionByUuid", "s", [identifier]))[0]
                    settings = unwrap((await self.call(path, CONNECTION, "GetSettings"))[0])
                    if settings.get("connection", {}).get("uuid") != identifier:
                        failed = True
                    else:
                        await self.call(path, CONNECTION, "Delete")
                except BusFailure as exc:
                    if not exc.name.endswith(("InvalidConnection", "UnknownConnection", "UnknownObject")):
                        failed = True
                except Exception:
                    failed = True
            if failed:
                raise NetworkError("rollback_failed")

        try:
            return await asyncio.wait_for(trial(), self.timeout - cleanup_time)
        except BaseException as exc:
            if checkpoint or attempted:
                # Cancellation must not skip restoration. The daemon shields this bounded task.
                cleanup = asyncio.create_task(asyncio.wait_for(restore(), cleanup_time))
                while not cleanup.done():
                    try:
                        await asyncio.shield(cleanup)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                try:
                    cleanup.result()
                except BaseException as rollback:
                    raise NetworkError("rollback_failed") from rollback
            if isinstance(exc, asyncio.CancelledError):
                raise
            if not isinstance(exc, Exception):
                raise
            raise safe_error(exc) from exc
        finally:
            if watch is not None:
                # A second cancellation must not leak the match/handler. stop()
                # has its own deadline and disconnect fallback.
                stopping = asyncio.create_task(watch.stop())
                while not stopping.done():
                    try:
                        await asyncio.shield(stopping)
                    except asyncio.CancelledError:
                        continue
