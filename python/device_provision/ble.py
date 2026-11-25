"""Bless peripheral and Bleak central transports for v3 provisioning streams."""
from __future__ import annotations

import asyncio
import contextlib
import sys
from typing import Callable, Optional

from .framing import FrameDecoder, FrameError, decode_message, encode_message, fragment
from .identity import DeviceIdentity, QRIdentity
from .network import NetworkManager
from .protocol import ClientSession, DeviceSession, ProtocolError, REJECTED, SERVICE_UUID, RX_UUID, TX_UUID
from .service import ProvisioningService
from .state import ProvisioningState


class TransportError(RuntimeError):
    pass


BLE_HELP = ("Check Bluetooth power and BLE adapter support. On macOS allow Bluetooth for your terminal; "
            "macOS Diagnostics do not need root. On Linux check bluetoothd/BlueZ; the NetworkManager "
            "provisioning POC service must run as root.")


def advertised_name(device_id: str) -> str:
    """Selection hint only; the full ASCII ID remains in the QR and HPKE info.

    BlueZ places LocalName in the 31-byte legacy scan response: 29 name bytes
    plus its two-byte AD header. CoreBluetooth has a smaller local-name budget;
    cap macOS diagnostics at ten bytes, also keeping Bless 0.2.6's internal
    timeout retry from dropping service UUIDs. Prefixes may collide.
    """
    return device_id[:10 if sys.platform == "darwin" else 29]


async def serve(identity: DeviceIdentity, state: ProvisioningState, adapter: Optional[str] = None,
                interface: Optional[str] = None, ready: Optional[Callable[[], None]] = None) -> None:
    from bless import BlessServer, GATTCharacteristicProperties, GATTAttributePermissions

    loop = asyncio.get_running_loop()
    server = BlessServer(name=advertised_name(identity.device_id), loop=loop, adapter=adapter)
    incoming: asyncio.Queue = asyncio.Queue(maxsize=512)
    decoder = FrameDecoder(185)
    session = DeviceSession(identity)
    backend = NetworkManager(interface)
    operations = ProvisioningService(session, state, backend)
    accepting, overflow, started = True, False, False
    close_after = None
    frame_packet_size = 0

    def enqueue(packet):
        nonlocal overflow
        if accepting and started:
            try:
                incoming.put_nowait(packet)
            except asyncio.QueueFull:
                overflow = True

    def written(characteristic, value, **kwargs):
        if characteristic is not None and characteristic.uuid.lower() == RX_UUID:
            try:
                loop.call_soon_threadsafe(enqueue, bytes(value))
            except RuntimeError:
                pass

    server.write_request_func = written
    server.read_request_func = lambda characteristic, **kwargs: bytearray()

    async def emit(response):
        nonlocal close_after
        for chunk in fragment(encode_message(response), session.packet_size):
            tx.value = bytearray(chunk)
            deadline = loop.time() + 5
            while not server.update_value(SERVICE_UUID, TX_UUID):
                if loop.time() >= deadline:
                    raise TransportError("BLE notification queue stalled; no unreceived result is a success")
                await asyncio.sleep(0.03)
            await asyncio.sleep(0.03)
        # The service closes state BEFORE emitting connected. Start drain only after
        # the entire terminal encrypted frame has entered the notification queue.
        if not state.allowed() and close_after is None:
            close_after = loop.time() + 2

    try:
        await server.add_new_service(SERVICE_UUID)
        await server.add_new_characteristic(
            SERVICE_UUID, RX_UUID, GATTCharacteristicProperties.write,
            None, GATTAttributePermissions.writeable)
        await server.add_new_characteristic(
            SERVICE_UUID, TX_UUID, GATTCharacteristicProperties.notify,
            None, GATTAttributePermissions.readable)
        tx = server.get_characteristic(TX_UUID)
        while True:
            allowed = state.allowed()
            if allowed and not started:
                await server.start(prioritize_local_name=False)
                started = True
                close_after = None
            elif not allowed and started and (close_after is None or loop.time() >= close_after):
                await server.stop()
                started = False
                decoder.reset()
                session.reset()
                session.packet_size = 20
                frame_packet_size = 0
                while not incoming.empty():
                    incoming.get_nowait()
            if ready is not None:
                ready()
                ready = None
            if not started:
                await asyncio.sleep(1)
                continue  # Stay alive for a local owner-authorized reopen, including after reboot.
            try:
                packet = await asyncio.wait_for(incoming.get(), 1)
            except asyncio.TimeoutError:
                continue
            if overflow:
                raise TransportError("BLE receive queue overflow; disconnect clients and restart the service")
            try:
                if packet and packet[0] == 1:
                    frame_packet_size = 0
                frame_packet_size = max(frame_packet_size, len(packet))
                complete = decoder.feed(packet)
                if complete is None:
                    continue
                message = decode_message(complete)
                if message.get("type") == "challenge_request" and frame_packet_size > 20:
                    raise FrameError("Challenge requests use minimum-MTU framing")
                if message.get("type") != "challenge_request" and frame_packet_size > session.packet_size:
                    raise FrameError("Packet exceeds negotiated size")
                # This single worker owns all frames, challenges and network transactions.
                # BLE disconnects do not implicitly cancel a running join or reopen setup.
                await operations.handle(message, emit)
            except FrameError:
                session.reset()
                await emit(REJECTED)
    except (TransportError, asyncio.CancelledError):
        raise
    except Exception as exc:
        raise TransportError("Unable to run provisioning peripheral. Check the private state file. " + BLE_HELP) from exc
    finally:
        accepting = False
        backend.close()
        session.reset()
        decoder.reset()
        if started:
            with contextlib.suppress(Exception):
                await server.stop()


async def request(qr: QRIdentity, command: dict, address: Optional[str] = None,
                  timeout: float = 150.0, scan_timeout: float = 5.0,
                  progress: Optional[Callable[[dict], None]] = None) -> dict:
    from bleak import BleakClient, BleakScanner

    loop = asyncio.get_running_loop()
    decoder = FrameDecoder(185)
    incoming: asyncio.Queue = asyncio.Queue(maxsize=512)
    disconnected = asyncio.Event()
    overflow, accepting = False, True

    def enqueue(packet):
        nonlocal overflow
        if accepting:
            try:
                incoming.put_nowait(packet)
            except asyncio.QueueFull:
                overflow = True
                disconnected.set()

    def notified(characteristic, value):
        try:
            loop.call_soon_threadsafe(enqueue, bytes(value))
        except RuntimeError:
            pass

    def lost(client):
        try:
            loop.call_soon_threadsafe(disconnected.set)
        except RuntimeError:
            pass

    async def receive():
        while True:
            if disconnected.is_set():
                raise TransportError("BLE disconnected before a verified final result; device may still be joining")
            packet_task = asyncio.create_task(incoming.get())
            lost_task = asyncio.create_task(disconnected.wait())
            try:
                done, _ = await asyncio.wait((packet_task, lost_task), return_when=asyncio.FIRST_COMPLETED)
                if lost_task in done or overflow:
                    raise TransportError("BLE disconnected before a verified final result; device may still be joining")
                result = decoder.feed(packet_task.result())
                if result is not None:
                    return decode_message(result)
            finally:
                for task in (packet_task, lost_task):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(packet_task, lost_task, return_exceptions=True)

    async def send_frame(client, message, packet_size):
        for packet in fragment(encode_message(message), packet_size):
            await client.write_gatt_char(RX_UUID, packet, response=True)

    async def exchange(client):
        size = min(185, max(20, client.mtu_size - 3))
        session = ClientSession(qr, command, size)
        await client.start_notify(TX_UUID, notified)
        await send_frame(client, {"type": "challenge_request", "version": 3, "packet_size": size}, 20)
        challenge = await receive()
        outgoing = session.create_request(challenge)
        await send_frame(client, outgoing, session.packet_size)
        while True:
            value = session.accept_reply(await receive())
            if progress is not None:
                progress(value)
            if value["final"]:
                return value

    try:
        discovered = await BleakScanner.discover(timeout=scan_timeout, return_adv=True,
                                                 service_uuids=[SERVICE_UUID])
        candidates = [device for device, advertisement in discovered.values()
                      if SERVICE_UUID in [u.lower() for u in advertisement.service_uuids]
                      and (address is None or device.address.lower() == address.lower())]
        if not candidates:
            raise TransportError("No provisioning service found. Setup may be closed; use local reopen. " + BLE_HELP)
        if len(candidates) != 1:
            addresses = ", ".join(device.address for device in candidates)
            raise TransportError("Multiple peripherals found; choose --address from: " + addresses
                                 + ". Addresses select transport only; the QR authenticates the device.")
        async with BleakClient(candidates[0], disconnected_callback=lost, timeout=20,
                               services=[SERVICE_UUID]) as client:
            service = client.services.get_service(SERVICE_UUID)
            if service is None or service.get_characteristic(RX_UUID) is None or service.get_characteristic(TX_UUID) is None:
                raise TransportError("Peripheral lacks the provisioning GATT service/characteristics")
            return await asyncio.wait_for(exchange(client), timeout)
    except asyncio.TimeoutError as exc:
        raise TransportError("Timed out without a verified final result; the device may still be joining. Reconnect and check status") from exc
    except (TransportError, ProtocolError, asyncio.CancelledError):
        raise
    except FrameError as exc:
        raise TransportError("Invalid BLE response framing; disconnect and retry") from exc
    except Exception as exc:
        raise TransportError("BLE connection failed. " + BLE_HELP) from exc
    finally:
        accepting = False
        decoder.reset()
