"""HPKE-PSK v3 commands and direction-separated, sequential authenticated events."""
from __future__ import annotations

import hmac
import ipaddress
import re
import secrets
import time
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from .framing import decode_message, encode_message
from .identity import DeviceIdentity, QRIdentity, b64, unb64

SERVICE_UUID = "8a46a1b0-5f14-4ad9-a7a8-21fc87a08001"
RX_UUID = "8a46a1b0-5f14-4ad9-a7a8-21fc87a08002"
TX_UUID = "8a46a1b0-5f14-4ad9-a7a8-21fc87a08003"
PROTOCOL_LABEL = b"karaali-provision/v3"
REQUEST_AAD = b"karaali-provision/v3/request"
EXPORT_CONTEXT = b"karaali-provision/v3/device-to-phone"
CHALLENGE_TTL = 60.0
MAX_REQUEST = 4096
MAX_EVENT = 5600
REJECTED = {"type": "error", "code": "rejected"}
SECURITIES = {"wpa2-psk", "wpa3-sae", "enterprise", "open", "unsupported"}


class ProtocolError(ValueError):
    """Unverified protocol result; never a successful operation."""


def new_suite() -> CipherSuite:
    return CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256,
                           AEADId.CHACHA20_POLY1305)


def hpke_public(key: bytes):
    return KEMKey.from_pyca_cryptography_key(X25519PublicKey.from_public_bytes(key))


def hpke_private(key: bytes):
    return KEMKey.from_pyca_cryptography_key(X25519PrivateKey.from_private_bytes(key))


def psk_id(device_id: str) -> bytes:
    return b"karaali-provision/v3/setup/" + device_id.encode("ascii")


def make_info(device_id: str, challenge: bytes, packet_size: int = 20) -> bytes:
    return (PROTOCOL_LABEL + b"\x00" + device_id.encode("ascii") + b"\x00" + challenge
            + packet_size.to_bytes(2, "big"))


def reply_nonce(counter: int) -> bytes:
    return b"\x00\x00\x00\x01" + counter.to_bytes(8, "big")


def reply_aad(info: bytes, counter: int) -> bytes:
    return info + b"\x00reply\x00" + counter.to_bytes(8, "big")


def utf8(value: object, maximum: int) -> bool:
    try:
        return isinstance(value, str) and 1 <= len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        return False


def usable_address(value: object) -> bool:
    if not isinstance(value, str) or "%" in value:
        return False
    try:
        address = ipaddress.ip_address(value)
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None:
            address = mapped
        return not (address.is_unspecified or address.is_loopback or address.is_link_local
                    or address.is_multicast or (address.version == 4 and int(address) == 0xffffffff))
    except ValueError:
        return False


def validate_command(command: dict) -> dict:
    if not isinstance(command, dict):
        raise ProtocolError("Invalid command")
    op = command.get("op")
    if op == "echo":
        valid = set(command) <= {"op", "text"} and utf8(command.get("text"), 512)
    elif op in ("scan", "status"):
        valid = set(command) == {"op"}
    elif op == "configure":
        password = command.get("password")
        valid_password = isinstance(password, str) and (
            re.fullmatch(r"[\x20-\x7e]{8,63}", password) is not None
            or re.fullmatch(r"[0-9a-fA-F]{64}", password) is not None)
        valid = (set(command) <= {"op", "ssid", "password", "hidden"}
                 and utf8(command.get("ssid"), 32) and valid_password
                 and type(command.get("hidden", False)) is bool)
    else:
        valid = False
    if not valid or len(encode_message(command)) > MAX_REQUEST:
        raise ProtocolError("Invalid command arguments; check SSID, passphrase, or echo limits")
    return command


def valid_network(value: object, require_addresses: bool = False) -> bool:
    return (isinstance(value, dict) and utf8(value.get("ssid"), 32)
            and utf8(value.get("interface"), 128) and utf8(value.get("profile_uuid"), 64)
            and isinstance(value.get("addresses"), list)
            and (not require_addresses or bool(value["addresses"]))
            and all(usable_address(a) for a in value["addresses"]))


def validate_event(value: dict, command: dict, device_id: str) -> None:
    op, event, final = command.get("op"), value.get("event"), value.get("final")
    valid = (value.get("device_id") == device_id and value.get("op") == op
             and type(final) is bool)
    if event == "error":
        shape = final is True and utf8(value.get("code"), 64) and utf8(value.get("message"), 512)
    elif op == "echo":
        shape = event == "echo" and final is True and value.get("echo") == command["text"]
    elif op == "status":
        shape = (event == "status" and final is True and type(value.get("provisioned")) is bool
                 and type(value.get("setup_allowed")) is bool and "network" in value
                 and (value["network"] is None or valid_network(value["network"])))
    elif op == "scan" and event == "scanning":
        shape = final is False
    elif op == "scan" and event == "networks":
        rows = value.get("networks")
        shape = (final is True and utf8(value.get("interface"), 128)
                 and type(value.get("truncated")) is bool and isinstance(rows, list)
                 and len(rows) <= 16)
        if shape:
            shape = all(isinstance(row, dict) and utf8(row.get("ssid"), 32)
                        and type(row.get("strength")) is int and 0 <= row["strength"] <= 100
                        and row.get("security") in SECURITIES
                        and type(row.get("supported")) is bool
                        and row["supported"] == (row["security"] == "wpa2-psk") for row in rows)
    elif op == "configure" and event in ("connecting", "obtaining_ip", "saving"):
        shape = final is False and value.get("ssid") == command["ssid"]
    elif op == "configure" and event == "connected":
        shape = (final is True and value.get("ssid") == command["ssid"]
                 and value.get("provisioned") is True and valid_network(value, True))
    else:
        shape = False
    if not valid or not shape:
        raise ProtocolError("Authenticated reply has invalid operation or event fields")


class AuthenticatedRequest:
    """Reply key exists even when authenticated JSON or command arguments are invalid."""

    def __init__(self, device_id: str, challenge: bytes, info: bytes, key: bytes, plaintext: bytes):
        self.device_id, self.challenge, self.info = device_id, challenge, info
        self._key, self._counter, self._final = key, 0, False
        self.command = {}
        self.valid = False
        try:
            self.command = decode_message(plaintext)
            validate_command(self.command)
            self.valid = True
        except (ValueError, TypeError):
            pass

    def reply(self, event: dict) -> dict:
        if self._final:
            raise ProtocolError("Reply stream already finished")
        # Unknown or missing op is represented safely; a valid client never sends one.
        op = self.command.get("op")
        if op not in ("echo", "scan", "status", "configure"):
            op = "invalid"
        value = {**event, "device_id": self.device_id, "op": op}
        plaintext = encode_message(value)
        if len(plaintext) > MAX_EVENT or type(value.get("final")) is not bool:
            raise ProtocolError("Invalid outgoing event")
        encrypted = ChaCha20Poly1305(self._key).encrypt(
            reply_nonce(self._counter), plaintext, reply_aad(self.info, self._counter))
        result = {"type": "reply", "challenge": b64(self.challenge), "counter": self._counter,
                  "ciphertext": b64(encrypted)}
        self._counter += 1
        self._final = value["final"]
        if self._final:
            self._key = None
        return result


class DeviceSession:
    """One single-use challenge; the transport serializes complete operations."""

    def __init__(self, identity: DeviceIdentity, clock: Callable[[], float] = time.monotonic):
        self.identity, self._clock = identity, clock
        self.packet_size = 20
        self.reset()

    def reset(self) -> None:
        self._challenge: Optional[bytes] = None
        self._deadline = 0.0

    def challenge(self, message: dict) -> dict:
        size = message.get("packet_size", 20)
        if (message.get("type") != "challenge_request" or type(message.get("version")) is not int
                or message["version"] != 3 or type(size) is not int or not 20 <= size <= 185):
            raise ProtocolError("rejected")
        self.packet_size = size
        self._challenge = secrets.token_bytes(32)
        self._deadline = self._clock() + CHALLENGE_TTL
        return {"type": "challenge", "version": 3, "device_id": self.identity.device_id,
                "challenge": b64(self._challenge), "packet_size": size}

    def authenticate(self, message: dict) -> AuthenticatedRequest:
        try:
            if self._clock() >= self._deadline:
                self.reset()
            if message.get("type") != "request":
                raise ValueError()
            challenge = unb64(message.get("challenge"), 32)
            if self._challenge is None or not hmac.compare_digest(challenge, self._challenge):
                raise ValueError()
            self.reset()  # Matching attempts burn the challenge before parsing any other field.
            enc, ciphertext = unb64(message.get("enc"), 32), unb64(message.get("ciphertext"))
            if not 16 <= len(ciphertext) <= MAX_REQUEST + 16:
                raise ValueError()
            info = make_info(self.identity.device_id, challenge, self.packet_size)
            recipient = new_suite().create_recipient_context(
                enc, hpke_private(self.identity.private_key), info=info,
                psk=self.identity.setup_secret, psk_id=psk_id(self.identity.device_id))
            plaintext = recipient.open(ciphertext, REQUEST_AAD)
            return AuthenticatedRequest(self.identity.device_id, challenge, info,
                                        recipient.export(EXPORT_CONTEXT, 32), plaintext)
        except Exception as exc:
            raise ProtocolError("rejected") from exc


class ClientSession:
    def __init__(self, qr: QRIdentity, command: dict, packet_size: int = 20):
        self.qr, self.command = qr, dict(validate_command(command))
        if type(packet_size) is not int or not 20 <= packet_size <= 185:
            raise ProtocolError("Invalid negotiated packet size")
        self.packet_size = packet_size
        self._plaintext = encode_message(command)
        self._challenge = self._reply_key = self._info = None
        self._counter, self._started, self._final = 0, False, False

    def create_request(self, challenge_message: dict) -> dict:
        if self._started:
            raise ProtocolError("Attempt already started; request a fresh challenge")
        try:
            size = challenge_message.get("packet_size")
            if (challenge_message.get("type") != "challenge"
                    or type(challenge_message.get("version")) is not int
                    or challenge_message["version"] != 3
                    or challenge_message.get("device_id") != self.qr.device_id
                    or type(size) is not int or not 20 <= size <= self.packet_size):
                raise ValueError()
            challenge = unb64(challenge_message.get("challenge"), 32)
            info = make_info(self.qr.device_id, challenge, size)
            enc, sender = new_suite().create_sender_context(
                hpke_public(self.qr.public_key), info=info, psk=self.qr.setup_secret,
                psk_id=psk_id(self.qr.device_id))
            ciphertext = sender.seal(self._plaintext, REQUEST_AAD)
            self._reply_key, self._challenge = sender.export(EXPORT_CONTEXT, 32), challenge
            self._info, self._started, self.packet_size = info, True, size
            return {"type": "request", "challenge": b64(challenge), "enc": b64(enc),
                    "ciphertext": b64(ciphertext)}
        except Exception as exc:
            raise ProtocolError("Unverified challenge rejected; check the QR identity and reconnect") from exc

    def accept_reply(self, message: dict) -> dict:
        try:
            if (not self._started or self._final or self._reply_key is None
                    or message.get("type") != "reply"
                    or unb64(message.get("challenge"), 32) != self._challenge
                    or type(message.get("counter")) is not int or message["counter"] != self._counter):
                raise ValueError()
            ciphertext = unb64(message.get("ciphertext"))
            if not 17 <= len(ciphertext) <= MAX_EVENT + 16:
                raise ValueError()
            plaintext = ChaCha20Poly1305(self._reply_key).decrypt(
                reply_nonce(self._counter), ciphertext, reply_aad(self._info, self._counter))
            value = decode_message(plaintext)
            validate_event(value, self.command, self.qr.device_id)
            self._counter += 1  # Never advance until both authentication and shape validation pass.
            self._final = value["final"]
            if self._final:
                self._reply_key = None
            return value
        except Exception as exc:
            raise ProtocolError("Reply authentication or event validation failed; reconnect and check the QR identity") from exc
