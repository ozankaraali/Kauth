"""Minimum-MTU framing and strict JSON at the BLE trust boundary."""
from __future__ import annotations

import json
from typing import Any, Optional

MAX_MESSAGE = 8192
PACKET_SIZE = 20
MAX_PACKET_SIZE = 185


class FrameError(ValueError):
    pass


def _object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise FrameError("Duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise FrameError("Invalid JSON constant")


def encode_message(message: dict) -> bytes:
    try:
        result = json.dumps(message, separators=(",", ":"), ensure_ascii=False,
                            allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise FrameError("Invalid JSON message") from exc
    if not 1 <= len(result) <= MAX_MESSAGE:
        raise FrameError("Message must contain 1..8192 bytes")
    return result


def decode_message(data: bytes) -> dict[str, Any]:
    if not 1 <= len(data) <= MAX_MESSAGE:
        raise FrameError("Message must contain 1..8192 bytes")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object,
                           parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise FrameError("Invalid JSON message") from exc
    if not isinstance(value, dict):
        raise FrameError("Message must be a JSON object")
    return value


def fragment(data: bytes, packet_size: int = PACKET_SIZE) -> list[bytes]:
    if type(packet_size) is not int or not PACKET_SIZE <= packet_size <= MAX_PACKET_SIZE:
        raise FrameError("Invalid negotiated packet size")
    if not 1 <= len(data) <= MAX_MESSAGE:
        raise FrameError("Message must contain 1..8192 bytes")
    first, rest = packet_size - 3, packet_size - 1
    packets = [b"\x01" + len(data).to_bytes(2, "big") + data[:first]]
    packets.extend(b"\x00" + data[i:i + rest] for i in range(first, len(data), rest))
    return packets


class FrameDecoder:
    def __init__(self, packet_size: int = PACKET_SIZE) -> None:
        if type(packet_size) is not int or not PACKET_SIZE <= packet_size <= MAX_PACKET_SIZE:
            raise FrameError("Invalid negotiated packet size")
        self.packet_size = packet_size
        self.reset()

    def reset(self) -> None:
        self._expected: Optional[int] = None
        self._buffer = bytearray()

    def feed(self, packet: bytes) -> Optional[bytes]:
        try:
            if not 1 <= len(packet) <= self.packet_size:
                raise FrameError("Invalid packet size")
            if packet[0] == 1:
                self.reset()
                if len(packet) < 4:
                    raise FrameError("Incomplete start packet")
                self._expected = int.from_bytes(packet[1:3], "big")
                if not 1 <= self._expected <= MAX_MESSAGE:
                    raise FrameError("Invalid frame length")
                payload = packet[3:]
            elif packet[0] == 0:
                if self._expected is None or len(packet) < 2:
                    raise FrameError("Unexpected or empty continuation")
                payload = packet[1:]
            else:
                raise FrameError("Invalid packet flag")
            self._buffer.extend(payload)
            if len(self._buffer) > self._expected:
                raise FrameError("Frame overrun")
            if len(self._buffer) == self._expected:
                result = bytes(self._buffer)
                self.reset()
                return result
            return None
        except FrameError:
            self.reset()
            raise
