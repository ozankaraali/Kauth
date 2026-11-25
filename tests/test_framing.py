import pytest

from device_provision.framing import (
    FrameDecoder, FrameError, decode_message, encode_message, fragment,
)


@pytest.mark.parametrize("size", [1, 17, 18, 19, 20, 36, 37, 4096, 8192])
def test_minimum_mtu_roundtrip(size):
    message = bytes(i % 256 for i in range(size))
    packets = fragment(message)
    assert packets[0][:3] == b"\x01" + size.to_bytes(2, "big")
    assert all(1 < len(packet) <= 20 for packet in packets)
    assert all(packet[0] == 0 for packet in packets[1:])
    receiver = FrameDecoder()
    for packet in packets[:-1]:
        assert receiver.feed(packet) is None
    assert receiver.feed(packets[-1]) == message
    with pytest.raises(FrameError):
        receiver.feed(b"\x00x")
    assert receiver.feed(b"\x01\x00\x01y") == b"y"


@pytest.mark.parametrize("data", [b"", b"x" * 8193])
def test_reject_invalid_outgoing_lengths(data):
    with pytest.raises(FrameError):
        fragment(data)


@pytest.mark.parametrize("packet", [b"", b"\x02x", b"\x00x", b"\x01", b"\x01\x00",
                                     b"\x01\x00\x01", b"\x01\x00\x00x", b"\x01\x20\x01x",
                                     b"\x01\x00\x01xx", b"\x01\x00\x20" + b"x" * 18])
def test_invalid_packets_reset_receiver(packet):
    receiver = FrameDecoder()
    with pytest.raises(FrameError):
        receiver.feed(packet)
    assert receiver.feed(b"\x01\x00\x01a") == b"a"


def test_partial_replacement_and_continuation_overrun():
    receiver = FrameDecoder()
    assert receiver.feed(b"\x01\x00\x05ab") is None
    assert receiver.feed(b"\x01\x00\x01z") == b"z"
    assert receiver.feed(b"\x01\x00\x03ab") is None
    with pytest.raises(FrameError):
        receiver.feed(b"\x00cd")
    with pytest.raises(FrameError):
        receiver.feed(b"\x00x")
    assert receiver.feed(b"\x01\x00\x03ab") is None
    with pytest.raises(FrameError):
        receiver.feed(b"\x00")
    with pytest.raises(FrameError):
        receiver.feed(b"\x00c")


@pytest.mark.parametrize("data", [b'[]', b'null', b'{"x":1,"x":2}', b'{"x":NaN}',
                                   b'{"x":Infinity}', b'{"x":"\xff"}', b'{} extra',
                                   b'[' * 2000, b'{}' + b' ' * 8191])
def test_strict_json(data):
    with pytest.raises(FrameError):
        decode_message(data)


def test_reject_oversized_encoded_message():
    with pytest.raises(FrameError):
        encode_message({"echo": "x" * 8192})


@pytest.mark.parametrize("packet_size", [20, 21, 64, 185])
@pytest.mark.parametrize("size", [1, 182, 183, 4096, 8192])
def test_negotiated_mtu_roundtrip(packet_size, size):
    message = bytes(i % 256 for i in range(size))
    receiver = FrameDecoder(185)
    packets = fragment(message, packet_size)
    assert all(len(packet) <= packet_size for packet in packets)
    for packet in packets:
        result = receiver.feed(packet)
    assert result == message


@pytest.mark.parametrize("size", [19, 186, True, 20.0])
def test_reject_invalid_negotiated_packet_size(size):
    with pytest.raises(FrameError):
        fragment(b"hello", size)
    with pytest.raises(FrameError):
        FrameDecoder(size)
