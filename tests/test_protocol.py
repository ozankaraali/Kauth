import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pyhpke import KEMKeyPair

from device_provision.framing import FrameDecoder, decode_message, encode_message, fragment
from device_provision.identity import DeviceIdentity, QRIdentity, b64, unb64
from device_provision.protocol import (
    CHALLENGE_TTL, EXPORT_CONTEXT, REQUEST_AAD, ClientSession, DeviceSession, ProtocolError,
    hpke_private, hpke_public, make_info, new_suite, psk_id, reply_aad, reply_nonce,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def identity():
    return DeviceIdentity.generate("test-device")


def wire(message, size=20):
    decoder = FrameDecoder(185)
    for packet in fragment(encode_message(message), size):
        result = decoder.feed(packet)
    return decode_message(result)


def prepare(identity, command=None, qr=None, clock=None, packet_size=20):
    command = command or {"op": "echo", "text": "hello world"}
    device = DeviceSession(identity, **({"clock": clock} if clock else {}))
    client = ClientSession(qr or identity.qr, command, packet_size)
    challenge = wire(device.challenge(wire({"type": "challenge_request", "version": 3,
                                            "packet_size": packet_size})), packet_size)
    request = wire(client.create_request(challenge), packet_size)
    return device, client, request


@pytest.mark.parametrize("text", ["hello world", "  merhaba \U0001f44b 世界\n", "é" * 256,
                                  "x" * 512, "\x00" * 512, "\n\t\r\b\f"])
@pytest.mark.parametrize("packet_size", [20, 185])
def test_exact_authenticated_echo(identity, text, packet_size):
    device, client, request = prepare(identity, {"op": "echo", "text": text}, packet_size=packet_size)
    context = device.authenticate(request)
    event = {"event": "echo", "final": True, "echo": text}
    reply = wire(context.reply(event), packet_size)
    assert client.accept_reply(reply) == {"device_id": identity.device_id, "op": "echo", **event}
    with pytest.raises(ProtocolError):
        device.authenticate(request)
    with pytest.raises(ProtocolError):
        client.accept_reply(reply)
    with pytest.raises(ProtocolError):
        context.reply(event)


@pytest.mark.parametrize("command", [
    {"op": "echo", "text": ""}, {"op": "echo", "text": "é" * 257},
    {"op": "echo", "text": "\ud800"}, {"op": "scan", "password": "secret"},
    {"op": "configure", "ssid": "a" * 33, "password": "password"},
    {"op": "configure", "ssid": "ok", "password": "short"},
    {"op": "configure", "ssid": "ok", "password": "é" * 8},
    {"op": "configure", "ssid": "ok", "password": "g" * 64},
    {"op": "configure", "ssid": "ok", "password": "abc\x00defgh"},
    {"op": "configure", "ssid": "ok", "password": "abc\ndefgh"},
    {"op": "configure", "ssid": "ok", "password": "abc\x7fdefgh"},
    {"op": "configure", "ssid": "ok", "password": "password", "hidden": 1},
])
def test_client_command_boundaries(identity, command):
    with pytest.raises(ProtocolError):
        ClientSession(identity.qr, command)


@pytest.mark.parametrize("password", [" " * 8, "x" * 63, "aF09" * 16])
def test_passphrase_boundaries_preserve_exact_ssid(identity, password):
    command = {"op": "configure", "ssid": "  café \n", "password": password}
    device, _, outgoing = prepare(identity, command)
    assert device.authenticate(outgoing).command == command


@pytest.mark.parametrize("wrong", ["public_key", "setup_secret"])
def test_wrong_key_or_psk_consumes_attempt(identity, wrong):
    other = DeviceIdentity.generate(identity.device_id)
    qr = QRIdentity(identity.device_id,
                    other.public_key if wrong == "public_key" else identity.public_key,
                    other.setup_secret if wrong == "setup_secret" else identity.setup_secret)
    device, _, bad = prepare(identity, qr=qr)
    challenge = {"type": "challenge", "version": 3, "packet_size": 20,
                 "device_id": identity.device_id, "challenge": bad["challenge"]}
    valid = ClientSession(identity.qr, {"op": "status"}).create_request(challenge)
    with pytest.raises(ProtocolError):
        device.authenticate(bad)
    with pytest.raises(ProtocolError):
        device.authenticate(valid)


def test_public_key_without_secret_cannot_authorize(identity):
    device = DeviceSession(identity)
    challenge = device.challenge({"type": "challenge_request", "version": 3})
    enc, sender = new_suite().create_sender_context(
        hpke_public(identity.public_key), info=make_info(identity.device_id, unb64(challenge["challenge"])))
    outgoing = {"type": "request", "challenge": challenge["challenge"], "enc": b64(enc),
                "ciphertext": b64(sender.seal(encode_message({"op": "scan"}), REQUEST_AAD))}
    with pytest.raises(ProtocolError):
        device.authenticate(outgoing)


@pytest.mark.parametrize("change", ["tamper", "missing_enc", "bad_enc", "missing_ciphertext",
                                    "bad_base64", "short_ciphertext", "wrong_field_type"])
def test_failed_matching_attempt_is_consumed(identity, change):
    device, _, request = prepare(identity)
    bad = copy.deepcopy(request)
    if change == "tamper":
        ciphertext = bytearray(unb64(bad["ciphertext"]))
        ciphertext[-1] ^= 1
        bad["ciphertext"] = b64(ciphertext)
    elif change == "missing_enc":
        del bad["enc"]
    elif change == "bad_enc":
        bad["enc"] = b64(bytes(32))
    elif change == "missing_ciphertext":
        del bad["ciphertext"]
    elif change == "bad_base64":
        bad["ciphertext"] = "not!base64"
    elif change == "short_ciphertext":
        bad["ciphertext"] = b64(bytes(15))
    else:
        bad["enc"] = {"not": "a key"}
    with pytest.raises(ProtocolError):
        device.authenticate(bad)
    with pytest.raises(ProtocolError):
        device.authenticate(request)


@pytest.mark.parametrize("plaintext", [b"", b"\xff", b'{"op":"configure","password":"short"}'])
def test_authenticated_invalid_command_retains_encrypted_error_context(identity, plaintext):
    device = DeviceSession(identity)
    challenge = device.challenge({"type": "challenge_request", "version": 3})
    info = make_info(identity.device_id, unb64(challenge["challenge"]))
    enc, sender = new_suite().create_sender_context(hpke_public(identity.public_key), info=info,
        psk=identity.setup_secret, psk_id=psk_id(identity.device_id))
    outgoing = {"type": "request", "challenge": challenge["challenge"], "enc": b64(enc),
                "ciphertext": b64(sender.seal(plaintext, REQUEST_AAD))}
    context = device.authenticate(outgoing)
    assert not context.valid
    reply = context.reply({"event": "error", "final": True, "code": "invalid_request", "message": "Invalid request"})
    decoded = ChaCha20Poly1305(sender.export(EXPORT_CONTEXT, 32)).decrypt(
        reply_nonce(0), unb64(reply["ciphertext"]), reply_aad(info, 0))
    assert json.loads(decoded)["code"] == "invalid_request"
    with pytest.raises(ProtocolError):
        device.authenticate(outgoing)


def test_expiry_replacement_and_unknown_challenge(identity):
    now = [10.0]
    device, _, request = prepare(identity, clock=lambda: now[0])
    with pytest.raises(ProtocolError):
        device.authenticate({**request, "challenge": b64(bytes(32))})
    assert device.authenticate(request).valid  # Unknown challenge did not consume the real one.
    device, _, request = prepare(identity, clock=lambda: now[0])
    now[0] += CHALLENGE_TTL
    with pytest.raises(ProtocolError):
        device.authenticate(request)
    old = device.challenge({"type": "challenge_request", "version": 3})
    new = device.challenge({"type": "challenge_request", "version": 3})
    with pytest.raises(ProtocolError):
        device.authenticate(ClientSession(identity.qr, {"op": "scan"}).create_request(old))
    assert device.authenticate(ClientSession(identity.qr, {"op": "scan"}).create_request(new)).valid


@pytest.mark.parametrize("field,value", [("version", True), ("version", 1), ("version", 2),
                                         ("version", "3"), ("version", 3.0), ("device_id", "different"),
                                         ("challenge", "AA=="), ("packet_size", 186), ("packet_size", True)])
def test_client_rejects_wrong_challenge(identity, field, value):
    challenge = DeviceSession(identity).challenge({"type": "challenge_request", "version": 3})
    challenge[field] = value
    with pytest.raises(ProtocolError):
        ClientSession(identity.qr, {"op": "status"}).create_request(challenge)


@pytest.mark.parametrize("version", [None, True, 1, 2, "3", 3.0, 4])
def test_server_rejects_non_v3_before_issuing_challenge(identity, version):
    device = DeviceSession(identity)
    with pytest.raises(ProtocolError):
        device.challenge({"type": "challenge_request", "version": version})
    assert device._challenge is None


def test_wrong_selected_device_rejects_qr_before_encrypting(identity):
    other = DeviceIdentity.generate("other-device")
    challenge = DeviceSession(other).challenge({"type": "challenge_request", "version": 3})
    client = ClientSession(identity.qr, {"op": "configure", "ssid": "Home", "password": "password"})
    with pytest.raises(ProtocolError):
        client.create_request(challenge)
    assert not client._started and client._reply_key is None


@pytest.mark.parametrize("binding", ["info", "psk_id", "aad"])
def test_v2_domain_inputs_cannot_authorize_v3(identity, binding):
    device = DeviceSession(identity)
    challenge = device.challenge({"type": "challenge_request", "version": 3})
    info = make_info(identity.device_id, unb64(challenge["challenge"]))
    identifier, aad = psk_id(identity.device_id), REQUEST_AAD
    # Version-2 domains remain invalid after negotiating a version-3 challenge.
    if binding == "info":
        info = info.replace(b"/v3", b"/v2", 1)
    elif binding == "psk_id":
        identifier = identifier.replace(b"/v3", b"/v2", 1)
    else:
        aad = aad.replace(b"/v3", b"/v2", 1)
    enc, sender = new_suite().create_sender_context(
        hpke_public(identity.public_key), info=info, psk=identity.setup_secret, psk_id=identifier)
    with pytest.raises(ProtocolError):
        device.authenticate({"type": "request", "challenge": challenge["challenge"], "enc": b64(enc),
                             "ciphertext": b64(sender.seal(encode_message({"op": "status"}), aad))})


@pytest.mark.parametrize("change", ["tamper", "challenge", "counter", "bool_counter", "device_id", "op", "echo", "final"])
def test_reply_validation_does_not_advance_counter(identity, change):
    device, client, outgoing = prepare(identity)
    context = device.authenticate(outgoing)
    event = {"device_id": identity.device_id, "op": "echo", "event": "echo", "final": True, "echo": "hello world"}
    key, info = context._key, context.info
    reply = context.reply(event)
    bad = copy.deepcopy(reply)
    if change == "tamper":
        data = bytearray(unb64(bad["ciphertext"]))
        data[-1] ^= 1
        bad["ciphertext"] = b64(data)
    elif change == "challenge":
        bad["challenge"] = b64(bytes(32))
    elif change in ("counter", "bool_counter"):
        bad["counter"] = 1 if change == "counter" else False
    else:
        event[change] = "wrong"
        bad["ciphertext"] = b64(ChaCha20Poly1305(key).encrypt(reply_nonce(0), encode_message(event), reply_aad(info, 0)))
    with pytest.raises(ProtocolError):
        client.accept_reply(bad)
    assert client.accept_reply(reply)["echo"] == "hello world"


def test_stream_requires_exact_counter_and_final(identity):
    device, client, outgoing = prepare(identity, {"op": "scan"})
    context = device.authenticate(outgoing)
    first = context.reply({"event": "scanning", "final": False})
    final = context.reply({"event": "networks", "final": True, "interface": "wlan0", "networks": [], "truncated": False})
    with pytest.raises(ProtocolError):
        client.accept_reply(final)
    assert not client.accept_reply(first)["final"]
    with pytest.raises(ProtocolError):
        client.accept_reply(first)
    assert client.accept_reply(final)["final"]
    with pytest.raises(ProtocolError):
        client.accept_reply(final)


def test_packet_size_is_cryptographically_bound(identity):
    device, _, outgoing = prepare(identity, packet_size=185)
    device.packet_size = 20
    with pytest.raises(ProtocolError):
        device.authenticate(outgoing)


def test_official_rfc9180_psk_vector():
    vector = json.loads((FIXTURES / "rfc9180-psk.json").read_text())
    assert (vector["mode"], vector["kem_id"], vector["kdf_id"], vector["aead_id"]) == (1, 32, 1, 3)
    raw = lambda field: bytes.fromhex(vector[field])
    suite = new_suite()
    enc, sender = suite.create_sender_context(
        hpke_public(raw("pkRm")), info=raw("info"), psk=raw("psk"), psk_id=raw("psk_id"),
        eks=KEMKeyPair(hpke_private(raw("skEm")), hpke_public(raw("pkEm"))))
    assert enc == raw("enc")
    recipient = suite.create_recipient_context(enc, hpke_private(raw("skRm")), info=raw("info"),
                                               psk=raw("psk"), psk_id=raw("psk_id"))
    for sample in vector["encryptions"]:
        plaintext, aad, ciphertext = (bytes.fromhex(sample[x]) for x in ("pt", "aad", "ct"))
        assert sender.seal(plaintext, aad) == ciphertext
        assert recipient.open(ciphertext, aad) == plaintext
    for sample in vector["exports"]:
        context = bytes.fromhex(sample["exporter_context"])
        expected = bytes.fromhex(sample["exported_value"])
        assert sender.export(context, sample["L"]) == expected
        assert recipient.export(context, sample["L"]) == expected


def test_frozen_interop_fixture(monkeypatch):
    fixture = json.loads((FIXTURES / "interop.json").read_text())
    # QR identity schema remains 1; the independent transport fixture uses v3.
    assert fixture["version"] == 3
    identity = DeviceIdentity.from_dict({**fixture, "version": 1})
    challenge = unb64(fixture["challenge"])
    monkeypatch.setattr("device_provision.protocol.secrets.token_bytes", lambda size: challenge)
    device = DeviceSession(identity)
    device.challenge({"type": "challenge_request", "version": fixture["version"], "packet_size": fixture["packet_size"]})
    context = device.authenticate({"type": "request", "challenge": fixture["challenge"],
                                  "enc": fixture["enc"], "ciphertext": fixture["request_ciphertext"]})
    assert context.command == json.loads(fixture["request_plaintext"])
    assert context._key == unb64(fixture["exported_reply_key"])
    info = make_info(identity.device_id, challenge, fixture["packet_size"])
    plaintext = ChaCha20Poly1305(context._key).decrypt(
        reply_nonce(0), unb64(fixture["reply_ciphertext"]), reply_aad(info, 0))
    assert json.loads(plaintext) == json.loads(fixture["reply_plaintext"])
    reply = context.reply({"event": "echo", "final": True, "echo": fixture["plaintext"]})
    emitted = ChaCha20Poly1305(unb64(fixture["exported_reply_key"])).decrypt(
        reply_nonce(0), unb64(reply["ciphertext"]), reply_aad(info, 0))
    assert json.loads(emitted) == json.loads(fixture["reply_plaintext"])
