import XCTest
import CryptoKit
@testable import Kauth

final class ProvisioningCryptoTests: XCTestCase {
    private func fixture(_ name: String = "interop") throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: name, withExtension: "json"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func string(_ object: [String: Any], _ key: String) throws -> String {
        try XCTUnwrap(object[key] as? String)
    }

    private func bytes(_ object: [String: Any], _ key: String) throws -> Data {
        try XCTUnwrap(Data(base64Encoded: string(object, key)))
    }

    private func hex(_ object: [String: Any], _ key: String) throws -> Data {
        let value = Array(try string(object, key).utf8)
        guard value.count.isMultiple(of: 2) else { throw ProvisioningError.invalidMessage }
        var result = Data()
        for index in stride(from: 0, to: value.count, by: 2) {
            result.append(try XCTUnwrap(UInt8(String(decoding: value[index...index + 1], as: UTF8.self), radix: 16)))
        }
        return result
    }

    private func identity(_ object: [String: Any]) throws -> SetupIdentity {
        let data = try ProvisioningWire.encode([
            "version": 1, "device_id": string(object, "device_id"),
            "public_key": string(object, "public_key"), "setup_secret": string(object, "setup_secret")
        ])
        return try SetupIdentity(json: String(decoding: data, as: UTF8.self))
    }

    private func challenge(_ object: [String: Any]) throws -> Data {
        try ProvisioningWire.encode([
            "type": "challenge", "version": 3, "packet_size": 20,
            "device_id": string(object, "device_id"), "challenge": string(object, "challenge")
        ])
    }

    private func recipient(_ object: [String: Any], enc: Data, psk: Data? = nil) throws -> HPKE.Recipient {
        try HPKE.Recipient(
            privateKey: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes(object, "private_key")),
            ciphersuite: ProvisioningWire.suite,
            info: ProvisioningWire.info(deviceID: string(object, "device_id"), challenge: bytes(object, "challenge"), packetSize: 20),
            encapsulatedKey: enc,
            presharedKey: SymmetricKey(data: psk ?? bytes(object, "setup_secret")),
            presharedKeyIdentifier: ProvisioningWire.pskID(string(object, "device_id"))
        )
    }

    private func makeReply(_ object: [String: Any], request: Data, payload: [String: Any], counter: UInt64 = 0) throws -> Data {
        let requestObject = try ProvisioningWire.object(request)
        var receiver = try recipient(object, enc: ProvisioningWire.base64(requestObject["enc"], count: 32))
        _ = try receiver.open(ProvisioningWire.base64(requestObject["ciphertext"]), authenticating: ProvisioningWire.requestAAD)
        let replyKey = try receiver.exportSecret(context: ProvisioningWire.exportContext, outputByteCount: 32)
        var event = payload
        if event["device_id"] == nil { event["device_id"] = try string(object, "device_id") }
        let cleartext = try ProvisioningWire.encode(event)
        let info = try ProvisioningWire.info(deviceID: string(object, "device_id"), challenge: bytes(object, "challenge"), packetSize: 20)
        let box = try ChaChaPoly.seal(cleartext, using: replyKey, nonce: ProvisioningWire.replyNonce(counter),
                                     authenticating: ProvisioningWire.replyAAD(info: info, counter: counter))
        return try ProvisioningWire.encode(["type": "reply", "challenge": string(object, "challenge"), "counter": counter,
                                     "ciphertext": (box.ciphertext + box.tag).base64EncodedString()])
    }

    private func attempt(_ object: [String: Any], _ command: ProvisioningCommand) throws -> ProvisioningAttempt {
        try ProvisioningAttempt(identity: identity(object), command: command, challengeMessage: challenge(object), requestedPacketSize: 20)
    }

    private func assertJSONEqual(_ left: Data, _ right: Data, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertEqual(try ProvisioningWire.object(left) as NSDictionary, try ProvisioningWire.object(right) as NSDictionary, file: file, line: line)
    }

    func testIndependentDeterministicRequestExportAndReply() throws {
        let object = try fixture()
        XCTAssertTrue(ProvisioningWire.integer(object["version"], equals: 3))
        var receiver = try recipient(object, enc: bytes(object, "enc"))
        let plaintext = try receiver.open(bytes(object, "request_ciphertext"), authenticating: ProvisioningWire.requestAAD)
        try assertJSONEqual(plaintext, Data(string(object, "request_plaintext").utf8))
        let key = try receiver.exportSecret(context: ProvisioningWire.exportContext, outputByteCount: 32)
        XCTAssertEqual(key.withUnsafeBytes { Data($0) }, try bytes(object, "exported_reply_key"))
        let ciphertext = try bytes(object, "reply_ciphertext")
        let box = try ChaChaPoly.SealedBox(nonce: ProvisioningWire.replyNonce(0), ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
        let info = try ProvisioningWire.info(deviceID: string(object, "device_id"), challenge: bytes(object, "challenge"), packetSize: 20)
        let reply = try ChaChaPoly.open(box, using: key, authenticating: ProvisioningWire.replyAAD(info: info, counter: 0))
        try assertJSONEqual(reply, Data(string(object, "reply_plaintext").utf8))
    }

    func testOfficialRFC9180PSKVectorAllSequencesAndExports() throws {
        let object = try fixture("rfc9180-psk")
        XCTAssertTrue(ProvisioningWire.integer(object["mode"], equals: 1))
        XCTAssertTrue(ProvisioningWire.integer(object["kem_id"], equals: 32))
        XCTAssertTrue(ProvisioningWire.integer(object["kdf_id"], equals: 1))
        XCTAssertTrue(ProvisioningWire.integer(object["aead_id"], equals: 3))
        var receiver = try HPKE.Recipient(
            privateKey: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hex(object, "skRm")),
            ciphersuite: ProvisioningWire.suite, info: hex(object, "info"), encapsulatedKey: hex(object, "enc"),
            presharedKey: SymmetricKey(data: hex(object, "psk")), presharedKeyIdentifier: hex(object, "psk_id")
        )
        let encryptions = try XCTUnwrap(object["encryptions"] as? [[String: Any]])
        XCTAssertEqual(encryptions.count, 257)
        for entry in encryptions {
            XCTAssertEqual(try receiver.open(hex(entry, "ct"), authenticating: hex(entry, "aad")), try hex(entry, "pt"))
        }
        for entry in try XCTUnwrap(object["exports"] as? [[String: Any]]) {
            let key = try receiver.exportSecret(context: hex(entry, "exporter_context"), outputByteCount: XCTUnwrap(entry["L"] as? Int))
            XCTAssertEqual(key.withUnsafeBytes { Data($0) }, try hex(entry, "exported_value"))
        }
    }

    func testSenderRecipientRoundTripExactUTF8AndControlBoundary() throws {
        let object = try fixture()
        for text in [try string(object, "plaintext"), "  hello world\n", "e\u{301}", String(repeating: "\u{0000}", count: 512)] {
            var session = try attempt(object, .echo(text))
            let request = try ProvisioningWire.object(session.request)
            XCTAssertEqual(request["type"] as? String, "request")
            var receiver = try recipient(object, enc: ProvisioningWire.base64(request["enc"]))
            let cleartext = try receiver.open(ProvisioningWire.base64(request["ciphertext"]), authenticating: ProvisioningWire.requestAAD)
            try assertJSONEqual(cleartext, ProvisioningWire.encode(["op": "echo", "text": text]))
            let response = try makeReply(object, request: session.request,
                                         payload: ["op": "echo", "event": "echo", "final": true, "echo": text])
            var decoder = FrameDecoder()
            var decoded: Data?
            for packet in try FrameDecoder.packets(for: response) { decoded = try decoder.receive(packet) }
            XCTAssertEqual(decoded, response)
            guard case .echo(let echo) = try session.authenticate(reply: XCTUnwrap(decoded)) else {
                return XCTFail("Expected authenticated echo")
            }
            XCTAssertEqual(Data(echo.utf8), Data(text.utf8))
            XCTAssertEqual(session.expectedCounter, 1)
            XCTAssertTrue(session.finished)
            XCTAssertThrowsError(try session.authenticate(reply: response))
        }
    }

    func testReplyTamperingBindingsAndCounterDoNotAdvanceState() throws {
        let object = try fixture()
        let text = "hello world"
        var session = try attempt(object, .echo(text))
        let payload: [String: Any] = ["op": "echo", "event": "echo", "final": true, "echo": text]
        let response = try makeReply(object, request: session.request, payload: payload)
        let original = try ProvisioningWire.object(response)
        var tampered = original
        var ciphertext = try ProvisioningWire.base64(original["ciphertext"])
        ciphertext[0] ^= 1
        tampered["ciphertext"] = ciphertext.base64EncodedString()
        XCTAssertThrowsError(try session.authenticate(reply: ProvisioningWire.encode(tampered)))
        tampered = original
        tampered["challenge"] = Data(repeating: 0, count: 32).base64EncodedString()
        XCTAssertThrowsError(try session.authenticate(reply: ProvisioningWire.encode(tampered)))
        for counter in [true, -1, 1, "0", 0.5] as [Any] {
            tampered = original
            tampered["counter"] = counter
            XCTAssertThrowsError(try session.authenticate(reply: ProvisioningWire.encode(tampered)))
        }
        for (key, value) in [("echo", "wrong"), ("device_id", "wrong-device"), ("op", "scan"), ("event", "connected")] {
            var wrong = payload
            wrong[key] = value
            XCTAssertThrowsError(try session.authenticate(reply: makeReply(object, request: session.request, payload: wrong)))
        }
        XCTAssertEqual(session.expectedCounter, 0)
        _ = try session.authenticate(reply: response)
        XCTAssertEqual(session.expectedCounter, 1)
    }

    func testStreamingCountersAndTerminalRejection() throws {
        let object = try fixture()
        var session = try attempt(object, .configure(ssid: " Home ", password: "password", hidden: true))
        let events: [[String: Any]] = [
            ["op": "configure", "event": "connecting", "final": false, "ssid": " Home "],
            ["op": "configure", "event": "obtaining_ip", "final": false, "ssid": " Home "],
            ["op": "configure", "event": "saving", "final": false, "ssid": " Home "],
            ["op": "configure", "event": "connected", "final": true, "ssid": " Home ",
             "interface": "wlan0", "addresses": ["192.168.1.20", "fd00::2"], "profile_uuid": "profile", "provisioned": true]
        ]
        let future = try makeReply(object, request: session.request, payload: events[1], counter: 1)
        XCTAssertThrowsError(try session.authenticate(reply: future))
        for (index, event) in events.enumerated() {
            let response = try makeReply(object, request: session.request, payload: event, counter: UInt64(index))
            _ = try session.authenticate(reply: response)
            XCTAssertEqual(session.expectedCounter, UInt64(index + 1))
            XCTAssertEqual(session.finished, index == events.count - 1)
            XCTAssertThrowsError(try session.authenticate(reply: response))
        }
        let afterFinal = try makeReply(object, request: session.request, payload: events[3], counter: 4)
        XCTAssertThrowsError(try session.authenticate(reply: afterFinal))
        XCTAssertEqual(session.expectedCounter, 4)
    }

    func testWrongPSKKeyAndRequestTamperingFailAuthentication() throws {
        let object = try fixture()
        let enc = try bytes(object, "enc")
        let ciphertext = try bytes(object, "request_ciphertext")
        var wrongPSK = try recipient(object, enc: enc, psk: Data(repeating: 0, count: 32))
        XCTAssertThrowsError(try wrongPSK.open(ciphertext, authenticating: ProvisioningWire.requestAAD))
        var wrongIdentity = object
        wrongIdentity["private_key"] = Curve25519.KeyAgreement.PrivateKey().rawRepresentation.base64EncodedString()
        var wrongKey = try recipient(wrongIdentity, enc: enc)
        XCTAssertThrowsError(try wrongKey.open(ciphertext, authenticating: ProvisioningWire.requestAAD))
        wrongIdentity = object
        wrongIdentity["device_id"] = "other-device"
        var wrongID = try recipient(wrongIdentity, enc: enc)
        XCTAssertThrowsError(try wrongID.open(ciphertext, authenticating: ProvisioningWire.requestAAD))
        var receiver = try recipient(object, enc: enc)
        var changed = ciphertext
        changed[0] ^= 1
        XCTAssertThrowsError(try receiver.open(changed, authenticating: ProvisioningWire.requestAAD))
    }

    func testQRAndInputValidation() throws {
        let object = try fixture()
        var qr: [String: Any] = ["version": 1, "device_id": "valid-01", "public_key": try string(object, "public_key"),
                                 "setup_secret": try string(object, "setup_secret")]
        for version in [true, 0, 2, "1"] as [Any] {
            qr["version"] = version
            XCTAssertThrowsError(try SetupIdentity(json: String(decoding: ProvisioningWire.encode(qr), as: UTF8.self)))
        }
        qr["version"] = 1
        for id in ["", "UPPER", "a/b", "é", String(repeating: "a", count: 33)] {
            qr["device_id"] = id
            XCTAssertThrowsError(try SetupIdentity(json: String(decoding: ProvisioningWire.encode(qr), as: UTF8.self)))
        }
        for text in ["", String(repeating: "é", count: 257)] {
            XCTAssertThrowsError(try attempt(object, .echo(text)))
        }
        var invalidChallenge = try ProvisioningWire.object(challenge(object))
        invalidChallenge["device_id"] = "wrong-device"
        XCTAssertThrowsError(try ProvisioningAttempt(identity: identity(object), command: .echo("hello"),
                                             challengeMessage: ProvisioningWire.encode(invalidChallenge), requestedPacketSize: 20))
    }

    func testFramingBoundsResetsAndMalformedPackets() throws {
        for length in [1, 17, 18, 36, 37, ProvisioningWire.maximumMessage] {
            let message = Data(repeating: 65, count: length)
            let packets = try FrameDecoder.packets(for: message)
            XCTAssertTrue(packets.allSatisfy { $0.count <= 20 })
            var decoder = FrameDecoder()
            var result: Data?
            for packet in packets { result = try decoder.receive(packet) }
            XCTAssertEqual(result, message)
            XCTAssertThrowsError(try decoder.receive(Data([0, 1])))
        }
        var decoder = FrameDecoder()
        for packet in [Data(), Data([2]), Data([0, 1]), Data([1]), Data([1, 0, 0]), Data([1, 32, 1]), Data([1, 0, 1, 1, 2])] {
            XCTAssertThrowsError(try decoder.receive(packet))
        }
        XCTAssertNil(try decoder.receive(Data([1, 0, 2, 1])))
        XCTAssertEqual(try decoder.receive(Data([1, 0, 1, 9])), Data([9]))
        XCTAssertNil(try decoder.receive(Data([1, 0, 2, 1])))
        XCTAssertThrowsError(try decoder.receive(Data([0, 2, 3])))
        XCTAssertThrowsError(try decoder.receive(Data([0, 2])))
        XCTAssertThrowsError(try FrameDecoder.packets(for: Data()))
        XCTAssertThrowsError(try FrameDecoder.packets(for: Data(repeating: 1, count: ProvisioningWire.maximumMessage + 1)))
    }

    func testEncryptedConfigureRequestAndAuthenticatedScanStream() throws {
        let object = try fixture()
        let command = ProvisioningCommand.configure(ssid: " Home é ", password: "private password", hidden: true)
        let configure = try attempt(object, command)
        let envelope = try ProvisioningWire.object(configure.request)
        var receiver = try recipient(object, enc: ProvisioningWire.base64(envelope["enc"]))
        let cleartext = try receiver.open(ProvisioningWire.base64(envelope["ciphertext"]), authenticating: ProvisioningWire.requestAAD)
        try assertJSONEqual(cleartext, ProvisioningWire.encode(["op": "configure", "ssid": " Home é ",
                                                       "password": "private password", "hidden": true]))
        var scan = try attempt(object, .scan)
        let scanning: [String: Any] = ["op": "scan", "event": "scanning", "final": false]
        var invalid = scanning
        invalid["final"] = true
        XCTAssertThrowsError(try scan.authenticate(reply: makeReply(object, request: scan.request, payload: invalid)))
        XCTAssertEqual(scan.expectedCounter, 0)
        guard case .scanning = try scan.authenticate(reply: makeReply(object, request: scan.request, payload: scanning)) else {
            return XCTFail("Expected authenticated scan progress")
        }
        let complete: [String: Any] = ["op": "scan", "event": "networks", "final": true, "interface": "wlan0",
                                       "networks": [["ssid": "Home", "strength": 75, "security": "wpa2-psk", "supported": true]],
                                       "truncated": false]
        guard case .networks(let interface, let rows, let truncated) = try scan.authenticate(
            reply: makeReply(object, request: scan.request, payload: complete, counter: 1)) else {
            return XCTFail("Expected authenticated networks")
        }
        XCTAssertEqual(interface, "wlan0")
        XCTAssertEqual(rows.first?.ssid, "Home")
        XCTAssertFalse(truncated)
        XCTAssertTrue(scan.finished)
        XCTAssertThrowsError(try scan.authenticate(reply: makeReply(object, request: scan.request, payload: complete, counter: 2)))
    }

    func testNegotiationBoundsAndCryptoBinding() throws {
        let object = try fixture()
        var message = try ProvisioningWire.object(challenge(object))
        for value in [19, 186, true, "20", 20.5] as [Any] {
            message["packet_size"] = value
            XCTAssertThrowsError(try ProvisioningAttempt(identity: identity(object), command: .scan,
                                                 challengeMessage: ProvisioningWire.encode(message), requestedPacketSize: 185))
        }
        message["packet_size"] = 185
        XCTAssertThrowsError(try ProvisioningAttempt(identity: identity(object), command: .scan,
                                             challengeMessage: ProvisioningWire.encode(message), requestedPacketSize: 20))
        let session = try ProvisioningAttempt(identity: identity(object), command: .scan,
                                       challengeMessage: ProvisioningWire.encode(message), requestedPacketSize: 185)
        let request = try ProvisioningWire.object(session.request)
        var wrongInfoRecipient = try recipient(object, enc: ProvisioningWire.base64(request["enc"]))
        XCTAssertThrowsError(try wrongInfoRecipient.open(ProvisioningWire.base64(request["ciphertext"]), authenticating: ProvisioningWire.requestAAD))
        var receiver = try HPKE.Recipient(
            privateKey: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes(object, "private_key")),
            ciphersuite: ProvisioningWire.suite,
            info: ProvisioningWire.info(deviceID: string(object, "device_id"), challenge: bytes(object, "challenge"), packetSize: 185),
            encapsulatedKey: ProvisioningWire.base64(request["enc"]),
            presharedKey: SymmetricKey(data: bytes(object, "setup_secret")),
            presharedKeyIdentifier: ProvisioningWire.pskID(string(object, "device_id")))
        try assertJSONEqual(receiver.open(ProvisioningWire.base64(request["ciphertext"]), authenticating: ProvisioningWire.requestAAD),
                            ProvisioningWire.encode(["op": "scan"]))
        for size in [20, 21, 185] {
            let data = Data(repeating: 123, count: 8192)
            var decoder = FrameDecoder()
            var result: Data?
            for packet in try FrameDecoder.packets(for: data, packetSize: size) {
                XCTAssertLessThanOrEqual(packet.count, size)
                result = try decoder.receive(packet)
            }
            XCTAssertEqual(result, data)
        }
        var decoder = FrameDecoder()
        XCTAssertThrowsError(try decoder.receive(Data(repeating: 1, count: 186)))
        for size in [19, 186] { XCTAssertThrowsError(try FrameDecoder.packets(for: Data([1]), packetSize: size)) }
        message["packet_size"] = 20
        for version in [1, 2, true, "3", 3.5] as [Any] {
            message["version"] = version
            XCTAssertThrowsError(try ProvisioningAttempt(identity: identity(object), command: .scan,
                                                 challengeMessage: ProvisioningWire.encode(message), requestedPacketSize: 20))
        }
    }

    func testSSIDPasswordAndUsableAddressBoundaries() throws {
        for ssid in [" ", " café ", String(repeating: "é", count: 16)] {
            XCTAssertTrue(ProvisioningWire.validSSID(ssid))
            let data = try ProvisioningCommand.configure(ssid: ssid, password: "password", hidden: true).plaintext()
            let parsed = try ProvisioningWire.object(data)
            XCTAssertEqual(Data(try XCTUnwrap(parsed["ssid"] as? String).utf8), Data(ssid.utf8))
            XCTAssertEqual(parsed["hidden"] as? Bool, true)
        }
        for ssid in ["", String(repeating: "é", count: 17)] {
            XCTAssertThrowsError(try ProvisioningCommand.configure(ssid: ssid, password: "password", hidden: false).plaintext())
        }
        for password in ["12345678", String(repeating: " ", count: 63), String(repeating: "aF", count: 32)] {
            XCTAssertTrue(ProvisioningWire.validPassword(password))
        }
        for password in ["1234567", "é12345678", "1234567\u{0}", "1234567\n", "1234567\u{7f}",
                         String(repeating: "z", count: 64), String(repeating: "a", count: 65)] {
            XCTAssertThrowsError(try ProvisioningCommand.configure(ssid: "Home", password: password, hidden: false).plaintext())
        }
        for ip in ["192.168.1.2", "10.0.0.1", "100.64.0.2", "fd00::1", "2001:db8::2", "::ffff:192.168.1.2"] {
            XCTAssertTrue(ProvisioningWire.validIP(ip, requireUsable: true), ip)
        }
        for ip in ["", "bad", "0.0.0.0", "127.1.2.3", "169.254.1.1", "224.0.0.1", "255.255.255.255",
                   "::", "::1", "fe80::1", "febf::1", "ff02::1", "::ffff:127.0.0.1", "192.168.1.2/24", "1.2.3.4\u{0}evil"] {
            XCTAssertFalse(ProvisioningWire.validIP(ip, requireUsable: true), ip)
        }
    }

    func testAuthenticatedEventShapesAndErrors() throws {
        let object = try fixture()
        let ssid = "e\u{301}"
        let command = ProvisioningCommand.configure(ssid: ssid, password: "password", hidden: false)
        let success: [String: Any] = ["op": "configure", "event": "connected", "final": true, "ssid": ssid,
                                      "interface": "wlan0", "addresses": ["192.168.1.2"], "profile_uuid": "profile", "provisioned": true]
        let mutations: [(String, Any)] = [
            ("final", false), ("final", 1), ("ssid", "é"), ("ssid", ""), ("interface", ""),
            ("addresses", [] as [String]), ("addresses", ["127.0.0.1"]), ("addresses", ["192.168.1.2", "fe80::1"]),
            ("addresses", ["not-an-ip"]), ("profile_uuid", ""), ("provisioned", false), ("provisioned", 1), ("event", "status")
        ]
        var session = try attempt(object, command)
        for (key, value) in mutations {
            var malformed = success
            malformed[key] = value
            XCTAssertThrowsError(try session.authenticate(reply: makeReply(object, request: session.request, payload: malformed)), key)
            XCTAssertEqual(session.expectedCounter, 0)
        }
        for event in ["connecting", "obtaining_ip", "saving"] {
            let invalid: [String: Any] = ["op": "configure", "event": event, "final": true, "ssid": ssid]
            XCTAssertThrowsError(try session.authenticate(reply: makeReply(object, request: session.request, payload: invalid)))
        }
        for code in ["authentication_failed", "timeout", "backend_unavailable", "rollback_failed", "state_write_failed"] {
            var failedSession = try attempt(object, command)
            let error: [String: Any] = ["op": "configure", "event": "error", "final": true, "code": code, "message": "Safe explanation."]
            guard case .error(let receivedCode, let message) = try failedSession.authenticate(
                reply: makeReply(object, request: failedSession.request, payload: error)) else { return XCTFail("Expected device error") }
            XCTAssertEqual(receivedCode, code)
            XCTAssertEqual(message, "Safe explanation.")
            XCTAssertTrue(failedSession.finished)
        }
        for (key, value) in [("final", false), ("code", ""), ("message", ""), ("message", "unsafe\ncontrol")] as [(String, Any)] {
            var malformed: [String: Any] = ["op": "configure", "event": "error", "final": true, "code": "timeout", "message": "Timed out."]
            malformed[key] = value
            XCTAssertThrowsError(try session.authenticate(reply: makeReply(object, request: session.request, payload: malformed)))
        }
        XCTAssertThrowsError(try session.authenticate(reply: ProvisioningWire.encode(["type": "error", "code": "rejected"])))
        _ = try session.authenticate(reply: makeReply(object, request: session.request, payload: success))
        XCTAssertTrue(session.finished)
    }

    func testScanAndStatusShapeValidation() throws {
        let object = try fixture()
        let id = try string(object, "device_id")
        let row: [String: Any] = ["ssid": "Home", "strength": 100, "security": "wpa2-psk", "supported": true]
        let scan: [String: Any] = ["device_id": id, "op": "scan", "event": "networks", "final": true,
                                  "interface": "wlan0", "networks": [row], "truncated": false]
        _ = try AuthenticatedReply.parse(ProvisioningWire.encode(scan), deviceID: id, command: .scan)
        for (key, value) in [("strength", -1), ("strength", 101), ("strength", true), ("strength", 0.5),
                             ("supported", false), ("supported", 1), ("security", "wpa3-sae"), ("ssid", "")] as [(String, Any)] {
            var badRow = row
            badRow[key] = value
            var badScan = scan
            badScan["networks"] = [badRow]
            XCTAssertThrowsError(try AuthenticatedReply.parse(ProvisioningWire.encode(badScan), deviceID: id, command: .scan))
        }
        for security in ["wpa3-sae", "enterprise", "open", "unsupported"] {
            var unsupported = row
            unsupported["security"] = security
            unsupported["supported"] = false
            var validScan = scan
            validScan["networks"] = [unsupported]
            _ = try AuthenticatedReply.parse(ProvisioningWire.encode(validScan), deviceID: id, command: .scan)
        }
        for rows in [[row, row], Array(repeating: row, count: 17)] {
            var badScan = scan
            badScan["networks"] = rows
            XCTAssertThrowsError(try AuthenticatedReply.parse(ProvisioningWire.encode(badScan), deviceID: id, command: .scan))
        }
        var status: [String: Any] = ["device_id": id, "op": "status", "event": "status", "final": true,
                                    "provisioned": false, "setup_allowed": true, "network": NSNull()]
        _ = try AuthenticatedReply.parse(ProvisioningWire.encode(status), deviceID: id, command: .status)
        status["network"] = ["ssid": "Home", "interface": "wlan0", "addresses": ["192.168.1.2"], "profile_uuid": "profile"]
        _ = try AuthenticatedReply.parse(ProvisioningWire.encode(status), deviceID: id, command: .status)
        for (key, value) in [("provisioned", 0), ("setup_allowed", "true"), ("network", "absent"), ("final", false)] as [(String, Any)] {
            var badStatus = status
            badStatus[key] = value
            XCTAssertThrowsError(try AuthenticatedReply.parse(ProvisioningWire.encode(badStatus), deviceID: id, command: .status))
        }
    }
}
