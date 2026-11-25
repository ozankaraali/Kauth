import Foundation
import CoreFoundation
import CryptoKit
import Darwin

enum ProvisioningError: LocalizedError {
    case invalidQR, invalidMessage, invalidFrame, invalidText, invalidSSID, invalidPassword, authentication, unverifiedRejection

    var errorDescription: String? {
        switch self {
        case .invalidQR: return "Invalid setup QR. Use the device's version 1 QR with its public key and setup secret."
        case .invalidMessage: return "The device sent an invalid or unexpected message. Reconnect and try again."
        case .invalidFrame: return "The Bluetooth message was malformed. Reconnect and try again."
        case .invalidText: return "Enter between 1 and 512 UTF-8 bytes. Your text is sent without trimming."
        case .invalidSSID: return "Enter an SSID between 1 and 32 UTF-8 bytes. Spaces are preserved."
        case .invalidPassword: return "WPA2 requires 8–63 printable ASCII characters or exactly 64 hexadecimal digits."
        case .authentication: return "Device authentication failed. Check the setup QR and reconnect. No reply was trusted."
        case .unverifiedRejection: return "An unverified device error was received. Check the setup QR and reconnect."
        }
    }
}

enum ProvisioningWire {
    static let maximumMessage = 8192
    static let suite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .chaChaPoly)
    static let requestAAD = Data("karaali-provision/v3/request".utf8)
    static let exportContext = Data("karaali-provision/v3/device-to-phone".utf8)

    static func info(deviceID: String, challenge: Data, packetSize: Int) -> Data {
        Data("karaali-provision/v3\0\(deviceID)\0".utf8) + challenge + Data([UInt8(packetSize >> 8), UInt8(packetSize & 255)])
    }

    static func pskID(_ deviceID: String) -> Data {
        Data("karaali-provision/v3/setup/\(deviceID)".utf8)
    }

    static func counterBytes(_ counter: UInt64) -> Data {
        var bigEndian = counter.bigEndian
        return withUnsafeBytes(of: &bigEndian) { Data($0) }
    }

    static func replyNonce(_ counter: UInt64) throws -> ChaChaPoly.Nonce {
        try ChaChaPoly.Nonce(data: Data([0, 0, 0, 1]) + counterBytes(counter))
    }

    static func replyAAD(info: Data, counter: UInt64) -> Data {
        info + Data("\0reply\0".utf8) + counterBytes(counter)
    }

    static func object(_ data: Data) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= maximumMessage,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ProvisioningError.invalidMessage
        }
        return object
    }

    static func encode(_ object: [String: Any]) throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard !data.isEmpty, data.count <= maximumMessage else { throw ProvisioningError.invalidMessage }
        return data
    }

    static func integer(_ value: Any?, equals expected: UInt64) -> Bool {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              ["c", "s", "i", "l", "q", "C", "S", "I", "L", "Q"].contains(String(cString: number.objCType)),
              number.stringValue == String(expected) else { return false }
        return true
    }

    static func boolean(_ value: Any?) throws -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
            throw ProvisioningError.invalidMessage
        }
        return number.boolValue
    }

    static func validSSID(_ value: String) -> Bool { (1...32).contains(value.utf8.count) }

    static func validPassword(_ value: String) -> Bool {
        let bytes = value.utf8
        return ((8...63).contains(bytes.count) && bytes.allSatisfy { (32...126).contains($0) })
            || (bytes.count == 64 && bytes.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) })
    }

    static func validIP(_ value: String, requireUsable: Bool) -> Bool {
        guard !value.utf8.contains(0) else { return false }
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            let host = UInt32(bigEndian: ipv4.s_addr)
            return !requireUsable || (host != 0 && host >> 24 != 127 && host >> 16 != 0xa9fe
                && host >> 28 != 0xe && host != UInt32.max)
        }
        var ipv6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            if !requireUsable { return true }
            return withUnsafeBytes(of: &ipv6) { bytes in
                if bytes.prefix(10).allSatisfy({ $0 == 0 }) && bytes[10] == 255 && bytes[11] == 255 {
                    let host = UInt32(bytes[12]) << 24 | UInt32(bytes[13]) << 16 | UInt32(bytes[14]) << 8 | UInt32(bytes[15])
                    return host != 0 && host >> 24 != 127 && host >> 16 != 0xa9fe
                        && host >> 28 != 0xe && host != UInt32.max
                }
                return !bytes.allSatisfy { $0 == 0 }
                    && !(bytes.prefix(15).allSatisfy { $0 == 0 } && bytes[15] == 1)
                    && !(bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80) && bytes[0] != 0xff
            }
        }
        return false
    }

    static func base64(_ value: Any?, count: Int? = nil) throws -> Data {
        guard let string = value as? String,
              let data = Data(base64Encoded: string), data.base64EncodedString() == string,
              count == nil || data.count == count else { throw ProvisioningError.invalidMessage }
        return data
    }
}

struct SetupIdentity {
    let deviceID: String
    let publicKey: Curve25519.KeyAgreement.PublicKey
    let setupSecret: SymmetricKey

    init(json: String) throws {
        do {
            let object = try ProvisioningWire.object(Data(json.utf8))
            guard ProvisioningWire.integer(object["version"], equals: 1),
                  let deviceID = object["device_id"] as? String,
                  (1...32).contains(deviceID.utf8.count),
                  deviceID.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }) else {
                throw ProvisioningError.invalidQR
            }
            self.deviceID = deviceID
            publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ProvisioningWire.base64(object["public_key"], count: 32))
            setupSecret = SymmetricKey(data: try ProvisioningWire.base64(object["setup_secret"], count: 32))
        } catch {
            throw ProvisioningError.invalidQR
        }
    }
}

enum ProvisioningCommand {
    case echo(String), scan, status, configure(ssid: String, password: String, hidden: Bool)

    var op: String {
        switch self {
        case .echo: return "echo"
        case .scan: return "scan"
        case .status: return "status"
        case .configure: return "configure"
        }
    }

    func validate() throws {
        switch self {
        case .echo(let text):
            guard (1...512).contains(text.utf8.count) else { throw ProvisioningError.invalidText }
        case .configure(let ssid, let password, _):
            guard ProvisioningWire.validSSID(ssid) else { throw ProvisioningError.invalidSSID }
            guard ProvisioningWire.validPassword(password) else { throw ProvisioningError.invalidPassword }
        case .scan, .status: break
        }
    }

    func plaintext() throws -> Data {
        try validate()
        var object: [String: Any] = ["op": op]
        switch self {
        case .echo(let text):
            object["text"] = text
        case .configure(let ssid, let password, let hidden):
            object["ssid"] = ssid
            object["password"] = password
            object["hidden"] = hidden
        case .scan, .status: break
        }
        let data = try ProvisioningWire.encode(object)
        guard data.count <= 4096 else { throw ProvisioningError.invalidMessage }
        return data
    }
}

struct WiFiNetwork: Identifiable {
    let ssid: String
    let strength: Int
    let security: String
    let supported: Bool
    var id: Data { Data(ssid.utf8) + Data([0]) + Data(security.utf8) }
    var securityDescription: String {
        switch security {
        case "wpa2-psk": return "WPA2 Personal"
        case "wpa3-sae": return "WPA3-only · unsupported"
        case "enterprise": return "Enterprise · unsupported"
        case "open": return "Open · unsupported"
        default: return "Unsupported security"
        }
    }
}

struct DeviceNetwork {
    let ssid: String
    let interface: String
    let addresses: [String]
    let profileUUID: String

    init(object: [String: Any], requireUsable: Bool) throws {
        guard let ssid = object["ssid"] as? String, ProvisioningWire.validSSID(ssid),
              let interface = object["interface"] as? String, !interface.isEmpty,
              let addresses = object["addresses"] as? [String],
              (!requireUsable || !addresses.isEmpty),
              addresses.allSatisfy({ ProvisioningWire.validIP($0, requireUsable: requireUsable) }),
              let profileUUID = object["profile_uuid"] as? String, !profileUUID.isEmpty else {
            throw ProvisioningError.invalidMessage
        }
        self.ssid = ssid
        self.interface = interface
        self.addresses = addresses
        self.profileUUID = profileUUID
    }
}

enum AuthenticatedReply {
    case echo(String)
    case scanning
    case networks(interface: String, rows: [WiFiNetwork], truncated: Bool)
    case progress(event: String, ssid: String)
    case connected(DeviceNetwork)
    case status(provisioned: Bool, setupAllowed: Bool, network: DeviceNetwork?)
    case error(code: String, message: String)

    var final: Bool {
        switch self {
        case .scanning, .progress: return false
        default: return true
        }
    }

    static func parse(_ data: Data, deviceID: String, command: ProvisioningCommand) throws -> Self {
        guard data.count <= 5600 else { throw ProvisioningError.invalidMessage }
        let object = try ProvisioningWire.object(data)
        guard object["device_id"] as? String == deviceID, object["op"] as? String == command.op,
              let event = object["event"] as? String else { throw ProvisioningError.invalidMessage }
        let final = try ProvisioningWire.boolean(object["final"])
        let result: Self
        if event == "error" {
            guard let code = object["code"] as? String, !code.isEmpty,
                  let message = object["message"] as? String, !message.isEmpty,
                  message.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw ProvisioningError.invalidMessage
            }
            result = .error(code: code, message: message)
        } else {
            switch (command, event) {
            case (.echo(let expected), "echo"):
                guard let echo = object["echo"] as? String, Data(echo.utf8) == Data(expected.utf8) else {
                    throw ProvisioningError.invalidMessage
                }
                result = .echo(echo)
            case (.scan, "scanning"): result = .scanning
            case (.scan, "networks"):
                guard let interface = object["interface"] as? String, !interface.isEmpty,
                      let entries = object["networks"] as? [[String: Any]], entries.count <= 16 else {
                    throw ProvisioningError.invalidMessage
                }
                var rows: [WiFiNetwork] = []
                var identifiers = Set<Data>()
                for entry in entries {
                    guard let ssid = entry["ssid"] as? String, ProvisioningWire.validSSID(ssid),
                          let strength = entry["strength"] as? Int, (0...100).contains(strength),
                          ProvisioningWire.integer(entry["strength"], equals: UInt64(strength)),
                          let security = entry["security"] as? String,
                          ["wpa2-psk", "wpa3-sae", "enterprise", "open", "unsupported"].contains(security) else {
                        throw ProvisioningError.invalidMessage
                    }
                    let supported = try ProvisioningWire.boolean(entry["supported"])
                    guard supported == (security == "wpa2-psk") else { throw ProvisioningError.invalidMessage }
                    let row = WiFiNetwork(ssid: ssid, strength: strength, security: security, supported: supported)
                    guard identifiers.insert(row.id).inserted else { throw ProvisioningError.invalidMessage }
                    rows.append(row)
                }
                result = .networks(interface: interface, rows: rows, truncated: try ProvisioningWire.boolean(object["truncated"]))
            case (.configure(let requested, _, _), "connecting"),
                 (.configure(let requested, _, _), "obtaining_ip"),
                 (.configure(let requested, _, _), "saving"):
                guard let ssid = object["ssid"] as? String, Data(ssid.utf8) == Data(requested.utf8) else {
                    throw ProvisioningError.invalidMessage
                }
                result = .progress(event: event, ssid: ssid)
            case (.configure(let requested, _, _), "connected"):
                let network = try DeviceNetwork(object: object, requireUsable: true)
                guard Data(network.ssid.utf8) == Data(requested.utf8),
                      try ProvisioningWire.boolean(object["provisioned"]) else { throw ProvisioningError.invalidMessage }
                result = .connected(network)
            case (.status, "status"):
                let network: DeviceNetwork?
                if object["network"] is NSNull { network = nil }
                else if let value = object["network"] as? [String: Any] {
                    network = try DeviceNetwork(object: value, requireUsable: false)
                } else { throw ProvisioningError.invalidMessage }
                result = .status(provisioned: try ProvisioningWire.boolean(object["provisioned"]),
                                 setupAllowed: try ProvisioningWire.boolean(object["setup_allowed"]), network: network)
            default: throw ProvisioningError.invalidMessage
            }
        }
        guard final == result.final else { throw ProvisioningError.invalidMessage }
        return result
    }
}

struct ProvisioningAttempt {
    let challenge: Data
    let request: Data
    let packetSize: Int
    private let deviceID: String
    private let command: ProvisioningCommand
    private let info: Data
    private let replyKey: SymmetricKey
    private(set) var expectedCounter: UInt64 = 0
    private(set) var finished = false

    init(identity: SetupIdentity, command: ProvisioningCommand, challengeMessage: Data, requestedPacketSize: Int) throws {
        let plaintext = try command.plaintext()
        let object = try ProvisioningWire.object(challengeMessage)
        guard (20...185).contains(requestedPacketSize), object["type"] as? String == "challenge",
              ProvisioningWire.integer(object["version"], equals: 3),
              object["device_id"] as? String == identity.deviceID,
              let size = object["packet_size"] as? Int, (20...requestedPacketSize).contains(size),
              ProvisioningWire.integer(object["packet_size"], equals: UInt64(size)) else { throw ProvisioningError.invalidMessage }
        packetSize = size
        challenge = try ProvisioningWire.base64(object["challenge"], count: 32)
        deviceID = identity.deviceID
        // The reply validator needs the SSID, never the Wi-Fi password.
        if case .configure(let ssid, _, let hidden) = command {
            self.command = .configure(ssid: ssid, password: "", hidden: hidden)
        } else { self.command = command }
        info = ProvisioningWire.info(deviceID: identity.deviceID, challenge: challenge, packetSize: size)
        var sender = try HPKE.Sender(recipientKey: identity.publicKey, ciphersuite: ProvisioningWire.suite,
                                     info: info, presharedKey: identity.setupSecret,
                                     presharedKeyIdentifier: ProvisioningWire.pskID(identity.deviceID))
        let ciphertext = try sender.seal(plaintext, authenticating: ProvisioningWire.requestAAD)
        replyKey = try sender.exportSecret(context: ProvisioningWire.exportContext, outputByteCount: 32)
        request = try ProvisioningWire.encode([
            "type": "request", "challenge": challenge.base64EncodedString(),
            "enc": sender.encapsulatedKey.base64EncodedString(), "ciphertext": ciphertext.base64EncodedString()
        ])
    }

    mutating func authenticate(reply data: Data) throws -> AuthenticatedReply {
        do {
            let object = try ProvisioningWire.object(data)
            guard !finished, expectedCounter < UInt64.max, object["type"] as? String == "reply",
                  try ProvisioningWire.base64(object["challenge"], count: 32) == challenge,
                  ProvisioningWire.integer(object["counter"], equals: expectedCounter) else { throw ProvisioningError.authentication }
            let ciphertext = try ProvisioningWire.base64(object["ciphertext"])
            guard ciphertext.count >= 16 else { throw ProvisioningError.authentication }
            let box = try ChaChaPoly.SealedBox(nonce: ProvisioningWire.replyNonce(expectedCounter),
                                             ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
            let cleartext = try ChaChaPoly.open(box, using: replyKey,
                                               authenticating: ProvisioningWire.replyAAD(info: info, counter: expectedCounter))
            let reply = try AuthenticatedReply.parse(cleartext, deviceID: deviceID, command: command)
            expectedCounter += 1
            finished = reply.final
            return reply
        } catch {
            throw ProvisioningError.authentication
        }
    }
}

struct FrameDecoder {
    private var expectedLength: Int?
    private var buffer = Data()

    mutating func reset() {
        expectedLength = nil
        buffer.removeAll(keepingCapacity: true)
    }

    mutating func receive(_ packet: Data) throws -> Data? {
        do {
            guard packet.count <= 185, let flag = packet.first else { throw ProvisioningError.invalidFrame }
            let payload: Data.SubSequence
            switch flag {
            case 1:
                reset()
                guard packet.count >= 3 else { throw ProvisioningError.invalidFrame }
                let length = Int(packet[packet.startIndex + 1]) * 256 + Int(packet[packet.startIndex + 2])
                guard (1...ProvisioningWire.maximumMessage).contains(length) else { throw ProvisioningError.invalidFrame }
                expectedLength = length
                payload = packet.dropFirst(3)
            case 0:
                guard expectedLength != nil else { throw ProvisioningError.invalidFrame }
                payload = packet.dropFirst()
            default: throw ProvisioningError.invalidFrame
            }
            guard let length = expectedLength, buffer.count + payload.count <= length else { throw ProvisioningError.invalidFrame }
            buffer.append(payload)
            if buffer.count == length {
                let result = buffer
                reset()
                return result
            }
            return nil
        } catch {
            reset()
            throw error
        }
    }

    static func packets(for message: Data, packetSize: Int = 20) throws -> [Data] {
        guard (20...185).contains(packetSize), (1...ProvisioningWire.maximumMessage).contains(message.count) else {
            throw ProvisioningError.invalidFrame
        }
        var packets = [Data([1, UInt8(message.count >> 8), UInt8(message.count & 255)]) + message.prefix(packetSize - 3)]
        var offset = min(packetSize - 3, message.count)
        while offset < message.count {
            let end = min(offset + packetSize - 1, message.count)
            packets.append(Data([0]) + message.subdata(in: offset..<end))
            offset = end
        }
        return packets
    }
}
