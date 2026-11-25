import Foundation
import Security

struct RememberedNetworkProfile: Codable, Equatable {
    let ssid: String
    let password: String
    let hidden: Bool

    // Swift String equality normalizes Unicode; network identifiers are exact bytes.
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.ssid.utf8.elementsEqual(rhs.ssid.utf8)
            && lhs.password.utf8.elementsEqual(rhs.password.utf8)
            && lhs.hidden == rhs.hidden
    }
}

enum NetworkStoreError: LocalizedError {
    case keychain(OSStatus)
    case invalidData

    var errorDescription: String? {
        switch self {
        case .keychain(let status): return "Keychain could not complete the operation (status \(status))."
        case .invalidData: return "The remembered network could not be read. Forget it and save it again after a successful join."
        }
    }
}

// No QR material belongs here. Keep this source independent of UI, Bluetooth and HPKE.
struct ProvisioningNetworkStore {
    let service: String
    let account: String

    init(service: String = "com.ozankaraali.Kauth.network", account: String = "remembered-wpa2") {
        self.service = service
        self.account = account
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }

    func load() throws -> RememberedNetworkProfile? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw NetworkStoreError.keychain(status) }
        guard let data = result as? Data,
              let profile = try? JSONDecoder().decode(RememberedNetworkProfile.self, from: data) else {
            throw NetworkStoreError.invalidData
        }
        return profile
    }

    func save(_ profile: RememberedNetworkProfile) throws {
        let attributes: [String: Any] = [
            kSecValueData as String: try JSONEncoder().encode(profile),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        // Replace in place: a failed update must not delete the previous profile.
        let update = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw NetworkStoreError.keychain(update) }
        let status = SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil)
        guard status == errSecSuccess else { throw NetworkStoreError.keychain(status) }
    }

    func forget() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NetworkStoreError.keychain(status)
        }
    }
}
