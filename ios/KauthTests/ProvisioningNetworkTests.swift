import XCTest
import Security
@testable import Kauth

final class ProvisioningNetworkTests: XCTestCase {
    private func isolatedStore() -> ProvisioningNetworkStore {
        let store = ProvisioningNetworkStore(
            service: "com.ozankaraali.Kauth.tests.\(UUID().uuidString)",
            account: UUID().uuidString
        )
        addTeardownBlock { try store.forget() }
        return store
    }

    private func query(_ store: ProvisioningNetworkStore) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: store.service,
         kSecAttrAccount as String: store.account,
         kSecAttrSynchronizable as String: false]
    }

    func testRealKeychainLifecycleAndProtection() throws {
        let store = isolatedStore()
        XCTAssertNil(try store.load())
        let first = RememberedNetworkProfile(ssid: " cafe\u{301} ", password: " secret pass ", hidden: true)
        try store.save(first)

        // A new store instance exercises launch/reload, rather than an in-memory cache.
        let reopened = ProvisioningNetworkStore(service: store.service, account: store.account)
        XCTAssertEqual(try reopened.load(), first)
        var request = query(store)
        request[kSecReturnAttributes as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(request as CFDictionary, &result), errSecSuccess)
        let attributes = try XCTUnwrap(result as? [String: Any])
        XCTAssertEqual(attributes[kSecAttrAccessible as String] as? String,
                       kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        XCTAssertEqual(attributes[kSecAttrSynchronizable as String] as? Bool, false)

        let replacement = RememberedNetworkProfile(ssid: "Second site", password: "next-password", hidden: false)
        try reopened.save(replacement)
        XCTAssertEqual(try store.load(), replacement)
        try store.forget()
        XCTAssertNil(try reopened.load())
        try store.forget() // Explicit forget is idempotent.
    }

    func testRealKeychainNamespacesAreIsolated() throws {
        let first = isolatedStore()
        let second = isolatedStore()
        let profile = RememberedNetworkProfile(ssid: "Site", password: "password123", hidden: false)
        try first.save(profile)
        XCTAssertNil(try second.load())
        try second.forget()
        XCTAssertEqual(try first.load(), profile)
    }

    func testCorruptKeychainItemFailsRatherThanInventingProfile() throws {
        let store = isolatedStore()
        try store.save(RememberedNetworkProfile(ssid: "Site", password: "password123", hidden: false))
        XCTAssertEqual(SecItemUpdate(query(store) as CFDictionary,
                                     [kSecValueData as String: Data("not a profile".utf8)] as CFDictionary),
                       errSecSuccess)
        XCTAssertThrowsError(try store.load()) { error in
            guard case NetworkStoreError.invalidData = error else {
                return XCTFail("Expected a safe invalid-data error")
            }
        }
        try store.forget()
        XCTAssertNil(try store.load())
    }

    func testOnlyOptedInExactSuccessfulSubmissionReplacesRememberedProfile() throws {
        let store = isolatedStore()
        let original = RememberedNetworkProfile(ssid: "Original", password: "original-password", hidden: false)
        try store.save(original)
        let submitted = RememberedNetworkProfile(ssid: " cafe\u{301} ", password: " submitted pass ", hidden: true)
        var policy = ProvisioningNetworkPolicy()

        policy.begin(submitted, remember: false)
        if let authorized = policy.authenticatedSuccess(ssid: submitted.ssid) { try store.save(authorized) }
        XCTAssertEqual(try store.load(), original)

        policy.begin(submitted, remember: true)
        // Failed, cancelled and disconnected exchanges all discard the authorization.
        policy.cancel()
        if let authorized = policy.authenticatedSuccess(ssid: submitted.ssid) { try store.save(authorized) }
        XCTAssertEqual(try store.load(), original)

        policy.begin(submitted, remember: true)
        // Canonically equal Swift strings are different Wi-Fi identifiers on the wire.
        XCTAssertNil(policy.authenticatedSuccess(ssid: " caf\u{e9} "))
        XCTAssertNil(policy.authenticatedSuccess(ssid: submitted.ssid))
        XCTAssertEqual(try store.load(), original)

        policy.begin(submitted, remember: true)
        var changedForm = ProvisioningNetworkForm()
        changedForm.use(submitted)
        changedForm.password = "different-password"
        changedForm.hidden = false
        let authorized = try XCTUnwrap(policy.authenticatedSuccess(ssid: submitted.ssid))
        XCTAssertEqual(authorized, submitted)
        XCTAssertNotEqual(authorized, changedForm.profile)
        try store.save(authorized)
        XCTAssertEqual(try store.load(), submitted)
        XCTAssertNil(policy.authenticatedSuccess(ssid: submitted.ssid))
    }

    func testNewAttemptCannotReuseEarlierOptIn() {
        let profile = RememberedNetworkProfile(ssid: "Site", password: "password123", hidden: false)
        var policy = ProvisioningNetworkPolicy()
        policy.begin(profile, remember: true)
        policy.begin(profile, remember: false)
        XCTAssertNil(policy.authenticatedSuccess(ssid: profile.ssid))
    }

    func testExplicitReuseAndSSIDChangesPreserveExactBytes() {
        let profile = RememberedNetworkProfile(ssid: " cafe\u{301} ", password: " password123 ", hidden: true)
        var form = ProvisioningNetworkForm()
        XCTAssertFalse(form.remember)
        form.use(profile)
        XCTAssertEqual(form.profile, profile)
        XCTAssertFalse(form.remember)
        form.selectSSID(profile.ssid)
        XCTAssertEqual(form.password, profile.password)
        form.remember = true
        form.selectSSID(" caf\u{e9} ")
        XCTAssertEqual(form.password, "")
        XCTAssertFalse(form.remember)
        XCTAssertTrue(form.ssid.utf8.elementsEqual(" caf\u{e9} ".utf8))
        form.use(profile)
        form.remember = true
        form.joined()
        XCTAssertEqual(form.password, "")
        XCTAssertFalse(form.remember)
        XCTAssertTrue(form.ssid.utf8.elementsEqual(profile.ssid.utf8))
        form.use(profile)
        XCTAssertEqual(form.password, profile.password)
    }
}
