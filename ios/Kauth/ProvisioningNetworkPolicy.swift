import Foundation

// A one-shot authorization bound to the submitted profile, never mutable form data.
struct ProvisioningNetworkPolicy {
    private var pending: RememberedNetworkProfile?

    mutating func begin(_ profile: RememberedNetworkProfile, remember: Bool) {
        pending = remember ? profile : nil
    }

    mutating func cancel() { pending = nil }

    // The caller must first authenticate and validate the final configure reply.
    mutating func authenticatedSuccess(ssid: String) -> RememberedNetworkProfile? {
        defer { pending = nil }
        guard let pending, pending.ssid.utf8.elementsEqual(ssid.utf8) else { return nil }
        return pending
    }
}

struct ProvisioningNetworkForm {
    var ssid = ""
    var password = ""
    var hidden = false
    var remember = false

    var profile: RememberedNetworkProfile {
        RememberedNetworkProfile(ssid: ssid, password: password, hidden: hidden)
    }

    mutating func selectSSID(_ value: String) {
        if !ssid.utf8.elementsEqual(value.utf8) {
            password = ""
            remember = false
        }
        ssid = value
    }

    mutating func use(_ profile: RememberedNetworkProfile) {
        ssid = profile.ssid
        password = profile.password
        hidden = profile.hidden
        remember = false
    }

    mutating func joined() {
        password = ""
        remember = false
    }
}
