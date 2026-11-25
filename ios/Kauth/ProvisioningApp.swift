import SwiftUI
import UIKit

@main
struct ProvisioningApp: App {
    var body: some Scene {
        WindowGroup { ProvisioningView() }
    }
}

struct ProvisioningView: View {
    @StateObject private var bluetooth = ProvisioningBluetooth()
    @Environment(\.scenePhase) private var scenePhase
    @State private var identity: SetupIdentity?
    @State private var qrJSON = ""
    @State private var text = "hello world"
    @State private var showScanner = false
    @State private var showHelp = false
    @State private var showImport = false
    @State private var showAdvanced = false
    @State private var importError: String?
    @State private var networkForm = ProvisioningNetworkForm()
    @State private var revealPassword = false
    @State private var manualSSID = false

    var body: some View {
        NavigationStack {
            Form {
                introduction
                if let network = bluetooth.connectedNetwork {
                    connectedSection(network)
                } else {
                    identitySection
                    if identity != nil {
                        deviceSection
                        activitySection
                        if deviceVerified && !bluetooth.busy {
                            wifiScanSection
                            wifiCredentialsSection
                        }
                    }
                }
            }
            .scrollBounceBehavior(.basedOnSize)
            .navigationTitle("Device Setup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showHelp = true } label: {
                        Image(systemName: "questionmark.circle")
                    }.accessibilityLabel("Help")
                }
            }
        }
        .tint(.teal)
        .sheet(isPresented: $showHelp, onDismiss: { showAdvanced = false }) { helpView }
        .sheet(isPresented: $showScanner) {
            NavigationStack {
                QRScanner { result in
                    showScanner = false
                    switch result {
                    case .success(let value): importQR(value)
                    case .failure(let error): importError = error.localizedDescription
                    }
                }
                .overlay(alignment: .bottom) {
                    Text("Point at the setup QR supplied with this device.")
                        .font(.callout.bold()).padding()
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16)).padding()
                }
                .navigationTitle("Scan setup QR")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { showScanner = false }
                    }
                }
            }
            .overlay { privacyCover }
        }
        .overlay { privacyCover }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background {
                bluetooth.cancel()
                showScanner = false
                revealPassword = false
            } else if phase == .active {
                bluetooth.refreshRememberedNetwork()
            }
        }
        .onChange(of: bluetooth.connectedNetwork != nil) { _, connected in
            if connected { networkForm.joined(); revealPassword = false }
        }
    }

    private var introduction: some View {
        Section {
            VStack(alignment: .leading, spacing: 22) {
                HStack(alignment: .center, spacing: 16) {
                    Image(systemName: bluetooth.connectedNetwork == nil ? "wifi" : "checkmark.circle.fill")
                        .font(.system(size: 32, weight: .semibold))
                        .foregroundStyle(.teal)
                        .frame(width: 64, height: 64)
                        .background(.teal.opacity(0.12), in: RoundedRectangle(cornerRadius: 20))
                        .accessibilityHidden(true)
                    Text(bluetooth.connectedNetwork == nil ? "Let’s get your\ndevice connected" : "You’re all connected")
                        .font(.title2.bold()).fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(.isHeader)
                }
                Text(stepDescription).font(.subheadline).foregroundStyle(.secondary)
                HStack(alignment: .top, spacing: 8) {
                    setupStep(0, title: "Scan QR", symbol: "qrcode.viewfinder")
                    setupStep(1, title: "Verify", symbol: "checkmark.shield")
                    setupStep(2, title: "Join Wi-Fi", symbol: "wifi")
                }
            }.padding(.vertical, 12)
        }
        .listRowBackground(LinearGradient(
            colors: [Color.teal.opacity(0.08), Color(uiColor: .secondarySystemGroupedBackground)],
            startPoint: .topLeading, endPoint: .bottomTrailing))
    }

    private var setupStepIndex: Int {
        identity == nil ? 0 : (deviceVerified ? 2 : 1)
    }

    private func setupStep(_ index: Int, title: String, symbol: String) -> some View {
        let complete = bluetooth.connectedNetwork != nil || index < setupStepIndex
        let current = index == setupStepIndex && bluetooth.connectedNetwork == nil
        return VStack(spacing: 8) {
            Image(systemName: complete ? "checkmark" : symbol)
                .font(.system(size: 19, weight: .semibold))
                .foregroundStyle(complete || current ? Color.teal : Color.secondary)
                .frame(width: 44, height: 44)
                .background(complete || current ? Color.teal.opacity(0.12) : Color.secondary.opacity(0.07), in: Circle())
            Text(title).font(.caption.weight(current ? .semibold : .regular))
                .foregroundStyle(current ? Color.primary : Color.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title), \(complete ? "complete" : current ? "current step" : "up next")")
    }

    private var stepDescription: String {
        if bluetooth.connectedNetwork != nil { return "Setup complete" }
        if identity == nil { return "1 of 3 · Scan the device’s QR" }
        if !deviceVerified { return "2 of 3 · Find and verify the device" }
        return "3 of 3 · Choose Wi-Fi and join"
    }

    private var identitySection: some View {
        Section {
            if let identity {
                Label(identity.deviceID, systemImage: "qrcode").font(.headline)
                    .textSelection(.enabled)
                Text("Setup QR loaded. Next, we’ll check the nearby device against it.")
                    .foregroundStyle(.secondary)
                Button("Scan a different QR") { resetDevice(); showScanner = true }
                    .disabled(bluetooth.busy)
            } else {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Scan the QR supplied with your device.")
                        .font(.body)
                    Button { showScanner = true } label: {
                        HStack(spacing: 10) {
                            Image(systemName: "camera.fill")
                            Text("Scan setup QR").fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity).padding(.vertical, 8)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    Label("Keep your setup card private.", systemImage: "lock")
                        .labelStyle(.titleAndIcon)
                        .font(.footnote).foregroundStyle(.secondary)
                }.padding(.vertical, 6)
            }
            if let importError {
                Label(importError, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
                Button("Camera or permission help") { showHelp = true }
            }
        } header: { Text("Setup QR") }
    }

    private var deviceSection: some View {
        Section {
            if let device = bluetooth.selectedDevice {
                Label(device.name, systemImage: deviceVerified ? "checkmark.shield.fill" : "sensor.tag.radiowaves.forward")
                    .font(.headline)
                Text(deviceVerified ? "Verified against your setup QR." : "Selected, not yet verified.")
                    .foregroundStyle(deviceVerified ? Color.teal : Color.secondary)
                if !deviceVerified && !bluetooth.busy {
                    Button("Verify device and find Wi-Fi") { perform(.scan) }
                }
            }
            ForEach(bluetooth.devices) { device in
                Button {
                    guard let identity else { return }
                    clearCredentials()
                    bluetooth.select(device.id, identity: identity)
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Label(device.name, systemImage: "sensor.tag.radiowaves.forward")
                            .font(.headline)
                        Text("Tap to verify · \(String(device.id.uuidString.prefix(8)))")
                            .font(.caption).foregroundStyle(.secondary)
                    }.padding(.vertical, 4)
                }.accessibilityHint("Checks this device against your QR, then finds its Wi-Fi networks. Does not join a network.")
            }
            if !bluetooth.findingDevices {
                Button(bluetooth.selectedDevice == nil ? "Find nearby devices" : "Choose another device") {
                    clearCredentials()
                    bluetooth.findDevices()
                }.disabled(bluetooth.busy)
            }
        } header: { Text("Nearby device") } footer: {
            Text("A Bluetooth name is only a label. Selecting a device checks it securely and scans for Wi-Fi; it never sends your Wi-Fi password.")
        }
    }

    private var activitySection: some View {
        Section {
            HStack(alignment: .top, spacing: 12) {
                if bluetooth.busy { ProgressView().accessibilityLabel("Working") }
                else { Image(systemName: bluetooth.failure ? "exclamationmark.triangle" : "info.circle") }
                Text(bluetooth.status)
                    .foregroundStyle(bluetooth.failure ? Color.red : Color.primary)
                    .accessibilityIdentifier("exchangeStatus")
            }
            if bluetooth.busy {
                Button(bluetooth.findingDevices ? "Stop searching" : "Disconnect", role: .cancel) { bluetooth.cancel() }
                if !bluetooth.findingDevices {
                    Text("After Join, disconnecting stops progress updates, not the device’s network operation.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            } else if bluetooth.selectedDevice != nil {
                Button("Check device status") { perform(.status) }
                    .disabled(!canPerform)
            }
            if let network = bluetooth.statusNetwork {
                Text("Currently on \(network.ssid)").font(.headline)
                Text("This is a status check, not confirmation of a new Join.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            if bluetooth.failure {
                Text("Check the QR belongs to this device. We won’t switch devices or retry your password automatically.")
                    .font(.footnote).foregroundStyle(.secondary)
                Button("Help with this step") { showHelp = true }
            }
        } header: { Text(bluetooth.busy ? "Working" : "Device update") }
    }

    private var wifiScanSection: some View {
        Section {
            if let ssid = bluetooth.rememberedSSID {
                Button {
                    if let profile = bluetooth.useRememberedNetwork() {
                        networkForm.use(profile)
                        manualSSID = true
                        revealPassword = false
                    }
                } label: {
                    Label("Use saved network: \(ssid)", systemImage: "key.fill")
                }
                Text("Fills the form only. Review it, then tap Join.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            ForEach(bluetooth.networks) { network in
                Button {
                    networkForm.selectSSID(network.ssid)
                    revealPassword = false
                    manualSSID = false
                    networkForm.hidden = false
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(network.ssid).foregroundStyle(.primary)
                            Text(network.securityDescription).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if !manualSSID && networkForm.ssid.utf8.elementsEqual(network.ssid.utf8) {
                            Image(systemName: "checkmark.circle.fill").accessibilityLabel("Selected")
                        }
                    }.padding(.vertical, 3)
                }.disabled(!network.supported)
            }
            if !bluetooth.scanInterface.isEmpty && bluetooth.networks.isEmpty {
                Text("No named networks found. Scan again or enter the network name below.")
                    .foregroundStyle(.secondary)
            }
            if bluetooth.scanTruncated {
                Text("Showing the 16 strongest networks. You can enter another network below.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Button("Refresh Wi-Fi list") { perform(.scan) }
            Toggle("Enter a network name manually", isOn: $manualSSID)
        } header: { Text("Choose Wi-Fi") } footer: {
            Text("These networks are seen by the device, not your iPhone. Use a WPA2 Personal network; WPA3-only, enterprise and open networks aren’t supported.")
        }.disabled(bluetooth.busy)
    }

    private var wifiCredentialsSection: some View {
        Section {
            if manualSSID {
                TextField("Network name (SSID)", text: Binding(
                    get: { networkForm.ssid },
                    set: { networkForm.selectSSID($0); revealPassword = false }
                ))
                .autocorrectionDisabled().textInputAutocapitalization(.never)
                .accessibilityLabel("Exact Wi-Fi network name")
            } else if !networkForm.ssid.isEmpty {
                LabeledContent("Network", value: networkForm.ssid)
            } else {
                Text("Choose a network above to continue.").foregroundStyle(.secondary)
            }
            if manualSSID || !networkForm.ssid.isEmpty {
                Toggle("Hidden network", isOn: $networkForm.hidden)
                Group {
                    if revealPassword { TextField("Wi-Fi password", text: $networkForm.password) }
                    else { SecureField("Wi-Fi password", text: $networkForm.password) }
                }
                .autocorrectionDisabled().textInputAutocapitalization(.never)
                .privacySensitive().accessibilityLabel("Wi-Fi password")
                Toggle("Show password", isOn: $revealPassword)
                Toggle("Save for the next device", isOn: $networkForm.remember)
                Text("Saving is optional, on this iPhone only, and happens only after a verified successful Join.")
                    .font(.footnote).foregroundStyle(.secondary)
                Button {
                    revealPassword = false
                    perform(.configure(ssid: networkForm.ssid, password: networkForm.password, hidden: networkForm.hidden),
                            rememberNetwork: networkForm.remember)
                } label: {
                    Label("Join Wi-Fi", systemImage: "wifi")
                        .frame(maxWidth: .infinity, alignment: .center).padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canPerform || !deviceVerified || !ProvisioningWire.validSSID(networkForm.ssid) || !ProvisioningWire.validPassword(networkForm.password))
            }
        } header: { Text("Review and join") } footer: {
            Text("Names and passwords are sent exactly as entered, including spaces. Password: 8–63 printable ASCII characters, or 64 hexadecimal digits. Your password is encrypted before Bluetooth transmission.")
        }.disabled(bluetooth.busy)
    }

    private func connectedSection(_ network: DeviceNetwork) -> some View {
        Section {
            Label("Wi-Fi connected", systemImage: "checkmark.circle.fill")
                .font(.title2.bold()).foregroundStyle(.teal)
            if let identity { Text(identity.deviceID).font(.headline) }
            Text(network.ssid).font(.title3).textSelection(.enabled)
            Text("The device confirmed this Join, received a usable network address, and saved its setup. Internet access was not tested.")
            if let message = bluetooth.storageMessage {
                Text(message).foregroundStyle(bluetooth.storageWarning ? Color.orange : Color.secondary)
            }
            Button("Set up next device") { resetDevice(); showScanner = true }
                .buttonStyle(.borderedProminent)
            Text("A saved network is never sent automatically. Scan the next QR, verify that device, then choose Use saved network and Join.")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }

    private var helpView: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Keep the device powered and nearby. If it was already set up, ask IT to reopen setup.")
                    if canPerform {
                        Button("Check device connection") { perform(.status) }
                    }
                    Button("Open app settings") {
                        if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
                    }
                } header: {
                    Text("Trouble connecting?")
                } footer: {
                    Text("Unexpected Bluetooth PIN? Cancel unless you can verify it on both devices.")
                }
                if bluetooth.rememberedSSID != nil || bluetooth.storageWarning {
                    Section("Saved network") {
                        if let ssid = bluetooth.rememberedSSID { Text(ssid) }
                        if let message = bluetooth.storageMessage { Text(message).font(.footnote) }
                        Button("Forget saved network", role: .destructive) {
                            bluetooth.forgetRememberedNetwork()
                            if !bluetooth.storageWarning { clearCredentials() }
                        }.disabled(bluetooth.busy)
                    }
                }
                Section {
                    DisclosureGroup("Advanced diagnostics", isExpanded: $showAdvanced) {
                        Text(bluetooth.status).font(.footnote).textSelection(.enabled)
                        if let detail = bluetooth.diagnosticDetail { Text(detail).font(.footnote) }
                        if let device = bluetooth.selectedDevice {
                            Text("\(device.name) · \(device.signal) dBm").font(.footnote)
                            Text(device.id.uuidString).font(.caption.monospaced()).textSelection(.enabled)
                        }
                        if let network = bluetooth.connectedNetwork ?? bluetooth.statusNetwork {
                            LabeledContent("Interface", value: network.interface)
                            ForEach(network.addresses, id: \.self) { Text($0).textSelection(.enabled) }
                        }
                        DisclosureGroup("Import QR text", isExpanded: $showImport) {
                            TextEditor(text: $qrJSON)
                                .font(.system(.body, design: .monospaced)).frame(minHeight: 120)
                                .autocorrectionDisabled().textInputAutocapitalization(.never)
                                .privacySensitive().accessibilityLabel("Setup QR JSON")
                            Button("Load QR and find device") { importQR(qrJSON) }
                                .disabled(qrJSON.isEmpty || bluetooth.busy)
                            if let importError { Text(importError).foregroundStyle(.red) }
                        }
                        if identity != nil {
                            Button("Forget setup QR", role: .destructive) { resetDevice() }
                                .disabled(bluetooth.busy)
                        }
                        TextField("Test message", text: $text, axis: .vertical)
                            .lineLimit(2...5).autocorrectionDisabled().textInputAutocapitalization(.never)
                            .privacySensitive().disabled(bluetooth.busy)
                        Button("Send encrypted test message") { perform(.echo(text)) }
                            .disabled(!canPerform || !(1...512).contains(text.utf8.count))
                        if let echo = bluetooth.verifiedEcho {
                            Text(echo).font(.system(.body, design: .monospaced)).privacySensitive()
                        }
                    }
                }
            }
            .scrollBounceBehavior(.basedOnSize)
            .navigationTitle("Help")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showHelp = false } } }
        }
        .tint(.teal)
        .overlay { privacyCover }
    }

    @ViewBuilder private var privacyCover: some View {
        if scenePhase != .active && hasSensitiveContent {
            Color(uiColor: .systemBackground).ignoresSafeArea()
                .overlay { Image(systemName: "lock").font(.title2).foregroundStyle(.secondary) }
                .accessibilityLabel("Private content hidden")
                .accessibilityAddTraits(.isModal)
        }
    }

    private var hasSensitiveContent: Bool {
        showScanner || !networkForm.password.isEmpty
            || (showHelp && showAdvanced
                && ((showImport && !qrJSON.isEmpty) || !text.isEmpty || bluetooth.verifiedEcho != nil))
    }

    private var deviceVerified: Bool {
        guard let identity, let verifiedID = bluetooth.verifiedDeviceID else { return false }
        return verifiedID.utf8.elementsEqual(identity.deviceID.utf8)
    }

    private var canPerform: Bool { identity != nil && bluetooth.selectedDevice != nil && !bluetooth.busy }

    private func perform(_ command: ProvisioningCommand, rememberNetwork: Bool = false) {
        guard let identity else { return }
        bluetooth.perform(command, identity: identity, rememberNetwork: rememberNetwork)
    }

    private func clearCredentials() {
        networkForm = ProvisioningNetworkForm()
        manualSSID = false
        revealPassword = false
    }

    private func resetDevice() {
        bluetooth.forget()
        identity = nil
        qrJSON = ""
        importError = nil
        clearCredentials()
    }

    private func importQR(_ value: String) {
        do {
            let imported = try SetupIdentity(json: value)
            resetDevice()
            identity = imported
            showImport = false
            showHelp = false
            bluetooth.findDevices()
        } catch {
            importError = "This isn’t a valid setup QR. Scan the private QR supplied with this device, or check the imported text."
        }
    }
}
