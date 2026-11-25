import Foundation
import CoreBluetooth
import Combine

struct NearbyDevice: Identifiable {
    let id: UUID
    let name: String
    let signal: Int
}

// CoreBluetooth delegates and UI commands all run on the main queue.
final class ProvisioningBluetooth: NSObject, ObservableObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    private enum Stage { case idle, poweringOn, scanning, waitingDisconnect, connecting, discovering, subscribing, challenge, reply }
    private static let service = CBUUID(string: "8a46a1b0-5f14-4ad9-a7a8-21fc87a08001")
    private static let rx = CBUUID(string: "8a46a1b0-5f14-4ad9-a7a8-21fc87a08002")
    private static let tx = CBUUID(string: "8a46a1b0-5f14-4ad9-a7a8-21fc87a08003")

    @Published private(set) var devices: [NearbyDevice] = []
    @Published private(set) var status = "No device reply has been verified yet."
    @Published private(set) var diagnosticDetail: String?
    @Published private(set) var busy = false
    @Published private(set) var failure = false
    @Published private(set) var selectedDevice: NearbyDevice?
    @Published private(set) var verifiedDeviceID: String?
    @Published private(set) var networks: [WiFiNetwork] = []
    @Published private(set) var scanInterface = ""
    @Published private(set) var scanTruncated = false
    @Published private(set) var connectedNetwork: DeviceNetwork?
    @Published private(set) var verifiedEcho: String?
    @Published private(set) var deviceStatus: String?
    @Published private(set) var statusNetwork: DeviceNetwork?
    @Published private(set) var rememberedSSID: String?
    @Published private(set) var storageMessage: String?
    @Published private(set) var storageWarning = false

    private var central: CBCentralManager?
    @Published private var stage: Stage = .idle
    private var peripherals: [UUID: CBPeripheral] = [:]
    private var peripheral: CBPeripheral?
    private var selectedPeripheral: CBPeripheral?
    private var receiveCharacteristic: CBCharacteristic?
    private var transmitCharacteristic: CBCharacteristic?
    private var identity: SetupIdentity?
    private var command: ProvisioningCommand?
    private var requestedPacketSize = 20
    private var attempt: ProvisioningAttempt?
    private var decoder = FrameDecoder()
    private var outgoing: [Data] = []
    private var nextPacket = 0
    private var writing = false
    private var timeout: DispatchWorkItem?
    private let networkStore = ProvisioningNetworkStore()
    private var networkPolicy = ProvisioningNetworkPolicy()


    var findingDevices: Bool {
        stage == .scanning || (stage == .poweringOn && command == nil)
    }
    override init() {
        super.init()
        refreshRememberedNetwork()
    }

    func refreshRememberedNetwork() {
        do { rememberedSSID = try networkStore.load()?.ssid }
        catch { storageFailed(error) }
    }

    func useRememberedNetwork() -> RememberedNetworkProfile? {
        do {
            let profile = try networkStore.load()
            rememberedSSID = profile?.ssid
            storageMessage = profile == nil ? "No remembered network is available." : nil
            storageWarning = false
            return profile
        } catch {
            storageFailed(error)
            return nil
        }
    }

    func forgetRememberedNetwork() {
        do {
            try networkStore.forget()
            rememberedSSID = nil
            storageWarning = false
            storageMessage = "Remembered network removed from this iPhone."
        } catch { storageFailed(error) }
    }

    private func remember(_ profile: RememberedNetworkProfile) {
        do {
            try networkStore.save(profile)
            rememberedSSID = profile.ssid
            storageWarning = false
            storageMessage = "Network remembered in this iPhone's Keychain."
        } catch {
            storageFailed(error, prefix: "Wi-Fi joined successfully, but this network was not remembered. ")
        }
    }

    private func storageFailed(_ error: Error, prefix: String = "") {
        storageWarning = true
        storageMessage = prefix + error.localizedDescription
    }

    func findDevices() {
        cancel(silent: true)
        selectedPeripheral = nil
        selectedDevice = nil
        peripherals.removeAll()
        clearResults()
        prepareBluetooth()
    }

    func select(_ id: UUID, identity: SetupIdentity) {
        guard stage == .scanning, let selected = peripherals[id],
              let device = devices.first(where: { $0.id == id }) else { return }
        selectedPeripheral = selected
        selectedDevice = device
        finishTransport()
        verifiedDeviceID = nil
        perform(.scan, identity: identity)
    }

    func perform(_ command: ProvisioningCommand, identity: SetupIdentity, rememberNetwork: Bool = false) {
        guard !busy, selectedPeripheral != nil else { return }
        do { try command.validate() }
        catch let error as ProvisioningError { fail(error.localizedDescription); return }
        catch { fail(ProvisioningError.invalidMessage.localizedDescription); return }
        networkPolicy.cancel()
        if case .configure(let ssid, let password, let hidden) = command {
            networkPolicy.begin(RememberedNetworkProfile(ssid: ssid, password: password, hidden: hidden),
                                remember: rememberNetwork)
            storageMessage = nil
            storageWarning = false
        }
        connectedNetwork = nil
        diagnosticDetail = nil
        verifiedEcho = nil
        if case .scan = command {
            networks = []
            scanInterface = ""
            scanTruncated = false
        }
        deviceStatus = nil
        statusNetwork = nil
        self.identity = identity
        self.command = command
        prepareBluetooth()
    }

    private func prepareBluetooth() {
        failure = false
        #if targetEnvironment(simulator)
        fail("Nearby-device setup needs Bluetooth on a physical iPhone. It is unavailable in the simulator.")
        #else
        busy = true
        stage = .poweringOn
        status = "Checking Bluetooth permission…"
        armTimeout(seconds: 15, message: "Bluetooth did not become ready. Check Settings → Bluetooth and try again.")
        if let central { handlePowerState(central) }
        else { central = CBCentralManager(delegate: self, queue: .main) }
        #endif
    }

    private func connectSelected() {
        guard let selected = selectedPeripheral, let central else { return }
        peripheral = selected
        selected.delegate = self
        status = "Connecting to the selected device…"
        armTimeout(seconds: 15, message: "Couldn’t reach the device. Keep it nearby and make sure setup is open. See Help if it was already configured.")
        if selected.state == .disconnecting {
            stage = .waitingDisconnect
        } else if selected.state == .connected {
            discoverService(selected)
        } else {
            stage = .connecting
            central.connect(selected, options: nil)
        }
    }

    private func discoverService(_ peripheral: CBPeripheral) {
        stage = .discovering
        status = "Checking the device’s setup service…"
        peripheral.discoverServices([Self.service])
    }

    func cancel(silent: Bool = false) {
        let wasBusy = busy
        finishTransport()
        if !silent && wasBusy {
            failure = false
            status = "Disconnected. If you tapped Join, the device may still be joining. Check its status before trying again."
        }
    }

    func forget() {
        cancel(silent: true)
        selectedDevice = nil
        selectedPeripheral = nil
        peripherals.removeAll()
        clearResults()
        failure = false
        status = "No device reply has been verified yet."
    }

    private func clearResults() {
        verifiedDeviceID = nil
        diagnosticDetail = nil
        networks = []
        scanInterface = ""
        scanTruncated = false
        connectedNetwork = nil
        verifiedEcho = nil
        deviceStatus = nil
        statusNetwork = nil
    }

    private func armTimeout(seconds: Double, message: String) {
        timeout?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.fail(message) }
        timeout = work
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: work)
    }

    private func finishTransport() {
        stage = .idle
        timeout?.cancel()
        timeout = nil
        central?.stopScan()
        if let peripheral {
            peripheral.delegate = nil
            central?.cancelPeripheralConnection(peripheral)
        }
        peripheral = nil
        receiveCharacteristic = nil
        transmitCharacteristic = nil
        peripherals.removeAll()
        devices = []
        outgoing.removeAll()
        nextPacket = 0
        writing = false
        decoder.reset()
        attempt = nil
        identity = nil
        command = nil
        networkPolicy.cancel()
        busy = false
    }

    private func fail(_ message: String) {
        finishTransport()
        verifiedDeviceID = nil
        failure = true
        status = message
    }

    private func handlePowerState(_ central: CBCentralManager) {
        guard stage != .idle else { return }
        switch central.state {
        case .poweredOn:
            guard stage == .poweringOn else { return }
            if selectedPeripheral != nil && command != nil {
                connectSelected()
            } else {
                stage = .scanning
                status = "Looking for nearby devices…"
                central.scanForPeripherals(withServices: [Self.service], options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
                armTimeout(seconds: 30, message: "No device was selected. Make sure setup is open, then tap Find nearby devices to search again.")
            }
        case .unauthorized:
            fail("Bluetooth permission is denied. Allow Bluetooth for Kauth in Settings → Privacy & Security → Bluetooth.")
        case .poweredOff:
            fail("Bluetooth is off. Turn it on in Settings → Bluetooth, then retry.")
        case .unsupported:
            fail("This device does not support Bluetooth Low Energy. Use a compatible physical iPhone.")
        case .resetting:
            fail("Bluetooth is resetting. Wait a moment, then reconnect.")
        case .unknown: break
        @unknown default: fail("Bluetooth is unavailable. Check Settings and retry.")
        }
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) { handlePowerState(central) }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard stage == .scanning, peripherals[peripheral.identifier] == nil else { return }
        peripherals[peripheral.identifier] = peripheral
        let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name ?? "Setup device"
        devices.append(NearbyDevice(id: peripheral.identifier, name: name, signal: RSSI.intValue))
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard self.peripheral === peripheral, stage == .connecting else { return }
        discoverService(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        guard self.peripheral === peripheral else { return }
        fail("Could not connect. Keep the device nearby and retry.")
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        guard self.peripheral === peripheral else { return }
        if stage == .waitingDisconnect { connectSelected(); return }
        fail("Disconnected before the result was verified. A Join may still be running. Check device status before trying again.")
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard self.peripheral === peripheral, stage == .discovering else { return }
        guard error == nil, let service = peripheral.services?.first(where: { $0.uuid == Self.service }) else {
            fail("Setup is not available on this device. Check that you chose the right device and that setup is open."); return
        }
        peripheral.discoverCharacteristics([Self.rx, Self.tx], for: service)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard self.peripheral === peripheral, stage == .discovering else { return }
        guard error == nil,
              let rx = service.characteristics?.first(where: { $0.uuid == Self.rx }), rx.properties.contains(.write),
              let tx = service.characteristics?.first(where: { $0.uuid == Self.tx }), tx.properties.contains(.notify) else {
            fail("This device’s Bluetooth setup service is not compatible. Check the device software and try again."); return
        }
        receiveCharacteristic = rx
        transmitCharacteristic = tx
        stage = .subscribing
        peripheral.setNotifyValue(true, for: tx)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral, characteristic === transmitCharacteristic else { return }
        guard error == nil, characteristic.isNotifying else {
            fail("Couldn’t receive device updates over Bluetooth. Keep the device nearby and try again."); return
        }
        guard stage == .subscribing else { return }
        stage = .challenge
        status = "Checking the device against your setup QR…"
        armTimeout(seconds: 25, message: "The device did not finish verification. Check the QR and keep the device nearby, then try again.")
        requestedPacketSize = min(185, max(20, peripheral.maximumWriteValueLength(for: .withoutResponse)))
        do {
            try enqueue(ProvisioningWire.encode(["type": "challenge_request", "version": 3, "packet_size": requestedPacketSize]), packetSize: 20)
        } catch { fail(ProvisioningError.invalidMessage.localizedDescription) }
    }

    private func enqueue(_ message: Data, packetSize: Int) throws {
        outgoing.append(contentsOf: try FrameDecoder.packets(for: message, packetSize: packetSize))
        writeNext()
    }

    private func writeNext() {
        guard !writing, nextPacket < outgoing.count, let peripheral, let receiveCharacteristic else { return }
        writing = true
        peripheral.writeValue(outgoing[nextPacket], for: receiveCharacteristic, type: .withResponse)
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral, characteristic === receiveCharacteristic, writing else { return }
        guard error == nil else { fail("A Bluetooth write failed. Reconnect and retry."); return }
        writing = false
        nextPacket += 1
        if nextPacket == outgoing.count {
            outgoing.removeAll(keepingCapacity: true)
            nextPacket = 0
        }
        writeNext()
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard self.peripheral === peripheral, characteristic === transmitCharacteristic else { return }
        guard error == nil, let packet = characteristic.value else {
            fail("A Bluetooth notification failed. Reconnect and retry."); return
        }
        do {
            guard let message = try decoder.receive(packet) else { return }
            let object = try ProvisioningWire.object(message)
            if object["type"] as? String == "error" { throw ProvisioningError.unverifiedRejection }
            switch stage {
            case .challenge:
                guard let identity, let command else { throw ProvisioningError.invalidMessage }
                let newAttempt = try ProvisioningAttempt(identity: identity, command: command, challengeMessage: message,
                                                  requestedPacketSize: requestedPacketSize)
                attempt = newAttempt
                stage = .reply
                status = "Sending your request securely…"
                let duration: Double
                switch command {
                case .configure: duration = 150
                case .scan: duration = 45
                default: duration = 25
                }
                armTimeout(seconds: duration, message: "No verified result arrived in time. This does not mean the password is wrong. A Join may still be running; check device status before trying again.")
                self.command = nil
                try enqueue(newAttempt.request, packetSize: newAttempt.packetSize)
            case .reply:
                guard var currentAttempt = attempt else { throw ProvisioningError.invalidMessage }
                let reply = try currentAttempt.authenticate(reply: message)
                attempt = currentAttempt
                let profile: RememberedNetworkProfile?
                if case .connected(let network) = reply {
                    profile = networkPolicy.authenticatedSuccess(ssid: network.ssid)
                } else {
                    profile = nil
                }
                switch reply {
                case .networks, .status, .echo, .connected:
                    verifiedDeviceID = identity?.deviceID
                default: break
                }
                if reply.final { finishTransport() }
                apply(reply)
                if let profile { remember(profile) }
            default: throw ProvisioningError.invalidMessage
            }
        } catch let error as ProvisioningError {
            switch error {
            case .authentication, .unverifiedRejection:
                fail("Couldn’t verify this device with your QR. Check the physical device and its QR; no unverified reply was trusted. If you already tapped Join, check device status before retrying.")
            default:
                fail(error.localizedDescription + " If you already tapped Join, it may still be running; check device status before retrying.")
            }
        } catch {
            fail("Couldn’t verify the device’s reply. Check the device and QR. If you already tapped Join, it may still be running; check device status before retrying.")
        }
    }

    private func apply(_ reply: AuthenticatedReply) {
        failure = false
        switch reply {
        case .echo(let text):
            verifiedEcho = text
            status = "Device verified. Your test message came back unchanged."
        case .scanning:
            status = "Device verified. Looking for Wi-Fi networks…"
        case .networks(let interface, let rows, let truncated):
            networks = rows
            scanInterface = interface
            scanTruncated = truncated
            status = "Device verified. Choose a network below."
        case .progress(let event, let ssid):
            switch event {
            case "connecting": status = "Joining \(ssid)…"
            case "obtaining_ip": status = "Getting a network address on \(ssid)…"
            default: status = "Saving the connection to \(ssid)…"
            }
        case .connected(let network):
            connectedNetwork = network
            status = "Connected to \(network.ssid). The device has a network address and saved its setup."
        case .status(let provisioned, let setupAllowed, let network):
            deviceStatus = "Provisioned: \(provisioned ? "yes" : "no") · Setup allowed: \(setupAllowed ? "yes" : "no")"
            statusNetwork = network
            status = "Device verified. Current status received."
        case .error(let code, let message):
            failure = true
            diagnosticDetail = "Authenticated device error [\(code)]: \(message)"
            status = "The device could not complete this step. Check Help & diagnostics for its report before trying again."
            if code == "backend_unavailable" {
                status = "Wi-Fi setup is unavailable. Ask support to check the device’s network service."
                diagnosticDetail = "Authenticated device error [\(code)]: \(message). Wi-Fi setup requires the Linux service with NetworkManager; macOS supports diagnostics only."
            }
        }
    }
}
