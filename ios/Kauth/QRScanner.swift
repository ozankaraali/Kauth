import SwiftUI
import AVFoundation
import UIKit

struct QRScanner: UIViewControllerRepresentable {
    let onResult: (Result<String, Error>) -> Void

    func makeUIViewController(context: Context) -> QRScannerController {
        QRScannerController(onResult: onResult)
    }

    func updateUIViewController(_ controller: QRScannerController, context: Context) {}

    static func dismantleUIViewController(_ controller: QRScannerController, coordinator: ()) {
        controller.stop()
    }
}

private struct ScannerError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

final class QRScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let onResult: (Result<String, Error>) -> Void
    private let session = AVCaptureSession()
    private let captureQueue = DispatchQueue(label: "com.ozankaraali.Kauth.camera")
    private var preview: AVCaptureVideoPreviewLayer?
    private var active = false
    private var completed = false
    private var observers: [NSObjectProtocol] = []

    init(onResult: @escaping (Result<String, Error>) -> Void) {
        self.onResult = onResult
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { nil }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)
        self.preview = preview
        for name in [Notification.Name.AVCaptureSessionRuntimeError, .AVCaptureSessionWasInterrupted] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: session, queue: .main) { [weak self] _ in
                self?.fail("Camera capture was interrupted. Close the scanner and try again, or paste the QR JSON.")
            })
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
        if let connection = preview?.connection, connection.isVideoRotationAngleSupported(90) {
            connection.videoRotationAngle = 90
        }
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        active = true
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: configure()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    guard let self, self.active else { return }
                    if granted { self.configure() }
                    else { self.fail("Camera permission is denied. Enable it in Settings → Privacy & Security → Camera, or paste the QR JSON.") }
                }
            }
        case .denied, .restricted:
            fail("Camera access is unavailable. Enable permission in Settings → Privacy & Security → Camera, or paste the QR JSON.")
        @unknown default: fail("Camera access is unavailable. Paste the QR JSON instead.")
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        stop()
    }

    func stop() {
        active = false
        captureQueue.async { [session] in
            if session.isRunning { session.stopRunning() }
        }
    }

    private func configure() {
        captureQueue.async { [weak self] in
            guard let self else { return }
            do {
                if self.session.inputs.isEmpty {
                    guard let camera = AVCaptureDevice.default(for: .video) else {
                        throw ScannerError(message: "No camera is available. Use a physical iPhone or paste the QR JSON.")
                    }
                    let input = try AVCaptureDeviceInput(device: camera)
                    let output = AVCaptureMetadataOutput()
                    self.session.beginConfiguration()
                    defer { self.session.commitConfiguration() }
                    guard self.session.canAddInput(input) else {
                        throw ScannerError(message: "The camera could not be opened. Close other camera apps or paste the QR JSON.")
                    }
                    self.session.addInput(input)
                    guard self.session.canAddOutput(output) else {
                        throw ScannerError(message: "QR capture is unavailable. Paste the QR JSON instead.")
                    }
                    self.session.addOutput(output)
                    guard output.availableMetadataObjectTypes.contains(.qr) else {
                        throw ScannerError(message: "This camera cannot scan QR codes. Paste the QR JSON instead.")
                    }
                    output.setMetadataObjectsDelegate(self, queue: .main)
                    output.metadataObjectTypes = [.qr]
                }
                self.session.startRunning()
                DispatchQueue.main.async { self.view.setNeedsLayout() }
            } catch {
                DispatchQueue.main.async { self.fail((error as? ScannerError)?.message ?? "The camera could not start. Try again or paste the QR JSON.") }
            }
        }
    }

    private func fail(_ message: String) {
        guard active, !completed else { return }
        completed = true
        stop()
        onResult(.failure(ScannerError(message: message)))
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard active, !completed,
              let code = metadataObjects.compactMap({ $0 as? AVMetadataMachineReadableCodeObject }).first(where: { $0.type == .qr }),
              let value = code.stringValue else { return }
        completed = true
        stop()
        onResult(.success(value))
    }

    deinit {
        observers.forEach { NotificationCenter.default.removeObserver($0) }
    }
}
