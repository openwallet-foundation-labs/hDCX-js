import AppleProximity
import Foundation
import SwiftUI
import Wallet
import WalletAPI // ProximityTransport

/// Reader/verifier-side ISO 18013-5 proximity — the iOS counterpart of android `ProximityReaderScreen`.
/// Scans the holder's QR DeviceEngagement, connects over BLE as the central, requests the PID elements, and
/// renders the verified result. Brand palette + Manrope.
struct ReaderView: View {
    let onClose: () -> Void

    private let wallet = DemoWallet.shared
    @State private var phase: Phase = .idle
    @State private var showScanner = false
    @State private var results: [ReaderResultDoc] = []
    @State private var errorMessage: String?
    @State private var transport: (any ProximityTransport)?

    enum Phase { case idle, connecting, reading, results, failed }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                CircleIconButton(system: "xmark") { close() }
                Text("Reader").font(WalletFont.titleMedium).foregroundStyle(WalletTheme.ink)
                Spacer()
            }
            Spacer().frame(height: 12)
            content.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(WalletTheme.screen.ignoresSafeArea())
        .sheet(isPresented: $showScanner) {
            ScannerSheet { scanned in Task { await read(scanned) } }
        }
    }

    @ViewBuilder private var content: some View {
        switch phase {
        case .idle:
            idleStep
        case .connecting:
            FlowLoading(title: "Connecting…", subtitle: "Pairing with the wallet over Bluetooth.")
        case .reading:
            FlowLoading(title: "Reading…", subtitle: "Requesting and verifying the document.")
        case .results:
            resultsStep
        case .failed:
            FlowResult(kind: .failure, title: "Couldn't read", subtitle: errorMessage ?? "The read failed.", buttonTitle: "Try again", onButton: { phase = .idle })
        }
    }

    private var idleStep: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "qrcode.viewfinder").font(.system(size: 56)).foregroundStyle(WalletTheme.brand)
            Text("Scan a wallet's code").font(WalletFont.titleMedium).foregroundStyle(WalletTheme.ink)
            Text("Ask the holder to show their in-person sharing QR, then scan it to read and verify their document.")
                .font(WalletFont.bodyMedium).foregroundStyle(WalletTheme.inkMuted).multilineTextAlignment(.center)
            Spacer()
            PrimaryButton(title: "Scan holder QR") { showScanner = true }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var resultsStep: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(Array(results.enumerated()), id: \.offset) { _, doc in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(prettyConfig(doc.docType)).font(WalletFont.titleSmall).foregroundStyle(WalletTheme.ink)
                                Spacer()
                                TrustPill(trusted: doc.deviceAuthenticated, trustedText: "Verified", untrustedText: "Unverified")
                            }
                            WalletCard(padding: .flush) {
                                if doc.claims.isEmpty {
                                    WalletInfoRow(label: "Claims", value: "—")
                                } else {
                                    ForEach(Array(doc.claims.enumerated()), id: \.offset) { _, claim in
                                        WalletInfoRow(label: label(claim.element), value: claim.value)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            SecondaryButton(title: "Scan another") { phase = .idle; results = [] }
                .padding(.top, 12)
        }
    }

    private func label(_ element: String) -> String {
        let spaced = element.replacingOccurrences(of: "_", with: " ")
        return spaced.prefix(1).uppercased() + spaced.dropFirst()
    }

    // MARK: - Behavior

    private func read(_ scanned: String) async {
        guard let engagement = Self.decodeEngagement(scanned) else {
            errorMessage = "That QR isn't an in-person sharing code."
            phase = .failed
            return
        }
        phase = .connecting
        do {
            let t = try await makeReaderTransport(engagement)
            transport = t
            phase = .reading
            let verified = try await wallet.reader.read(transport: t, engagement: engagement, documents: MdocReaderRequests.pid())
            results = MdocReaderRequests.flatten(verified)
            phase = .results
        } catch {
            errorMessage = String(describing: error)
            phase = .failed
        }
        if let transport { await transport.close(); self.transport = nil }
    }

    /// Peripheral-server holder → this reader is the central (connects out). Central-client holder → this
    /// reader is the peripheral (advertises + exposes Ident). Picked from the scanned engagement's BLE mode.
    private func makeReaderTransport(_ engagement: [UInt8]) async throws -> any ProximityTransport {
        if let central = try? BleCentralTransport.reader(engagement: engagement, logger: bleLogger) {
            return central
        }
        let peripheral = try BlePeripheralTransport.reader(engagement: engagement, logger: bleLogger)
        try await peripheral.start()
        return peripheral
    }

    private var bleLogger: @Sendable (String) -> Void {
        { m in Task { @MainActor in LogStore.shared.log("BLE ▸ \(m)") } }
    }

    private func close() {
        if let transport { Task { await transport.close() } }
        onClose()
    }

    /// Parses an ISO 18013-5 `mdoc:`-prefixed QR into the DeviceEngagement bytes (base64url).
    private static func decodeEngagement(_ qr: String) -> [UInt8]? {
        guard qr.hasPrefix("mdoc:") else { return nil }
        var b64 = String(qr.dropFirst("mdoc:".count))
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64.append("=") }
        guard let data = Data(base64Encoded: b64) else { return nil }
        return [UInt8](data)
    }
}
