import AppleCore
import SwiftUI
import UIKit
import Wallet
import WalletTestKit

/// The Debug log screen — a dark console over the in-app `LogStore`, with level filtering, copy/clear, and
/// the on-device adapter qualification (Secure Enclave + Keychain against the SDK contract suites). Mirrors
/// android `DebugScreen`. Pushed from Settings; uses a custom dark top bar.
struct DebugView: View {
    @Environment(\.dismiss) private var dismiss
    // The @Observable singleton; reads of `log.lines` in body are tracked by Observation.
    private let log = LogStore.shared
    @State private var filter: Level?
    @State private var testing = false

    enum Level: String, CaseIterable { case all, info, warn, error }

    private func levelOf(_ line: String) -> Level {
        if line.contains("❌") || line.contains("ERROR") { return .error }
        if line.contains("⚠") || line.contains("WARN") { return .warn }
        return .info
    }

    /// Newest first (android v0.5 "newest-first debug log").
    private var shown: [String] {
        let lines = log.lines
        let filtered = (filter == nil || filter == .all) ? lines : lines.filter { levelOf($0) == filter }
        return filtered.reversed()
    }

    var body: some View {
        VStack(spacing: 0) {
            topBar
            filterChips
            logList
        }
        .background(WalletTheme.Console.bg.ignoresSafeArea())
        .toolbar(.hidden, for: .navigationBar)
    }

    private var topBar: some View {
        HStack(spacing: 8) {
            Button { dismiss() } label: {
                Image(systemName: "chevron.left")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(WalletTheme.Console.text)
                    .frame(width: 34, height: 34)
                    .background(WalletTheme.Console.panel, in: Circle())
            }
            Text("Debug log")
                .font(.system(.subheadline, design: .monospaced))
                .foregroundStyle(WalletTheme.Console.text)
            Spacer()
            consoleAction("Test", disabled: testing) { Task { await runContractTests() } }
            consoleAction("Copy") { UIPasteboard.general.string = log.asText() }
            consoleAction("Clear") { log.clear() }
        }
        .padding(.horizontal, 12).padding(.top, 8).padding(.bottom, 8)
    }

    private var filterChips: some View {
        HStack(spacing: 6) {
            ForEach(Level.allCases, id: \.self) { level in
                let active = (filter ?? .all) == level
                Button { filter = level } label: {
                    Text(level.rawValue.uppercased())
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(active ? WalletTheme.Console.text : WalletTheme.Console.textDim)
                        .padding(.horizontal, 11).padding(.vertical, 6)
                        .background(active ? WalletTheme.Console.chipActive : WalletTheme.Console.panel,
                                    in: RoundedRectangle(cornerRadius: 8))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8)
                                .strokeBorder(active ? WalletTheme.Console.border : .clear, lineWidth: 1)
                        }
                }
                .buttonStyle(.plain)
            }
            Spacer()
        }
        .padding(.horizontal, 12).padding(.bottom, 10)
    }

    private var logList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 4) {
                ForEach(Array(shown.enumerated()), id: \.offset) { _, line in
                    Text(line)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(color(for: line))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
            }
            .padding(.horizontal, 14).padding(.bottom, 24)
        }
    }

    private func color(for line: String) -> Color {
        switch levelOf(line) {
        case .error: return WalletTheme.Console.error
        case .warn: return WalletTheme.Console.warn
        default: return WalletTheme.Console.text
        }
    }

    private func consoleAction(_ text: String, disabled: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(text)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(WalletTheme.Console.info)
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(WalletTheme.Console.panel, in: RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
        .disabled(disabled)
    }

    /// On-device adapter qualification: "adapter qualification = passing the shared contract suite."
    private func runContractTests() async {
        testing = true
        defer { testing = false }
        log.log("Running adapter contract suites…")
        do {
            try await SecureAreaContract.verify(SecureEnclaveSecureArea())
            try await StorageDriverContract.verify(KeychainStorageDriver())
            log.log("✅ Secure Enclave + Keychain adapters pass the SDK contract suites.")
        } catch {
            log.log("❌ adapter contract: \(error)")
        }
    }
}
