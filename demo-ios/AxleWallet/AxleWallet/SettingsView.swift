import SwiftUI

/// The Settings tab — Wallet facts, Proximity sharing preferences, and developer tools (Debug log, Reset).
/// A 1:1 port of android `SettingsScreen`, with the same sections, rows, and copy.
struct SettingsView: View {
    @Environment(WalletModel.self) private var model
    @Environment(AppLock.self) private var appLock
    @State private var resetConfirm = false
    /// Holder BLE role for in-person present: false = peripheral-server (advertise), true = central-client (connect out).
    @AppStorage("bleCentral") private var bleCentral = false

    private var version: String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "—"
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Settings").font(WalletFont.titleLarge).foregroundStyle(WalletTheme.ink)

                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel("Wallet")
                        WalletCard(padding: .flush) {
                            valueRow("Security hardware", "Secure Enclave")
                            divider
                            valueRow("Trusted list", "Synced")
                            divider
                            valueRow("Version", version)
                        }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel("Proximity sharing")
                        WalletCard(padding: .flush) {
                            choiceRow("Bluetooth role", ["Peripheral", "Central"], bleCentral ? 1 : 0) { bleCentral = $0 == 1 }
                        }
                        Text("Peripheral advertises and lets the reader connect (widest compatibility). Central makes this device connect out to the reader instead.")
                            .font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        SectionLabel("Developer")
                        WalletCard(padding: .flush) {
                            NavigationLink { DebugView() } label: {
                                navRow("Debug log")
                            }
                            .buttonStyle(.plain)
                            divider
                            Button { resetConfirm = true } label: {
                                actionRow("Reset wallet", tint: WalletTheme.danger)
                            }
                            .buttonStyle(.plain)
                        }
                        Text("Reset erases all credentials and activity from this device. You can be issued new documents afterwards.")
                            .font(WalletFont.bodySmall).foregroundStyle(WalletTheme.inkMuted)
                    }
                }
                .padding(.horizontal, 20).padding(.top, 16).padding(.bottom, 24)
            }
            .walletScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
            .alert("Reset wallet?", isPresented: $resetConfirm) {
                Button("Reset", role: .destructive) {
                    Task { await model.reset() }
                    appLock.reset() // clear the PIN/biometric and drop back to onboarding
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This erases all credentials, transaction history, and your PIN. You'll set the wallet up again.")
            }
        }
    }

    // MARK: - Rows (android ValueRow / ChoiceRow / NavRow / ActionRow)

    private var divider: some View { Rectangle().fill(WalletTheme.divider).frame(height: 1) }

    private func valueRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).font(WalletFont.bodyLarge).foregroundStyle(WalletTheme.ink)
            Spacer()
            Text(value).font(WalletFont.bodyMedium).foregroundStyle(WalletTheme.inkMuted)
        }
        .padding(.horizontal, 16).padding(.vertical, 15)
    }

    private func navRow(_ label: String) -> some View {
        HStack {
            Text(label).font(WalletFont.bodyLarge).foregroundStyle(WalletTheme.ink)
            Spacer()
            Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(WalletTheme.inkFaint)
        }
        .padding(.horizontal, 16).padding(.vertical, 15)
        .contentShape(Rectangle())
    }

    private func actionRow(_ label: String, tint: Color) -> some View {
        HStack {
            Text(label).font(WalletFont.bodyLarge).foregroundStyle(tint)
            Spacer()
        }
        .padding(.horizontal, 16).padding(.vertical, 15)
        .contentShape(Rectangle())
    }

    private func choiceRow(_ label: String, _ options: [String], _ selected: Int, _ onSelect: @escaping (Int) -> Void) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(label).font(WalletFont.bodyLarge).foregroundStyle(WalletTheme.ink)
            HStack(spacing: 8) {
                ForEach(Array(options.enumerated()), id: \.offset) { i, option in
                    let on = i == selected
                    Button { onSelect(i) } label: {
                        Text(option)
                            .font(WalletFont.labelMedium)
                            .foregroundStyle(on ? .white : WalletTheme.inkBody)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 9)
                            .background(on ? WalletTheme.brand : WalletTheme.screen, in: RoundedRectangle(cornerRadius: 10))
                            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(on ? WalletTheme.brand : WalletTheme.cardBorderStrong, lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }
}
