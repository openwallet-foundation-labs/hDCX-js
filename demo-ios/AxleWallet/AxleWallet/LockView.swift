import SwiftUI

/// The app-lock screen — enter the 6-digit PIN or unlock with Face ID / Touch ID. Mirrors android
/// `LockScreen`: biometric is offered immediately when enabled, with the PIN pad as the fallback.
struct LockView: View {
    let onUnlock: () -> Void

    @State private var pin = ""
    @State private var error = false
    private let canBiometric = WalletSecurity.biometricEnabled && BiometricAuth.canUse()

    var body: some View {
        ZStack {
            WalletTheme.screen.ignoresSafeArea()
            VStack(spacing: 0) {
                Text("★").font(WalletFont.titleMedium).foregroundStyle(WalletTheme.gold)
                    .frame(width: 64, height: 64)
                    .background(LinearGradient(colors: DocGradients.pid, startPoint: .topLeading, endPoint: .bottomTrailing),
                                in: RoundedRectangle(cornerRadius: 18))
                Spacer().frame(height: 20)
                Text("Enter your PIN").font(WalletFont.titleMedium).foregroundStyle(WalletTheme.ink)
                Spacer().frame(height: 8)
                Text(error ? "Wrong PIN — try again." : "Unlock your wallet to continue.")
                    .font(WalletFont.bodyMedium).foregroundStyle(error ? WalletTheme.danger : WalletTheme.inkMuted)
                    .multilineTextAlignment(.center)
                Spacer().frame(height: 28)
                PinDots(filled: pin.count, error: error)
                Spacer().frame(height: 40)
                Keypad(
                    onDigit: { if pin.count < 6 { pin += $0 } },
                    onDelete: { pin = String(pin.dropLast()) },
                    onBiometric: canBiometric ? { promptBiometric() } : nil
                )
            }
            .padding(24)
        }
        .onAppear { if canBiometric { promptBiometric() } }
        .onChange(of: pin) { _, newPin in if newPin.count == 6 { verify() } }
    }

    private func promptBiometric() {
        BiometricAuth.prompt(reason: "Unlock your wallet", onSuccess: onUnlock)
    }

    private func verify() {
        if WalletSecurity.verifyPin(pin) {
            onUnlock()
        } else {
            error = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.65) { pin = ""; error = false }
        }
    }
}
