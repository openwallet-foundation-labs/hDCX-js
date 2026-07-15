import SwiftUI

/// First-run setup — Welcome → Create PIN → Confirm PIN → (Face ID) → Done. A 1:1 mirror of android
/// `OnboardingScreen`: the 6-digit PIN is stored as a PBKDF2 hash, then optional biometric unlock.
struct OnboardingView: View {
    let onDone: () -> Void

    @State private var step: Step = .welcome
    @State private var firstPin = ""
    @State private var pin = ""
    @State private var error = false
    private let canBiometric = BiometricAuth.canUse()

    enum Step { case welcome, createPin, confirmPin, biometric, done }

    var body: some View {
        ZStack {
            WalletTheme.screen.ignoresSafeArea()
            content.padding(24)
        }
        .onChange(of: pin) { _, newPin in if newPin.count == 6 { handlePinComplete() } }
    }

    @ViewBuilder private var content: some View {
        switch step {
        case .welcome:
            welcome
        case .createPin:
            pinStep(title: "Create a wallet PIN", subtitle: "You'll use this 6-digit PIN to unlock your wallet.")
        case .confirmPin:
            pinStep(title: "Confirm your PIN",
                    subtitle: error ? "PINs didn't match — try again." : "Re-enter the PIN to confirm.")
        case .biometric:
            biometricStep
        case .done:
            doneStep
        }
    }

    private var welcome: some View {
        VStack(spacing: 0) {
            starTile(size: 76, corner: 22, font: WalletFont.titleLarge)
            Spacer().frame(height: 24)
            Text("Axle Wallet").font(WalletFont.titleLarge).foregroundStyle(WalletTheme.ink)
            Spacer().frame(height: 8)
            Text("eIDAS 2.0 EU Digital Identity Wallet")
                .font(WalletFont.bodyMedium).foregroundStyle(WalletTheme.inkMuted)
                .multilineTextAlignment(.center).frame(maxWidth: 320)
            Spacer().frame(height: 36)
            PrimaryButton(title: "Get started") { step = .createPin }.frame(maxWidth: 320)
        }
    }

    private func pinStep(title: String, subtitle: String) -> some View {
        VStack(spacing: 0) {
            Text(title).font(WalletFont.titleMedium).foregroundStyle(WalletTheme.ink)
            Spacer().frame(height: 8)
            Text(subtitle).font(WalletFont.bodyMedium).foregroundStyle(error ? WalletTheme.danger : WalletTheme.inkMuted)
                .multilineTextAlignment(.center).frame(maxWidth: 300)
            Spacer().frame(height: 28)
            PinDots(filled: pin.count, error: error)
            Spacer().frame(height: 40)
            Keypad(onDigit: { if pin.count < 6 { pin += $0 } }, onDelete: { pin = String(pin.dropLast()) })
        }
    }

    private var biometricStep: some View {
        VStack(spacing: 0) {
            Image(systemName: "faceid").font(.system(size: 38)).foregroundStyle(WalletTheme.brand)
                .frame(width: 76, height: 76).background(WalletTheme.brandSoftBg, in: Circle())
            Spacer().frame(height: 24)
            Text("Unlock with \(BiometricAuth.label())").font(WalletFont.titleMedium).foregroundStyle(WalletTheme.ink)
            Spacer().frame(height: 8)
            Text("Use \(BiometricAuth.label()) to unlock your wallet instead of typing your PIN each time.")
                .font(WalletFont.bodyMedium).foregroundStyle(WalletTheme.inkMuted)
                .multilineTextAlignment(.center).frame(maxWidth: 320)
            Spacer().frame(height: 36)
            PrimaryButton(title: "Enable \(BiometricAuth.label())") {
                BiometricAuth.prompt(reason: "Confirm to enable biometric unlock", onSuccess: { finish(biometric: true) })
            }.frame(maxWidth: 320)
            Spacer().frame(height: 10)
            SecondaryButton(title: "Not now") { finish(biometric: false) }.frame(maxWidth: 320)
        }
    }

    private var doneStep: some View {
        VStack(spacing: 0) {
            Image(systemName: "checkmark").font(.system(size: 40, weight: .bold)).foregroundStyle(WalletTheme.trust)
                .frame(width: 84, height: 84).background(WalletTheme.trustBg, in: Circle())
            Spacer().frame(height: 24)
            Text("Your wallet is ready").font(WalletFont.titleLarge).foregroundStyle(WalletTheme.ink)
            Spacer().frame(height: 12)
            Text("Keys are protected by this device's secure hardware.")
                .font(WalletFont.bodyMedium).foregroundStyle(WalletTheme.inkMuted)
                .multilineTextAlignment(.center).frame(maxWidth: 300)
            Spacer().frame(height: 36)
            PrimaryButton(title: "Enter wallet", action: onDone).frame(maxWidth: 320)
        }
    }

    private func starTile(size: CGFloat, corner: CGFloat, font: Font) -> some View {
        Text("★").font(font).foregroundStyle(WalletTheme.gold)
            .frame(width: size, height: size)
            .background(LinearGradient(colors: DocGradients.pid, startPoint: .topLeading, endPoint: .bottomTrailing),
                        in: RoundedRectangle(cornerRadius: corner))
    }

    private func handlePinComplete() {
        switch step {
        case .createPin:
            firstPin = pin
            after(0.14) { pin = ""; step = .confirmPin }
        case .confirmPin:
            if pin == firstPin {
                after(0.12) { if canBiometric { step = .biometric } else { finish(biometric: false) } }
            } else {
                error = true
                after(0.65) { pin = ""; error = false }
            }
        default:
            break
        }
    }

    private func finish(biometric: Bool) {
        WalletSecurity.completeOnboarding(pin: firstPin, biometric: biometric)
        step = .done
    }

    private func after(_ seconds: Double, _ body: @escaping () -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: body)
    }
}
