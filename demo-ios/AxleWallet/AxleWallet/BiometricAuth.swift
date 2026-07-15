import Foundation
import LocalAuthentication

/// Thin wrapper over `LocalAuthentication` for the app-lock / onboarding biometric step — the iOS
/// counterpart of android `BiometricAuth`.
enum BiometricAuth {
    /// True when the device has an enrolled biometric (Face ID / Touch ID) we can prompt for.
    static func canUse() -> Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    /// Label for the device's biometric modality.
    static func label() -> String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        default: return "Biometrics"
        }
    }

    static func prompt(reason: String, onSuccess: @escaping () -> Void, onError: @escaping (String) -> Void = { _ in }) {
        let context = LAContext()
        context.localizedFallbackTitle = "Use PIN"
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
            DispatchQueue.main.async {
                if ok { onSuccess() } else { onError(error?.localizedDescription ?? "Authentication failed") }
            }
        }
    }
}
