import CommonCrypto
import Foundation

/// On-device secret store for the app lock — the iOS counterpart of android `WalletSecurity`. The 6-digit
/// PIN is kept only as a PBKDF2 hash (salt + hash in the Keychain, `WhenUnlockedThisDeviceOnly`); the raw
/// digits never touch disk. The onboarding / biometric flags are non-secret and live in UserDefaults.
enum WalletSecurity {
    private static let service = "com.hopae.axle.wallet.pin"
    private static let iterations: UInt32 = 120_000
    private static let onboardedKey = "wallet.onboarded"
    private static let biometricKey = "wallet.biometric"

    static var isOnboarded: Bool { UserDefaults.standard.bool(forKey: onboardedKey) }
    static var biometricEnabled: Bool { UserDefaults.standard.bool(forKey: biometricKey) }
    static func setBiometricEnabled(_ enabled: Bool) { UserDefaults.standard.set(enabled, forKey: biometricKey) }

    static func setPin(_ pin: String) {
        var salt = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt)
        keychainSet("salt", Data(salt))
        keychainSet("hash", Data(pbkdf2(pin, salt: salt)))
    }

    static func verifyPin(_ pin: String) -> Bool {
        guard let salt = keychainGet("salt"), let expected = keychainGet("hash") else { return false }
        return constantTimeEqual(Data(pbkdf2(pin, salt: [UInt8](salt))), expected)
    }

    /// Finalises first-run setup: stores the PIN, the biometric preference, and the onboarded flag.
    static func completeOnboarding(pin: String, biometric: Bool) {
        setPin(pin)
        UserDefaults.standard.set(biometric, forKey: biometricKey)
        UserDefaults.standard.set(true, forKey: onboardedKey)
    }

    /// Factory reset: clear the PIN and flags so the wallet re-onboards.
    static func reset() {
        keychainDelete("salt")
        keychainDelete("hash")
        UserDefaults.standard.removeObject(forKey: onboardedKey)
        UserDefaults.standard.removeObject(forKey: biometricKey)
    }

    // MARK: - PBKDF2 (SHA-256, 120k iterations — matches android)

    private static func pbkdf2(_ pin: String, salt: [UInt8]) -> [UInt8] {
        let password = Data(pin.utf8)
        var derived = [UInt8](repeating: 0, count: 32)
        password.withUnsafeBytes { pw in
            salt.withUnsafeBytes { sa in
                _ = CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pw.baseAddress!.assumingMemoryBound(to: Int8.self), password.count,
                    sa.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations,
                    &derived, derived.count
                )
            }
        }
        return derived
    }

    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    // MARK: - Keychain (generic password, service + account)

    private static func keychainSet(_ account: String, _ data: Data) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }

    private static func keychainGet(_ account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    private static func keychainDelete(_ account: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ] as CFDictionary)
    }
}
