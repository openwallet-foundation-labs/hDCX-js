import CborCose
import Foundation

/*
 * Port SPI. Platform features are injected by the host app;
 * core stays buildable and testable on plain Linux.
 */

/// Private-key custody port. Crypto boundary rule: every operation that touches a
/// private key goes through this port; public-key verification stays in core.
///
/// Adapters: AndroidKeystore/StrongBox, SecureEnclave, SoftwareSecureArea (testkit),
/// remote WSCD/HSM later. Adapter qualification = passing the shared contract test suite.
public protocol SecureArea: Sendable {
    var id: SecureAreaId { get }
    var capabilities: SecureAreaCapabilities { get }

    /// Creates a key and returns its handle plus public key (always needed for proofs).
    func createKey(spec: KeySpec) async throws -> KeyInfo

    func publicKey(key: KeyHandle) async throws -> EcPublicKey

    /// Raw r||s signature; the adapter shows the user-auth prompt when the key requires it.
    func sign(key: KeyHandle, algorithm: SigningAlgorithm, data: [UInt8], hint: AuthorizationHint?) async throws -> [UInt8]

    /// ECDH shared secret (18013-5 session encryption, JWE ECDH-ES).
    func keyAgreement(key: KeyHandle, peerPublicKey: EcPublicKey, hint: AuthorizationHint?) async throws -> [UInt8]

    /// Nil when the area cannot attest (e.g. software area without attestation).
    func attestation(key: KeyHandle, challenge: [UInt8]) async throws -> KeyAttestation?

    func deleteKey(key: KeyHandle) async throws
}

/// Encrypted blob storage; no domain logic.
public protocol StorageDriver: Sendable {
    func put(collection: String, key: String, value: [UInt8]) async throws
    func get(collection: String, key: String) async throws -> [UInt8]?
    func delete(collection: String, key: String) async throws
    func keys(collection: String) async throws -> [String]
    func transaction(_ block: @Sendable (any StorageTx) async throws -> Void) async throws
}

public protocol StorageTx: Sendable {
    func put(collection: String, key: String, value: [UInt8]) async throws
    func get(collection: String, key: String) async throws -> [UInt8]?
    func delete(collection: String, key: String) async throws
}

public enum HttpMethod: Sendable {
    case get, post, put, patch, delete
}

public struct HttpRequest: Sendable {
    public let method: HttpMethod
    public let url: String
    public let headers: [(String, String)]
    public let body: [UInt8]?
    /// OpenID flows need redirect interception (e.g. capturing authorization responses).
    public let followRedirects: Bool

    public init(
        method: HttpMethod,
        url: String,
        headers: [(String, String)] = [],
        body: [UInt8]? = nil,
        followRedirects: Bool = true
    ) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.followRedirects = followRedirects
    }
}

public struct HttpResponse: Sendable {
    public let status: Int
    public let headers: [(String, String)]
    public let body: [UInt8]

    public init(status: Int, headers: [(String, String)], body: [UInt8]) {
        self.status = status
        self.headers = headers
        self.body = body
    }
}

public protocol HttpTransport: Sendable {
    func execute(_ request: HttpRequest) async throws -> HttpResponse
}

// ISO 18013-5 proximity transport is the ProximityTransport port (send/receive/close).

/// Wallet-provider backend port: WUA and key attestations (HAIP wallet attestation).
public protocol WalletAttestationProvider: Sendable {
    func walletAttestation(keyInfo: KeyInfo) async throws -> String
    func keyAttestation(keys: [KeyInfo], nonce: String?) async throws -> String
}

/// Injectable clock — tests pin it for deterministic validity checks.
public protocol WalletClock: Sendable {
    func now() -> Date
}

public struct SystemClock: WalletClock {
    public init() {}
    public func now() -> Date { Date() }
}

/// Injectable randomness — tests use fixed seeds for deterministic transcripts.
public protocol Rng: Sendable {
    func nextBytes(_ size: Int) -> [UInt8]
}

public struct SystemRng: Rng {
    public init() {}
    public func nextBytes(_ size: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        return (0..<size).map { _ in UInt8.random(in: .min ... .max, using: &rng) }
    }
}

public enum LogLevel: Sendable {
    case debug, info, warn, error
}

public protocol WalletLogger: Sendable {
    func log(level: LogLevel, message: String, error: Error?)
}
