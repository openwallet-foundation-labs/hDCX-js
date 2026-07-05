import CborCose
import Foundation

/*
 * Shared value types for the port SPI.
 * Naming is the cross-platform contract: Kotlin mirrors these 1:1.
 */

public struct SecureAreaId: Hashable, Sendable {
    public let value: String

    public init(_ value: String) {
        self.value = value
    }

    public static let `default` = SecureAreaId("default")
}

public enum SigningAlgorithm: Hashable, Sendable {
    case es256, es384, es512
}

/// Opaque reference to a key inside a specific secure area.
public struct KeyHandle: Hashable, Sendable {
    public let secureArea: SecureAreaId
    public let alias: String

    public init(secureArea: SecureAreaId, alias: String) {
        self.secureArea = secureArea
        self.alias = alias
    }
}

public enum UserAuthPolicy: Equatable, Sendable {
    case notRequired
    case required(timeout: TimeInterval?)
}

public enum HardwarePolicy: Sendable {
    case preferred, required, software
}

public struct KeySpec: Sendable {
    public let secureArea: SecureAreaId
    public let algorithm: SigningAlgorithm
    public let userAuthentication: UserAuthPolicy
    public let hardware: HardwarePolicy
    public let attestationChallenge: [UInt8]?

    public init(
        secureArea: SecureAreaId = .default,
        algorithm: SigningAlgorithm = .es256,
        userAuthentication: UserAuthPolicy = .notRequired,
        hardware: HardwarePolicy = .preferred,
        attestationChallenge: [UInt8]? = nil
    ) {
        self.secureArea = secureArea
        self.algorithm = algorithm
        self.userAuthentication = userAuthentication
        self.hardware = hardware
        self.attestationChallenge = attestationChallenge
    }
}

public enum KeyUse: Sendable {
    case rotate, oneTime
}

public struct CredentialPolicy: Equatable, Sendable {
    public let batchSize: Int
    public let use: KeyUse

    public init(batchSize: Int = 1, use: KeyUse = .rotate) {
        self.batchSize = batchSize
        self.use = use
    }
}

/// Text shown by the adapter's user-auth prompt (BiometricPrompt / LAContext).
public struct AuthorizationHint: Sendable {
    public let title: String
    public let subtitle: String?

    public init(title: String, subtitle: String? = nil) {
        self.title = title
        self.subtitle = subtitle
    }
}

/// Opaque key attestation as produced by the secure area (format is adapter-specific).
public struct KeyAttestation: Sendable {
    public let format: String
    public let data: [UInt8]

    public init(format: String, data: [UInt8]) {
        self.format = format
        self.data = data
    }
}

public struct KeyInfo: Sendable {
    public let handle: KeyHandle
    public let algorithm: SigningAlgorithm
    public let publicKey: EcPublicKey

    public init(handle: KeyHandle, algorithm: SigningAlgorithm, publicKey: EcPublicKey) {
        self.handle = handle
        self.algorithm = algorithm
        self.publicKey = publicKey
    }
}

public struct SecureAreaCapabilities: Sendable {
    public let algorithms: Set<SigningAlgorithm>
    public let hardwareBacked: Bool
    public let userAuthentication: Bool
    public let keyAttestation: Bool
    public let keyAgreement: Bool

    public init(
        algorithms: Set<SigningAlgorithm>,
        hardwareBacked: Bool,
        userAuthentication: Bool,
        keyAttestation: Bool,
        keyAgreement: Bool
    ) {
        self.algorithms = algorithms
        self.hardwareBacked = hardwareBacked
        self.userAuthentication = userAuthentication
        self.keyAttestation = keyAttestation
        self.keyAgreement = keyAgreement
    }
}

/* ---- credential model identifiers ---- */

public struct CredentialId: Hashable, Sendable {
    public let value: String

    public init(_ value: String) {
        self.value = value
    }
}

public enum CredentialFormat: Hashable, Sendable {
    case msoMdoc(docType: String)
    case sdJwtVc(vct: String)
}

/* ---- algorithm mappings (SigningAlgorithm <-> COSE/curve) ---- */

public extension SigningAlgorithm {
    var curve: EcCurve {
        switch self {
        case .es256: return .p256
        case .es384: return .p384
        case .es512: return .p521
        }
    }

    var coseAlgorithm: CoseAlgorithm {
        switch self {
        case .es256: return .es256
        case .es384: return .es384
        case .es512: return .es512
        }
    }
}

/// Bridges a `SecureArea` key into the COSE layer: `CoseSign1.sign(signer:)`.
/// This is the production path — private keys never leave the port.
public struct SecureAreaCoseSigner: CoseSigner {
    private let area: any SecureArea
    private let key: KeyHandle
    private let signingAlgorithm: SigningAlgorithm
    private let hint: AuthorizationHint?

    public var algorithm: CoseAlgorithm { signingAlgorithm.coseAlgorithm }

    public init(area: any SecureArea, key: KeyHandle, algorithm: SigningAlgorithm, hint: AuthorizationHint? = nil) {
        self.area = area
        self.key = key
        self.signingAlgorithm = algorithm
        self.hint = hint
    }

    public func sign(_ toBeSigned: [UInt8]) async throws -> [UInt8] {
        try await area.sign(key: key, algorithm: signingAlgorithm, data: toBeSigned, hint: hint)
    }
}
