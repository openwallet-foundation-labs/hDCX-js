import Foundation
import SdJwt
import WalletAPI

/// Format-agnostic credential view, assembled from the storage envelope.
public struct Credential {
    public let id: CredentialId
    public let format: CredentialFormat
    public let lifecycle: Lifecycle
    public let issuer: IssuerInfo?
    public let display: CredentialDisplay?
    public let configurationId: String?
    public let createdAt: Date
}

/// Where the credential came from (captured from issuer metadata at issuance).
public struct IssuerInfo { public let url: String; public let displayName: String? }

/// Display metadata for a credential type (issuer-metadata derived).
public struct CredentialDisplay {
    public let name: String?
    public let logoUri: String?
    public let backgroundColor: String?
}

public enum Lifecycle {
    case issued(claims: [Claim], validity: ValidityInfo?, instances: CredentialInstances)
    case deferred(retryAfter: Date?)
    case pending(authorizationUrl: String?)
}

/// A disclosed claim, path-addressed (namespace+element for mdoc, JSON path for SD-JWT VC).
public struct Claim { public let path: [String]; public let value: ClaimValue }

/// A claim value with a format-agnostic rendering.
public struct ClaimValue {
    let json: JsonValue // internal — not exposed in the public signature
    public func display() -> String {
        switch json {
        case let .str(s): return s
        case let .numInt(n): return String(n)
        case let .numDouble(d): return String(d)
        case let .bool(b): return String(b)
        case .null: return ""
        default: return json.serialize()
        }
    }
}

public struct ValidityInfo { public let validFrom: Date?; public let validUntil: Date? }

/// Batch instance accounting (HAIP one-time-use / rotate).
public struct CredentialInstances { public let remaining: Int; public let use: KeyUse }
