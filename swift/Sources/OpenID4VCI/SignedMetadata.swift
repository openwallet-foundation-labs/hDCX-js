import Foundation
import SdJwt

/// The JOSE `typ` every signed Credential Issuer Metadata JWT carries (OpenID4VCI §12.2.3).
public let signedMetadataTyp = "openidvci-issuer-metadata+jwt"

/// Proves the signature of the issuer's signed metadata JWT and establishes trust in its signer,
/// returning the verified payload claims (OpenID4VCI §12.2.3). The spec leaves key resolution and
/// trust out of scope, so the adapter reads `x5c` / `kid` / `trust_chain` and chains the key to a
/// trust anchor — keeping OpenID4VCI decoupled from the trust module. The client itself enforces
/// the spec's `typ`, `alg`, `sub`, `iat` and `exp` rules.
public protocol SignedMetadataVerifier: Sendable {
    func verify(signedMetadataJws: String) async throws -> JsonValue
}

/// How the wallet negotiates Credential Issuer Metadata (OpenID4VCI §12.2.2). The `Accept` header
/// signals whether the wallet supports signed metadata: issuers MUST be able to serve unsigned
/// `application/json` and MAY serve a signed `application/jwt`. There is no `signed_metadata` JSON
/// member — the signed form is the whole response body.
public enum IssuerMetadataPolicy {
    /// Ask for unsigned `application/json` only (default).
    case ignoreSigned
    /// Prefer signed `application/jwt`; accept unsigned JSON when the issuer does not sign.
    case preferSigned(any SignedMetadataVerifier)
    /// Require signed `application/jwt`; fail when the issuer answers with unsigned JSON.
    case requireSigned(any SignedMetadataVerifier)

    /// The `Accept` header this policy sends on the metadata GET (§12.2.2).
    var acceptHeader: String {
        switch self {
        case .ignoreSigned: return "application/json"
        case .preferSigned: return "application/jwt, application/json;q=0.9"
        case .requireSigned: return "application/jwt"
        }
    }

    var verifier: (any SignedMetadataVerifier)? {
        switch self {
        case .ignoreSigned: return nil
        case let .preferSigned(v): return v
        case let .requireSigned(v): return v
        }
    }

    var requiresSigned: Bool {
        if case .requireSigned = self { return true }
        return false
    }
}
