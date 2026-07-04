import CborCose
import Foundation
import WalletAPI

public struct SdJwtVcError: Error, CustomStringConvertible {
    public let description: String

    init(_ description: String) {
        self.description = description
    }
}

/// Resolved issuer signing key (SD-JWT VC §3.5).
public struct IssuerSigningKey {
    public let publicKey: EcPublicKey
    public let algorithm: SigningAlgorithm

    public init(publicKey: EcPublicKey, algorithm: SigningAlgorithm) {
        self.publicKey = publicKey
        self.algorithm = algorithm
    }
}

/// Resolves the issuer key for an SD-JWT VC from its `iss` and JWS header.
/// Implementations: metadata (.well-known/jwt-vc-issuer), x509 (trust module, M3), or pinned.
public protocol IssuerKeyResolver: Sendable {
    func resolve(iss: String, header: JsonValue) async throws -> IssuerSigningKey
}

/// A verified SD-JWT VC: profile-validated claims plus the fields callers act on.
public struct VerifiedSdJwtVc {
    public let vct: String
    public let issuer: String
    public let claims: JsonValue
    public let holderKey: EcPublicKey?
    /// Status list reference (`status.status_list`) if present, for the status module.
    public let status: JsonValue?
    public let disclosedPaths: [String: [String]]
}

/// SD-JWT VC verifier (draft-ietf-oauth-sd-jwt-vc): the profile layer over RFC 9901.
///
/// Enforces: `typ` ∈ {dc+sd-jwt, vc+sd-jwt}; required `iss` and `vct`; time claims
/// (iat/exp/nbf) via `JwtTimeValidator`; issuer key resolution via `IssuerKeyResolver`;
/// optional holder key binding. Fail-closed throughout.
public struct SdJwtVcVerifier {
    // draft-ietf-oauth-sd-jwt-vc §3.1: typ MUST be dc+sd-jwt. (vc+sd-jwt was the
    // pre-2024-11 value, dropped over a conflict with W3C's vc media type.)
    private static let requiredTyp = "dc+sd-jwt"

    private let issuerKeyResolver: any IssuerKeyResolver
    private let timeValidator: JwtTimeValidator

    public init(issuerKeyResolver: any IssuerKeyResolver, timeValidator: JwtTimeValidator) {
        self.issuerKeyResolver = issuerKeyResolver
        self.timeValidator = timeValidator
    }

    public func verify(
        _ sdJwtVc: SdJwt,
        keyBinding: SdJwtVerifier.KbRequirement? = nil
    ) async throws -> VerifiedSdJwtVc {
        let jws = try Jws.parse(sdJwtVc.jwt)

        guard case let .str(typ)? = jws.header["typ"] else {
            throw SdJwtVcError("missing 'typ' header")
        }
        guard typ == Self.requiredTyp else {
            throw SdJwtVcError("unexpected typ '\(typ)' for SD-JWT VC (expected \(Self.requiredTyp))")
        }

        // Peek issuer before signature verification only to resolve the key; the resolved
        // key then authenticates the payload, and iss is re-read from verified claims below.
        guard let payloadText = String(bytes: jws.payloadBytes, encoding: .utf8),
              let unverified = try? JsonValue.parse(payloadText),
              case .obj = unverified,
              case let .str(issForResolve)? = unverified["iss"]
        else { throw SdJwtVcError("missing 'iss'") }

        let issuerKey = try await issuerKeyResolver.resolve(iss: issForResolve, header: jws.header)

        let verified = try SdJwtVerifier.verify(
            sdJwtVc, issuerKey: issuerKey.publicKey, algorithm: issuerKey.algorithm, keyBinding: keyBinding
        )
        let payload = verified.payload

        guard case let .str(iss)? = payload["iss"] else {
            throw SdJwtVcError("missing 'iss' in verified payload")
        }
        guard case let .str(vct)? = payload["vct"] else {
            throw SdJwtVcError("missing 'vct'")
        }

        try timeValidator.validate(payload)

        var status: JsonValue?
        if case .obj = payload["status"] { status = payload["status"] }

        return VerifiedSdJwtVc(
            vct: vct,
            issuer: iss,
            claims: verified.claims,
            holderKey: SdJwtVerifier.holderKeyFromCnf(payload),
            status: status,
            disclosedPaths: verified.disclosedPaths
        )
    }
}

/// Resolver using the SD-JWT VC issuer metadata endpoint (draft §5):
/// `https://<host>/.well-known/jwt-vc-issuer/<path>`. Selects the JWK by `kid` header,
/// or the sole key when no `kid`. Cross-language and testable over `HttpTransport`.
public struct JwtVcMetadataKeyResolver: IssuerKeyResolver {
    private let http: any HttpTransport

    public init(http: any HttpTransport) {
        self.http = http
    }

    public func resolve(iss: String, header: JsonValue) async throws -> IssuerSigningKey {
        let metadata = try await fetchJson(metadataUrl(iss))
        guard case let .str(metaIssuer)? = metadata["issuer"], metaIssuer == iss else {
            throw SdJwtVcError("issuer metadata 'issuer' does not match '\(iss)'")
        }

        let jwks: JsonValue
        if case .obj = metadata["jwks"] {
            jwks = metadata["jwks"]!
        } else if case let .str(uri)? = metadata["jwks_uri"] {
            jwks = try await fetchJson(uri)
        } else {
            throw SdJwtVcError("issuer metadata has neither jwks nor jwks_uri")
        }

        guard case let .arr(keys)? = jwks["keys"] else { throw SdJwtVcError("jwks.keys missing") }

        let jwk: JsonValue
        if case let .str(kid)? = header["kid"] {
            guard let match = keys.first(where: {
                if case let .str(k)? = $0["kid"] { return k == kid }
                return false
            }) else { throw SdJwtVcError("no JWK with kid '\(kid)'") }
            jwk = match
        } else if keys.count == 1 {
            jwk = keys[0]
        } else {
            throw SdJwtVcError("multiple JWKs but no kid in header")
        }

        guard let publicKey = JwkEc.fromJson(jwk) else {
            throw SdJwtVcError("issuer JWK is not a supported EC key")
        }
        var algorithm = defaultAlg(publicKey.curve)
        if case let .str(alg)? = jwk["alg"], let parsed = signingAlgorithmFromJwsName(alg) {
            algorithm = parsed
        }
        return IssuerSigningKey(publicKey: publicKey, algorithm: algorithm)
    }

    private func defaultAlg(_ curve: EcCurve) -> SigningAlgorithm {
        switch curve {
        case .p256: return .es256
        case .p384: return .es384
        case .p521: return .es512
        }
    }

    private func fetchJson(_ url: String) async throws -> JsonValue {
        let response = try await http.execute(HttpRequest(method: .get, url: url, headers: [("Accept", "application/json")]))
        guard (200...299).contains(response.status) else {
            throw SdJwtVcError("GET \(url) failed: HTTP \(response.status)")
        }
        guard let text = String(bytes: response.body, encoding: .utf8),
              let json = try? JsonValue.parse(text), case .obj = json
        else { throw SdJwtVcError("\(url) did not return a JSON object") }
        return json
    }

    private func metadataUrl(_ iss: String) throws -> String {
        guard iss.hasPrefix("https://") else { throw SdJwtVcError("issuer must be https") }
        let rest = String(iss.dropFirst("https://".count))
        if let slash = rest.firstIndex(of: "/") {
            let host = rest[rest.startIndex..<slash]
            let path = rest[slash...]
            return "https://\(host)/.well-known/jwt-vc-issuer\(path)"
        }
        return "https://\(rest)/.well-known/jwt-vc-issuer"
    }
}
