import Foundation
import OpenID4VCI
import SdJwt

/// Verifies signed Credential Issuer Metadata (OpenID4VCI §12.2.3): resolves the signer's key from the
/// JWS `x5c` header and validates that chain to a trust anchor. The spec leaves "establish trust in the
/// signer" out of scope; this is the x5c form, and how the EUDI reference issuer signs — a leaf chaining
/// to `PID Issuer CA`. The `typ` / `alg` / `sub` / `iat` / `exp` rules are enforced by `Openid4VciClient`.
public struct X5cSignedMetadataVerifier: SignedMetadataVerifier {
    private let validator: X509ChainValidator

    public init(validator: X509ChainValidator) {
        self.validator = validator
    }

    public func verify(signedMetadataJws: String) async throws -> JsonValue {
        let jws = try Jws.parse(signedMetadataJws)
        guard case let .arr(items)? = jws.header["x5c"] else {
            throw TrustError("signed metadata JWS has no x5c header")
        }
        let chainDer: [[UInt8]] = try items.map {
            guard case let .str(b64) = $0, let data = Data(base64Encoded: b64) else {
                throw TrustError("x5c entries must be base64 strings")
            }
            return [UInt8](data)
        }

        let leaf = try await validator.validate(chainDer)[0] // throws if the chain does not reach an anchor
        guard jws.verify(key: try X509Support.ecPublicKey(leaf), expected: try X509Support.signingAlgorithm(leaf)) else {
            throw TrustError("signed metadata signature invalid")
        }
        let payload = try JsonValue.parse(try Base64Url.decodeToString(jws.payloadB64))
        guard case .obj = payload else { throw TrustError("signed metadata payload is not a JSON object") }
        return payload
    }
}
