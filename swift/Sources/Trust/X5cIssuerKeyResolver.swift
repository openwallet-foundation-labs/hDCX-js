import Foundation
import SdJwt

/// Resolves an SD-JWT VC issuer key from the JWS `x5c` header, validating the certificate chain
/// to a trust anchor. This is how the real EUDI issuer signs — an x5c leaf chaining to
/// `PID Issuer CA`, not a metadata endpoint.
public struct X5cIssuerKeyResolver: IssuerKeyResolver {
    private let validator: X509ChainValidator

    public init(validator: X509ChainValidator) {
        self.validator = validator
    }

    public func resolve(iss: String, header: JsonValue) async throws -> IssuerSigningKey {
        guard case let .arr(items)? = header["x5c"] else { throw TrustError("issuer JWS has no x5c header") }
        let chainDer: [[UInt8]] = try items.map {
            guard case let .str(b64) = $0, let data = Data(base64Encoded: b64) else {
                throw TrustError("x5c entries must be base64 strings")
            }
            return [UInt8](data)
        }
        let chain = try await validator.validate(chainDer)
        let leaf = chain[0]
        return IssuerSigningKey(publicKey: try X509Support.ecPublicKey(leaf), algorithm: try X509Support.signingAlgorithm(leaf))
    }
}
