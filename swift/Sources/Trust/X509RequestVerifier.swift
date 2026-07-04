import Foundation
import OpenID4VP
import SdJwt

/// Verifies an OpenID4VP signed request object (OpenID4VP §5.10): the JWS signature against the
/// x5c leaf key, the certificate chain to a trust anchor, and the client_id scheme —
/// `x509_san_dns` (leaf SAN dNSName == client_id host) or `x509_hash`
/// (base64url(SHA-256(leaf DER)) == client_id value). The live EUDI verifier uses `x509_hash`.
public struct X509RequestVerifier: RequestTrustVerifier {
    private let validator: X509ChainValidator

    public init(validator: X509ChainValidator) {
        self.validator = validator
    }

    public func verifyRequestObject(_ jws: Jws, clientId: String, scheme: String) async throws -> VerifierInfo {
        guard let x5c = jws.x5c else { throw VpError.verifierNotTrusted("x509 request without x5c") }
        let chain = try await validator.validate(x5c) // throws if chain not trusted
        let leaf = chain[0]

        guard case let .str(algName)? = jws.header["alg"], let alg = signingAlgorithmFromJwsName(algName) else {
            throw VpError.invalidRequest("unsupported request alg")
        }
        guard jws.verify(key: try X509Support.ecPublicKey(leaf), expected: alg) else {
            throw VpError.verifierNotTrusted("request signature invalid")
        }

        switch scheme {
        case "x509_san_dns":
            let expected = clientId.hasPrefix("x509_san_dns:") ? String(clientId.dropFirst("x509_san_dns:".count)) : clientId
            guard X509Support.dnsNames(leaf).contains(where: { $0.caseInsensitiveCompare(expected) == .orderedSame }) else {
                throw VpError.verifierNotTrusted("client_id '\(expected)' not in certificate SAN dNSName")
            }
        case "x509_hash":
            let expected = clientId.hasPrefix("x509_hash:") ? String(clientId.dropFirst("x509_hash:".count)) : clientId
            guard try X509Support.sha256Thumbprint(leaf) == expected else {
                throw VpError.verifierNotTrusted("client_id hash does not match the certificate")
            }
        default:
            throw VpError.unsupported("client_id scheme '\(scheme)' for x509 verification")
        }

        return VerifierInfo(
            clientId: clientId, clientIdScheme: scheme,
            certificateChainDer: try chain.map { try X509Support.der($0) },
            commonName: X509Support.commonName(leaf), trusted: true
        )
    }
}
