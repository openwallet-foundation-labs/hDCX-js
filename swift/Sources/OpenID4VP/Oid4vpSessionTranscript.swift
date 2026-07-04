import CborCose
import Crypto
import Foundation
import SdJwt

/// The mdoc `SessionTranscript` for OpenID4VP (OpenID4VP 1.0, "Handover and SessionTranscript
/// Definitions"): `[null, null, OpenID4VPHandover]` where
/// `OpenID4VPHandover = ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce, jwk_thumbprint, response_uri]))]`.
/// `jwk_thumbprint` is the verifier encryption key's RFC 7638 thumbprint, or null when unencrypted.
public enum Oid4vpSessionTranscript {

    public static func build(clientId: String, responseUri: String?, nonce: String, verifierJwkThumbprint: [UInt8]?) throws -> Cbor {
        let handoverInfo = Cbor.array([
            .text(clientId),
            .text(nonce),
            verifierJwkThumbprint.map { Cbor.bytes($0) } ?? .null,
            .text(responseUri ?? ""),
        ])
        return try sessionTranscript("OpenID4VPHandover", handoverInfo)
    }

    /// SessionTranscript for OpenID4VP over the W3C Digital Credentials API (OpenID4VP 1.0 DC API
    /// profile): the handover binds the caller `origin` instead of a response_uri —
    /// `OpenID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover", SHA-256(CBOR([origin, nonce, jwk_thumbprint]))]`.
    public static func dcApi(origin: String, nonce: String, verifierJwkThumbprint: [UInt8]?) throws -> Cbor {
        let handoverInfo = Cbor.array([
            .text(origin),
            .text(nonce),
            verifierJwkThumbprint.map { Cbor.bytes($0) } ?? .null,
        ])
        return try sessionTranscript("OpenID4VPDCAPIHandover", handoverInfo)
    }

    private static func sessionTranscript(_ handoverType: String, _ handoverInfo: Cbor) throws -> Cbor {
        let hash = [UInt8](SHA256.hash(data: Data(try CborEncoder.encode(handoverInfo))))
        return .array([.null, .null, .array([.text(handoverType), .bytes(hash)])])
    }
}

/// RFC 7638 JWK thumbprint (SHA-256) of an EC public key — members in lexicographic order.
public func ecJwkThumbprint(_ key: EcPublicKey) -> [UInt8] {
    let crv: String
    switch key.curve {
    case .p256: crv = "P-256"
    case .p384: crv = "P-384"
    case .p521: crv = "P-521"
    }
    let json = #"{"crv":"\#(crv)","kty":"EC","x":"\#(Base64Url.encode(key.x))","y":"\#(Base64Url.encode(key.y))"}"#
    return [UInt8](SHA256.hash(data: Data(json.utf8)))
}
