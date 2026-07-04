import CborCose
import Crypto
import Foundation
import SdJwt
import SwiftASN1
import WalletAPI
import X509

public struct TrustError: Error, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// swift-certificates-backed X.509 helpers shared by the issuer and verifier trust paths.
enum X509Support {

    static func parse(_ der: [UInt8]) throws -> Certificate {
        do { return try Certificate(derEncoded: der) }
        catch { throw TrustError("invalid X.509 certificate: \(error)") }
    }

    static func der(_ cert: Certificate) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        return serializer.serializedBytes
    }

    /// EC public key (P-256/384/521) as raw coordinates.
    static func ecPublicKey(_ cert: Certificate) throws -> EcPublicKey {
        if let p = P256.Signing.PublicKey(cert.publicKey) {
            let raw = p.rawRepresentation
            return EcPublicKey(curve: .p256, x: [UInt8](raw.prefix(32)), y: [UInt8](raw.suffix(32)))
        }
        if let p = P384.Signing.PublicKey(cert.publicKey) {
            let raw = p.rawRepresentation
            return EcPublicKey(curve: .p384, x: [UInt8](raw.prefix(48)), y: [UInt8](raw.suffix(48)))
        }
        if let p = P521.Signing.PublicKey(cert.publicKey) {
            let raw = p.rawRepresentation
            return EcPublicKey(curve: .p521, x: [UInt8](raw.prefix(66)), y: [UInt8](raw.suffix(66)))
        }
        throw TrustError("certificate key is not a supported EC key")
    }

    static func signingAlgorithm(_ cert: Certificate) throws -> SigningAlgorithm {
        if P256.Signing.PublicKey(cert.publicKey) != nil { return .es256 }
        if P384.Signing.PublicKey(cert.publicKey) != nil { return .es384 }
        if P521.Signing.PublicKey(cert.publicKey) != nil { return .es512 }
        throw TrustError("unsupported EC curve")
    }

    static func dnsNames(_ cert: Certificate) -> [String] {
        guard let ext = try? cert.extensions.subjectAlternativeNames else { return [] }
        var out: [String] = []
        for name in ext {
            if case let .dnsName(dns) = name { out.append(dns) }
        }
        return out
    }

    static func commonName(_ cert: Certificate) -> String? {
        for rdn in cert.subject {
            for attr in rdn where attr.type == .RDNAttributeType.commonName {
                return attr.value.description
            }
        }
        return nil
    }

    /// base64url(SHA-256(DER)) — the x509_hash client_id value.
    static func sha256Thumbprint(_ cert: Certificate) throws -> String {
        Base64Url.encode([UInt8](SHA256.hash(data: Data(try der(cert)))))
    }
}
