import CborCose
import Crypto
import Foundation

/// Resolves the mdoc issuer's public key from the `issuerAuth` x5chain, validating the chain to
/// a trust anchor. Implemented by the `Trust` module (mirrors SD-JWT VC's IssuerKeyResolver).
public protocol MdocIssuerTrust: Sendable {
    func issuerKey(x5chain: [[UInt8]]) async throws -> EcPublicKey
}

/// A verified mdoc: integrity-checked disclosed elements plus the holder (device) binding.
public struct VerifiedMdoc {
    public let docType: String
    public let deviceKey: EcPublicKey
    /// namespace -> (elementIdentifier -> value).
    public let elements: [String: [String: Cbor]]
    public let signed: Date
    public let validFrom: Date
    public let validUntil: Date
}

/// Verifies an mdoc `IssuerSigned` (ISO 18013-5 §9.1.2): resolves + trusts the issuer key from
/// the COSE x5chain, verifies the `issuerAuth` COSE_Sign1 over the MSO, checks every disclosed
/// element's digest against the MSO `valueDigests`, and enforces `validityInfo`.
public struct MdocVerifier {
    private let trust: any MdocIssuerTrust
    private let now: () -> Date

    public init(trust: any MdocIssuerTrust, now: @escaping () -> Date = { Date() }) {
        self.trust = trust
        self.now = now
    }

    public func verify(_ issuerSigned: IssuerSigned) async throws -> VerifiedMdoc {
        guard let x5chain = issuerSigned.issuerCertChain else { throw MdocError("issuerAuth has no x5chain") }
        let issuerKey = try await trust.issuerKey(x5chain: x5chain)

        let cose = issuerSigned.issuerAuth
        guard cose.verify(publicKey: issuerKey) else { throw MdocError("issuerAuth signature invalid") }

        let mso = try issuerSigned.parseMso()

        guard mso.digestAlgorithm.uppercased() == "SHA-256" else {
            throw MdocError("unsupported MSO digest algorithm \(mso.digestAlgorithm)")
        }

        let instant = now()
        if instant < mso.validFrom { throw MdocError("mdoc not yet valid (validFrom=\(mso.validFrom))") }
        if instant > mso.validUntil { throw MdocError("mdoc expired (validUntil=\(mso.validUntil))") }

        var elements: [String: [String: Cbor]] = [:]
        for (namespace, items) in issuerSigned.nameSpaces {
            guard let nsDigests = mso.valueDigests[namespace] else {
                throw MdocError("MSO has no digests for namespace '\(namespace)'")
            }
            for entry in items {
                guard let expected = nsDigests[entry.item.digestId] else {
                    throw MdocError("no MSO digest for \(namespace)/\(entry.item.digestId)")
                }
                let actual = [UInt8](SHA256.hash(data: Data(entry.itemBytes)))
                guard actual == expected else {
                    throw MdocError("digest mismatch for \(namespace)/\(entry.item.elementIdentifier)")
                }
                elements[namespace, default: [:]][entry.item.elementIdentifier] = entry.item.elementValue
            }
        }

        return VerifiedMdoc(
            docType: mso.docType, deviceKey: mso.deviceKey, elements: elements,
            signed: mso.signed, validFrom: mso.validFrom, validUntil: mso.validUntil
        )
    }
}
