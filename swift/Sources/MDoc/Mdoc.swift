import CborCose
import Foundation

public struct MdocError: Error, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// CBOR tag 24: an embedded CBOR data item carried as a byte string (RFC 8949 §3.4.5.1).
let TAG_ENCODED_CBOR: UInt64 = 24
let TAG_TDATE: UInt64 = 0

/// One data element inside an mdoc namespace (ISO 18013-5 §8.3.2.1.2.2).
public struct IssuerSignedItem {
    public let digestId: Int64
    public let random: [UInt8]
    public let elementIdentifier: String
    public let elementValue: Cbor
}

/// An item plus the exact `#6.24(bstr)` bytes the issuer digested (`IssuerSignedItemBytes`).
public struct IssuerSignedItemEntry {
    public let item: IssuerSignedItem
    public let itemBytes: [UInt8]
}

/// Mobile Security Object (ISO 18013-5 §9.1.2.4) — the issuer-signed integrity structure.
public struct MobileSecurityObject {
    public let version: String
    public let digestAlgorithm: String
    /// namespace -> (digestID -> digest bytes).
    public let valueDigests: [String: [Int64: [UInt8]]]
    public let deviceKey: EcPublicKey
    public let docType: String
    public let signed: Date
    public let validFrom: Date
    public let validUntil: Date
}

/// IssuerSigned (ISO 18013-5 §8.3.2.1.2.2): the disclosable items + the issuer's COSE_Sign1.
public struct IssuerSigned {
    public let nameSpaces: [(String, [IssuerSignedItemEntry])]
    public let issuerAuth: CoseSign1

    /// The x5chain (COSE header 33) presented by the issuer, leaf-first DER.
    public var issuerCertChain: [[UInt8]]? {
        (try? issuerAuth.protectedHeaders())?.x5chain ?? issuerAuth.unprotected.x5chain
    }

    /// Parses the MSO from the `issuerAuth` payload. Trust the result only after verifying the signature.
    public func parseMso() throws -> MobileSecurityObject {
        guard let payload = issuerAuth.payload else { throw MdocError("issuerAuth has no payload") }
        return try MsoCodec.parse(try unwrapTag24(payload))
    }

    /// namespace -> [(elementIdentifier, value)] across all issuer-signed items.
    public func elements() -> [(String, [(String, Cbor)])] {
        nameSpaces.map { ns, items in (ns, items.map { ($0.item.elementIdentifier, $0.item.elementValue) }) }
    }

    public static func decode(_ bytes: [UInt8]) throws -> IssuerSigned {
        try fromCbor(try CborDecoder.decode(bytes))
    }

    public static func fromCbor(_ cbor: Cbor) throws -> IssuerSigned {
        guard case let .map(entries) = cbor else { throw MdocError("IssuerSigned must be a map") }
        guard let issuerAuthCbor = value(entries, "issuerAuth") else { throw MdocError("missing issuerAuth") }
        let issuerAuth = try CoseSign1.fromCbor(issuerAuthCbor)
        guard case let .map(nsEntries)? = value(entries, "nameSpaces") else { throw MdocError("missing nameSpaces") }

        var nameSpaces: [(String, [IssuerSignedItemEntry])] = []
        for (nsKey, arr) in nsEntries {
            guard case let .text(ns) = nsKey else { throw MdocError("namespace key must be text") }
            guard case let .array(items) = arr else { throw MdocError("namespace value must be an array") }
            let entries: [IssuerSignedItemEntry] = try items.map { entry in
                guard case let .tagged(tag, inner) = entry, tag == TAG_ENCODED_CBOR else { throw MdocError("item must be tag 24") }
                guard case let .bytes(innerBytes) = inner else { throw MdocError("tag 24 value must be bstr") }
                let item = try parseItem(try CborDecoder.decode(innerBytes))
                return IssuerSignedItemEntry(item: item, itemBytes: try CborEncoder.encode(entry))
            }
            nameSpaces.append((ns, entries))
        }
        return IssuerSigned(nameSpaces: nameSpaces, issuerAuth: issuerAuth)
    }

    private static func parseItem(_ cbor: Cbor) throws -> IssuerSignedItem {
        guard case let .map(m) = cbor else { throw MdocError("IssuerSignedItem must be a map") }
        guard case let .uint(digestId)? = value(m, "digestID") else { throw MdocError("missing digestID") }
        guard case let .bytes(random)? = value(m, "random") else { throw MdocError("missing random") }
        guard case let .text(elementId)? = value(m, "elementIdentifier") else { throw MdocError("missing elementIdentifier") }
        guard let elementValue = value(m, "elementValue") else { throw MdocError("missing elementValue") }
        return IssuerSignedItem(digestId: Int64(digestId), random: random, elementIdentifier: elementId, elementValue: elementValue)
    }
}

func value(_ entries: [(Cbor, Cbor)], _ name: String) -> Cbor? {
    entries.first { if case let .text(t) = $0.0 { return t == name }; return false }?.1
}

/// issuerAuth payload is MobileSecurityObjectBytes = #6.24(bstr .cbor MSO); unwrap to the MSO bytes.
func unwrapTag24(_ payload: [UInt8]) throws -> [UInt8] {
    let decoded = try CborDecoder.decode(payload)
    switch decoded {
    case let .tagged(tag, inner) where tag == TAG_ENCODED_CBOR:
        guard case let .bytes(b) = inner else { throw MdocError("tag 24 payload must be bstr") }
        return b
    case .map:
        return payload // already the bare MSO
    default:
        throw MdocError("unexpected issuerAuth payload shape")
    }
}

enum MsoCodec {
    static func parse(_ msoBytes: [UInt8]) throws -> MobileSecurityObject {
        guard case let .map(m) = try CborDecoder.decode(msoBytes) else { throw MdocError("MSO must be a map") }

        guard case let .map(vdEntries)? = value(m, "valueDigests") else { throw MdocError("missing valueDigests") }
        var valueDigests: [String: [Int64: [UInt8]]] = [:]
        for (nsKey, digestsCbor) in vdEntries {
            guard case let .text(ns) = nsKey, case let .map(digs) = digestsCbor else { throw MdocError("bad valueDigests") }
            var byId: [Int64: [UInt8]] = [:]
            for (idKey, digest) in digs {
                guard case let .uint(id) = idKey, case let .bytes(d) = digest else { throw MdocError("bad digest entry") }
                byId[Int64(id)] = d
            }
            valueDigests[ns] = byId
        }

        guard case let .map(dki)? = value(m, "deviceKeyInfo"),
              let deviceKeyCbor = value(dki, "deviceKey") else { throw MdocError("missing deviceKey") }

        guard case let .map(validity)? = value(m, "validityInfo") else { throw MdocError("missing validityInfo") }
        func tdate(_ name: String) throws -> Date {
            guard let v = value(validity, name) else { throw MdocError("validityInfo missing \(name)") }
            let text: String?
            switch v {
            case let .tagged(_, inner): if case let .text(t) = inner { text = t } else { text = nil }
            case let .text(t): text = t
            default: text = nil
            }
            guard let s = text, let date = isoFormatter.date(from: s) else { throw MdocError("\(name) must be a tdate") }
            return date
        }

        guard case let .text(version)? = value(m, "version") else { throw MdocError("missing version") }
        guard case let .text(digestAlg)? = value(m, "digestAlgorithm") else { throw MdocError("missing digestAlgorithm") }
        guard case let .text(docType)? = value(m, "docType") else { throw MdocError("missing docType") }

        return MobileSecurityObject(
            version: version, digestAlgorithm: digestAlg, valueDigests: valueDigests,
            deviceKey: try CoseKey.decode(deviceKeyCbor), docType: docType,
            signed: try tdate("signed"), validFrom: try tdate("validFrom"), validUntil: try tdate("validUntil")
        )
    }

    static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()
}
