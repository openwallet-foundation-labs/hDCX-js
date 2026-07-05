import CborCose

private let tagEncodedCbor: UInt64 = 24

/// The mdoc proximity `SessionTranscript` (ISO/IEC 18013-5 §9.1.5.1):
/// `[DeviceEngagementBytes, EReaderKeyBytes, Handover]`, where the first two are `#6.24(bstr)`
/// and Handover is `null` for QR-code engagement. Also builds a minimal QR `DeviceEngagement`.
public enum ProximitySessionTranscript {

    public static func build(deviceEngagement: [UInt8], eReaderKey: EcPublicKey, handover: Cbor = .null) throws -> Cbor {
        let deviceEngagementBytes = Cbor.tagged(tagEncodedCbor, .bytes(deviceEngagement))
        let eReaderKeyBytes = Cbor.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(CoseKey.encode(eReaderKey))))
        return .array([deviceEngagementBytes, eReaderKeyBytes, handover])
    }

    /// SessionTranscript bytes fed to session-key derivation (HKDF salt = SHA-256 of these).
    public static func encode(_ sessionTranscript: Cbor) throws -> [UInt8] { try CborEncoder.encode(sessionTranscript) }
}

/// A minimal QR-code `DeviceEngagement` (ISO/IEC 18013-5 §8.2.1.1): version + EDeviceKey.
public enum DeviceEngagement {

    public static func qr(eDeviceKey: EcPublicKey) throws -> [UInt8] {
        let eDeviceKeyBytes = Cbor.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(CoseKey.encode(eDeviceKey))))
        let security = Cbor.array([.int(1), eDeviceKeyBytes]) // [cipher-suite 1, EDeviceKeyBytes]
        let engagement = Cbor.map([(.int(0), .text("1.0")), (.int(1), security)])
        return try CborEncoder.encode(engagement)
    }

    /// Extracts the mdoc's ephemeral public key (EDeviceKey) from a QR `DeviceEngagement` — the reader side.
    public static func parseEDeviceKey(_ engagement: [UInt8]) throws -> EcPublicKey {
        guard case let .map(entries) = try CborDecoder.decode(engagement) else {
            throw ProximityError("DeviceEngagement must be a map")
        }
        guard let security = entries.first(where: { if case let .uint(k) = $0.0 { return k == 1 }; return false })?.1,
              case let .array(items) = security, items.count >= 2,
              case let .tagged(_, inner) = items[1], case let .bytes(keyBytes) = inner else {
            throw ProximityError("missing EDeviceKey")
        }
        return try CoseKey.decode(try CborDecoder.decode(keyBytes))
    }
}
