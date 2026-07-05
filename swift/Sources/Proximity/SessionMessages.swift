import CborCose
import Foundation

/// ISO/IEC 18013-5 device-retrieval message framing (§9.1.1):
///  - `SessionEstablishment = {"eReaderKey": EReaderKeyBytes, "data": <encrypted DeviceRequest>}`
///  - `SessionData = {"data": <encrypted DeviceResponse>, "status": uint?}`
///
/// The encrypted `data` payloads are produced/consumed by `SessionEncryption`; this only wraps them.
public enum SessionMessages {
    private static let tagEncodedCbor: UInt64 = 24

    public static func encodeEstablishment(eReaderKey: EcPublicKey, encryptedDeviceRequest: [UInt8]) throws -> [UInt8] {
        let eReaderKeyBytes = Cbor.tagged(tagEncodedCbor, .bytes(try CborEncoder.encode(CoseKey.encode(eReaderKey))))
        return try CborEncoder.encode(.map([
            (.text("eReaderKey"), eReaderKeyBytes),
            (.text("data"), .bytes(encryptedDeviceRequest)),
        ]))
    }

    public static func decodeEstablishment(_ bytes: [UInt8]) throws -> SessionEstablishment {
        let map = try CborDecoder.decode(bytes)
        guard case let .tagged(_, inner)? = field(map, "eReaderKey"), case let .bytes(keyBytes) = inner else {
            throw ProximityError("missing eReaderKey")
        }
        let eReaderKey = try CoseKey.decode(try CborDecoder.decode(keyBytes))
        guard case let .bytes(data)? = field(map, "data") else { throw ProximityError("missing data") }
        return SessionEstablishment(eReaderKey: eReaderKey, encryptedDeviceRequest: data)
    }

    public static func encodeData(_ encryptedDeviceResponse: [UInt8], status: Int64? = nil) throws -> [UInt8] {
        var entries: [(Cbor, Cbor)] = [(.text("data"), .bytes(encryptedDeviceResponse))]
        if let status { entries.append((.text("status"), .int(status))) }
        return try CborEncoder.encode(.map(entries))
    }

    public static func decodeData(_ bytes: [UInt8]) throws -> [UInt8] {
        guard case let .bytes(data)? = field(try CborDecoder.decode(bytes), "data") else { throw ProximityError("missing data") }
        return data
    }

    private static func field(_ c: Cbor, _ key: String) -> Cbor? {
        guard case let .map(entries) = c else { return nil }
        return entries.first(where: { if case let .text(k) = $0.0 { return k == key }; return false })?.1
    }
}

public struct SessionEstablishment {
    public let eReaderKey: EcPublicKey
    public let encryptedDeviceRequest: [UInt8]
}
