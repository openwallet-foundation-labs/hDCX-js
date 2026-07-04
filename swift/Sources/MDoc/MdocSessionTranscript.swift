import CborCose
import Crypto
import Foundation

/// mdoc `SessionTranscript` builders for the ISO transports (proximity handovers live in `Proximity`).
public enum MdocSessionTranscript {

    /// SessionTranscript for the ISO `org-iso-mdoc` Digital Credentials API protocol
    /// (ISO/IEC TS 18013-7:2025 Annex C): `[null, null, ["dcapi", SHA-256(CBOR([base64url(EncryptionInfo), origin]))]]`.
    public static func dcApiIsoMdoc(encryptionInfoBase64: String, origin: String) throws -> Cbor {
        let info = Cbor.array([.text(encryptionInfoBase64), .text(origin)])
        let hash = [UInt8](SHA256.hash(data: Data(try CborEncoder.encode(info))))
        return .array([.null, .null, .array([.text("dcapi"), .bytes(hash)])])
    }
}
