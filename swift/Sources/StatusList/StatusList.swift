import Foundation
import SdJwt

public struct StatusListError: Error, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// A credential's reference into a status list (IETF Token Status List §5).
public struct StatusReference {
    public let index: Int64
    public let uri: String

    public init(index: Int64, uri: String) {
        self.index = index
        self.uri = uri
    }

    /// Extracts `status.status_list = { idx, uri }` from a credential's claims (nil if absent).
    public static func fromClaims(_ claims: JsonValue) -> StatusReference? {
        guard let statusList = claims["status"]?["status_list"],
              case let .numInt(idx)? = statusList["idx"],
              case let .str(uri)? = statusList["uri"] else { return nil }
        return StatusReference(index: idx, uri: uri)
    }
}

/// Status values (IETF Token Status List §7.1); higher values are issuer/application-defined.
public enum CredentialStatus: Int {
    case valid = 0
    case invalid = 1
    case suspended = 2
    case unknown = -1

    static func of(_ value: Int) -> CredentialStatus { CredentialStatus(rawValue: value) ?? .unknown }
}

/// A decoded status list: a packed bit array of `bits`-bit entries (IETF Token Status List §4).
/// Within each byte the lowest-index entry occupies the least-significant bits.
public struct StatusList {
    public let bits: Int
    private let unpacked: [UInt8]

    init(bits: Int, unpacked: [UInt8]) throws {
        guard bits == 1 || bits == 2 || bits == 4 || bits == 8 else { throw StatusListError("invalid bits per entry: \(bits)") }
        self.bits = bits
        self.unpacked = unpacked
    }

    public var size: Int64 { Int64(unpacked.count) * Int64(8 / bits) }

    public func rawStatusAt(_ index: Int64) throws -> Int {
        guard index >= 0 && index < size else { throw StatusListError("status index \(index) out of range (size \(size))") }
        let entriesPerByte = Int64(8 / bits)
        let byte = Int(unpacked[Int(index / entriesPerByte)])
        let shift = Int(index % entriesPerByte) * bits
        let mask = (1 << bits) - 1
        return (byte >> shift) & mask
    }

    public func statusAt(_ index: Int64) throws -> CredentialStatus { CredentialStatus.of(try rawStatusAt(index)) }

    /// Parses a Status List Token JWS payload (`status_list = { bits, lst }`).
    public static func fromTokenPayload(_ payload: JsonValue) throws -> StatusList {
        guard let sl = payload["status_list"] else { throw StatusListError("missing status_list") }
        guard case let .numInt(bits)? = sl["bits"] else { throw StatusListError("missing bits") }
        guard case let .str(lst)? = sl["lst"] else { throw StatusListError("missing lst") }
        return try StatusList(bits: Int(bits), unpacked: try Zlib.inflate(Base64Url.decode(lst)))
    }
}
