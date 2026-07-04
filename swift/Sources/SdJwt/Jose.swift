import CborCose
import Crypto
import Foundation
import WalletAPI

public struct JoseError: Error, CustomStringConvertible {
    public let description: String

    init(_ description: String) {
        self.description = description
    }
}

public enum Base64Url {
    public static func encode(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func encode(_ text: String) -> String {
        encode([UInt8](text.utf8))
    }

    public static func decode(_ text: String) throws -> [UInt8] {
        var t = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        guard let data = Data(base64Encoded: t) else { throw JoseError("invalid base64url") }
        return [UInt8](data)
    }

    public static func decodeToString(_ text: String) throws -> String {
        guard let s = String(bytes: try decode(text), encoding: .utf8) else {
            throw JoseError("base64url payload is not UTF-8")
        }
        return s
    }
}

public extension SigningAlgorithm {
    var jwsName: String {
        switch self {
        case .es256: return "ES256"
        case .es384: return "ES384"
        case .es512: return "ES512"
        }
    }
}

public func signingAlgorithmFromJwsName(_ name: String) -> SigningAlgorithm? {
    switch name {
    case "ES256": return .es256
    case "ES384": return .es384
    case "ES512": return .es512
    default: return nil
    }
}

/// JWS ECDSA signatures are raw r||s (RFC 7518 §3.4) — same shape the SecureArea port emits.
public protocol JwsSigner: Sendable {
    var algorithm: SigningAlgorithm { get }
    func sign(_ signingInput: [UInt8]) async throws -> [UInt8]
}

/// Production signer: private keys never leave the SecureArea port.
public struct SecureAreaJwsSigner: JwsSigner {
    private let area: any SecureArea
    private let key: KeyHandle
    public let algorithm: SigningAlgorithm
    private let hint: AuthorizationHint?

    public init(area: any SecureArea, key: KeyHandle, algorithm: SigningAlgorithm, hint: AuthorizationHint? = nil) {
        self.area = area
        self.key = key
        self.algorithm = algorithm
        self.hint = hint
    }

    public func sign(_ signingInput: [UInt8]) async throws -> [UInt8] {
        try await area.sign(key: key, algorithm: algorithm, data: signingInput, hint: hint)
    }
}

/// Compact-serialization JWS (scratch implementation — no third-party JOSE).
public struct Jws {
    public let header: JsonValue
    public let headerB64: String
    public let payloadB64: String
    public let signature: [UInt8]

    public init(header: JsonValue, headerB64: String, payloadB64: String, signature: [UInt8]) {
        self.header = header
        self.headerB64 = headerB64
        self.payloadB64 = payloadB64
        self.signature = signature
    }

    public var payloadBytes: [UInt8] {
        (try? Base64Url.decode(payloadB64)) ?? []
    }

    /// x5c header (RFC 7515 §4.1.6): DER certs, standard base64. Chain VALIDATION is the trust module's job.
    public var x5c: [[UInt8]]? {
        guard case let .arr(items)? = header["x5c"] else { return nil }
        var out: [[UInt8]] = []
        for item in items {
            guard case let .str(s) = item, let data = Data(base64Encoded: s) else { return nil }
            out.append([UInt8](data))
        }
        return out
    }

    public var signingInput: [UInt8] {
        [UInt8]("\(headerB64).\(payloadB64)".utf8)
    }

    public func compact() -> String {
        "\(headerB64).\(payloadB64).\(Base64Url.encode(signature))"
    }

    /// Header `alg` must equal `expected` — no algorithm negotiation from attacker input.
    public func verify(key: EcPublicKey, expected: SigningAlgorithm) -> Bool {
        guard header["crit"] == nil else { return false } // RFC 7515 §4.1.11: unknown crit extensions MUST be rejected
        guard case let .str(alg)? = header["alg"], alg == expected.jwsName else { return false }
        return Ecdsa.verify(key: key, algorithm: expected.coseAlgorithm, data: signingInput, rawSignature: signature)
    }

    public static func parse(_ compact: String) throws -> Jws {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty }) else {
            throw JoseError("malformed compact JWS")
        }
        guard let header = try? JsonValue.parse(try Base64Url.decodeToString(parts[0])),
              case .obj = header
        else { throw JoseError("invalid JWS header") }
        return Jws(header: header, headerB64: parts[0], payloadB64: parts[1], signature: try Base64Url.decode(parts[2]))
    }

    public static func sign(header: JsonValue, payload: [UInt8], signer: any JwsSigner) async throws -> Jws {
        guard case let .str(alg)? = header["alg"], alg == signer.algorithm.jwsName else {
            throw JoseError("header alg must match signer algorithm")
        }
        let h64 = Base64Url.encode(header.serialize())
        let p64 = Base64Url.encode(payload)
        let signature = try await signer.sign([UInt8]("\(h64).\(p64)".utf8))
        return Jws(header: header, headerB64: h64, payloadB64: p64, signature: signature)
    }
}

/// cnf.jwk (EC) <-> EcPublicKey for holder key binding.
public enum JwkEc {
    public static func toJson(_ key: EcPublicKey) -> JsonValue {
        let crv: String
        switch key.curve {
        case .p256: crv = "P-256"
        case .p384: crv = "P-384"
        case .p521: crv = "P-521"
        }
        return .obj([
            ("kty", .str("EC")),
            ("crv", .str(crv)),
            ("x", .str(Base64Url.encode(key.x))),
            ("y", .str(Base64Url.encode(key.y))),
        ])
    }

    public static func fromJson(_ jwk: JsonValue) -> EcPublicKey? {
        guard case let .str(kty)? = jwk["kty"], kty == "EC" else { return nil }
        let curve: EcCurve
        switch jwk["crv"] {
        case .str("P-256"): curve = .p256
        case .str("P-384"): curve = .p384
        case .str("P-521"): curve = .p521
        default: return nil
        }
        guard case let .str(x)? = jwk["x"], case let .str(y)? = jwk["y"],
              let xb = try? Base64Url.decode(x), let yb = try? Base64Url.decode(y)
        else { return nil }
        return EcPublicKey(curve: curve, x: xb, y: yb)
    }
}

func sha256(_ bytes: [UInt8]) -> [UInt8] {
    [UInt8](SHA256.hash(data: Data(bytes)))
}
