import CborCose
import Foundation
import WalletAPI

public struct SdJwtError: Error, CustomStringConvertible {
    public let description: String

    init(_ description: String) {
        self.description = description
    }
}

/// RFC 9901 Disclosure: base64url(JSON array). Digest is over the base64url string bytes.
public struct Disclosure {
    public let encoded: String
    public let salt: String
    /// nil for array-element disclosures.
    public let claimName: String?
    public let value: JsonValue
    public let digest: String

    private init(encoded: String, salt: String, claimName: String?, value: JsonValue) {
        self.encoded = encoded
        self.salt = salt
        self.claimName = claimName
        self.value = value
        self.digest = Base64Url.encode(sha256([UInt8](encoded.utf8)))
    }

    private static func checkName(_ name: String) throws {
        if name == "_sd" || name == "..." || name == "_sd_alg" {
            throw SdJwtError("reserved claim name '\(name)'")
        }
    }

    public static func objectProperty(salt: String, name: String, value: JsonValue) throws -> Disclosure {
        try checkName(name)
        let json = JsonValue.arr([.str(salt), .str(name), value]).serialize()
        return Disclosure(encoded: Base64Url.encode(json), salt: salt, claimName: name, value: value)
    }

    public static func arrayElement(salt: String, value: JsonValue) -> Disclosure {
        let json = JsonValue.arr([.str(salt), value]).serialize()
        return Disclosure(encoded: Base64Url.encode(json), salt: salt, claimName: nil, value: value)
    }

    public static func parse(_ encoded: String) throws -> Disclosure {
        guard let text = try? Base64Url.decodeToString(encoded),
              let parsed = try? JsonValue.parse(text),
              case let .arr(items) = parsed
        else { throw SdJwtError("malformed disclosure") }
        guard case let .str(salt)? = items.first else {
            throw SdJwtError("disclosure salt must be a string")
        }
        switch items.count {
        case 2:
            return Disclosure(encoded: encoded, salt: salt, claimName: nil, value: items[1])
        case 3:
            guard case let .str(name) = items[1] else {
                throw SdJwtError("disclosure claim name must be a string")
            }
            try checkName(name)
            return Disclosure(encoded: encoded, salt: salt, claimName: name, value: items[2])
        default:
            throw SdJwtError("disclosure array must have 2 or 3 elements")
        }
    }
}

/// `<issuer-jwt>~<disclosure>*~[<kb-jwt>]` (RFC 9901 §4).
public struct SdJwt {
    public let jwt: String
    public let disclosures: [Disclosure]
    public let kbJwt: String?

    public init(jwt: String, disclosures: [Disclosure], kbJwt: String? = nil) {
        self.jwt = jwt
        self.disclosures = disclosures
        self.kbJwt = kbJwt
    }

    public func serialize() -> String {
        presentationWithoutKb() + (kbJwt ?? "")
    }

    /// The exact string the KB-JWT's sd_hash commits to (ends with '~').
    public func presentationWithoutKb() -> String {
        var out = jwt
        for d in disclosures {
            out += "~" + d.encoded
        }
        return out + "~"
    }

    public static func parse(_ text: String) throws -> SdJwt {
        let parts = text.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 2, !parts[0].isEmpty else { throw SdJwtError("malformed SD-JWT") }
        var disclosures: [Disclosure] = []
        for segment in parts[1..<(parts.count - 1)] {
            guard !segment.isEmpty else { throw SdJwtError("empty disclosure segment") }
            disclosures.append(try Disclosure.parse(segment))
        }
        let last = parts.last!
        return SdJwt(jwt: parts[0], disclosures: disclosures, kbJwt: last.isEmpty ? nil : last)
    }
}

/// Shared digest-resolution walker (RFC 9901 §7.3 processing): used by the verifier
/// and by the holder (to learn where each disclosure attaches for selection).
final class SdProcessor {
    let byDigest: [String: Disclosure]
    private(set) var placements: [String: [String]] = [:]
    private(set) var parents: [String: String] = [:]
    private var used: Set<String> = []
    private var referenced: Set<String> = []
    private var parentStack: [String] = []

    init(_ disclosures: [Disclosure]) throws {
        var map: [String: Disclosure] = [:]
        for d in disclosures {
            guard map.updateValue(d, forKey: d.digest) == nil else {
                throw SdJwtError("duplicate disclosure")
            }
        }
        byDigest = map
    }

    func process(_ payload: JsonValue) throws -> JsonValue {
        guard case .obj = payload else { throw SdJwtError("payload must be an object") }
        let out = try processObj(payload, path: [], topLevel: true)
        guard used.count == byDigest.count else {
            throw SdJwtError("disclosure not referenced by any digest")
        }
        return out
    }

    private func reference(_ digest: String) throws {
        guard referenced.insert(digest).inserted else {
            throw SdJwtError("digest appears more than once")
        }
    }

    private func consume(_ digest: String, _ disclosure: Disclosure, path: [String]) throws -> JsonValue {
        used.insert(digest)
        placements[digest] = path
        if let parent = parentStack.last { parents[digest] = parent }
        parentStack.append(digest)
        defer { parentStack.removeLast() }
        return try processValue(disclosure.value, path: path)
    }

    private func processObj(_ value: JsonValue, path: [String], topLevel: Bool = false) throws -> JsonValue {
        guard case let .obj(entries) = value else { throw SdJwtError("expected object") }
        var out: [(String, JsonValue)] = []
        var names: Set<String> = []

        func add(_ name: String, _ v: JsonValue) throws {
            guard names.insert(name).inserted else { throw SdJwtError("duplicate claim name '\(name)'") }
            out.append((name, v))
        }

        for (key, v) in entries {
            switch key {
            case "_sd":
                guard case let .arr(digests) = v else { throw SdJwtError("_sd must be an array") }
                for item in digests {
                    guard case let .str(digest) = item else { throw SdJwtError("_sd entries must be strings") }
                    try reference(digest)
                    guard let disclosure = byDigest[digest] else { continue } // undisclosed
                    guard let name = disclosure.claimName else {
                        throw SdJwtError("array-element disclosure referenced from _sd")
                    }
                    try add(name, try consume(digest, disclosure, path: path + [name]))
                }
            case "...":
                throw SdJwtError("'...' is only allowed inside arrays")
            case "_sd_alg":
                guard topLevel else { throw SdJwtError("_sd_alg outside top level") }
            default:
                try add(key, try processValue(v, path: path + [key]))
            }
        }
        return .obj(out)
    }

    private func processValue(_ value: JsonValue, path: [String]) throws -> JsonValue {
        switch value {
        case .obj: return try processObj(value, path: path)
        case .arr: return try processArr(value, path: path)
        default: return value
        }
    }

    private func processArr(_ value: JsonValue, path: [String]) throws -> JsonValue {
        guard case let .arr(items) = value else { throw SdJwtError("expected array") }
        var out: [JsonValue] = []
        for (index, element) in items.enumerated() {
            if case let .obj(entries) = element, entries.count == 1, entries[0].0 == "..." {
                guard case let .str(digest) = entries[0].1 else {
                    throw SdJwtError("'...' value must be a string")
                }
                try reference(digest)
                guard let disclosure = byDigest[digest] else { continue } // undisclosed element omitted
                guard disclosure.claimName == nil else {
                    throw SdJwtError("object-property disclosure referenced from array")
                }
                out.append(try consume(digest, disclosure, path: path + [String(index)]))
            } else {
                out.append(try processValue(element, path: path + [String(index)]))
            }
        }
        return .arr(out)
    }
}

public enum SdJwtVerifier {

    /// What the verifier requires of a Key Binding JWT (RFC 9901 §7.3 step 5).
    ///
    /// The spec leaves the `iat` window to the verifier ("within an acceptable window", §7.3(5.e)), so it
    /// is policy here: `maxAgeSeconds` bounds how stale a presentation may be — the replay window — and
    /// `skewSeconds` tolerates a holder clock running slightly fast.
    public struct KbRequirement {
        public let audience: String
        public let nonce: String
        /// Epoch seconds. Injectable so tests (and offline verification) can pin the moment of judgement.
        public let now: () -> Int64
        public let maxAgeSeconds: Int64
        public let skewSeconds: Int64

        public init(audience: String, nonce: String,
                    now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) },
                    maxAgeSeconds: Int64 = 300, skewSeconds: Int64 = 60) {
            self.audience = audience
            self.nonce = nonce
            self.now = now
            self.maxAgeSeconds = maxAgeSeconds
            self.skewSeconds = skewSeconds
        }
    }

    public struct VerifiedSdJwt {
        /// Processed claims: digests resolved, _sd/_sd_alg removed.
        public let claims: JsonValue
        /// Raw issuer payload (incl. cnf) for callers that need it.
        public let payload: JsonValue
        /// digest -> path of every disclosed claim.
        public let disclosedPaths: [String: [String]]
    }

    public static func verify(
        _ sdJwt: SdJwt,
        issuerKey: EcPublicKey,
        algorithm: SigningAlgorithm,
        keyBinding: KbRequirement? = nil
    ) throws -> VerifiedSdJwt {
        let jws = try Jws.parse(sdJwt.jwt)
        try requireSecureAlg(jws, "issuer-signed JWT") // §7.1(2.a)
        guard jws.verify(key: issuerKey, expected: algorithm) else {
            throw SdJwtError("issuer signature invalid")
        }
        guard let payloadText = String(bytes: jws.payloadBytes, encoding: .utf8),
              let payload = try? JsonValue.parse(payloadText),
              case .obj = payload
        else { throw SdJwtError("issuer payload must be a JSON object") }

        if case let .str(sdAlg)? = payload["_sd_alg"], sdAlg != "sha-256" {
            throw SdJwtError("unsupported _sd_alg '\(sdAlg)'")
        }

        let processor = try SdProcessor(sdJwt.disclosures)
        let claims = try processor.process(payload)

        if let keyBinding {
            guard let kbJwt = sdJwt.kbJwt else { throw SdJwtError("key binding required but missing") }
            guard let holderKey = holderKeyFromCnf(payload) else {
                throw SdJwtError("cnf.jwk missing or unsupported")
            }
            try verifyKeyBinding(kbJwt, holderKey: holderKey, requirement: keyBinding, sdJwt: sdJwt)
        }

        return VerifiedSdJwt(claims: claims, payload: payload, disclosedPaths: processor.placements)
    }

    public static func holderKeyFromCnf(_ payload: JsonValue) -> EcPublicKey? {
        guard let cnf = payload["cnf"], let jwk = cnf["jwk"] else { return nil }
        return JwkEc.fromJson(jwk)
    }

    /// RFC 9901 §7.1(2.a) and §7.3(5.b): "The `none` algorithm MUST NOT be accepted." `Jws.verify` would
    /// already reject it, since the header `alg` must equal the algorithm the caller pinned — but only as
    /// a signature failure. Naming the rule keeps the refusal explicit and the diagnostic honest.
    private static func requireSecureAlg(_ jws: Jws, _ where_: String) throws {
        guard case let .str(alg)? = jws.header["alg"] else { throw SdJwtError("\(where_) has no alg") }
        if alg.lowercased() == "none" { throw SdJwtError("\(where_) must not use the 'none' algorithm") }
    }

    private static func verifyKeyBinding(
        _ kbJwt: String,
        holderKey: EcPublicKey,
        requirement: KbRequirement,
        sdJwt: SdJwt
    ) throws {
        let jws = try Jws.parse(kbJwt)
        guard case let .str(typ)? = jws.header["typ"], typ == "kb+jwt" else {
            throw SdJwtError("kb-jwt typ must be kb+jwt")
        }
        try requireSecureAlg(jws, "kb-jwt") // §7.3(5.b)
        guard case let .str(algName)? = jws.header["alg"],
              let algorithm = signingAlgorithmFromJwsName(algName)
        else { throw SdJwtError("kb-jwt alg unsupported") }
        guard jws.verify(key: holderKey, expected: algorithm) else {
            throw SdJwtError("kb-jwt signature invalid")
        }
        guard let text = String(bytes: jws.payloadBytes, encoding: .utf8),
              let payload = try? JsonValue.parse(text)
        else { throw SdJwtError("kb-jwt payload must be JSON") }

        guard case let .str(nonce)? = payload["nonce"], nonce == requirement.nonce else {
            throw SdJwtError("kb-jwt nonce mismatch")
        }
        guard case let .str(aud)? = payload["aud"], aud == requirement.audience else {
            throw SdJwtError("kb-jwt aud mismatch")
        }
        // §7.3(5.e): the KB-JWT's creation time must fall within the verifier's acceptable window. Presence
        // alone proves nothing — a KB-JWT minted months ago would otherwise still authorise a presentation.
        guard case let .numInt(iat)? = payload["iat"] else { throw SdJwtError("kb-jwt iat missing") }
        let now = requirement.now()
        if iat > now + requirement.skewSeconds { throw SdJwtError("kb-jwt iat is \(iat - now)s in the future") }
        if iat < now - requirement.maxAgeSeconds {
            throw SdJwtError("kb-jwt is \(now - iat)s old; the acceptable window is \(requirement.maxAgeSeconds)s")
        }

        let expected = Base64Url.encode(sha256([UInt8](sdJwt.presentationWithoutKb().utf8)))
        guard case let .str(sdHash)? = payload["sd_hash"], sdHash == expected else {
            throw SdJwtError("kb-jwt sd_hash mismatch")
        }
    }
}

public enum SdJwtHolder {

    /// Processed claim tree of a held credential (disclosures resolved), without verifying the issuer signature.
    public static func processedClaims(_ issued: SdJwt) throws -> JsonValue {
        let jws = try Jws.parse(issued.jwt)
        guard let text = String(bytes: jws.payloadBytes, encoding: .utf8),
              let payload = try? JsonValue.parse(text), case .obj = payload
        else { throw SdJwtError("issuer payload must be an object") }
        return try SdProcessor(issued.disclosures).process(payload)
    }

    /// Selects disclosures by processed-claim path. Ancestors of a selected disclosure
    /// (recursive disclosures) are included automatically.
    public static func present(_ issued: SdJwt, select: ([String]) -> Bool) throws -> SdJwt {
        let jws = try Jws.parse(issued.jwt)
        guard let text = String(bytes: jws.payloadBytes, encoding: .utf8),
              let payload = try? JsonValue.parse(text)
        else { throw SdJwtError("issuer payload must be JSON") }

        let processor = try SdProcessor(issued.disclosures)
        _ = try processor.process(payload)

        var selected: Set<String> = []
        for (digest, path) in processor.placements where select(path) {
            var current: String? = digest
            while let c = current, selected.insert(c).inserted {
                current = processor.parents[c]
            }
        }
        return SdJwt(jwt: issued.jwt, disclosures: issued.disclosures.filter { selected.contains($0.digest) })
    }

    public static func presentWithKeyBinding(
        _ issued: SdJwt,
        select: ([String]) -> Bool,
        audience: String,
        nonce: String,
        issuedAt: Int64,
        signer: any JwsSigner,
        extraClaims: [(String, JsonValue)] = []
    ) async throws -> SdJwt {
        let bare = try present(issued, select: select)
        let sdHash = Base64Url.encode(sha256([UInt8](bare.presentationWithoutKb().utf8)))
        let header = JsonValue.obj([
            ("typ", .str("kb+jwt")),
            ("alg", .str(signer.algorithm.jwsName)),
        ])
        let payload = JsonValue.obj([
            ("iat", .numInt(issuedAt)),
            ("aud", .str(audience)),
            ("nonce", .str(nonce)),
            ("sd_hash", .str(sdHash)),
        ] + extraClaims)
        let kb = try await Jws.sign(header: header, payload: [UInt8](payload.serialize().utf8), signer: signer)
        return SdJwt(jwt: bare.jwt, disclosures: bare.disclosures, kbJwt: kb.compact())
    }
}

/* ---------- issuance ---------- */

public struct SdArrayElement {
    let value: JsonValue
    let selectivelyDisclosable: Bool

    public static func plain(_ value: JsonValue) -> SdArrayElement {
        SdArrayElement(value: value, selectivelyDisclosable: false)
    }

    public static func sd(_ value: JsonValue) -> SdArrayElement {
        SdArrayElement(value: value, selectivelyDisclosable: true)
    }
}

public final class SdObjectBuilder {
    enum Part {
        case plain(String, JsonValue)
        case sd(String, JsonValue)
        case plainObj(String, SdObjectBuilder)
        case sdObj(String, SdObjectBuilder)
        case arr(String, [SdArrayElement])
    }

    var parts: [Part] = []

    public init() {}

    public func claim(_ name: String, _ value: JsonValue) { parts.append(.plain(name, value)) }
    public func claim(_ name: String, _ value: String) { claim(name, .str(value)) }
    public func claim(_ name: String, _ value: Int64) { claim(name, .numInt(value)) }
    public func sd(_ name: String, _ value: JsonValue) { parts.append(.sd(name, value)) }
    public func sd(_ name: String, _ value: String) { sd(name, .str(value)) }

    public func obj(_ name: String, _ block: (SdObjectBuilder) -> Void) {
        let b = SdObjectBuilder()
        block(b)
        parts.append(.plainObj(name, b))
    }

    public func sdObj(_ name: String, _ block: (SdObjectBuilder) -> Void) {
        let b = SdObjectBuilder()
        block(b)
        parts.append(.sdObj(name, b))
    }

    public func arr(_ name: String, _ elements: [SdArrayElement]) {
        parts.append(.arr(name, elements))
    }

    func build(salt: () -> String, out: inout [Disclosure], decoys: Int = 0) throws -> JsonValue {
        var entries: [(String, JsonValue)] = []
        var sdDigests: [String] = []

        func disclose(_ name: String, _ value: JsonValue) throws {
            let d = try Disclosure.objectProperty(salt: salt(), name: name, value: value)
            out.append(d)
            sdDigests.append(d.digest)
        }

        for part in parts {
            switch part {
            case let .plain(name, value):
                entries.append((name, value))
            case let .sd(name, value):
                try disclose(name, value)
            case let .plainObj(name, builder):
                entries.append((name, try builder.build(salt: salt, out: &out, decoys: decoys)))
            case let .sdObj(name, builder):
                try disclose(name, try builder.build(salt: salt, out: &out, decoys: decoys))
            case let .arr(name, elements):
                var items: [JsonValue] = []
                for element in elements {
                    if element.selectivelyDisclosable {
                        let d = Disclosure.arrayElement(salt: salt(), value: element.value)
                        out.append(d)
                        items.append(.obj([("...", .str(d.digest))]))
                    } else {
                        items.append(element.value)
                    }
                }
                entries.append((name, .arr(items)))
            }
        }
        // decoy digests (RFC 9901 §4.2.5): hash of fresh salt — indistinguishable from real ones
        if !sdDigests.isEmpty && decoys > 0 {
            for _ in 0..<decoys {
                sdDigests.append(Base64Url.encode(sha256([UInt8](salt().utf8))))
            }
        }
        // sorted for determinism (RFC allows any order; production may shuffle via Rng later)
        if !sdDigests.isEmpty {
            entries.append(("_sd", .arr(sdDigests.sorted().map { .str($0) })))
        }
        return .obj(entries)
    }
}

public struct SdJwtIssuer {
    private let saltProvider: () -> String

    public init(saltProvider: @escaping () -> String) {
        self.saltProvider = saltProvider
    }

    public static func randomSalts(_ rng: any Rng) -> () -> String {
        { Base64Url.encode(rng.nextBytes(16)) }
    }

    public func issue(
        signer: any JwsSigner,
        holderKey: EcPublicKey? = nil,
        typ: String = "dc+sd-jwt",
        decoysPerSdStruct: Int = 0,
        _ block: (SdObjectBuilder) -> Void
    ) async throws -> SdJwt {
        var disclosures: [Disclosure] = []
        let builder = SdObjectBuilder()
        block(builder)
        let body = try builder.build(salt: saltProvider, out: &disclosures, decoys: decoysPerSdStruct)

        guard case var .obj(entries) = body else { throw SdJwtError("internal: body must be object") }
        entries.append(("_sd_alg", .str("sha-256")))
        if let holderKey {
            entries.append(("cnf", .obj([("jwk", JwkEc.toJson(holderKey))])))
        }

        let header = JsonValue.obj([
            ("typ", .str(typ)),
            ("alg", .str(signer.algorithm.jwsName)),
        ])
        let jws = try await Jws.sign(
            header: header,
            payload: [UInt8](JsonValue.obj(entries).serialize().utf8),
            signer: signer
        )
        return SdJwt(jwt: jws.compact(), disclosures: disclosures)
    }
}
