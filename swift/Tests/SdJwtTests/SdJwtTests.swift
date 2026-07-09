import CborCose
import Foundation
import WalletAPI
import WalletTestKit
import XCTest
@testable import SdJwt

final class DisclosureVectorTests: XCTestCase {

    private func vectorsURL() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("vectors/sdjwt/rfc9901-disclosures.json")
    }

    /// RFC 9901 example disclosures, extracted from the RFC text and self-verified at extraction time.
    func testRfc9901Disclosures() throws {
        let text = try String(contentsOf: vectorsURL(), encoding: .utf8)
        let root = try JsonValue.parse(text)
        guard case let .arr(vectors)? = root["vectors"] else { return XCTFail("bad vector file") }
        XCTAssertGreaterThan(vectors.count, 50)

        for entry in vectors {
            guard case let .str(digest)? = entry["digest"],
                  case let .str(encoded)? = entry["disclosure"],
                  case let .str(contents)? = entry["contents"]
            else { return XCTFail("bad vector entry") }

            let disclosure = try Disclosure.parse(encoded)
            XCTAssertEqual(digest, disclosure.digest, "digest mismatch for \(encoded)")

            guard case let .arr(items) = try JsonValue.parse(contents) else {
                return XCTFail("contents not an array")
            }
            guard case let .str(salt) = items[0] else { return XCTFail("salt not a string") }
            XCTAssertEqual(salt, disclosure.salt)
            switch items.count {
            case 2:
                XCTAssertNil(disclosure.claimName)
                XCTAssertEqual(items[1], disclosure.value)
            case 3:
                guard case let .str(name) = items[1] else { return XCTFail("name not a string") }
                XCTAssertEqual(name, disclosure.claimName)
                XCTAssertEqual(items[2], disclosure.value)
            default:
                XCTFail("unexpected contents arity")
            }
        }
    }

    func testEncodeParseRoundtrip() throws {
        let d = try Disclosure.objectProperty(salt: "salt-123", name: "given_name", value: JsonValue.str("John"))
        let parsed = try Disclosure.parse(d.encoded)
        XCTAssertEqual(d.salt, parsed.salt)
        XCTAssertEqual(d.claimName, parsed.claimName)
        XCTAssertEqual(d.value, parsed.value)
        XCTAssertEqual(d.digest, parsed.digest)
    }
}

final class SdJwtE2eTests: XCTestCase {

    private func fixedSalts() -> () -> String {
        var n = 0
        return {
            n += 1
            return String(format: "salt-%02d", n)
        }
    }

    private func issueSample(
        issuerSigner: any JwsSigner,
        holderKey: EcPublicKey
    ) async throws -> SdJwt {
        try await SdJwtIssuer(saltProvider: fixedSalts()).issue(signer: issuerSigner, holderKey: holderKey) { b in
            b.claim("iss", "https://issuer.example")
            b.claim("iat", Int64(1_700_000_000))
            b.claim("vct", "urn:eudi:pid:1")
            b.sd("given_name", "John")
            b.sd("family_name", "Doe")
            b.sd("email", JsonValue.str("john@example.com"))
            b.obj("address") { a in
                a.sd("street_address", JsonValue.str("Main St 1"))
                a.claim("country", "DE")
            }
            b.arr("nationalities", [.sd(JsonValue.str("DE")), .plain(JsonValue.str("US"))])
            b.sdObj("secret_box") { s in
                s.sd("inner", JsonValue.str("treasure"))
            }
        }
    }

    func testIssuePresentVerify() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let holderKeyInfo = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let issuerSigner = SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256)
        let holderSigner = SecureAreaJwsSigner(area: area, key: holderKeyInfo.handle, algorithm: .es256)

        let issued = try await issueSample(issuerSigner: issuerSigner, holderKey: holderKeyInfo.publicKey)

        // serialization roundtrip
        let reparsed = try SdJwt.parse(issued.serialize())
        XCTAssertEqual(issued.disclosures.map(\.encoded), reparsed.disclosures.map(\.encoded))
        XCTAssertNil(reparsed.kbJwt)

        // full verification (all disclosures, no KB)
        let full = try SdJwtVerifier.verify(reparsed, issuerKey: issuerKey.publicKey, algorithm: .es256)
        XCTAssertEqual(JsonValue.str("John"), full.claims["given_name"])
        XCTAssertEqual(JsonValue.str("Doe"), full.claims["family_name"])
        XCTAssertEqual(JsonValue.str("Main St 1"), full.claims["address"]?["street_address"])
        XCTAssertEqual(JsonValue.arr([JsonValue.str("DE"), JsonValue.str("US")]), full.claims["nationalities"])
        XCTAssertEqual(JsonValue.str("treasure"), full.claims["secret_box"]?["inner"])
        XCTAssertNil(full.claims["_sd_alg"])
        XCTAssertNil(full.claims["_sd"])

        // subset presentation with key binding
        let wanted: Set<[String]> = [
            ["given_name"],
            ["address", "street_address"],
            ["secret_box", "inner"],
        ]
        let presented = try await SdJwtHolder.presentWithKeyBinding(
            issued,
            select: { wanted.contains($0) },
            audience: "https://verifier.example",
            nonce: "nonce-123",
            issuedAt: 1_700_000_100,
            signer: holderSigner
        )

        let verified = try SdJwtVerifier.verify(
            try SdJwt.parse(presented.serialize()),
            issuerKey: issuerKey.publicKey,
            algorithm: .es256,
            keyBinding: SdJwtVerifier.KbRequirement(audience: "https://verifier.example", nonce: "nonce-123", now: { 1_700_000_100 })
        )
        XCTAssertEqual(JsonValue.str("John"), verified.claims["given_name"])
        XCTAssertNil(verified.claims["family_name"], "family_name must stay undisclosed")
        XCTAssertNil(verified.claims["email"])
        XCTAssertEqual(JsonValue.str("Main St 1"), verified.claims["address"]?["street_address"])
        XCTAssertEqual(JsonValue.str("treasure"), verified.claims["secret_box"]?["inner"], "recursive parent auto-included")
        XCTAssertEqual(JsonValue.arr([JsonValue.str("US")]), verified.claims["nationalities"], "undisclosed sd array element omitted")
    }

    func testNegativeCases() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let holderKeyInfo = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let wrongKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let issuerSigner = SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256)
        let holderSigner = SecureAreaJwsSigner(area: area, key: holderKeyInfo.handle, algorithm: .es256)

        let issued = try await issueSample(issuerSigner: issuerSigner, holderKey: holderKeyInfo.publicKey)

        // wrong issuer key
        XCTAssertThrowsError(try SdJwtVerifier.verify(issued, issuerKey: wrongKey.publicKey, algorithm: .es256))

        // tampered disclosure -> unused disclosure error
        let forged = try Disclosure.objectProperty(salt: "salt-99", name: "given_name", value: JsonValue.str("Mallory"))
        let tampered = SdJwt(jwt: issued.jwt, disclosures: issued.disclosures.dropLast() + [forged])
        XCTAssertThrowsError(try SdJwtVerifier.verify(tampered, issuerKey: issuerKey.publicKey, algorithm: .es256))

        let presented = try await SdJwtHolder.presentWithKeyBinding(
            issued,
            select: { _ in true },
            audience: "https://verifier.example",
            nonce: "nonce-123",
            issuedAt: 1_700_000_100,
            signer: holderSigner
        )

        // nonce mismatch
        XCTAssertThrowsError(
            try SdJwtVerifier.verify(
                presented, issuerKey: issuerKey.publicKey, algorithm: .es256,
                keyBinding: SdJwtVerifier.KbRequirement(audience: "https://verifier.example", nonce: "other", now: { 1_700_000_100 })
            )
        )

        // sd_hash mismatch: drop a disclosure after KB was bound
        let stripped = SdJwt(
            jwt: presented.jwt,
            disclosures: Array(presented.disclosures.dropFirst()),
            kbJwt: presented.kbJwt
        )
        XCTAssertThrowsError(
            try SdJwtVerifier.verify(
                stripped, issuerKey: issuerKey.publicKey, algorithm: .es256,
                keyBinding: SdJwtVerifier.KbRequirement(audience: "https://verifier.example", nonce: "nonce-123", now: { 1_700_000_100 })
            )
        )

        // KB required but missing
        XCTAssertThrowsError(
            try SdJwtVerifier.verify(
                issued, issuerKey: issuerKey.publicKey, algorithm: .es256,
                keyBinding: SdJwtVerifier.KbRequirement(audience: "https://verifier.example", nonce: "nonce-123", now: { 1_700_000_100 })
            )
        )
    }

    func testDecoysAndX5cHeader() async throws {
        let area = SoftwareSecureArea()
        let k = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let signer = SecureAreaJwsSigner(area: area, key: k.handle, algorithm: .es256)

        let issued = try await SdJwtIssuer(saltProvider: fixedSalts()).issue(signer: signer, decoysPerSdStruct: 3) { b in
            b.sd("given_name", "John")
        }
        let v = try SdJwtVerifier.verify(issued, issuerKey: k.publicKey, algorithm: .es256)
        XCTAssertEqual(JsonValue.str("John"), v.claims["given_name"])
        guard case let .arr(sd)? = v.payload["_sd"] else { return XCTFail("no _sd") }
        XCTAssertEqual(4, sd.count, "1 real + 3 decoy digests")

        let cert: [UInt8] = [0x30, 0x01, 0x02]
        let header = JsonValue.obj([
            ("alg", JsonValue.str("ES256")),
            ("x5c", JsonValue.arr([JsonValue.str(Data(cert).base64EncodedString())])),
        ])
        XCTAssertEqual([cert], Jws(header: header, headerB64: "h", payloadB64: "p", signature: []).x5c)
    }

    func testJsonSerializerBasics() throws {
        let obj = JsonValue.obj([
            ("b", JsonValue.str("q\"\\\n")),
            ("a", JsonValue.numInt(-42)),
            ("c", JsonValue.arr([JsonValue.bool(true), JsonValue.null])),
        ])
        let text = obj.serialize()
        XCTAssertEqual("{\"b\":\"q\\\"\\\\\\n\",\"a\":-42,\"c\":[true,null]}", text)
        XCTAssertEqual(obj, try JsonValue.parse(text), "parse(serialize()) must be identity")
        XCTAssertEqual(JsonValue.str("😀ü水"), try JsonValue.parse("\"\\ud83d\\ude00ü水\""))
        XCTAssertThrowsError(try JsonValue.parse("{} trailing"))
        XCTAssertThrowsError(try JsonValue.parse("{\"a\":1,\"a\":2}"))
        XCTAssertThrowsError(try JsonValue.parse("{\"a\":}"))
        XCTAssertEqual(JsonValue.numInt(9_007_199_254_740_993), try JsonValue.parse("9007199254740993"), "big integers stay exact")
    }
}
