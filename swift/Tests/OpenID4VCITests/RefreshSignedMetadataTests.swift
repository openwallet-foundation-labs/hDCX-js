import CborCose
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VCI

/// Minor HAIP gaps: refresh-token reissuance (RFC 6749 §6) and signed issuer metadata
/// (OpenID4VCI §12.2.2 content negotiation + §12.2.3 signed-metadata rules).
final class RefreshSignedMetadataTests: XCTestCase {

    private let now: Int64 = 1_700_000_000
    private let issuer = "https://issuer.example"

    private struct TestRng: Rng {
        func nextBytes(_ size: Int) -> [UInt8] { (0..<size).map { UInt8(($0 + 1) & 0xff) } }
    }

    /// Verifier: proves the JWS signature against the issuer key (trust is the adapter's job).
    private struct TestVerifier: SignedMetadataVerifier {
        let key: EcPublicKey
        func verify(signedMetadataJws: String) async throws -> JsonValue {
            let jws = try Jws.parse(signedMetadataJws)
            guard jws.verify(key: key, expected: .es256) else { throw VciError.metadata("bad signed metadata signature") }
            return try JsonValue.parse(try Base64Url.decodeToString(jws.payloadB64))
        }
    }

    private func makeKeys(_ area: SoftwareSecureArea) async throws -> IssuanceKeys {
        let proofKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpopKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        return IssuanceKeys(
            proofSigner: SecureAreaJwsSigner(area: area, key: proofKey.handle, algorithm: .es256), proofPublicKey: proofKey.publicKey,
            dpopSigner: SecureAreaJwsSigner(area: area, key: dpopKey.handle, algorithm: .es256), dpopPublicKey: dpopKey.publicKey
        )
    }

    /// A §12.2.3 payload: the metadata parameters as top-level claims, plus sub/iat (and optionally exp).
    private func metadataClaims(
        sub: String? = nil,
        iat: Int64? = 1_700_000_000,
        exp: Int64? = nil,
        nonceEndpoint: String? = nil
    ) -> JsonValue {
        var entries: [(String, JsonValue)] = [
            ("credential_issuer", .str(issuer)),
            ("credential_endpoint", .str("\(issuer)/credential")),
            ("nonce_endpoint", .str(nonceEndpoint ?? "\(issuer)/signed-nonce")),
            ("sub", .str(sub ?? issuer)),
        ]
        if let iat { entries.append(("iat", .numInt(iat))) }
        if let exp { entries.append(("exp", .numInt(exp))) }
        return .obj(entries)
    }

    private func signMetadata(
        _ area: SoftwareSecureArea,
        _ key: KeyInfo,
        _ payload: JsonValue? = nil,
        typ: String = signedMetadataTyp
    ) async throws -> String {
        let header = JsonValue.obj([("alg", .str("ES256")), ("typ", .str(typ))])
        let jws = try await Jws.sign(header: header, payload: [UInt8]((payload ?? metadataClaims()).serialize().utf8),
                                     signer: SecureAreaJwsSigner(area: area, key: key.handle, algorithm: .es256))
        return jws.compact()
    }

    private func client(_ mock: MockIssuer, _ key: EcPublicKey, require: Bool = true) -> Openid4VciClient {
        Openid4VciClient(
            http: mock, rng: TestRng(), clock: { self.now },
            metadataPolicy: require ? .requireSigned(TestVerifier(key: key)) : .preferSigned(TestVerifier(key: key))
        )
    }

    private func expectMetadataError(_ mock: MockIssuer, _ key: EcPublicKey, _ message: String) async {
        do {
            _ = try await client(mock, key).loadIssuerMetadata(issuer)
            XCTFail(message)
        } catch VciError.metadata {
        } catch {
            XCTFail("\(message) — got \(error)")
        }
    }

    func testReissueWithRefreshToken() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        let client = Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now })

        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        let first = try await client.issueWithPreAuthorizedCode(offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: try await makeKeys(area), txCode: "1234")
        XCTAssertEqual(1, first.credentials.count)
        XCTAssertTrue(first.canReissue, "issuer granted a refresh token")

        let renewed = try await client.reissue(first, keys: try await makeKeys(area))
        XCTAssertEqual(1, renewed.credentials.count)
        XCTAssertTrue(renewed.canReissue)
    }

    func testRequireSignedUsesVerifiedMetadata() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setSignedMetadata(try await signMetadata(area, issuerKey))

        let meta = try await client(mock, issuerKey.publicKey).loadIssuerMetadata(issuer)

        XCTAssertEqual(issuer, meta.credentialIssuer)
        XCTAssertEqual("\(issuer)/signed-nonce", meta.nonceEndpoint) // came from the JWT payload, not the JSON
        let accept = await mock.lastMetadataAccept
        XCTAssertEqual("application/jwt", accept) // §12.2.2: signalled signed-only
    }

    func testIgnoreSignedAsksForJsonOnly() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setSignedMetadata(try await signMetadata(area, issuerKey))

        let meta = try await Openid4VciClient(http: mock, rng: TestRng(), clock: { self.now }).loadIssuerMetadata(issuer)

        let accept = await mock.lastMetadataAccept
        XCTAssertEqual("application/json", accept)
        XCTAssertEqual("\(issuer)/nonce", meta.nonceEndpoint) // unsigned JSON; signed metadata never requested
    }

    func testPreferSignedUsesSignedThenFallsBackToJson() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))

        let signing = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await signing.setSignedMetadata(try await signMetadata(area, issuerKey))
        let signed = try await client(signing, issuerKey.publicKey, require: false).loadIssuerMetadata(issuer)
        XCTAssertEqual("\(issuer)/signed-nonce", signed.nonceEndpoint)
        let accept = await signing.lastMetadataAccept
        XCTAssertTrue(accept!.contains("application/jwt"))

        let unsigned = MockIssuer(area: area, issuerKey: issuerKey, now: now) // does not sign — must not fail
        let plain = try await client(unsigned, issuerKey.publicKey, require: false).loadIssuerMetadata(issuer)
        XCTAssertEqual("\(issuer)/nonce", plain.nonceEndpoint)
    }

    func testRequireSignedRejectsUnsignedMetadata() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now) // no signed metadata

        await expectMetadataError(mock, issuerKey.publicKey, "expected metadata error")
    }

    func testRequireSignedRejectsBadSignature() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let rogue = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setSignedMetadata(try await signMetadata(area, rogue))

        await expectMetadataError(mock, issuerKey.publicKey, "expected bad signature")
    }

    func testRejectsWrongTyp() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setSignedMetadata(try await signMetadata(area, issuerKey, typ: "jwt"))

        await expectMetadataError(mock, issuerKey.publicKey, "expected typ rejection")
    }

    func testRejectsSymmetricAlg() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        // §12.2.3: alg MUST NOT be `none` or a MAC — rejected on the header, before any signature check.
        let header = #"{"alg":"HS256","typ":"\#(signedMetadataTyp)"}"#
        let jws = Base64Url.encode([UInt8](header.utf8)) + "."
            + Base64Url.encode([UInt8](metadataClaims().serialize().utf8)) + ".c2ln"
        await mock.setSignedMetadata(jws)

        await expectMetadataError(mock, issuerKey.publicKey, "expected alg rejection")
    }

    func testRejectsSubMismatch() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setSignedMetadata(try await signMetadata(area, issuerKey, metadataClaims(sub: "https://evil.example")))

        await expectMetadataError(mock, issuerKey.publicKey, "expected sub rejection")
    }

    func testRejectsMissingIat() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setSignedMetadata(try await signMetadata(area, issuerKey, metadataClaims(iat: nil)))

        await expectMetadataError(mock, issuerKey.publicKey, "expected iat rejection")
    }

    func testRejectsExpiredMetadata() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        await mock.setSignedMetadata(try await signMetadata(area, issuerKey, metadataClaims(exp: now - 1)))

        await expectMetadataError(mock, issuerKey.publicKey, "expected exp rejection")
    }
}
