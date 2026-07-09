import CborCose
import Foundation
import WalletAPI
import WalletTestKit
import XCTest
@testable import SdJwt

/// RFC 9901 verification rules that had no test:
///  - §7.1(2.a) / §7.3(5.b): "The `none` algorithm MUST NOT be accepted."
///  - §7.3(5.e): the KB-JWT's `iat` must fall "within an acceptable window" — presence is not enough,
///    or a KB-JWT minted long ago would still authorise a presentation today.
final class SdJwtVerifierHardeningTests: XCTestCase {

    private let audience = "https://verifier.example"
    private let nonce = "nonce-123"
    private let presentedAt: Int64 = 1_700_000_100

    private struct Party {
        let issuer: EcPublicKey
        let issued: SdJwt
        let holderSigner: any JwsSigner
    }

    private func party() async throws -> Party {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let holderKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        var n = 0
        let issued = try await SdJwtIssuer(saltProvider: { n += 1; return "salt-\(n)" }).issue(
            signer: SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256),
            holderKey: holderKey.publicKey
        ) { b in
            b.claim("iss", .str("https://issuer.example"))
            b.sd("family_name", .str("Han"))
        }
        return Party(issuer: issuerKey.publicKey, issued: issued,
                     holderSigner: SecureAreaJwsSigner(area: area, key: holderKey.handle, algorithm: .es256))
    }

    private func present(_ p: Party, issuedAt: Int64) async throws -> SdJwt {
        try await SdJwtHolder.presentWithKeyBinding(
            p.issued, select: { _ in true }, audience: audience, nonce: nonce,
            issuedAt: issuedAt, signer: p.holderSigner)
    }

    private func kb(now: Int64, maxAge: Int64 = 300, skew: Int64 = 60) -> SdJwtVerifier.KbRequirement {
        SdJwtVerifier.KbRequirement(audience: audience, nonce: nonce, now: { now }, maxAgeSeconds: maxAge, skewSeconds: skew)
    }

    /// Re-headers a compact JWS as `alg: none` while keeping the original signature bytes, so it survives
    /// `Jws.parse` (which rejects an *empty* signature segment) and reaches the algorithm check.
    private func forgeNoneAlg(_ compact: String, typ: String?) -> String {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let headerJson = typ.map { #"{"alg":"none","typ":"\#($0)"}"# } ?? #"{"alg":"none"}"#
        return "\(Base64Url.encode([UInt8](headerJson.utf8))).\(parts[1]).\(parts[2])"
    }

    // MARK: §7.3(5.e) — the iat window

    func testAcceptsAFreshKeyBindingJwt() async throws {
        let p = try await party()
        let presented = try await present(p, issuedAt: presentedAt)
        _ = try SdJwtVerifier.verify(presented, issuerKey: p.issuer, algorithm: .es256, keyBinding: kb(now: presentedAt + 10))
    }

    /// The gap this closes: presence alone let a months-old KB-JWT through.
    func testRejectsAStaleKeyBindingJwt() async throws {
        let p = try await party()
        let presented = try await present(p, issuedAt: presentedAt)
        do {
            _ = try SdJwtVerifier.verify(presented, issuerKey: p.issuer, algorithm: .es256, keyBinding: kb(now: presentedAt + 301))
            XCTFail("a stale KB-JWT must be rejected")
        } catch let error as SdJwtError {
            XCTAssertTrue("\(error)".contains("old"), "the error explains the window: \(error)")
        }
    }

    func testRejectsAKeyBindingJwtFromTheFuture() async throws {
        let p = try await party()
        let presented = try await present(p, issuedAt: presentedAt + 3600) // holder clock an hour fast
        do {
            _ = try SdJwtVerifier.verify(presented, issuerKey: p.issuer, algorithm: .es256, keyBinding: kb(now: presentedAt))
            XCTFail("a future-dated KB-JWT must be rejected")
        } catch is SdJwtError {}
    }

    /// A holder clock slightly ahead is tolerated — that is what `skewSeconds` is for.
    func testToleratesSmallClockSkew() async throws {
        let p = try await party()
        let presented = try await present(p, issuedAt: presentedAt + 30)
        _ = try SdJwtVerifier.verify(presented, issuerKey: p.issuer, algorithm: .es256, keyBinding: kb(now: presentedAt, skew: 60))
    }

    // MARK: §7.1(2.a) / §7.3(5.b) — alg=none

    func testRejectsNoneAlgOnTheIssuerSignedJwt() async throws {
        let p = try await party()
        let forged = SdJwt(jwt: forgeNoneAlg(p.issued.jwt, typ: nil), disclosures: p.issued.disclosures, kbJwt: nil)
        do {
            _ = try SdJwtVerifier.verify(forged, issuerKey: p.issuer, algorithm: .es256)
            XCTFail("alg=none on the issuer JWT must be rejected")
        } catch let error as SdJwtError {
            XCTAssertTrue("\(error)".contains("none"), "the refusal names the algorithm: \(error)")
        }
    }

    func testRejectsNoneAlgOnTheKeyBindingJwt() async throws {
        let p = try await party()
        let presented = try await present(p, issuedAt: presentedAt)
        let forged = SdJwt(jwt: presented.jwt, disclosures: presented.disclosures,
                           kbJwt: forgeNoneAlg(presented.kbJwt!, typ: "kb+jwt"))
        do {
            _ = try SdJwtVerifier.verify(forged, issuerKey: p.issuer, algorithm: .es256, keyBinding: kb(now: presentedAt))
            XCTFail("alg=none on the KB-JWT must be rejected")
        } catch let error as SdJwtError {
            XCTAssertTrue("\(error)".contains("none"), "the refusal names the algorithm: \(error)")
        }
    }
}
