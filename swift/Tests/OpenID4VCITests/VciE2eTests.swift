import CborCose
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VCI

final class VciE2eTests: XCTestCase {

    private let now: Int64 = 1_700_000_000

    private struct CounterRng: Rng {
        final class Box: @unchecked Sendable { var n = 0 }
        let box = Box()
        func nextBytes(_ size: Int) -> [UInt8] {
            (0..<size).map { _ in box.n += 1; return UInt8((box.n & 0x7f) + 1) }
        }
    }

    private func makeKeys(_ area: SoftwareSecureArea) async throws -> IssuanceKeys {
        let proofKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpopKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        return IssuanceKeys(
            proofSigner: SecureAreaJwsSigner(area: area, key: proofKey.handle, algorithm: .es256),
            proofPublicKey: proofKey.publicKey,
            dpopSigner: SecureAreaJwsSigner(area: area, key: dpopKey.handle, algorithm: .es256),
            dpopPublicKey: dpopKey.publicKey
        )
    }

    func testPreAuthorizedFlowIssuesAndVerifiesSdJwtVc() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)

        let proofKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let dpopKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let keys = IssuanceKeys(
            proofSigner: SecureAreaJwsSigner(area: area, key: proofKey.handle, algorithm: .es256),
            proofPublicKey: proofKey.publicKey,
            dpopSigner: SecureAreaJwsSigner(area: area, key: dpopKey.handle, algorithm: .es256),
            dpopPublicKey: dpopKey.publicKey
        )

        let client = Openid4VciClient(http: mock, rng: CounterRng(), clock: { self.now })
        let offer = try CredentialOffer.parse(mock.credentialOfferJson)
        XCTAssertEqual("eu.europa.ec.eudi.pid.1", offer.credentialConfigurationIds.first)
        XCTAssertNotNil(offer.txCode)

        let response = try await client.issueWithPreAuthorizedCode(
            offer: offer, configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234"
        )

        let retried = await mock.seenDpopNonceRetry
        XCTAssertTrue(retried, "DPoP-Nonce retry path must be exercised")
        XCTAssertEqual(1, response.credentials.count)
        let credential = response.credentials[0].credential

        let verifier = SdJwtVcVerifier(
            issuerKeyResolver: JwtVcMetadataKeyResolver(http: mock),
            timeValidator: JwtTimeValidator(now: { Date(timeIntervalSince1970: TimeInterval(self.now)) })
        )
        let verified = try await verifier.verify(try SdJwt.parse(credential))

        XCTAssertEqual("eu.europa.ec.eudi.pid.1", verified.vct)
        XCTAssertEqual("https://issuer.example", verified.issuer)
        XCTAssertEqual(JsonValue.str("Doe"), verified.claims["family_name"])
        XCTAssertEqual(JsonValue.str("John"), verified.claims["given_name"])
        XCTAssertNotNil(verified.holderKey, "cnf holder key must be present")
        XCTAssertEqual(proofKey.publicKey.x, verified.holderKey?.x)
    }

    func testAuthorizationCodeFlowWithParIssuesCredential() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        let keys = try await makeKeys(area)
        let client = Openid4VciClient(http: mock, rng: CounterRng(), clock: { self.now })

        // Step 1: prepare (PAR pushed, authorization URL built)
        let prepared = try await client.prepareAuthorizationCodeIssuance(
            credentialIssuer: "https://issuer.example",
            configurationId: "eu.europa.ec.eudi.pid.1",
            redirectUri: "wallet://cb"
        )
        let usedPar = await mock.seenPar
        XCTAssertTrue(usedPar, "PAR endpoint must be used when the AS advertises it")
        XCTAssertTrue(prepared.authorizationUrl.hasPrefix("https://issuer.example/authorize?"))
        XCTAssertTrue(prepared.authorizationUrl.contains("request_uri="))

        // Step 2: emulate the browser hitting the authorization URL → redirect carrying the code
        let redirect = try await mock.execute(HttpRequest(method: .get, url: prepared.authorizationUrl))
        XCTAssertEqual(302, redirect.status)
        let location = redirect.headers.first { $0.0 == "Location" }!.1
        let code = String(location.split(separator: "=")[1].split(separator: "&")[0])

        // Step 3: finish (token via authorization_code + PKCE, then credential)
        let response = try await client.finishAuthorizationCodeIssuance(prepared: prepared, authorizationCode: code, keys: keys)
        XCTAssertEqual(1, response.credentials.count)

        let verifier = SdJwtVcVerifier(
            issuerKeyResolver: JwtVcMetadataKeyResolver(http: mock),
            timeValidator: JwtTimeValidator(now: { Date(timeIntervalSince1970: TimeInterval(self.now)) })
        )
        let verified = try await verifier.verify(try SdJwt.parse(response.credentials[0].credential))
        XCTAssertEqual("eu.europa.ec.eudi.pid.1", verified.vct)
        XCTAssertEqual(JsonValue.str("John"), verified.claims["given_name"])
    }

    func testExpiredCredentialIsRejected() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        let keys = try await makeKeys(area)
        let client = Openid4VciClient(http: mock, rng: CounterRng(), clock: { self.now })
        let credential = try await client.issueWithPreAuthorizedCode(
            offer: try CredentialOffer.parse(mock.credentialOfferJson),
            configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: "1234"
        ).credentials[0].credential

        let verifier = SdJwtVcVerifier(
            issuerKeyResolver: JwtVcMetadataKeyResolver(http: mock),
            timeValidator: JwtTimeValidator(now: { Date(timeIntervalSince1970: TimeInterval(self.now + 200_000)) })
        )
        do {
            _ = try await verifier.verify(try SdJwt.parse(credential))
            XCTFail("expired credential must be rejected")
        } catch is JwtTimeError {
            // expected
        }
    }

    func testTxCodeRequiredWhenMissing() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        let keys = try await makeKeys(area)
        let client = Openid4VciClient(http: mock, rng: CounterRng(), clock: { self.now })
        do {
            _ = try await client.issueWithPreAuthorizedCode(
                offer: try CredentialOffer.parse(mock.credentialOfferJson),
                configurationId: "eu.europa.ec.eudi.pid.1", keys: keys, txCode: nil
            )
            XCTFail("missing tx_code must throw")
        } catch VciError.txCodeRequired {
            // expected
        }
    }

    func testUnknownConfigurationRejected() async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mock = MockIssuer(area: area, issuerKey: issuerKey, now: now)
        let keys = try await makeKeys(area)
        let client = Openid4VciClient(http: mock, rng: CounterRng(), clock: { self.now })
        do {
            _ = try await client.issueWithPreAuthorizedCode(
                offer: try CredentialOffer.parse(mock.credentialOfferJson),
                configurationId: "unknown.config", keys: keys, txCode: "1234"
            )
            XCTFail("unknown config must throw")
        } catch VciError.invalidOffer {
            // expected
        }
    }
}
