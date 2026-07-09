import CborCose
import Crypto
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VP

final class VpE2eTests: XCTestCase {

    private let now: Int64 = 1_700_000_000

    private func enc(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    private actor MockVerifier: HttpTransport {
        let clientId = "verifier.example"
        let nonce = "vp-nonce-123"
        let responseUri = "https://verifier.example/response"
        private let issuerPublic: EcPublicKey
        private let encPubJwk: JsonValue
        private let encPrivD: [UInt8]
        private(set) var verifiedClaims: JsonValue?

        init(issuerPublic: EcPublicKey) {
            self.issuerPublic = issuerPublic
            let priv = P256.KeyAgreement.PrivateKey()
            let raw = priv.publicKey.rawRepresentation
            let ec = EcPublicKey(curve: .p256, x: [UInt8](raw.prefix(32)), y: [UInt8](raw.suffix(32)))
            if case let .obj(entries) = JwkEc.toJson(ec) {
                encPubJwk = .obj(entries + [("use", .str("enc")), ("alg", .str("ECDH-ES")), ("kid", .str("verifier-enc-key-1"))])
            } else {
                encPubJwk = JwkEc.toJson(ec)
            }
            encPrivD = [UInt8](priv.rawRepresentation)
        }

        func makeRequestUri(_ responseMode: String, encode: (String) -> String) -> String {
            let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}"#
            let clientMetadata = JsonValue.obj([
                ("jwks", .obj([("keys", .arr([encPubJwk]))])),
                ("encrypted_response_enc_values_supported", .arr([.str("A256GCM")])),
            ]).serialize()
            return "openid4vp://?client_id=\(encode(clientId))&nonce=\(encode(nonce))&response_mode=\(responseMode)&response_uri=\(encode(responseUri))&state=xyz&dcql_query=\(encode(dcql))&client_metadata=\(encode(clientMetadata))"
        }

        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            guard request.url == responseUri, request.method == .post else {
                return HttpResponse(status: 404, headers: [], body: [])
            }
            let bodyStr = String(bytes: request.body ?? [], encoding: .utf8) ?? ""
            var form: [String: String] = [:]
            for pair in bodyStr.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                form[String(kv[0]).removingPercentEncoding ?? ""] = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? "") : ""
            }
            let vpToken: JsonValue
            if let response = form["response"] {
                let dec = try Jwe.decryptEcdhEs(response, recipientPrivateD: encPrivD)
                let obj = try JsonValue.parse(String(bytes: dec, encoding: .utf8)!)
                vpToken = obj["vp_token"]!
            } else {
                vpToken = try JsonValue.parse(form["vp_token"]!)
            }
            guard case let .arr(items)? = vpToken["pid"], case let .str(presentation) = items[0] else {
                throw VpError.responseFailed("no pid presentation")
            }
            let verified = try SdJwtVerifier.verify(
                try SdJwt.parse(presentation), issuerKey: issuerPublic, algorithm: .es256,
                keyBinding: SdJwtVerifier.KbRequirement(audience: clientId, nonce: nonce, now: { 1_700_000_000 })
            )
            verifiedClaims = verified.claims
            return HttpResponse(status: 200, headers: [("Content-Type", "application/json")],
                                body: [UInt8](#"{"redirect_uri":"https://verifier.example/done"}"#.utf8))
        }
    }

    private func issuePid(_ area: SoftwareSecureArea, _ issuerKey: KeyInfo, _ holderKey: KeyInfo) async throws -> SdJwt {
        var n = 0
        let salts: () -> String = { n += 1; return "salt-\(n)" }
        return try await SdJwtIssuer(saltProvider: salts).issue(
            signer: SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256),
            holderKey: holderKey.publicKey
        ) { b in
            b.claim("iss", "https://issuer.example")
            b.claim("vct", "urn:eudi:pid:1")
            b.sd("family_name", "Han")
            b.sd("given_name", "Jongho")
            b.sd("birthdate", "1990-05-15")
        }
    }

    private func runFlow(_ responseMode: String) async throws {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let holderKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let pid = try await issuePid(area, issuerKey, holderKey)
        let held = try HeldSdJwtVc(credentialId: "pid-1", sdJwt: pid,
                                   holderSigner: SecureAreaJwsSigner(area: area, key: holderKey.handle, algorithm: .es256))

        let verifier = MockVerifier(issuerPublic: issuerKey.publicKey)
        let client = Openid4VpClient(http: verifier, clock: { self.now })

        let uri = await verifier.makeRequestUri(responseMode, encode: enc)
        let request = try await client.resolveRequest(uri)
        XCTAssertEqual("verifier.example", request.clientId)
        let matches = client.match(request, held: [held])
        XCTAssertTrue(matches.isSatisfiable())

        let result = try await client.respond(request: request, matches: matches, selection: .auto(matches), held: [held])
        XCTAssertEqual("https://verifier.example/done", result.redirectUri)

        let claims = await verifier.verifiedClaims!
        XCTAssertEqual(JsonValue.str("Han"), claims["family_name"])
        XCTAssertEqual(JsonValue.str("Jongho"), claims["given_name"])
        XCTAssertNil(claims["birthdate"], "unrequested claim must not be disclosed")
    }

    func testDirectPostJwtEncryptedResponse() async throws { try await runFlow("direct_post.jwt") }
    func testDirectPostPlainResponse() async throws { try await runFlow("direct_post") }
}
