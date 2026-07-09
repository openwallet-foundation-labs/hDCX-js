import CborCose
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VP

/// OpenID4VP DCQL `require_cryptographic_holder_binding` (§6.1): default true — the SD-JWT VC is presented
/// with a KB-JWT. When the verifier sets it false, the credential is presented without one.
final class HolderBindingTests: XCTestCase {

    private let now: Int64 = 1_700_000_000
    private let clientId = "verifier.example"

    private func enc(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    private actor Capturing: HttpTransport {
        private(set) var vpToken: JsonValue?
        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            let bodyStr = String(bytes: request.body ?? [], encoding: .utf8) ?? ""
            for pair in bodyStr.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                if String(kv[0]).removingPercentEncoding == "vp_token", kv.count > 1 {
                    vpToken = try? JsonValue.parse(String(kv[1]).removingPercentEncoding ?? "")
                }
            }
            return HttpResponse(status: 200, headers: [("Content-Type", "application/json")], body: [UInt8]("{}".utf8))
        }
    }

    private func requestUri(_ requireBinding: Bool?) -> String {
        let bind = requireBinding.map { #","require_cryptographic_holder_binding":\#($0 ? "true" : "false")"# } ?? ""
        let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]\#(bind)}]}"#
        return "openid4vp://?client_id=\(enc(clientId))&nonce=vp-nonce-123&response_mode=direct_post&response_uri=\(enc("https://verifier.example/response"))&state=x&dcql_query=\(enc(dcql))"
    }

    private func presentFor(_ requireBinding: Bool?) async throws -> SdJwt {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let holderKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        var n = 0
        let pid = try await SdJwtIssuer(saltProvider: { n += 1; return "salt-\(n)" }).issue(
            signer: SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256), holderKey: holderKey.publicKey
        ) { b in
            b.claim("iss", "https://issuer.example"); b.claim("vct", "urn:eudi:pid:1")
            b.sd("family_name", "Han"); b.sd("given_name", "Jongho")
        }
        let held: [any PresentableCredential] = [
            try HeldSdJwtVc(credentialId: "pid-1", sdJwt: pid, holderSigner: SecureAreaJwsSigner(area: area, key: holderKey.handle, algorithm: .es256)),
        ]
        let http = Capturing()
        let client = Openid4VpClient(http: http, clock: { self.now })
        let request = try await client.resolveRequest(requestUri(requireBinding))
        let matches = client.match(request, held: held)
        _ = try await client.respond(request: request, matches: matches, selection: .auto(matches), held: held)
        guard case let .arr(arr)? = await http.vpToken?["pid"], case let .str(s) = arr[0] else {
            throw VpError.responseFailed("no pid presentation")
        }
        return try SdJwt.parse(s)
    }

    private func disclosed(_ sdJwt: SdJwt, _ name: String) -> String? {
        guard let d = sdJwt.disclosures.first(where: { $0.claimName == name }), case let .str(v) = d.value else { return nil }
        return v
    }

    func testBindsWithKbJwtByDefault() async throws {
        let presented = try await presentFor(nil) // default true
        XCTAssertNotNil(presented.kbJwt, "a KB-JWT is appended by default")
        XCTAssertEqual("Han", disclosed(presented, "family_name"))
    }

    func testOmitsKbJwtWhenBindingNotRequired() async throws {
        let presented = try await presentFor(false)
        XCTAssertNil(presented.kbJwt, "no KB-JWT when require_cryptographic_holder_binding is false")
        XCTAssertTrue(presented.serialize().hasSuffix("~"), "serialization ends with a bare '~' (no key binding)")
        XCTAssertEqual("Han", disclosed(presented, "family_name"), "selective disclosure still works")
    }

    func testStillBindsWhenExplicitlyRequired() async throws {
        let presented = try await presentFor(true)
        XCTAssertNotNil(presented.kbJwt, "explicit true keeps the KB-JWT")
    }
}
