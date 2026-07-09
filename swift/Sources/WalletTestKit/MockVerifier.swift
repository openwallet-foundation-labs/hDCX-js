import CborCose
import Crypto
import Foundation
import OpenID4VP
import SdJwt
import WalletAPI

/// A mock OpenID4VP verifier (HttpTransport): builds a request, receives & verifies an SD-JWT VC response.
public actor MockVerifier: HttpTransport {
    public let clientId = "verifier.example"
    public let nonce = "vp-nonce-123"
    public let responseUri = "https://verifier.example/response"
    private let issuerPublic: EcPublicKey
    private let encPubJwk: JsonValue
    private let encPrivD: [UInt8]
    public private(set) var verifiedClaims: JsonValue?

    /// The `kid` of the verifier's encryption JWK; §8.3 makes the wallet repeat it in the JWE header.
    public static let encKid = "verifier-enc-key-1"

    /// The clock the verifier judges the KB-JWT `iat` against (§7.3(5.e)); defaults to real time, which
    /// matches a live wallet clock. Override to pin it when the presentation uses a fixed `iat`.
    public var kbClock: () -> Int64 = { Int64(Date().timeIntervalSince1970) }
    public func setKbClock(_ clock: @escaping () -> Int64) { kbClock = clock }

    /// JWE header values the wallet sent on an encrypted response (§8.3 `kid`, 18013-7 B.5.3 `apv`).
    public private(set) var seenJweKid: String?
    public private(set) var seenJweApv: String?

    /// The Authorization Error Response the wallet POSTed instead of a `vp_token` (§8.5), if any.
    public struct ErrorResponse: Sendable {
        public let error: String
        public let description: String?
        public let state: String?
    }
    public private(set) var errorResponse: ErrorResponse?

    /// When true, the verifier rejects the submitted response with HTTP 400 (e.g. issuer not trusted).
    public var rejectResponse = false
    public func setRejectResponse(_ value: Bool) { rejectResponse = value }

    public init(issuerPublic: EcPublicKey) {
        self.issuerPublic = issuerPublic
        let priv = P256.KeyAgreement.PrivateKey()
        let raw = priv.publicKey.rawRepresentation
        let ec = EcPublicKey(curve: .p256, x: [UInt8](raw.prefix(32)), y: [UInt8](raw.suffix(32)))
        if case let .obj(entries) = JwkEc.toJson(ec) {
            // §8.3: `alg` MUST be present on the JWK; the wallet echoes `kid` into the JWE header.
            encPubJwk = .obj(entries + [("use", .str("enc")), ("alg", .str("ECDH-ES")), ("kid", .str(MockVerifier.encKid))])
        } else {
            encPubJwk = JwkEc.toJson(ec)
        }
        encPrivD = [UInt8](priv.rawRepresentation)
    }

    public func requestUri(_ responseMode: String) -> String {
        let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}"#
        let clientMetadata = JsonValue.obj([
            ("jwks", .obj([("keys", .arr([encPubJwk]))])),
            ("encrypted_response_enc_values_supported", .arr([.str("A256GCM")])),
        ]).serialize()
        return "openid4vp://?client_id=\(enc(clientId))&nonce=\(enc(nonce))&response_mode=\(responseMode)" +
            "&response_uri=\(enc(responseUri))&state=xyz&dcql_query=\(enc(dcql))&client_metadata=\(enc(clientMetadata))"
    }

    /// An unsigned Digital Credentials API request object (Appendix A.3.1): the origin is the verifier's
    /// identity, so it carries no `client_id` and no `response_uri` — nothing is ever POSTed for it.
    public func dcApiRequestObject() -> String {
        let dcql = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}"#
        return JsonValue.obj([
            ("response_type", .str("vp_token")),
            ("response_mode", .str("dc_api")),
            ("nonce", .str(nonce)),
            ("dcql_query", try! JsonValue.parse(dcql)),
        ]).serialize()
    }

    public func execute(_ request: HttpRequest) async throws -> HttpResponse {
        guard request.url == responseUri, request.method == .post else {
            return HttpResponse(status: 404, headers: [], body: [])
        }
        if rejectResponse {
            return HttpResponse(status: 400, headers: [], body: Array(#"{"error":"invalid_vp_token"}"#.utf8))
        }
        let bodyStr = String(bytes: request.body ?? [], encoding: .utf8) ?? ""
        var form: [String: String] = [:]
        for pair in bodyStr.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            form[String(kv[0]).removingPercentEncoding ?? ""] = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? "") : ""
        }
        // OpenID4VP §8.5: an Authorization Error Response lands on the same endpoint as the vp_token.
        if let code = form["error"] {
            errorResponse = ErrorResponse(error: code, description: form["error_description"], state: form["state"])
            return HttpResponse(status: 200, headers: [("Content-Type", "application/json")],
                                body: [UInt8](#"{"redirect_uri":"https://verifier.example/done"}"#.utf8))
        }
        let vpToken: JsonValue
        if let response = form["response"] {
            // §8.3: the wallet must echo our kid; 18013-7 B.5.3: apv carries the request nonce.
            if case let .obj(hdr)? = try? JsonValue.parse(try Base64Url.decodeToString(String(response.split(separator: ".")[0]))) {
                let header = JsonValue.obj(hdr)
                if case let .str(k)? = header["kid"] { seenJweKid = k }
                if case let .str(a)? = header["apv"] { seenJweApv = try? Base64Url.decodeToString(a) }
            }
            let dec = try Jwe.decryptEcdhEs(response, recipientPrivateD: encPrivD)
            vpToken = try JsonValue.parse(String(bytes: dec, encoding: .utf8)!)["vp_token"]!
        } else {
            vpToken = try JsonValue.parse(form["vp_token"]!)
        }
        guard case let .arr(items)? = vpToken["pid"], case let .str(presentation) = items[0] else {
            throw VpError.responseFailed("no pid presentation")
        }
        let verified = try SdJwtVerifier.verify(
            try SdJwt.parse(presentation), issuerKey: issuerPublic, algorithm: .es256,
            keyBinding: SdJwtVerifier.KbRequirement(audience: clientId, nonce: nonce, now: kbClock))
        verifiedClaims = verified.claims
        return HttpResponse(status: 200, headers: [("Content-Type", "application/json")],
                            body: [UInt8](#"{"redirect_uri":"https://verifier.example/done"}"#.utf8))
    }

    private nonisolated func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s
    }
}
