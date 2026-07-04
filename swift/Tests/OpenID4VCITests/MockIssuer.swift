import CborCose
import Crypto
import Foundation
import SdJwt
import WalletAPI
import WalletTestKit
@testable import OpenID4VCI

/// A mock OpenID4VCI issuer that actually verifies DPoP + key proofs and issues a real
/// SD-JWT VC. Not a stub: signatures, htu/htm/ath, aud and c_nonce are checked, and the
/// first token request is answered with a DPoP-Nonce challenge to exercise the retry path.
actor MockIssuer: HttpTransport {
    private let area: SoftwareSecureArea
    private let issuerKey: KeyInfo
    private let now: Int64

    private let issuer = "https://issuer.example"
    private let preAuthCode = "PRE-AUTH-123"
    private var cNonce: String?
    private var accessToken: String?
    private(set) var seenDpopNonceRetry = false

    // authorization code flow state
    private var parRequestUri: String?
    private let authCode = "AUTH-CODE-XYZ"
    private var authCodeChallenge: String?
    private(set) var seenPar = false

    init(area: SoftwareSecureArea, issuerKey: KeyInfo, now: Int64) {
        self.area = area
        self.issuerKey = issuerKey
        self.now = now
    }

    nonisolated var credentialOfferJson: String {
        """
        {"credential_issuer":"https://issuer.example",
         "credential_configuration_ids":["eu.europa.ec.eudi.pid.1"],
         "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":
           {"pre-authorized_code":"PRE-AUTH-123","tx_code":{"length":4,"input_mode":"numeric"}}}}
        """
    }

    func execute(_ request: HttpRequest) async throws -> HttpResponse {
        let path = String(request.url.dropFirst(issuer.count))
        switch path {
        case "/.well-known/openid-credential-issuer": return ok(issuerMetadata())
        case "/.well-known/oauth-authorization-server": return ok(asMetadata())
        case "/.well-known/jwt-vc-issuer": return ok(jwtVcIssuerMetadata())
        case "/token": return try await handleToken(request)
        case "/nonce": return handleNonce()
        case "/credential": return try await handleCredential(request)
        case "/par": return handlePar(request)
        default:
            if path.hasPrefix("/authorize") { return handleAuthorize(request) }
            return HttpResponse(status: 404, headers: [], body: [UInt8]("not found".utf8))
        }
    }

    private func handlePar(_ request: HttpRequest) -> HttpResponse {
        seenPar = true
        let form = parseForm(String(bytes: request.body ?? [], encoding: .utf8) ?? "")
        precondition(form["response_type"] == "code", "PAR: response_type must be code")
        precondition(form["code_challenge_method"] == "S256", "PAR: expected S256 PKCE")
        precondition(form["redirect_uri"] != nil, "PAR: missing redirect_uri")
        guard case let .arr(details)? = try? JsonValue.parse(form["authorization_details"] ?? ""),
              case let .str(type)? = details[0]["type"], type == "openid_credential"
        else { preconditionFailure("PAR: bad authorization_details") }
        authCodeChallenge = form["code_challenge"]
        parRequestUri = "urn:ietf:params:oauth:request_uri:mock-\(form["state"] ?? "")"
        return HttpResponse(
            status: 201,
            headers: [("Content-Type", "application/json")],
            body: [UInt8](#"{"request_uri":"\#(parRequestUri!)","expires_in":90}"#.utf8)
        )
    }

    private func handleAuthorize(_ request: HttpRequest) -> HttpResponse {
        let query = request.url.contains("?") ? String(request.url.split(separator: "?", maxSplits: 1)[1]) : ""
        let params = parseForm(query)
        precondition(params["client_id"] != nil, "authorize: missing client_id")
        precondition(params["request_uri"] == parRequestUri, "authorize: unknown request_uri")
        return HttpResponse(status: 302, headers: [("Location", "wallet://cb?code=\(authCode)&state=...")], body: [])
    }

    private func handleToken(_ request: HttpRequest) async throws -> HttpResponse {
        let form = parseForm(String(bytes: request.body ?? [], encoding: .utf8) ?? "")
        let nonce = try await verifyDpop(request, htm: "POST", htu: "\(issuer)/token", accessToken: nil)

        switch form["grant_type"] {
        case grantPreAuthorized:
            precondition(form["pre-authorized_code"] == preAuthCode, "wrong pre-auth code")
            precondition(form["tx_code"] == "1234", "wrong tx_code")
        case "authorization_code":
            precondition(form["code"] == authCode, "wrong authorization code")
            let verifier = form["code_verifier"] ?? ""
            let computed = Base64Url.encode(sha256([UInt8](verifier.utf8)))
            precondition(computed == authCodeChallenge, "PKCE verification failed")
        default:
            preconditionFailure("unsupported grant_type \(form["grant_type"] ?? "nil")")
        }
        if nonce == nil {
            return HttpResponse(
                status: 400,
                headers: [("DPoP-Nonce", "dpop-nonce-token"), ("Content-Type", "application/json")],
                body: [UInt8](#"{"error":"use_dpop_nonce"}"#.utf8)
            )
        }
        seenDpopNonceRetry = true
        accessToken = "ACCESS-token-123"
        cNonce = "c-nonce-xyz"
        return ok(#"{"access_token":"\#(accessToken!)","token_type":"DPoP","expires_in":3600}"#)
    }

    private func handleNonce() -> HttpResponse {
        ok(#"{"c_nonce":"\#(cNonce ?? "c-nonce-xyz")"}"#)
    }

    private func handleCredential(_ request: HttpRequest) async throws -> HttpResponse {
        guard let token = accessToken else {
            return HttpResponse(status: 401, headers: [], body: [UInt8]("no token".utf8))
        }
        precondition(request.headers.contains { $0.0 == "Authorization" && $0.1 == "DPoP \(token)" }, "bad auth")
        _ = try await verifyDpop(request, htm: "POST", htu: "\(issuer)/credential", accessToken: token)

        guard case let .obj(entries)? = try? JsonValue.parse(String(bytes: request.body ?? [], encoding: .utf8) ?? "") else {
            preconditionFailure("bad credential request body")
        }
        let body = JsonValue.obj(entries)
        guard case let .arr(jwts)? = body["proofs"]?["jwt"], case let .str(proofJwt) = jwts[0] else {
            preconditionFailure("no proof jwt")
        }
        let holderKey = try await verifyKeyProof(proofJwt)
        let credential = try await issueSdJwtVc(holderKey: holderKey)
        return ok(#"{"credentials":[{"credential":"\#(credential)"}],"notification_id":"n-1"}"#)
    }

    /// Verifies a DPoP proof; returns its `nonce` claim (nil if absent). Fails on any invalidity.
    private func verifyDpop(_ request: HttpRequest, htm: String, htu: String, accessToken: String?) async throws -> String? {
        guard let dpop = request.headers.first(where: { $0.0 == "DPoP" })?.1 else {
            preconditionFailure("missing DPoP header")
        }
        let jws = try Jws.parse(dpop)
        guard case let .str(typ)? = jws.header["typ"], typ == "dpop+jwt" else { preconditionFailure("bad DPoP typ") }
        guard let jwk = jws.header["jwk"], let key = JwkEc.fromJson(jwk) else { preconditionFailure("bad DPoP jwk") }
        precondition(jws.verify(key: key, expected: .es256), "DPoP signature invalid")

        guard let claims = try? JsonValue.parse(String(bytes: jws.payloadBytes, encoding: .utf8) ?? "") else {
            preconditionFailure("bad DPoP payload")
        }
        guard case let .str(m)? = claims["htm"], m == htm else { preconditionFailure("DPoP htm mismatch") }
        guard case let .str(u)? = claims["htu"], u == htu else { preconditionFailure("DPoP htu mismatch") }
        guard case .str? = claims["jti"] else { preconditionFailure("DPoP jti missing") }
        if let accessToken {
            let expectedAth = Base64Url.encode(sha256([UInt8](accessToken.utf8)))
            guard case let .str(ath)? = claims["ath"], ath == expectedAth else { preconditionFailure("DPoP ath mismatch") }
        }
        if case let .str(nonce)? = claims["nonce"] { return nonce }
        return nil
    }

    private func verifyKeyProof(_ proofJwt: String) async throws -> EcPublicKey {
        let jws = try Jws.parse(proofJwt)
        guard case let .str(typ)? = jws.header["typ"], typ == "openid4vci-proof+jwt" else {
            preconditionFailure("wrong proof typ")
        }
        guard let jwk = jws.header["jwk"], let key = JwkEc.fromJson(jwk) else { preconditionFailure("bad proof jwk") }
        precondition(jws.verify(key: key, expected: .es256), "proof signature invalid")
        guard let claims = try? JsonValue.parse(String(bytes: jws.payloadBytes, encoding: .utf8) ?? "") else {
            preconditionFailure("bad proof payload")
        }
        guard case let .str(aud)? = claims["aud"], aud == issuer else { preconditionFailure("proof aud mismatch") }
        guard case let .str(nonce)? = claims["nonce"], nonce == cNonce else { preconditionFailure("proof nonce mismatch") }
        return key
    }

    private func issueSdJwtVc(holderKey: EcPublicKey) async throws -> String {
        let signer = SecureAreaJwsSigner(area: area, key: issuerKey.handle, algorithm: .es256)
        var n = 0
        let salts: () -> String = { n += 1; return "salt-\(n)" }
        let sdJwt = try await SdJwtIssuer(saltProvider: salts).issue(
            signer: signer, holderKey: holderKey, typ: "dc+sd-jwt", decoysPerSdStruct: 2
        ) { b in
            b.claim("iss", self.issuer)
            b.claim("vct", "eu.europa.ec.eudi.pid.1")
            b.claim("iat", self.now)
            b.claim("exp", self.now + 86_400)
            b.sd("family_name", "Doe")
            b.sd("given_name", "John")
            b.sd("birthdate", "1990-01-01")
        }
        return sdJwt.serialize()
    }

    private func issuerMetadata() -> String {
        """
        {"credential_issuer":"\(issuer)",
         "credential_endpoint":"\(issuer)/credential",
         "nonce_endpoint":"\(issuer)/nonce",
         "authorization_servers":["\(issuer)"],
         "credential_configurations_supported":{
           "eu.europa.ec.eudi.pid.1":{"format":"dc+sd-jwt","vct":"eu.europa.ec.eudi.pid.1",
             "proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}}}}
        """
    }

    private func asMetadata() -> String {
        """
        {"issuer":"\(issuer)","token_endpoint":"\(issuer)/token",
         "authorization_endpoint":"\(issuer)/authorize",
         "pushed_authorization_request_endpoint":"\(issuer)/par",
         "code_challenge_methods_supported":["S256"],
         "dpop_signing_alg_values_supported":["ES256"]}
        """
    }

    private func jwtVcIssuerMetadata() -> String {
        let jwk = JwkEc.toJson(issuerKey.publicKey).serialize()
        return #"{"issuer":"\#(issuer)","jwks":{"keys":[\#(jwk)]}}"#
    }

    private func ok(_ body: String) -> HttpResponse {
        HttpResponse(status: 200, headers: [("Content-Type", "application/json")], body: [UInt8](body.utf8))
    }

    private func parseForm(_ form: String) -> [String: String] {
        var out: [String: String] = [:]
        for pair in form.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            guard kv.count == 2 else { continue }
            let k = String(kv[0]).removingPercentEncoding ?? String(kv[0])
            let v = String(kv[1]).removingPercentEncoding ?? String(kv[1])
            out[k] = v
        }
        return out
    }
}
