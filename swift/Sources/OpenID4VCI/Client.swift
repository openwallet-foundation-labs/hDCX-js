import CborCose
import Foundation
import SdJwt
import WalletAPI

let grantPreAuthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

/// Opaque continuation for the authorization code grant, produced by
/// `prepareAuthorizationCodeIssuance`. Carries the PKCE verifier and resolved endpoints
/// across the browser redirect. `state` must be echoed by the redirect and checked by the
/// host (CSRF protection).
public struct PreparedAuthorization {
    public let authorizationUrl: String
    public let state: String
    let pkce: Pkce
    let redirectUri: String
    let configurationId: String
    let issuerMetadata: CredentialIssuerMetadata
    let asMetadata: AuthorizationServerMetadata
}

/// Holder key material for issuance: a key-proof (bound into the credential) and a DPoP key.
public struct IssuanceKeys {
    public let proofSigner: any JwsSigner
    public let proofPublicKey: EcPublicKey
    public let dpopSigner: any JwsSigner
    public let dpopPublicKey: EcPublicKey

    public init(
        proofSigner: any JwsSigner,
        proofPublicKey: EcPublicKey,
        dpopSigner: any JwsSigner,
        dpopPublicKey: EcPublicKey
    ) {
        self.proofSigner = proofSigner
        self.proofPublicKey = proofPublicKey
        self.dpopSigner = dpopSigner
        self.dpopPublicKey = dpopPublicKey
    }
}

/// OpenID4VCI 1.0 client (HAIP subset) over the `HttpTransport` port.
///
/// Implements the pre-authorized code grant end to end: issuer + AS metadata discovery,
/// DPoP-bound token request (with one-shot DPoP-Nonce retry), c_nonce acquisition, key
/// proof of possession, and the credential request.
public struct Openid4VciClient {
    private let http: any HttpTransport
    private let rng: any Rng
    private let clock: () -> Int64
    private let clientId: String

    public init(http: any HttpTransport, rng: any Rng, clock: @escaping () -> Int64, clientId: String = "wallet-dev") {
        self.http = http
        self.rng = rng
        self.clock = clock
        self.clientId = clientId
    }

    public func loadIssuerMetadata(_ credentialIssuer: String) async throws -> CredentialIssuerMetadata {
        try await CredentialIssuerMetadata.fromObj(getJson(wellKnown(credentialIssuer, "openid-credential-issuer")))
    }

    public func loadAuthorizationServerMetadata(_ issuer: String) async throws -> AuthorizationServerMetadata {
        for suffix in ["oauth-authorization-server", "openid-configuration"] {
            let response = try await rawGet(wellKnown(issuer, suffix))
            if (200...299).contains(response.status) {
                return try AuthorizationServerMetadata.fromObj(try parseObj(response, "AS metadata"))
            }
        }
        throw VciError.metadata("no authorization server metadata at \(issuer)")
    }

    /// Step 1 of the authorization code grant: pushes the authorization request (PAR when the
    /// AS supports it) and returns the URL the host must open in a browser, plus the opaque
    /// continuation to hand back to `finishAuthorizationCodeIssuance` after the redirect.
    public func prepareAuthorizationCodeIssuance(
        credentialIssuer: String,
        configurationId: String,
        redirectUri: String,
        issuerState: String? = nil
    ) async throws -> PreparedAuthorization {
        let issuerMeta = try await loadIssuerMetadata(credentialIssuer)
        let asMeta = try await loadAuthorizationServerMetadata(issuerMeta.authorizationServers[0])
        let pkce = Pkce.create(rng: rng)
        let state = Base64Url.encode(rng.nextBytes(16))

        let authorizationDetails = JsonValue.arr([
            .obj([
                ("type", .str("openid_credential")),
                ("credential_configuration_id", .str(configurationId)),
            ])
        ]).serialize()

        var baseParams: [(String, String)] = [
            ("response_type", "code"),
            ("client_id", clientId),
            ("redirect_uri", redirectUri),
            ("code_challenge", pkce.codeChallenge),
            ("code_challenge_method", pkce.method),
            ("authorization_details", authorizationDetails),
            ("state", state),
        ]
        if let issuerState { baseParams.append(("issuer_state", issuerState)) }

        let authorizationUrl: String
        if let parEndpoint = asMeta.pushedAuthorizationRequestEndpoint {
            let form = baseParams.map { "\(enc($0.0))=\(enc($0.1))" }.joined(separator: "&")
            let parResp = try await http.execute(HttpRequest(
                method: .post, url: parEndpoint,
                headers: [("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json")],
                body: [UInt8](form.utf8)
            ))
            try checkOAuth(parResp, parEndpoint)
            guard case let .str(requestUri)? = try parseObj(parResp, "PAR response")["request_uri"] else {
                throw VciError.protocolError("PAR response missing request_uri")
            }
            guard let authEndpoint = asMeta.authorizationEndpoint else {
                throw VciError.metadata("AS has PAR but no authorization_endpoint")
            }
            authorizationUrl = "\(authEndpoint)?client_id=\(enc(clientId))&request_uri=\(enc(requestUri))"
        } else {
            guard let authEndpoint = asMeta.authorizationEndpoint else {
                throw VciError.metadata("AS metadata has no authorization_endpoint")
            }
            let query = baseParams.map { "\(enc($0.0))=\(enc($0.1))" }.joined(separator: "&")
            authorizationUrl = "\(authEndpoint)?\(query)"
        }

        return PreparedAuthorization(
            authorizationUrl: authorizationUrl, state: state, pkce: pkce, redirectUri: redirectUri,
            configurationId: configurationId, issuerMetadata: issuerMeta, asMetadata: asMeta
        )
    }

    /// Step 2 of the authorization code grant: exchanges the redirect's `code` for a
    /// DPoP-bound access token and requests the credential. The host must verify the redirect
    /// `state` equals `prepared.state` before calling this.
    public func finishAuthorizationCodeIssuance(
        prepared: PreparedAuthorization,
        authorizationCode: String,
        keys: IssuanceKeys
    ) async throws -> CredentialResponse {
        let dpop = DpopProver(signer: keys.dpopSigner, publicKey: keys.dpopPublicKey, rng: rng, now: clock)
        var form = "grant_type=\(enc("authorization_code"))"
        form += "&code=\(enc(authorizationCode))"
        form += "&redirect_uri=\(enc(prepared.redirectUri))"
        form += "&code_verifier=\(enc(prepared.pkce.codeVerifier))"
        form += "&client_id=\(enc(clientId))"
        let tokenResp = try await postFormWithDpop(prepared.asMetadata.tokenEndpoint, form: form, dpop: dpop, accessToken: nil)
        let token = try TokenResponse.fromObj(try parseObj(tokenResp, "token response"))
        return try await requestCredential(prepared.issuerMetadata, prepared.configurationId, token, dpop, keys)
    }

    /// Runs the full pre-authorized code flow and returns the issued credential(s).
    public func issueWithPreAuthorizedCode(
        offer: CredentialOffer,
        configurationId: String,
        keys: IssuanceKeys,
        txCode: String? = nil
    ) async throws -> CredentialResponse {
        guard let preAuthCode = offer.preAuthorizedCode else {
            throw VciError.invalidOffer("offer has no pre-authorized_code grant")
        }
        if let tx = offer.txCode, txCode == nil {
            throw VciError.txCodeRequired(length: tx.length, inputMode: tx.inputMode)
        }
        guard offer.credentialConfigurationIds.contains(configurationId) else {
            throw VciError.invalidOffer("configuration '\(configurationId)' not in offer")
        }

        let issuerMeta = try await loadIssuerMetadata(offer.credentialIssuer)
        let asMeta = try await loadAuthorizationServerMetadata(issuerMeta.authorizationServers[0])

        let dpop = DpopProver(signer: keys.dpopSigner, publicKey: keys.dpopPublicKey, rng: rng, now: clock)

        var form = "grant_type=\(enc(grantPreAuthorized))"
        form += "&pre-authorized_code=\(enc(preAuthCode))"
        if let txCode { form += "&tx_code=\(enc(txCode))" }
        let tokenResp = try await postFormWithDpop(asMeta.tokenEndpoint, form: form, dpop: dpop, accessToken: nil)
        let token = try TokenResponse.fromObj(try parseObj(tokenResp, "token response"))
        guard token.tokenType.lowercased() == "dpop" else {
            throw VciError.protocolError("expected DPoP token_type, got '\(token.tokenType)'")
        }

        return try await requestCredential(issuerMeta, configurationId, token, dpop, keys)
    }

    /// Shared tail of every grant: c_nonce → key proof → credential request.
    private func requestCredential(
        _ issuerMeta: CredentialIssuerMetadata,
        _ configurationId: String,
        _ token: TokenResponse,
        _ dpop: DpopProver,
        _ keys: IssuanceKeys
    ) async throws -> CredentialResponse {
        var cNonce = token.cNonce
        if cNonce == nil, let nonceEndpoint = issuerMeta.nonceEndpoint {
            cNonce = try await fetchCNonce(nonceEndpoint)
        }

        let proofSigner = KeyProofSigner(signer: keys.proofSigner, publicKey: keys.proofPublicKey, now: clock)
        let proofJwt = try await proofSigner.proofJwt(credentialIssuer: issuerMeta.credentialIssuer, cNonce: cNonce, clientId: clientId)

        let requestFormat = issuerMeta.credentialConfigurationsSupported[configurationId]?.format ?? "dc+sd-jwt"
        let requestBody = JsonValue.obj([
            ("credential_configuration_id", .str(configurationId)),
            ("proofs", .obj([("jwt", .arr([.str(proofJwt)]))])),
        ]).serialize()

        let credResp = try await postJsonWithDpop(
            issuerMeta.credentialEndpoint, json: requestBody, dpop: dpop, accessToken: token.accessToken
        )
        return CredentialResponse.fromObj(try parseObj(credResp, "credential response"), requestedFormat: requestFormat)
    }

    // MARK: - HTTP helpers

    private func fetchCNonce(_ nonceEndpoint: String) async throws -> String {
        let response = try await http.execute(HttpRequest(method: .post, url: nonceEndpoint, headers: [("Accept", "application/json")]))
        try checkStatus(response, nonceEndpoint)
        guard case let .str(nonce)? = try parseObj(response, "nonce response")["c_nonce"] else {
            throw VciError.protocolError("nonce endpoint returned no c_nonce")
        }
        return nonce
    }

    private func postFormWithDpop(
        _ url: String, form: String, dpop: DpopProver, accessToken: String?, nonce: String? = nil
    ) async throws -> HttpResponse {
        var headers: [(String, String)] = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
            ("DPoP", try await dpop.proof(method: "POST", url: url, accessToken: accessToken, nonce: nonce)),
        ]
        if let accessToken { headers.append(("Authorization", "DPoP \(accessToken)")) }
        let response = try await http.execute(HttpRequest(method: .post, url: url, headers: headers, body: [UInt8](form.utf8)))

        if nonce == nil, let serverNonce = dpopNonceChallenge(response) {
            return try await postFormWithDpop(url, form: form, dpop: dpop, accessToken: accessToken, nonce: serverNonce)
        }
        try checkOAuth(response, url)
        return response
    }

    private func postJsonWithDpop(
        _ url: String, json: String, dpop: DpopProver, accessToken: String, nonce: String? = nil
    ) async throws -> HttpResponse {
        let headers: [(String, String)] = [
            ("Content-Type", "application/json"),
            ("Accept", "application/json"),
            ("DPoP", try await dpop.proof(method: "POST", url: url, accessToken: accessToken, nonce: nonce)),
            ("Authorization", "DPoP \(accessToken)"),
        ]
        let response = try await http.execute(HttpRequest(method: .post, url: url, headers: headers, body: [UInt8](json.utf8)))

        if nonce == nil, let serverNonce = dpopNonceChallenge(response) {
            return try await postJsonWithDpop(url, json: json, dpop: dpop, accessToken: accessToken, nonce: serverNonce)
        }
        try checkOAuth(response, url)
        return response
    }

    private func getJson(_ url: String) async throws -> JsonValue {
        let response = try await rawGet(url)
        try checkStatus(response, url)
        return try parseObj(response, url)
    }

    private func rawGet(_ url: String) async throws -> HttpResponse {
        try await http.execute(HttpRequest(method: .get, url: url, headers: [("Accept", "application/json")]))
    }

    private func dpopNonceChallenge(_ response: HttpResponse) -> String? {
        guard response.status == 400 || response.status == 401 else { return nil }
        return header(response, "DPoP-Nonce")
    }

    private func checkStatus(_ response: HttpResponse, _ endpoint: String) throws {
        guard (200...299).contains(response.status) else {
            throw VciError.http(status: response.status, endpoint: endpoint, body: bodyText(response, 500))
        }
    }

    private func checkOAuth(_ response: HttpResponse, _ endpoint: String) throws {
        if (200...299).contains(response.status) { return }
        if let text = String(bytes: response.body, encoding: .utf8),
           let obj = try? JsonValue.parse(text), case let .str(error)? = obj["error"] {
            var desc: String?
            if case let .str(d)? = obj["error_description"] { desc = d }
            throw VciError.oauth(error: error, description: desc, endpoint: endpoint)
        }
        throw VciError.http(status: response.status, endpoint: endpoint, body: bodyText(response, 500))
    }

    private func parseObj(_ response: HttpResponse, _ where_: String) throws -> JsonValue {
        guard let text = String(bytes: response.body, encoding: .utf8),
              let obj = try? JsonValue.parse(text), case .obj = obj
        else { throw VciError.protocolError("\(where_): not a JSON object") }
        return obj
    }

    private func header(_ response: HttpResponse, _ name: String) -> String? {
        response.headers.first { $0.0.caseInsensitiveCompare(name) == .orderedSame }?.1
    }

    private func bodyText(_ response: HttpResponse, _ limit: Int) -> String? {
        guard let text = String(bytes: response.body, encoding: .utf8) else { return nil }
        return String(text.prefix(limit))
    }

    private func wellKnown(_ base: String, _ suffix: String) throws -> String {
        var trimmed = base
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        guard trimmed.hasPrefix("https://") else { throw VciError.metadata("issuer must be https: \(base)") }
        let rest = String(trimmed.dropFirst("https://".count))
        if let slash = rest.firstIndex(of: "/") {
            let host = rest[rest.startIndex..<slash]
            let path = rest[slash...]
            return "https://\(host)/.well-known/\(suffix)\(path)"
        }
        return "https://\(rest)/.well-known/\(suffix)"
    }

    private func enc(_ v: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return v.addingPercentEncoding(withAllowedCharacters: allowed) ?? v
    }
}
