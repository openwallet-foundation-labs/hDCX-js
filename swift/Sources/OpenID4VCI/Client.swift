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
/// A holder key that proves possession and is bound into the issued credential.
public struct ProofKey {
    public let signer: any JwsSigner
    public let publicKey: EcPublicKey
    public init(signer: any JwsSigner, publicKey: EcPublicKey) {
        self.signer = signer; self.publicKey = publicKey
    }
}

/// Source of a Key Attestation JWT (OpenID4VCI §8.2.1.1) for the proof key(s), bound to the c_nonce.
public protocol KeyAttestationSource: Sendable {
    func attestation(cNonce: String?) async throws -> String
}

public struct IssuanceKeys {
    public let proofSigner: any JwsSigner
    public let proofPublicKey: EcPublicKey
    public let dpopSigner: any JwsSigner
    public let dpopPublicKey: EcPublicKey
    /// Additional proof keys for batch issuance — one credential is issued per proof key.
    public let additionalProofKeys: [ProofKey]

    public init(
        proofSigner: any JwsSigner,
        proofPublicKey: EcPublicKey,
        dpopSigner: any JwsSigner,
        dpopPublicKey: EcPublicKey,
        additionalProofKeys: [ProofKey] = []
    ) {
        self.proofSigner = proofSigner
        self.proofPublicKey = proofPublicKey
        self.dpopSigner = dpopSigner
        self.dpopPublicKey = dpopPublicKey
        self.additionalProofKeys = additionalProofKeys
    }

    /// All proof keys — the primary key first, then any batch keys.
    public var proofKeys: [ProofKey] {
        [ProofKey(signer: proofSigner, publicKey: proofPublicKey)] + additionalProofKeys
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
    /// HAIP attestation-based client authentication (adds OAuth-Client-Attestation[-PoP] to PAR/token).
    private let clientAuth: WalletClientAuth?
    /// Optional Key Attestation for the proof key(s), added to each key-proof header (HAIP).
    private let keyAttestation: (any KeyAttestationSource)?
    /// How to negotiate signed issuer metadata (OpenID4VCI §12.2.2/§12.2.3). Default: unsigned JSON.
    private let metadataPolicy: IssuerMetadataPolicy

    public init(http: any HttpTransport, rng: any Rng, clock: @escaping () -> Int64,
                clientId: String = "wallet-dev", clientAuth: WalletClientAuth? = nil,
                keyAttestation: (any KeyAttestationSource)? = nil,
                metadataPolicy: IssuerMetadataPolicy = .ignoreSigned) {
        self.http = http
        self.rng = rng
        self.clock = clock
        // With attestation-based client auth the client_id is the wallet instance's attestation subject.
        self.clientId = clientAuth?.clientId ?? clientId
        self.clientAuth = clientAuth
        self.keyAttestation = keyAttestation
        self.metadataPolicy = metadataPolicy
    }

    /// Client-attestation headers bound to the authorization server (empty when not configured).
    private func clientAuthHeaders(_ asMeta: AuthorizationServerMetadata) async throws -> [(String, String)] {
        try await clientAuth?.headers(audience: asMeta.issuer) ?? []
    }

    /// Resolves a credential offer from a wallet deep link / QR payload (OpenID4VCI §4.1):
    /// accepts `<scheme>://…?credential_offer=<url-encoded-json>`, a `credential_offer_uri`
    /// by reference (fetched here), or the raw offer JSON.
    public func resolveCredentialOffer(_ input: String) async throws -> CredentialOffer {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("{") { return try CredentialOffer.parse(trimmed) }
        if let value = queryParam(trimmed, "credential_offer") {
            return try CredentialOffer.parse(value)
        }
        if let uri = queryParam(trimmed, "credential_offer_uri") {
            let response = try await rawGet(uri)
            try checkStatus(response, uri)
            guard let text = String(bytes: response.body, encoding: .utf8) else {
                throw VciError.invalidOffer("offer uri body not UTF-8")
            }
            return try CredentialOffer.parse(text)
        }
        throw VciError.invalidOffer("no credential_offer or credential_offer_uri in input")
    }

    private func queryParam(_ input: String, _ name: String) -> String? {
        guard let q = input.split(separator: "?", maxSplits: 1).dropFirst().first else { return nil }
        for pair in q.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            if kv.count == 2, kv[0] == name {
                return String(kv[1]).removingPercentEncoding ?? String(kv[1])
            }
        }
        return nil
    }

    public func loadIssuerMetadata(_ credentialIssuer: String) async throws -> CredentialIssuerMetadata {
        let url = try wellKnown(credentialIssuer, "openid-credential-issuer")
        let response = try await http.execute(
            HttpRequest(method: .get, url: url, headers: [("Accept", metadataPolicy.acceptHeader)])
        )
        try checkStatus(response, url)
        return try CredentialIssuerMetadata.fromObj(try await metadataBody(response, url, credentialIssuer))
    }

    /// Picks the unsigned/signed branch by response media type (OpenID4VCI §12.2.2): `application/json`
    /// carries the metadata as-is, `application/jwt` carries it as the payload of a signed JWT. Issuers
    /// MUST label the body; when the header is absent we fall back to sniffing a JSON object.
    private func metadataBody(_ response: HttpResponse, _ url: String, _ credentialIssuer: String) async throws -> JsonValue {
        let mediaType = header(response, "Content-Type")?
            .split(separator: ";").first
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        let text = (String(bytes: response.body, encoding: .utf8) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let signed: Bool
        switch mediaType {
        case "application/jwt": signed = true
        case "application/json": signed = false
        default: signed = !text.hasPrefix("{")
        }
        if !signed {
            if metadataPolicy.requiresSigned {
                throw VciError.metadata("policy requires signed metadata but the issuer returned unsigned metadata")
            }
            return try parseObj(response, url)
        }
        return try await verifySignedMetadata(text, credentialIssuer)
    }

    /// Enforces the §12.2.3 shape — `typ`, an asymmetric `alg`, `sub` matching the Credential Issuer
    /// Identifier, a present `iat` and an unexpired `exp`. `SignedMetadataVerifier` proves the signature
    /// and the signer's trust; the verified payload *is* the metadata (all parameters are top-level claims).
    private func verifySignedMetadata(_ jws: String, _ credentialIssuer: String) async throws -> JsonValue {
        guard let verifier = metadataPolicy.verifier else {
            throw VciError.metadata("issuer returned signed metadata but no SignedMetadataVerifier is configured")
        }
        guard let parsed = try? Jws.parse(jws) else {
            throw VciError.metadata("signed metadata is not a compact JWS")
        }
        guard case let .str(typ)? = parsed.header["typ"], typ == signedMetadataTyp else {
            throw VciError.metadata("signed metadata typ must be '\(signedMetadataTyp)'")
        }
        guard case let .str(alg)? = parsed.header["alg"] else {
            throw VciError.metadata("signed metadata has no alg")
        }
        if alg.lowercased() == "none" || alg.hasPrefix("HS") {
            throw VciError.metadata("signed metadata alg must be an asymmetric signature, got '\(alg)'")
        }

        let claims = try await verifier.verify(signedMetadataJws: jws)

        guard case let .str(sub)? = claims["sub"] else {
            throw VciError.metadata("signed metadata has no sub")
        }
        func trimSlash(_ s: String) -> String { s.hasSuffix("/") ? String(s.dropLast()) : s }
        guard trimSlash(sub) == trimSlash(credentialIssuer) else {
            throw VciError.metadata("signed metadata sub '\(sub)' does not match the Credential Issuer Identifier '\(credentialIssuer)'")
        }
        guard case .numInt? = claims["iat"] else {
            throw VciError.metadata("signed metadata has no iat")
        }
        if case let .numInt(exp)? = claims["exp"], exp <= clock() {
            throw VciError.metadata("signed metadata expired at \(exp)")
        }
        return claims
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
        issuerState: String? = nil,
        /// Favor `scope` over `authorization_details` when the config advertises one (HAIP/EUDI default).
        preferScope: Bool = true
    ) async throws -> PreparedAuthorization {
        let issuerMeta = try await loadIssuerMetadata(credentialIssuer)
        let asMeta = try await loadAuthorizationServerMetadata(issuerMeta.authorizationServers[0])
        let pkce = Pkce.create(rng: rng)
        let state = Base64Url.encode(rng.nextBytes(16))

        let scope = issuerMeta.credentialConfigurationsSupported[configurationId]?.scope
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
        ]
        if preferScope, let scope {
            baseParams.append(("scope", scope))
        } else {
            baseParams.append(("authorization_details", authorizationDetails))
        }
        baseParams.append(("state", state))
        if let issuerState { baseParams.append(("issuer_state", issuerState)) }

        let authorizationUrl: String
        if let parEndpoint = asMeta.pushedAuthorizationRequestEndpoint {
            let form = baseParams.map { "\(enc($0.0))=\(enc($0.1))" }.joined(separator: "&")
            let parHeaders = [("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json")]
                + (try await clientAuthHeaders(asMeta))
            let parResp = try await http.execute(HttpRequest(
                method: .post, url: parEndpoint, headers: parHeaders, body: [UInt8](form.utf8)
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
        let token = try await exchangeCode(
            prepared.asMetadata, authorizationCode, prepared.redirectUri, prepared.pkce.codeVerifier, dpop
        )
        return try await requestCredential(prepared.issuerMetadata, prepared.configurationId, token, dpop, keys)
    }

    /// Stateless variant of `finishAuthorizationCodeIssuance`: a host that persisted only the
    /// `code_verifier` + `redirect_uri` across the browser redirect (rather than the whole
    /// `PreparedAuthorization`) reloads metadata and completes issuance here.
    public func exchangeAuthorizationCode(
        credentialIssuer: String,
        configurationId: String,
        authorizationCode: String,
        redirectUri: String,
        codeVerifier: String,
        keys: IssuanceKeys
    ) async throws -> CredentialResponse {
        let issuerMeta = try await loadIssuerMetadata(credentialIssuer)
        let asMeta = try await loadAuthorizationServerMetadata(issuerMeta.authorizationServers[0])
        let dpop = DpopProver(signer: keys.dpopSigner, publicKey: keys.dpopPublicKey, rng: rng, now: clock)
        let token = try await exchangeCode(asMeta, authorizationCode, redirectUri, codeVerifier, dpop)
        return try await requestCredential(issuerMeta, configurationId, token, dpop, keys)
    }

    private func exchangeCode(
        _ asMeta: AuthorizationServerMetadata,
        _ authorizationCode: String,
        _ redirectUri: String,
        _ codeVerifier: String,
        _ dpop: DpopProver
    ) async throws -> TokenResponse {
        var form = "grant_type=\(enc("authorization_code"))"
        form += "&code=\(enc(authorizationCode))"
        form += "&redirect_uri=\(enc(redirectUri))"
        form += "&code_verifier=\(enc(codeVerifier))"
        form += "&client_id=\(enc(clientId))"
        let tokenResp = try await postFormWithDpop(asMeta.tokenEndpoint, form: form, dpop: dpop, accessToken: nil, extraHeaders: try await clientAuthHeaders(asMeta))
        return try TokenResponse.fromObj(try parseObj(tokenResp, "token response"))
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
        let tokenResp = try await postFormWithDpop(asMeta.tokenEndpoint, form: form, dpop: dpop, accessToken: nil, extraHeaders: try await clientAuthHeaders(asMeta))
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

        // One key-proof per proof key (batch issuance yields one credential per proof).
        let keyAttestationJwt = try await keyAttestation?.attestation(cNonce: cNonce)
        var proofJwts: [JsonValue] = []
        for pk in keys.proofKeys {
            let proofSigner = KeyProofSigner(signer: pk.signer, publicKey: pk.publicKey, now: clock)
            proofJwts.append(.str(try await proofSigner.proofJwt(
                credentialIssuer: issuerMeta.credentialIssuer, cNonce: cNonce, clientId: clientId, keyAttestation: keyAttestationJwt)))
        }

        let requestFormat = issuerMeta.credentialConfigurationsSupported[configurationId]?.format ?? "dc+sd-jwt"
        let requestBody = JsonValue.obj([
            ("credential_configuration_id", .str(configurationId)),
            ("proofs", .obj([("jwt", .arr(proofJwts))])),
        ]).serialize()

        let credResp = try await postJsonWithDpop(
            issuerMeta.credentialEndpoint, json: requestBody, dpop: dpop, accessToken: token.accessToken
        )
        return CredentialResponse.fromObj(try parseObj(credResp, "credential response"), requestedFormat: requestFormat)
            .withContext(accessToken: token.accessToken, credentialIssuer: issuerMeta.credentialIssuer, requestedFormat: requestFormat,
                         refreshToken: token.refreshToken, configurationId: configurationId)
    }

    /// Reissues (renews) a credential using the refresh token from a prior issuance (OAuth 2.0
    /// refresh_token grant, RFC 6749 §6) — no browser re-authorization. Requires `canReissue`.
    public func reissue(_ previous: CredentialResponse, keys: IssuanceKeys) async throws -> CredentialResponse {
        guard let refreshToken = previous.refreshToken else { throw VciError.protocolError("no refresh_token to reissue") }
        guard let configurationId = previous.configurationId else { throw VciError.protocolError("no configuration_id to reissue") }
        let issuerMeta = try await loadIssuerMetadata(previous.credentialIssuer!)
        let asMeta = try await loadAuthorizationServerMetadata(issuerMeta.authorizationServers[0])

        let dpop = DpopProver(signer: keys.dpopSigner, publicKey: keys.dpopPublicKey, rng: rng, now: clock)
        let form = "grant_type=\(enc("refresh_token"))&refresh_token=\(enc(refreshToken))&client_id=\(enc(clientId))"
        let tokenResp = try await postFormWithDpop(asMeta.tokenEndpoint, form: form, dpop: dpop, accessToken: nil, extraHeaders: try await clientAuthHeaders(asMeta))
        let token = try TokenResponse.fromObj(try parseObj(tokenResp, "refresh token response"))
        return try await requestCredential(issuerMeta, configurationId, token, dpop, keys)
    }

    /// Polls the deferred credential endpoint (OpenID4VCI §9). Pass a `CredentialResponse` whose
    /// `isDeferred` is true. Throws `VciError.issuancePending` if the issuer is still not ready.
    public func fetchDeferredCredential(_ deferred: CredentialResponse, keys: IssuanceKeys) async throws -> CredentialResponse {
        guard let transactionId = deferred.transactionId else { throw VciError.protocolError("response has no transaction_id to defer") }
        guard let accessToken = deferred.accessToken else { throw VciError.protocolError("deferred response has no access token") }
        let issuerMeta = try await loadIssuerMetadata(deferred.credentialIssuer!)
        guard let endpoint = issuerMeta.deferredCredentialEndpoint else { throw VciError.metadata("issuer has no deferred_credential_endpoint") }

        let dpop = DpopProver(signer: keys.dpopSigner, publicKey: keys.dpopPublicKey, rng: rng, now: clock)
        let body = JsonValue.obj([("transaction_id", .str(transactionId))]).serialize()
        let response: HttpResponse
        do {
            response = try await postJsonWithDpop(endpoint, json: body, dpop: dpop, accessToken: accessToken)
        } catch let VciError.oauth(error, _, _) where error == "issuance_pending" {
            throw VciError.issuancePending
        }
        return CredentialResponse.fromObj(try parseObj(response, "deferred credential"), requestedFormat: deferred.requestedFormat)
            .withContext(accessToken: accessToken, credentialIssuer: deferred.credentialIssuer, requestedFormat: deferred.requestedFormat)
    }

    /// Sends an issuance notification (OpenID4VCI §10). No-op if the response carried no notification_id.
    public func sendNotification(_ response: CredentialResponse, event: NotificationEvent, keys: IssuanceKeys) async throws {
        guard let notificationId = response.notificationId else { return }
        guard let accessToken = response.accessToken else { throw VciError.protocolError("response has no access token") }
        let issuerMeta = try await loadIssuerMetadata(response.credentialIssuer!)
        guard let endpoint = issuerMeta.notificationEndpoint else { throw VciError.metadata("issuer has no notification_endpoint") }

        let dpop = DpopProver(signer: keys.dpopSigner, publicKey: keys.dpopPublicKey, rng: rng, now: clock)
        let body = JsonValue.obj([("notification_id", .str(notificationId)), ("event", .str(event.rawValue))]).serialize()
        try checkStatus(try await postJsonWithDpop(endpoint, json: body, dpop: dpop, accessToken: accessToken), endpoint)
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
        _ url: String, form: String, dpop: DpopProver, accessToken: String?, nonce: String? = nil,
        extraHeaders: [(String, String)] = []
    ) async throws -> HttpResponse {
        var headers: [(String, String)] = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
            ("DPoP", try await dpop.proof(method: "POST", url: url, accessToken: accessToken, nonce: nonce)),
        ]
        headers.append(contentsOf: extraHeaders)
        if let accessToken { headers.append(("Authorization", "DPoP \(accessToken)")) }
        let response = try await http.execute(HttpRequest(method: .post, url: url, headers: headers, body: [UInt8](form.utf8)))

        if nonce == nil, let serverNonce = dpopNonceChallenge(response) {
            return try await postFormWithDpop(url, form: form, dpop: dpop, accessToken: accessToken, nonce: serverNonce, extraHeaders: extraHeaders)
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
