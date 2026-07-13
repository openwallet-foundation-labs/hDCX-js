package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.Rng
import java.net.URLDecoder
import java.net.URLEncoder

/** A holder key that proves possession and is bound into the issued credential. */
data class ProofKey(val signer: JwsSigner, val publicKey: EcPublicKey)

/** Source of a Key Attestation JWT (OpenID4VCI §8.2.1.1) for the proof key(s), bound to the c_nonce. */
fun interface KeyAttestationSource {
    suspend fun attestation(cNonce: String?): String
}

/**
 * Holder key material for issuance: a key-proof (bound into the credential) and a DPoP key.
 * [additionalProofKeys] enables batch issuance — one credential is issued per proof key.
 */
class IssuanceKeys(
    val proofSigner: JwsSigner,
    val proofPublicKey: EcPublicKey,
    val dpopSigner: JwsSigner,
    val dpopPublicKey: EcPublicKey,
    val additionalProofKeys: List<ProofKey> = emptyList(),
    /**
     * Per-issuance Key Attestation source over exactly these [proofKeys] (bound to the c_nonce). Set by the
     * wallet when the issuer requires a key attestation; its `attested_keys` MUST be [proofKeys] in order, so
     * `attested_keys[0]` is [proofSigner]'s key (which signs the single jwt proof in the key-attestation-in-jwt shape).
     */
    val keyAttestation: KeyAttestationSource? = null,
) {
    /** All proof keys — the primary key first, then any batch keys. */
    val proofKeys: List<ProofKey> get() = listOf(ProofKey(proofSigner, proofPublicKey)) + additionalProofKeys
}

internal const val GRANT_PRE_AUTHORIZED = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

/**
 * Opaque continuation for the authorization code grant, produced by
 * [Openid4VciClient.prepareAuthorizationCodeIssuance]. Carries the PKCE verifier and
 * resolved endpoints across the browser redirect. [state] must be echoed by the redirect
 * and checked by the host (CSRF protection).
 */
class PreparedAuthorization internal constructor(
    val authorizationUrl: String,
    val state: String,
    internal val pkce: Pkce,
    internal val redirectUri: String,
    internal val configurationId: String,
    internal val issuerMetadata: CredentialIssuerMetadata,
    internal val asMetadata: AuthorizationServerMetadata,
)

/**
 * OpenID4VCI 1.0 client (HAIP subset) over the [HttpTransport] port.
 *
 * Implements the pre-authorized code grant end to end: issuer + AS metadata discovery,
 * DPoP-bound token request (with one-shot DPoP-Nonce retry), c_nonce acquisition, key
 * proof of possession, and the credential request. Authorization-code entry points build
 * on the same primitives (browser step is the host's responsibility).
 */
class Openid4VciClient(
    private val http: HttpTransport,
    private val rng: Rng,
    /** epoch seconds; injectable for deterministic tests. */
    private val clock: () -> Long,
    clientId: String = "wallet-dev",
    /** HAIP attestation-based client authentication (adds OAuth-Client-Attestation[-PoP] to PAR/token). */
    private val clientAuth: ClientAuthProvider? = null,
    /** Optional Key Attestation for the proof key(s), added to each key-proof header (HAIP). */
    private val keyAttestation: KeyAttestationSource? = null,
    /**
     * §8.2.1 Appendix F.3: use the `attestation` proof type — a single Key Attestation JWT with no
     * per-key proof of possession — instead of `jwt` proofs. Only applies when a [keyAttestation] source is
     * configured and the issuer's config lists `attestation` in `proof_types_supported`; otherwise `jwt` is
     * used. The attestation's `attested_keys` are the keys the Credential(s) bind to, so no key needs to sign.
     */
    private val preferAttestationProof: Boolean = false,
    /** How to negotiate signed issuer metadata (OpenID4VCI §12.2.2/§12.2.3). Default: unsigned JSON. */
    private val metadataPolicy: IssuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
    /** Encrypted Credential Requests/Responses (§8.2, §10). Default: only when the issuer requires it. */
    private val credentialEncryption: CredentialEncryption = CredentialEncryption.WhenRequired,
) {
    /** With attestation-based client auth the client_id is the wallet instance's attestation subject. */
    private val clientId: String = clientAuth?.clientId ?: clientId

    /**
     * Client-attestation (WUA) headers for a PAR/token request — empty unless attestation-based client auth
     * is both configured and the right method for this AS.
     *
     * Selection follows the AS's `token_endpoint_auth_methods_supported`: **`public` is preferred wherever it
     * is offered**, so the WUA is asserted only when the AS supports `attest_jwt_client_auth` and does *not*
     * also offer `public`. A WUA the AS can't validate (e.g. no trusted `x5c` chain) is rejected, so sending
     * one where `public` would do only breaks issuance. When the AS advertises no methods, default to public
     * (send nothing) — the safe choice, since asserting an unvalidatable WUA is what fails.
     */
    private suspend fun clientAuthHeaders(asMeta: AuthorizationServerMetadata): List<Pair<String, String>> {
        val auth = clientAuth ?: return emptyList()
        val methods = asMeta.tokenEndpointAuthMethodsSupported
        val useAttestation = methods.contains("attest_jwt_client_auth") && !methods.contains("public")
        return if (useAttestation) auth.headers(asMeta.issuer) else emptyList()
    }
    /**
     * Resolves a credential offer from a wallet deep link / QR payload (OpenID4VCI §4.1):
     * accepts `<scheme>://…?credential_offer=<url-encoded-json>`, a `credential_offer_uri`
     * by reference (fetched here), or the raw offer JSON.
     */
    suspend fun resolveCredentialOffer(input: String): CredentialOffer {
        val trimmed = input.trim()
        if (trimmed.startsWith("{")) return CredentialOffer.parse(trimmed)
        queryParam(trimmed, "credential_offer")?.let { return CredentialOffer.parse(it) }
        queryParam(trimmed, "credential_offer_uri")?.let { uri ->
            val response = rawGet(uri)
            checkStatus(response, uri)
            return CredentialOffer.parse(response.body.decodeToString())
        }
        throw VciException.InvalidOffer("no credential_offer or credential_offer_uri in input")
    }

    private fun queryParam(input: String, name: String): String? {
        val query = input.substringAfter('?', "")
        return query.split('&')
            .firstOrNull { it.substringBefore('=') == name }
            ?.substringAfter('=', "")
            ?.let { URLDecoder.decode(it, "UTF-8") }
    }

    suspend fun loadIssuerMetadata(credentialIssuer: String): CredentialIssuerMetadata {
        val url = wellKnown(credentialIssuer, "openid-credential-issuer")
        val response = http.execute(HttpRequest(HttpMethod.GET, url, listOf("Accept" to metadataPolicy.acceptHeader())))
        checkStatus(response, url)
        return CredentialIssuerMetadata.fromObj(metadataBody(response, url, credentialIssuer))
    }

    /**
     * Picks the unsigned/signed branch by response media type (OpenID4VCI §12.2.2): `application/json`
     * carries the metadata as-is, `application/jwt` carries it as the payload of a signed JWT. Issuers
     * MUST label the body; when the header is absent we fall back to sniffing a JSON object.
     */
    private suspend fun metadataBody(response: HttpResponse, url: String, credentialIssuer: String): JsonValue.Obj {
        val mediaType = header(response, "Content-Type")?.substringBefore(';')?.trim()?.lowercase()
        val text = response.body.decodeToString().trim()
        val signed = when (mediaType) {
            "application/jwt" -> true
            "application/json" -> false
            else -> !text.startsWith("{")
        }
        if (!signed) {
            if (metadataPolicy is IssuerMetadataPolicy.RequireSigned) {
                throw VciException.MetadataError("policy requires signed metadata but the issuer returned unsigned metadata")
            }
            return parseObj(response, url)
        }
        return verifySignedMetadata(text, credentialIssuer)
    }

    /**
     * Enforces the §12.2.3 shape — `typ`, an asymmetric `alg`, `sub` matching the Credential Issuer
     * Identifier, a present `iat` and an unexpired `exp`. [SignedMetadataVerifier] proves the signature
     * and the signer's trust; the verified payload *is* the metadata (all parameters are top-level claims).
     */
    private suspend fun verifySignedMetadata(jws: String, credentialIssuer: String): JsonValue.Obj {
        val verifier = metadataPolicy.verifierOrNull
            ?: throw VciException.MetadataError("issuer returned signed metadata but no SignedMetadataVerifier is configured")

        val parsed = runCatching { Jws.parse(jws) }.getOrElse {
            throw VciException.MetadataError("signed metadata is not a compact JWS")
        }
        val typ = (parsed.header["typ"] as? JsonValue.Str)?.value
        if (typ != SIGNED_METADATA_TYP) {
            throw VciException.MetadataError("signed metadata typ must be '$SIGNED_METADATA_TYP', got '${typ ?: "<missing>"}'")
        }
        val alg = (parsed.header["alg"] as? JsonValue.Str)?.value
            ?: throw VciException.MetadataError("signed metadata has no alg")
        if (alg.equals("none", ignoreCase = true) || alg.startsWith("HS")) {
            throw VciException.MetadataError("signed metadata alg must be an asymmetric signature, got '$alg'")
        }

        val claims = verifier.verify(jws)

        val sub = (claims["sub"] as? JsonValue.Str)?.value
            ?: throw VciException.MetadataError("signed metadata has no sub")
        if (sub.trimEnd('/') != credentialIssuer.trimEnd('/')) {
            throw VciException.MetadataError("signed metadata sub '$sub' does not match the Credential Issuer Identifier '$credentialIssuer'")
        }
        if (claims["iat"] !is JsonValue.NumInt) throw VciException.MetadataError("signed metadata has no iat")
        (claims["exp"] as? JsonValue.NumInt)?.let {
            if (it.value <= clock()) throw VciException.MetadataError("signed metadata expired at ${it.value}")
        }
        return claims
    }

    suspend fun loadAuthorizationServerMetadata(issuer: String): AuthorizationServerMetadata {
        // Try OAuth AS metadata, then OpenID configuration (issuers vary).
        for (suffix in listOf("oauth-authorization-server", "openid-configuration")) {
            val response = rawGet(wellKnown(issuer, suffix))
            if (response.status in 200..299) {
                return AuthorizationServerMetadata.fromObj(parseObj(response, "AS metadata"))
            }
        }
        throw VciException.MetadataError("no authorization server metadata at $issuer")
    }

    /**
     * Step 1 of the authorization code grant: pushes the authorization request (PAR when the
     * AS supports it) and returns the URL the host must open in a browser, plus the opaque
     * continuation to hand back to [finishAuthorizationCodeIssuance] after the redirect.
     */
    suspend fun prepareAuthorizationCodeIssuance(
        credentialIssuer: String,
        configurationId: String,
        redirectUri: String,
        issuerState: String? = null,
        /** Favor `scope` over `authorization_details` when the config advertises one (HAIP/EUDI default). */
        preferScope: Boolean = true,
    ): PreparedAuthorization {
        val issuerMeta = loadIssuerMetadata(credentialIssuer)
        val asMeta = loadAuthorizationServerMetadata(issuerMeta.authorizationServers.first())
        val pkce = Pkce.create(rng)
        val state = com.hopae.eudi.wallet.sdjwt.Base64Url.encode(rng.nextBytes(16))

        val scope = issuerMeta.credentialConfigurationsSupported[configurationId]?.scope
        val authorizationDetails = JsonValue.Arr(
            listOf(
                JsonValue.Obj(
                    listOf(
                        "type" to JsonValue.Str("openid_credential"),
                        "credential_configuration_id" to JsonValue.Str(configurationId),
                    )
                )
            )
        ).serialize()

        val baseParams = buildList {
            add("response_type" to "code")
            add("client_id" to clientId)
            add("redirect_uri" to redirectUri)
            add("code_challenge" to pkce.codeChallenge)
            add("code_challenge_method" to pkce.method)
            if (preferScope && scope != null) {
                add("scope" to scope)
            } else {
                add("authorization_details" to authorizationDetails)
            }
            add("state" to state)
            issuerState?.let { add("issuer_state" to it) }
        }

        val authorizationUrl = if (asMeta.pushedAuthorizationRequestEndpoint != null) {
            val form = baseParams.joinToString("&") { "${enc(it.first)}=${enc(it.second)}" }
            val parHeaders = listOf(
                "Content-Type" to "application/x-www-form-urlencoded", "Accept" to "application/json",
            ) + clientAuthHeaders(asMeta)
            val parResp = http.execute(
                HttpRequest(HttpMethod.POST, asMeta.pushedAuthorizationRequestEndpoint, parHeaders, form.encodeToByteArray())
            )
            checkOAuth(parResp, asMeta.pushedAuthorizationRequestEndpoint)
            val requestUri = (parseObj(parResp, "PAR response")["request_uri"] as? JsonValue.Str)?.value
                ?: throw VciException.ProtocolError("PAR response missing request_uri")
            val endpoint = asMeta.authorizationEndpoint
                ?: throw VciException.MetadataError("AS has PAR but no authorization_endpoint")
            "$endpoint?client_id=${enc(clientId)}&request_uri=${enc(requestUri)}"
        } else {
            val endpoint = asMeta.authorizationEndpoint
                ?: throw VciException.MetadataError("AS metadata has no authorization_endpoint")
            endpoint + "?" + baseParams.joinToString("&") { "${enc(it.first)}=${enc(it.second)}" }
        }

        return PreparedAuthorization(authorizationUrl, state, pkce, redirectUri, configurationId, issuerMeta, asMeta)
    }

    /**
     * Step 2 of the authorization code grant: exchanges the redirect's `code` for a
     * DPoP-bound access token and requests the credential. [prepared] comes from
     * [prepareAuthorizationCodeIssuance]; the host must verify the redirect `state`
     * equals [PreparedAuthorization.state] before calling this.
     */
    suspend fun finishAuthorizationCodeIssuance(
        prepared: PreparedAuthorization,
        authorizationCode: String,
        keys: IssuanceKeys,
    ): CredentialResponse {
        val dpop = DpopProver(keys.dpopSigner, keys.dpopPublicKey, rng, clock)
        val token = exchangeCode(
            prepared.asMetadata, authorizationCode, prepared.redirectUri, prepared.pkce.codeVerifier, dpop,
        )
        return requestCredential(prepared.issuerMetadata, prepared.configurationId, token, dpop, keys)
    }

    /**
     * Stateless variant of [finishAuthorizationCodeIssuance]: a host that persisted only the
     * `code_verifier` + `redirect_uri` across the browser redirect (rather than the whole
     * [PreparedAuthorization]) reloads metadata and completes issuance here.
     */
    suspend fun exchangeAuthorizationCode(
        credentialIssuer: String,
        configurationId: String,
        authorizationCode: String,
        redirectUri: String,
        codeVerifier: String,
        keys: IssuanceKeys,
    ): CredentialResponse {
        val issuerMeta = loadIssuerMetadata(credentialIssuer)
        val asMeta = loadAuthorizationServerMetadata(issuerMeta.authorizationServers.first())
        val dpop = DpopProver(keys.dpopSigner, keys.dpopPublicKey, rng, clock)
        val token = exchangeCode(asMeta, authorizationCode, redirectUri, codeVerifier, dpop)
        return requestCredential(issuerMeta, configurationId, token, dpop, keys)
    }

    private suspend fun exchangeCode(
        asMeta: AuthorizationServerMetadata,
        authorizationCode: String,
        redirectUri: String,
        codeVerifier: String,
        dpop: DpopProver,
    ): TokenResponse {
        val form = buildString {
            append("grant_type=").append(enc("authorization_code"))
            append("&code=").append(enc(authorizationCode))
            append("&redirect_uri=").append(enc(redirectUri))
            append("&code_verifier=").append(enc(codeVerifier))
            append("&client_id=").append(enc(clientId))
        }
        val tokenResp = postFormWithDpop(asMeta.tokenEndpoint, form, dpop, accessToken = null, extraHeaders = clientAuthHeaders(asMeta))
        return TokenResponse.fromObj(parseObj(tokenResp, "token response"))
    }

    /**
     * Runs the full pre-authorized code flow and returns the issued credential(s).
     * @throws VciException.TxCodeRequired if the offer needs a tx_code and [txCode] is null.
     */
    suspend fun issueWithPreAuthorizedCode(
        offer: CredentialOffer,
        configurationId: String,
        keys: IssuanceKeys,
        txCode: String? = null,
    ): CredentialResponse {
        val preAuthCode = offer.preAuthorizedCode
            ?: throw VciException.InvalidOffer("offer has no pre-authorized_code grant")
        if (offer.txCode != null && txCode == null) {
            throw VciException.TxCodeRequired(offer.txCode.length, offer.txCode.inputMode)
        }
        if (configurationId !in offer.credentialConfigurationIds) {
            throw VciException.InvalidOffer("configuration '$configurationId' not in offer")
        }

        val issuerMeta = loadIssuerMetadata(offer.credentialIssuer)
        val asMeta = loadAuthorizationServerMetadata(issuerMeta.authorizationServers.first())

        val dpop = DpopProver(keys.dpopSigner, keys.dpopPublicKey, rng, clock)

        // --- token request ---
        val form = buildString {
            append("grant_type=").append(enc(GRANT_PRE_AUTHORIZED))
            append("&pre-authorized_code=").append(enc(preAuthCode))
            txCode?.let { append("&tx_code=").append(enc(it)) }
        }
        val tokenResp = postFormWithDpop(asMeta.tokenEndpoint, form, dpop, accessToken = null, extraHeaders = clientAuthHeaders(asMeta))
        val token = TokenResponse.fromObj(parseObj(tokenResp, "token response"))
        if (!token.tokenType.equals("DPoP", ignoreCase = true)) {
            throw VciException.ProtocolError("expected DPoP token_type, got '${token.tokenType}'")
        }

        return requestCredential(issuerMeta, configurationId, token, dpop, keys)
    }

    /** Shared tail of every grant: c_nonce → key proof → credential request. */
    private suspend fun requestCredential(
        issuerMeta: CredentialIssuerMetadata,
        configurationId: String,
        token: TokenResponse,
        dpop: DpopProver,
        keys: IssuanceKeys,
    ): CredentialResponse {
        // OpenID4VCI 1.0 §7: the c_nonce is obtained only from the Nonce Endpoint (draft-13 and earlier
        // returned it in the token response; that path is gone).
        val cNonce = issuerMeta.nonceEndpoint?.let { fetchCNonce(it) }
        val config = issuerMeta.credentialConfigurationsSupported[configurationId]
        val requestFormat = config?.format ?: "dc+sd-jwt"
        val encryption = CredentialEncryptionSession.negotiate(credentialEncryption, issuerMeta)
        // §8.2: when the token response bound credential_identifiers to this config, the request MUST use a
        // credential_identifier and MUST NOT send credential_configuration_id. We request the first dataset;
        // the config maps 1:1 to a credential in this SDK, so any further identifiers are not auto-expanded.
        val credentialIdentifier = token.credentialIdentifiers[configurationId]?.firstOrNull()
        val requestBody = JsonValue.Obj(
            buildList {
                if (credentialIdentifier != null) {
                    add("credential_identifier" to JsonValue.Str(credentialIdentifier))
                } else {
                    add("credential_configuration_id" to JsonValue.Str(configurationId))
                }
                add("proofs" to proofs(issuerMeta, config, cNonce, keys))
                encryption?.let { add("credential_response_encryption" to it.requestObject()) }
            }
        ).serialize()

        val credResp = if (encryption == null) {
            postJsonWithDpop(issuerMeta.credentialEndpoint, requestBody, dpop, accessToken = token.accessToken)
        } else {
            postWithDpop(
                issuerMeta.credentialEndpoint, encryption.encryptRequest(requestBody), "application/jwt",
                dpop, accessToken = token.accessToken,
            )
        }
        return CredentialResponse.fromObj(credentialBody(credResp, encryption), requestFormat)
            .withContext(token.accessToken, issuerMeta.credentialIssuer, requestFormat, token.refreshToken, configurationId)
    }

    /**
     * The `proofs` object (§8.2.1 / ETSI TS 119 472-3 §4.6). Three shapes, decided by whether the issuer's
     * config requires a Key Attestation and by [preferAttestationProof]:
     *
     *  1. **bare `jwt`** — no attestation required: one `jwt` proof per proof key (Appendix F.1, batch), each
     *     its own proof of possession. Distinct keys, up to the issuer's `batch_size`.
     *  2. **`jwt` + Key Attestation** (default when attestation IS required): **exactly one** `jwt` proof —
     *     proof of possession by the *first* proof key — carrying the Key Attestation (whose `attested_keys`
     *     cover the whole batch) in its `key_attestation` header. NOT one-jwt-per-key (that N×N shape is
     *     rejected — ETSI CRED-REQ-4.6.1.2-01). Preferred because it still does a real PoP.
     *  3. **`attestation` proof** — only when [preferAttestationProof] and the issuer advertises the
     *     `attestation` proof type: a single Key Attestation JWT on its own, no PoP (Appendix F.3).
     */
    private suspend fun proofs(
        issuerMeta: CredentialIssuerMetadata,
        config: CredentialConfiguration?,
        cNonce: String?,
        keys: IssuanceKeys,
    ): JsonValue.Obj {
        val source = keys.keyAttestation ?: keyAttestation
        val attestationRequired = config?.keyAttestationRequired == true
        val wantAttestation = attestationRequired || (preferAttestationProof && source != null)

        if (wantAttestation) {
            val s = source ?: throw VciException.Unsupported(
                "issuer requires a key attestation for this credential but no attestation source is configured",
            )
            if (preferAttestationProof && config?.proofTypesSupported?.contains("attestation") == true) {
                // Shape 3 (Appendix F.3): a single Key Attestation JWT, its attested_keys bind the Credential(s).
                return JsonValue.Obj(listOf("attestation" to JsonValue.Arr(listOf(JsonValue.Str(s.attestation(cNonce))))))
            }
            // Shape 2: exactly one jwt proof — PoP by the first proof key — with the batch attestation in-header.
            val jwt = KeyProofSigner(keys.proofSigner, keys.proofPublicKey, clock)
                .proofJwt(issuerMeta.credentialIssuer, cNonce, clientId, s.attestation(cNonce))
            return JsonValue.Obj(listOf("jwt" to JsonValue.Arr(listOf(JsonValue.Str(jwt)))))
        }

        // Shape 1: bare jwt proof per proof key (batch), each its own PoP, no attestation.
        val proofJwts = keys.proofKeys.map { pk ->
            KeyProofSigner(pk.signer, pk.publicKey, clock).proofJwt(issuerMeta.credentialIssuer, cNonce, clientId, null)
        }
        return JsonValue.Obj(listOf("jwt" to JsonValue.Arr(proofJwts.map { JsonValue.Str(it) })))
    }

    /**
     * §8.3: an encrypted Credential Response arrives as `application/jwt`, an unencrypted one as
     * `application/json`. §10 also says a message that had to be encrypted but arrived in the clear
     * should be rejected — so a plaintext answer to an encrypted request is an error, not a fallback.
     */
    private fun credentialBody(response: HttpResponse, encryption: CredentialEncryptionSession?): JsonValue.Obj {
        val mediaType = header(response, "Content-Type")?.substringBefore(';')?.trim()?.lowercase()
        val text = response.body.decodeToString().trim()
        val encrypted = mediaType == "application/jwt" || (mediaType == null && !text.startsWith("{"))
        if (encryption == null) {
            if (encrypted) throw VciException.ProtocolError("issuer encrypted a response the wallet did not ask to be encrypted")
            return parseObj(response, "credential response")
        }
        if (!encrypted) throw VciException.ProtocolError("issuer answered an encrypted credential request in the clear")
        return encryption.decryptResponse(text)
    }

    /**
     * Reissues (renews) a credential using the refresh token from a prior issuance (OAuth 2.0
     * refresh_token grant, RFC 6749 §6) — no browser re-authorization. Bind [keys] to fresh holder
     * keys to rotate the credential's key. Requires [CredentialResponse.canReissue].
     */
    suspend fun reissue(previous: CredentialResponse, keys: IssuanceKeys): CredentialResponse {
        val refreshToken = previous.refreshToken ?: throw VciException.ProtocolError("no refresh_token to reissue")
        val configurationId = previous.configurationId ?: throw VciException.ProtocolError("no configuration_id to reissue")
        val issuerMeta = loadIssuerMetadata(previous.credentialIssuer!!)
        val asMeta = loadAuthorizationServerMetadata(issuerMeta.authorizationServers.first())

        val dpop = DpopProver(keys.dpopSigner, keys.dpopPublicKey, rng, clock)
        val form = buildString {
            append("grant_type=").append(enc("refresh_token"))
            append("&refresh_token=").append(enc(refreshToken))
            append("&client_id=").append(enc(clientId))
        }
        val tokenResp = postFormWithDpop(asMeta.tokenEndpoint, form, dpop, accessToken = null, extraHeaders = clientAuthHeaders(asMeta))
        val token = TokenResponse.fromObj(parseObj(tokenResp, "refresh token response"))
        return requestCredential(issuerMeta, configurationId, token, dpop, keys)
    }

    /**
     * Polls the deferred credential endpoint (OpenID4VCI §9) for a credential the issuer was not
     * yet ready to issue. Pass the [CredentialResponse] whose [CredentialResponse.isDeferred] is true.
     * Still not ready → the returned response is again `isDeferred` (§9.2, HTTP 202); a real failure throws.
     */
    suspend fun fetchDeferredCredential(deferred: CredentialResponse, keys: IssuanceKeys): CredentialResponse {
        val transactionId = deferred.transactionId
            ?: throw VciException.ProtocolError("response has no transaction_id to defer")
        val accessToken = deferred.accessToken ?: throw VciException.ProtocolError("deferred response has no access token")
        val issuerMeta = loadIssuerMetadata(deferred.credentialIssuer!!)
        val endpoint = issuerMeta.deferredCredentialEndpoint
            ?: throw VciException.MetadataError("issuer has no deferred_credential_endpoint")

        val dpop = DpopProver(keys.dpopSigner, keys.dpopPublicKey, rng, clock)
        // §9.1: the Deferred Credential Request/Response are encrypted exactly like the Credential
        // endpoint (§8.2/§10). A fresh session per request — its own response-encryption key.
        val encryption = CredentialEncryptionSession.negotiate(credentialEncryption, issuerMeta)
        val requestBody = JsonValue.Obj(
            buildList {
                add("transaction_id" to JsonValue.Str(transactionId))
                encryption?.let { add("credential_response_encryption" to it.requestObject()) }
            }
        ).serialize()

        // §9.2: "still deferred" is an HTTP 202 re-deferral (transaction_id + interval), which comes back
        // as a normal CredentialResponse the caller inspects via isDeferred — not an error. A real error
        // (invalid_transaction_id, credential_request_denied) surfaces from postWithDpop as usual.
        val response = if (encryption == null) {
            postJsonWithDpop(endpoint, requestBody, dpop, accessToken)
        } else {
            postWithDpop(endpoint, encryption.encryptRequest(requestBody), "application/jwt", dpop, accessToken)
        }
        return CredentialResponse.fromObj(credentialBody(response, encryption), deferred.requestedFormat)
            .withContext(accessToken, deferred.credentialIssuer, deferred.requestedFormat)
    }

    /**
     * Sends an issuance notification (OpenID4VCI §10) — the wallet reports the outcome of storing the
     * credential to the issuer's notification endpoint. No-op if the response carried no notification_id.
     */
    suspend fun sendNotification(response: CredentialResponse, event: NotificationEvent, keys: IssuanceKeys) {
        val notificationId = response.notificationId ?: return
        val accessToken = response.accessToken ?: throw VciException.ProtocolError("response has no access token")
        val issuerMeta = loadIssuerMetadata(response.credentialIssuer!!)
        val endpoint = issuerMeta.notificationEndpoint
            ?: throw VciException.MetadataError("issuer has no notification_endpoint")

        val dpop = DpopProver(keys.dpopSigner, keys.dpopPublicKey, rng, clock)
        val body = JsonValue.Obj(
            listOf("notification_id" to JsonValue.Str(notificationId), "event" to JsonValue.Str(event.wire))
        ).serialize()
        checkStatus(postJsonWithDpop(endpoint, body, dpop, accessToken), endpoint)
    }

    /* ---------------- HTTP helpers ---------------- */

    private suspend fun fetchCNonce(nonceEndpoint: String): String {
        val response = http.execute(HttpRequest(HttpMethod.POST, nonceEndpoint, listOf("Accept" to "application/json")))
        checkStatus(response, nonceEndpoint)
        return (parseObj(response, "nonce response")["c_nonce"] as? JsonValue.Str)?.value
            ?: throw VciException.ProtocolError("nonce endpoint returned no c_nonce")
    }

    /** POST a form, adding a DPoP proof; retries once if the server demands a DPoP nonce. */
    private suspend fun postFormWithDpop(
        url: String,
        form: String,
        dpop: DpopProver,
        accessToken: String?,
        nonce: String? = null,
        extraHeaders: List<Pair<String, String>> = emptyList(),
    ): HttpResponse {
        val headers = mutableListOf(
            "Content-Type" to "application/x-www-form-urlencoded",
            "Accept" to "application/json",
            "DPoP" to dpop.proof("POST", url, accessToken, nonce),
        )
        headers.addAll(extraHeaders)
        accessToken?.let { headers.add("Authorization" to "DPoP $it") }
        val response = http.execute(HttpRequest(HttpMethod.POST, url, headers, form.encodeToByteArray()))

        dpopNonceChallenge(response)?.let { serverNonce ->
            if (nonce == null) return postFormWithDpop(url, form, dpop, accessToken, serverNonce, extraHeaders)
        }
        checkOAuth(response, url)
        return response
    }

    private suspend fun postJsonWithDpop(
        url: String,
        json: String,
        dpop: DpopProver,
        accessToken: String,
        nonce: String? = null,
    ): HttpResponse = postWithDpop(url, json, "application/json", dpop, accessToken, nonce)

    /** §10: an encrypted Credential Request is a compact JWE with media type `application/jwt`. */
    private suspend fun postWithDpop(
        url: String,
        body: String,
        contentType: String,
        dpop: DpopProver,
        accessToken: String,
        nonce: String? = null,
    ): HttpResponse {
        val headers = listOf(
            "Content-Type" to contentType,
            "Accept" to if (contentType == "application/jwt") "application/jwt" else "application/json",
            "DPoP" to dpop.proof("POST", url, accessToken, nonce),
            "Authorization" to "DPoP $accessToken",
        )
        val response = http.execute(HttpRequest(HttpMethod.POST, url, headers, body.encodeToByteArray()))

        dpopNonceChallenge(response)?.let { serverNonce ->
            if (nonce == null) return postWithDpop(url, body, contentType, dpop, accessToken, serverNonce)
        }
        checkOAuth(response, url)
        return response
    }

    private suspend fun getJson(url: String): JsonValue.Obj {
        val response = rawGet(url)
        checkStatus(response, url)
        return parseObj(response, url)
    }

    private suspend fun rawGet(url: String): HttpResponse =
        http.execute(HttpRequest(HttpMethod.GET, url, listOf("Accept" to "application/json")))

    private fun dpopNonceChallenge(response: HttpResponse): String? {
        if (response.status != 400 && response.status != 401) return null
        return header(response, "DPoP-Nonce")
    }

    private fun checkStatus(response: HttpResponse, endpoint: String) {
        if (response.status !in 200..299) {
            throw VciException.Http(response.status, endpoint, response.body.decodeToString().take(500))
        }
    }

    private fun checkOAuth(response: HttpResponse, endpoint: String) {
        if (response.status in 200..299) return
        val obj = runCatching { JsonValue.parse(response.body.decodeToString()) as? JsonValue.Obj }.getOrNull()
        val error = (obj?.get("error") as? JsonValue.Str)?.value
        if (error != null) {
            throw VciException.OAuthError(
                error,
                (obj["error_description"] as? JsonValue.Str)?.value,
                endpoint,
            )
        }
        throw VciException.Http(response.status, endpoint, response.body.decodeToString().take(500))
    }

    private fun parseObj(response: HttpResponse, where: String): JsonValue.Obj =
        JsonValue.parse(response.body.decodeToString()) as? JsonValue.Obj
            ?: throw VciException.ProtocolError("$where: not a JSON object")

    private fun header(response: HttpResponse, name: String): String? =
        response.headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    private fun wellKnown(base: String, suffix: String): String {
        val trimmed = base.trimEnd('/')
        // RFC 8414: well-known segment is inserted after the host, before any path.
        if (!trimmed.startsWith("https://")) throw VciException.MetadataError("issuer must be https: $base")
        val rest = trimmed.removePrefix("https://")
        val slash = rest.indexOf('/')
        return if (slash < 0) {
            "https://$rest/.well-known/$suffix"
        } else {
            "https://${rest.substring(0, slash)}/.well-known/$suffix${rest.substring(slash)}"
        }
    }

    private fun enc(v: String): String = URLEncoder.encode(v, "UTF-8")
}
