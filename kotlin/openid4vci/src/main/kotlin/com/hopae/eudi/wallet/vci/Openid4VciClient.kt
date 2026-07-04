package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.Rng
import java.net.URLEncoder

/** Holder key material for issuance: a key-proof (bound into the credential) and a DPoP key. */
class IssuanceKeys(
    val proofSigner: JwsSigner,
    val proofPublicKey: EcPublicKey,
    val dpopSigner: JwsSigner,
    val dpopPublicKey: EcPublicKey,
)

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
    private val clientId: String = "wallet-dev",
) {
    suspend fun loadIssuerMetadata(credentialIssuer: String): CredentialIssuerMetadata {
        val url = wellKnown(credentialIssuer, "openid-credential-issuer")
        val body = getJson(url)
        return CredentialIssuerMetadata.fromObj(body)
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
    ): PreparedAuthorization {
        val issuerMeta = loadIssuerMetadata(credentialIssuer)
        val asMeta = loadAuthorizationServerMetadata(issuerMeta.authorizationServers.first())
        val pkce = Pkce.create(rng)
        val state = com.hopae.eudi.wallet.sdjwt.Base64Url.encode(rng.nextBytes(16))

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
            add("authorization_details" to authorizationDetails)
            add("state" to state)
            issuerState?.let { add("issuer_state" to it) }
        }

        val authorizationUrl = if (asMeta.pushedAuthorizationRequestEndpoint != null) {
            val form = baseParams.joinToString("&") { "${enc(it.first)}=${enc(it.second)}" }
            val parResp = http.execute(
                HttpRequest(
                    HttpMethod.POST,
                    asMeta.pushedAuthorizationRequestEndpoint,
                    listOf("Content-Type" to "application/x-www-form-urlencoded", "Accept" to "application/json"),
                    form.encodeToByteArray(),
                )
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
        val issuerMeta = prepared.issuerMetadata
        val asMeta = prepared.asMetadata
        val dpop = DpopProver(keys.dpopSigner, keys.dpopPublicKey, rng, clock)

        val form = buildString {
            append("grant_type=").append(enc("authorization_code"))
            append("&code=").append(enc(authorizationCode))
            append("&redirect_uri=").append(enc(prepared.redirectUri))
            append("&code_verifier=").append(enc(prepared.pkce.codeVerifier))
            append("&client_id=").append(enc(clientId))
        }
        val tokenResp = postFormWithDpop(asMeta.tokenEndpoint, form, dpop, accessToken = null)
        val token = TokenResponse.fromObj(parseObj(tokenResp, "token response"))

        return requestCredential(issuerMeta, prepared.configurationId, token, dpop, keys)
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
        val tokenResp = postFormWithDpop(asMeta.tokenEndpoint, form, dpop, accessToken = null)
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
        val cNonce = token.cNonce ?: issuerMeta.nonceEndpoint?.let { fetchCNonce(it) }

        val proofSigner = KeyProofSigner(keys.proofSigner, keys.proofPublicKey, clock)
        val proofJwt = proofSigner.proofJwt(issuerMeta.credentialIssuer, cNonce, clientId)

        val requestFormat = issuerMeta.credentialConfigurationsSupported[configurationId]?.format ?: "dc+sd-jwt"
        val requestBody = JsonValue.Obj(
            listOf(
                "credential_configuration_id" to JsonValue.Str(configurationId),
                "proofs" to JsonValue.Obj(
                    listOf("jwt" to JsonValue.Arr(listOf(JsonValue.Str(proofJwt))))
                ),
            )
        ).serialize()

        val credResp = postJsonWithDpop(
            issuerMeta.credentialEndpoint,
            requestBody,
            dpop,
            accessToken = token.accessToken,
        )
        return CredentialResponse.fromObj(parseObj(credResp, "credential response"), requestFormat)
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
    ): HttpResponse {
        val headers = mutableListOf(
            "Content-Type" to "application/x-www-form-urlencoded",
            "Accept" to "application/json",
            "DPoP" to dpop.proof("POST", url, accessToken, nonce),
        )
        accessToken?.let { headers.add("Authorization" to "DPoP $it") }
        val response = http.execute(HttpRequest(HttpMethod.POST, url, headers, form.encodeToByteArray()))

        dpopNonceChallenge(response)?.let { serverNonce ->
            if (nonce == null) return postFormWithDpop(url, form, dpop, accessToken, serverNonce)
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
    ): HttpResponse {
        val headers = listOf(
            "Content-Type" to "application/json",
            "Accept" to "application/json",
            "DPoP" to dpop.proof("POST", url, accessToken, nonce),
            "Authorization" to "DPoP $accessToken",
        )
        val response = http.execute(HttpRequest(HttpMethod.POST, url, headers, json.encodeToByteArray()))

        dpopNonceChallenge(response)?.let { serverNonce ->
            if (nonce == null) return postJsonWithDpop(url, json, dpop, accessToken, serverNonce)
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
