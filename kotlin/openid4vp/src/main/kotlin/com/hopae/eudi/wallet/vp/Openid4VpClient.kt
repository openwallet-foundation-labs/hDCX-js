package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwkEc
import com.hopae.eudi.wallet.sdjwt.Jwe
import com.hopae.eudi.wallet.sdjwt.JweEnc
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.Rng
import java.net.URLEncoder

/**
 * Per-query choice: which held credential(s) to present for a DCQL credential-query id. A `multiple: false`
 * query (§6.1) takes exactly one credential; a `multiple: true` query may take several — the vp_token then
 * carries one Presentation per chosen credential (§8.1).
 */
class PresentationSelection(val chosen: Map<String, List<String>>) {
    companion object {
        /**
         * Auto-pick for every required query: all matching candidates when the query is `multiple`, else the
         * first candidate only.
         */
        fun auto(matches: DcqlMatchResult): PresentationSelection {
            val chosen = matches.requiredQueryIds.mapNotNull { qid ->
                val candidates = matches.candidatesByQuery[qid].orEmpty()
                if (candidates.isEmpty()) return@mapNotNull null
                val ids = if (candidates.first().query.multiple) candidates.map { it.credential.credentialId }
                else listOf(candidates.first().credential.credentialId)
                qid to ids
            }.toMap()
            return PresentationSelection(chosen)
        }
    }
}

/** The only JWE key-agreement `alg` this SDK implements; §8.3 requires the JWE `alg` to equal the chosen JWK's. */
private const val ECDH_ES = "ECDH-ES"

/** Outcome of submitting the presentation. */
class SubmitResult(val redirectUri: String?)

/**
 * OpenID4VP 1.0 client (wallet/holder side) over the [HttpTransport] port. Resolves the
 * request, runs DCQL matching, builds the `vp_token`, and submits via `direct_post` or the
 * encrypted `direct_post.jwt` (JWE). SD-JWT VC presentations; mdoc arrives with M4.
 */
class Openid4VpClient(
    private val http: HttpTransport,
    /** epoch seconds; injectable for deterministic tests. */
    private val clock: () -> Long,
    /** Trust verifier for signed request objects (from the `trust` module); null = parse untrusted. */
    trust: RequestTrustVerifier? = null,
    /** Enables the `wallet_nonce` replay mitigation on `request_uri_method=post` (§5.10); null = don't send one. */
    rng: Rng? = null,
) {
    private val resolver = AuthorizationRequestResolver(http, trust, rng)

    suspend fun resolveRequest(requestUri: String): ResolvedRequest = resolver.resolve(requestUri)

    /** Resolves an OpenID4VP request delivered over the Digital Credentials API (with the caller [origin]). */
    suspend fun resolveDcApiRequest(requestObject: String, origin: String): ResolvedRequest =
        resolver.resolveDcApi(requestObject, origin)

    fun match(request: ResolvedRequest, held: List<PresentableCredential>): DcqlMatchResult =
        DcqlEngine.match(request.dcqlQuery, held)

    /**
     * Builds the presentations for [selection] and submits them. Throws
     * [VpException.QueryNotSatisfiable] if a required query has no chosen candidate.
     */
    suspend fun respond(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: List<PresentableCredential>,
    ): SubmitResult {
        val vpToken = buildVpToken(request, matches, selection, held)
        return when (request.responseMode) {
            "direct_post" -> submitDirectPost(request, vpToken)
            "direct_post.jwt" -> submitDirectPostJwt(request, vpToken)
            else -> throw VpException.Unsupported("response_mode ${request.responseMode}")
        }
    }

    /**
     * Builds the presentations for a Digital Credentials API request and returns the response object
     * to hand back to the platform (no HTTP POST): `{vp_token}` for `dc_api`, `{response: <JWE>}` for
     * `dc_api.jwt`. mdoc presentations bind the caller origin via the DC API handover.
     */
    suspend fun respondDcApi(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: List<PresentableCredential>,
    ): JsonValue.Obj {
        val vpToken = buildVpToken(request, matches, selection, held)
        return when (request.responseMode) {
            "dc_api" -> JsonValue.Obj(listOf("vp_token" to vpToken))
            "dc_api.jwt" -> {
                val recipient = verifierEncryptionKey(request)
                    ?: throw VpException.InvalidRequest("dc_api.jwt but no ECDH-ES verifier encryption key in client_metadata")
                val response = JsonValue.Obj(listOf("vp_token" to vpToken))
                val jwe = Jwe.encryptEcdhEs(
                    response.serialize().encodeToByteArray(), recipient.publicKey, encValue(request),
                    apv = apv(request), kid = recipient.kid,
                )
                JsonValue.Obj(listOf("response" to JsonValue.Str(jwe)))
            }
            else -> throw VpException.Unsupported("respondDcApi requires a dc_api response_mode, got ${request.responseMode}")
        }
    }

    /**
     * Sends an Authorization Error Response (§8.5) to the verifier's `response_uri`: a form POST of
     * `error` / `error_description` / `state`, symmetric to the success submission. Returns the
     * verifier's `redirect_uri` when it supplies one — which the wallet MUST then follow.
     *
     * Only defined for the `direct_post` response modes. Over the Digital Credentials API there is no
     * `response_uri`; the error is handed back to the platform, and §15.9.2 warns that returning
     * protocol errors there can itself reveal whether the wallet holds a matching credential.
     */
    suspend fun reportError(
        request: ResolvedRequest,
        code: VpErrorCode,
        description: String? = null,
    ): SubmitResult {
        val responseUri = request.responseUri
            ?: throw VpException.Unsupported("error responses are only sent to a response_uri (direct_post)")
        val form = buildString {
            append("error=").append(enc(code.code))
            description?.let { append("&error_description=").append(enc(it)) }
            request.state?.let { append("&state=").append(enc(it)) }
        }
        return post(responseUri, form)
    }

    private suspend fun buildVpToken(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: List<PresentableCredential>,
    ): JsonValue.Obj {
        val missing = matches.requiredQueryIds.filter { it !in selection.chosen }.toSet()
        if (missing.isNotEmpty()) throw VpException.QueryNotSatisfiable(missing)

        val heldById = held.associateBy { it.credentialId }
        val iat = clock()
        // Encrypted responses (direct_post.jwt / dc_api.jwt) carry a verifier encryption key: it binds the
        // mdoc handover (thumbprint) and doubles as the EReaderKey for mdoc deviceMac (ISO 18013-7 B.4.5).
        val encryptionKey = if (request.responseMode.endsWith(".jwt")) verifierEncryptionKey(request) else null
        val jwkThumbprint = encryptionKey?.let { ecJwkThumbprint(it.publicKey) }
        val deviceAuthAlgValues = deviceAuthAlgValues(request)

        val vpEntries = mutableListOf<Pair<String, JsonValue>>()
        for ((queryId, credentialIds) in selection.chosen) {
            val queryCandidates = matches.candidatesByQuery[queryId].orEmpty()
            // §8.1: a query that is not `multiple` MUST return exactly one Presentation.
            if (credentialIds.isEmpty()) throw VpException.SelectionIncomplete("no credential selected for query $queryId")
            if (queryCandidates.firstOrNull()?.query?.multiple != true && credentialIds.size > 1) {
                throw VpException.InvalidRequest("query '$queryId' is not 'multiple' but ${credentialIds.size} credentials were selected")
            }
            val presentations = credentialIds.map { credentialId ->
                val candidate = queryCandidates.firstOrNull { it.credential.credentialId == credentialId }
                    ?: throw VpException.SelectionIncomplete("no candidate $credentialId for query $queryId")
                val cred = heldById[credentialId] ?: throw VpException.SelectionIncomplete("unknown credential $credentialId")
                JsonValue.Str(
                    cred.present(
                        PresentationContext(
                            disclosedPaths = candidate.disclosedPaths,
                            clientId = request.clientId,
                            nonce = request.nonce,
                            responseUri = request.responseUri,
                            issuedAt = iat,
                            transactionData = request.transactionData,
                            verifierJwkThumbprint = jwkThumbprint,
                            origin = request.origin,
                            verifierEncryptionKey = encryptionKey?.publicKey,
                            deviceAuthAlgValues = deviceAuthAlgValues,
                            requireHolderBinding = candidate.query.requireCryptographicHolderBinding,
                        )
                    )
                )
            }
            vpEntries.add(queryId to JsonValue.Arr(presentations))
        }
        return JsonValue.Obj(vpEntries)
    }

    private suspend fun submitDirectPost(request: ResolvedRequest, vpToken: JsonValue.Obj): SubmitResult {
        val form = buildString {
            append("vp_token=").append(enc(vpToken.serialize()))
            request.state?.let { append("&state=").append(enc(it)) }
        }
        return post(request.responseUri ?: throw VpException.InvalidRequest("direct_post needs response_uri"), form)
    }

    private suspend fun submitDirectPostJwt(request: ResolvedRequest, vpToken: JsonValue.Obj): SubmitResult {
        val recipient = verifierEncryptionKey(request)
            ?: throw VpException.InvalidRequest("direct_post.jwt but no ECDH-ES verifier encryption key in client_metadata")
        val enc = encValue(request)
        val response = JsonValue.Obj(
            buildList {
                add("vp_token" to vpToken)
                request.state?.let { add("state" to JsonValue.Str(it)) }
            }
        )
        val jwe = Jwe.encryptEcdhEs(
            response.serialize().encodeToByteArray(), recipient.publicKey, enc,
            apv = apv(request), kid = recipient.kid,
        )
        val form = "response=" + enc(jwe)
        return post(request.responseUri ?: throw VpException.InvalidRequest("direct_post.jwt needs response_uri"), form)
    }

    private suspend fun post(url: String, form: String): SubmitResult {
        val resp = http.execute(
            HttpRequest(
                HttpMethod.POST, url,
                listOf("Content-Type" to "application/x-www-form-urlencoded", "Accept" to "application/json"),
                form.encodeToByteArray(),
            )
        )
        if (resp.status !in 200..299) {
            throw VpException.ResponseFailed("verifier returned HTTP ${resp.status}: ${resp.body.decodeToString().take(300)}")
        }
        val body = runCatching { JsonValue.parse(resp.body.decodeToString()) as? JsonValue.Obj }.getOrNull()
        return SubmitResult(redirectUri = (body?.get("redirect_uri") as? JsonValue.Str)?.value)
    }

    /** The verifier's chosen encryption key, with the `kid` §8.3 makes the wallet echo back. */
    private class VerifierEncryptionKey(val publicKey: com.hopae.eudi.wallet.cbor.cose.EcPublicKey, val kid: String?)

    /**
     * Selects the verifier's response-encryption key from `client_metadata.jwks` (OpenID4VP §8.3).
     * The spec requires `alg` on every JWK and requires the JWE `alg` to equal the chosen key's, so we
     * only consider `ECDH-ES` keys — the one key-agreement algorithm this SDK implements. `use: enc`
     * keys win over unmarked ones.
     */
    private fun verifierEncryptionKey(request: ResolvedRequest): VerifierEncryptionKey? {
        val jwks = request.clientMetadata?.get("jwks") as? JsonValue.Obj ?: return null
        val keys = (jwks["keys"] as? JsonValue.Arr)?.items?.filterIsInstance<JsonValue.Obj>() ?: return null
        val usable = keys.filter { (it["alg"] as? JsonValue.Str)?.value == ECDH_ES }
        val chosen = usable.firstOrNull { (it["use"] as? JsonValue.Str)?.value == "enc" } ?: usable.firstOrNull() ?: return null
        val publicKey = JwkEc.fromJson(chosen) ?: return null
        return VerifierEncryptionKey(publicKey, (chosen["kid"] as? JsonValue.Str)?.value)
    }

    /**
     * The verifier's accepted mdoc device-authentication algorithms (OpenID4VP §B.2.2): the
     * `deviceauth_alg_values` array under `client_metadata.vp_formats_supported.mso_mdoc` (or the older
     * `vp_formats`). Null when the verifier did not constrain it — then `deviceSignature` is used.
     */
    private fun deviceAuthAlgValues(request: ResolvedRequest): List<Long>? {
        val formats = (request.clientMetadata?.get("vp_formats_supported")
            ?: request.clientMetadata?.get("vp_formats")) as? JsonValue.Obj ?: return null
        val mdoc = formats["mso_mdoc"] as? JsonValue.Obj ?: return null
        val values = (mdoc["deviceauth_alg_values"] as? JsonValue.Arr)?.items ?: return null
        return values.mapNotNull {
            when (it) {
                is JsonValue.NumInt -> it.value
                is JsonValue.NumDouble -> it.value.toLong()
                else -> null
            }
        }.ifEmpty { null }
    }

    /**
     * ISO 18013-7 B.5.3: the mdoc sets `apv` to the base64url of the request `nonce`. `apu` would carry
     * the `mdocGeneratedNonce` of the TS-literal B.4.4 handover, which OpenID4VP 1.0 Final replaced —
     * so there is no `apu` to send. Both are ConcatKDF inputs and part of the AEAD tag either way.
     */
    private fun apv(request: ResolvedRequest): ByteArray = request.nonce.encodeToByteArray()

    private fun encValue(request: ResolvedRequest): JweEnc {
        val id = (request.clientMetadata?.get("encrypted_response_enc_values_supported") as? JsonValue.Arr)
            ?.items?.mapNotNull { (it as? JsonValue.Str)?.value }?.firstOrNull()
            ?: (request.clientMetadata?.get("authorization_encrypted_response_enc") as? JsonValue.Str)?.value
        return id?.let { JweEnc.from(it) } ?: JweEnc.A128GCM
    }

    private fun enc(v: String): String = URLEncoder.encode(v, "UTF-8")
}
