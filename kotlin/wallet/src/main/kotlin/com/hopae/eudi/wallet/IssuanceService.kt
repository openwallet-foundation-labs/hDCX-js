package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtException
import com.hopae.eudi.wallet.sdjwt.SdJwtHolder
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeyHandle
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.spi.WalletClock
import com.hopae.eudi.wallet.store.CredentialEnvelope
import com.hopae.eudi.wallet.store.CredentialInstance
import com.hopae.eudi.wallet.store.CredentialMetadata
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.EnvelopeLifecycle
import com.hopae.eudi.wallet.vci.CredentialResponse
import com.hopae.eudi.wallet.vci.IssuanceKeys
import com.hopae.eudi.wallet.vci.IssuedCredential
import com.hopae.eudi.wallet.vci.NotificationEvent
import com.hopae.eudi.wallet.vci.Openid4VciClient
import com.hopae.eudi.wallet.vci.ProofKey
import com.hopae.eudi.wallet.vci.VciException
import kotlinx.coroutines.CoroutineScope

/** OpenID4VCI issuance. Owns key creation, issuance, persistence, and follow-ups. */
class IssuanceService internal constructor(
    private val vci: Openid4VciClient,
    private val store: CredentialStore,
    private val storage: StorageDriver,
    private val secureArea: SecureArea,
    private val scope: CoroutineScope,
    private val rng: Rng,
    private val clock: WalletClock,
    private val redirectUri: String,
) {
    private class BuiltKeys(val keys: IssuanceKeys, val proofKeys: List<KeyInfo>, val dpopKey: KeyInfo)

    /** Step 1 of the 2-phase flow: resolve an offer deep link / QR / raw JSON. */
    suspend fun resolveOffer(offerUri: String): CredentialOffer =
        CredentialOffer(catchingVci { vci.resolveCredentialOffer(offerUri) })

    /** Starts an issuance session — pre-authorized or authorization-code grant, driven as a state machine. */
    fun start(request: IssuanceRequest): IssuanceSession = session {
        emit(IssuanceState.Processing)
        val built = buildKeys(request.keySpec, request.policy.batchSize)
        val response = when (val source = request.source) {
            is IssuanceRequest.Source.FromOffer -> issueFromOffer(this, source.offer, request, built.keys)
            is IssuanceRequest.Source.FromIssuer -> authorizationCodeFlow(this, source.credentialIssuer, request.configurationId, null, built.keys)
        }
        // §9.2: the issuer may defer issuance — store the credential deferred and surface a Deferred
        // state (with the retry instant) instead of Completed, so the host knows to resume later.
        if (response.isDeferred) {
            val id = persistDeferred(response, built, request)
            emit(IssuanceState.Deferred(id, retryInstant(response)))
            return@session
        }
        val id = persistIssued(response, built.proofKeys.map { it.handle }, built.dpopKey.handle, request.policy, existingId = null)
        emit(IssuanceState.Completed(IssuanceResult(listOf(id))))
    }

    /**
     * Retries a deferred credential (OpenID4VCI §9). Ends in [IssuanceState.Completed] when the issuer
     * is ready, or [IssuanceState.Deferred] again (§9.2, HTTP 202) when it still needs more time.
     */
    fun resumeDeferred(credentialId: CredentialId): IssuanceSession = session {
        emit(IssuanceState.Processing)
        val envelope = store.get(credentialId) ?: throw WalletError.Issuance.CredentialRequestFailed("credential not found")
        val deferred = envelope.lifecycle as? EnvelopeLifecycle.Deferred
            ?: throw WalletError.Issuance.CredentialRequestFailed("credential is not deferred")
        val ctx = FollowUpContext.decode(deferred.transactionContext)
        val response = catchingVci { vci.fetchDeferredCredential(ctx.toCredentialResponse(), rebuildKeys(ctx)) }

        // §9.2: still deferred — refresh the stored transaction_id + retryAfter and report Deferred again.
        if (response.isDeferred) {
            val retryAfter = retryInstant(response)
            val refreshed = ctx.withTransactionId(response.transactionId).encode()
            store.save(CredentialEnvelope(envelope.id, envelope.format, envelope.createdAt, EnvelopeLifecycle.Deferred(refreshed, retryAfter), envelope.metadata))
            emit(IssuanceState.Deferred(credentialId, retryAfter))
            return@session
        }

        val id = persistIssued(response, ctx.proofKeys, ctx.dpopKey, ctx.policy, existingId = credentialId)
        emit(IssuanceState.Completed(IssuanceResult(listOf(id))))
    }

    /** The §8.3 `interval` as an absolute instant, or null when the issuer gave none. */
    private fun retryInstant(response: CredentialResponse): java.time.Instant? =
        response.interval?.let { clock.now().plusSeconds(it) }

    /** Renews a credential via the stored refresh token (RFC 6749 §6) — rotates to fresh proof keys. */
    fun reissue(credentialId: CredentialId): IssuanceSession = session {
        emit(IssuanceState.Processing)
        val ctx = loadFollowUp(credentialId) ?: throw WalletError.Issuance.CredentialRequestFailed("credential cannot be reissued")
        val fresh = buildKeys(KeySpec(secureArea = secureArea.id), ctx.policy.batchSize, dpopKey = ctx.dpopKey)
        val response = catchingVci { vci.reissue(ctx.toCredentialResponse(), fresh.keys) }
        val id = persistIssued(response, fresh.proofKeys.map { it.handle }, ctx.dpopKey, ctx.policy, existingId = credentialId)
        emit(IssuanceState.Completed(IssuanceResult(listOf(id))))
    }

    private fun session(flow: suspend IssuanceSession.() -> Unit): IssuanceSession =
        IssuanceSession(scope, flow).also { it.launch() }

    private suspend fun issueFromOffer(session: IssuanceSession, offer: CredentialOffer, request: IssuanceRequest, keys: IssuanceKeys): CredentialResponse =
        if (offer.raw.preAuthorizedCode != null) {
            val txCode = request.txCode ?: if (offer.requiresTxCode) session.awaitTxCode(offer.txCode) else null
            catchingVci { vci.issueWithPreAuthorizedCode(offer.raw, request.configurationId, keys, txCode) }
        } else {
            authorizationCodeFlow(session, offer.raw.credentialIssuer, request.configurationId, offer.raw.authorizationCodeIssuerState, keys)
        }

    private suspend fun authorizationCodeFlow(session: IssuanceSession, credentialIssuer: String, configurationId: String, issuerState: String?, keys: IssuanceKeys): CredentialResponse {
        val prepared = catchingVci { vci.prepareAuthorizationCodeIssuance(credentialIssuer, configurationId, redirectUri, issuerState) }
        val redirect = session.awaitAuthorization(prepared.authorizationUrl)
        val code = extractCode(redirect) ?: throw WalletError.Issuance.AuthorizationFailed(null, "no authorization code in redirect")
        return catchingVci { vci.finishAuthorizationCodeIssuance(prepared, code, keys) }
    }

    /** One key per credential in the batch (HAIP one-time-use), plus a DPoP key (reused on [dpopKey]). */
    private suspend fun buildKeys(keySpec: KeySpec, batchSize: Int, dpopKey: KeyHandle? = null): BuiltKeys {
        val spec = KeySpec(
            secureArea = secureArea.id, algorithm = keySpec.algorithm,
            userAuthentication = keySpec.userAuthentication, hardware = keySpec.hardware,
            attestationChallenge = keySpec.attestationChallenge,
        )
        val proofKeys = (1..batchSize.coerceAtLeast(1)).map { secureArea.createKey(spec) }
        val dpop = dpopKey?.let { KeyInfo(it, spec.algorithm, secureArea.publicKey(it)) } ?: secureArea.createKey(spec)
        fun signer(k: KeyInfo) = SecureAreaJwsSigner(secureArea, k.handle, k.algorithm)
        val keys = IssuanceKeys(
            signer(proofKeys[0]), proofKeys[0].publicKey,
            signer(dpop), dpop.publicKey,
            additionalProofKeys = proofKeys.drop(1).map { ProofKey(signer(it), it.publicKey) },
        )
        return BuiltKeys(keys, proofKeys, dpop)
    }

    private suspend fun rebuildKeys(ctx: FollowUpContext): IssuanceKeys {
        fun signer(h: KeyHandle) = SecureAreaJwsSigner(secureArea, h, SigningAlgorithm.ES256)
        val proofPubs = ctx.proofKeys.map { secureArea.publicKey(it) }
        return IssuanceKeys(
            signer(ctx.proofKeys[0]), proofPubs[0],
            signer(ctx.dpopKey), secureArea.publicKey(ctx.dpopKey),
            additionalProofKeys = ctx.proofKeys.drop(1).mapIndexed { i, h -> ProofKey(signer(h), proofPubs[i + 1]) },
        )
    }

    private suspend fun persistDeferred(response: CredentialResponse, built: BuiltKeys, request: IssuanceRequest): CredentialId {
        val ctx = contextOf(response, built.proofKeys.map { it.handle }, built.dpopKey.handle, request.policy, request.configurationId)
        val id = newId()
        val format = if (ctx.requestedFormat == "mso_mdoc") CredentialFormat.MsoMdoc(ctx.configurationId) else CredentialFormat.SdJwtVc(ctx.configurationId)
        store.save(CredentialEnvelope(id, format, clock.now(), EnvelopeLifecycle.Deferred(ctx.encode(), retryInstant(response)), captureMetadata(response)))
        return id
    }

    private suspend fun persistIssued(response: CredentialResponse, proofKeys: List<KeyHandle>, dpopKey: KeyHandle, policy: CredentialPolicy, existingId: CredentialId?): CredentialId {
        if (response.credentials.isEmpty()) throw WalletError.Issuance.CredentialRequestFailed("issuer returned no credentials")
        response.credentials.forEach { rejectIssuerBoundKb(it) }
        val format = decode(response.credentials.first()).first
        val instances = response.credentials.mapIndexed { i, credential -> CredentialInstance(proofKeys[i], decode(credential).second) }
        val id = existingId ?: newId()
        store.save(CredentialEnvelope(id, format, clock.now(), EnvelopeLifecycle.Issued(policy, instances), captureMetadata(response)))
        // Persist reissue context and best-effort notify the issuer of acceptance.
        storage.put("followup", id.value, contextOf(response, proofKeys, dpopKey, policy, response.configurationId ?: "").encode())
        autoNotify(response, dpopKey)
        return id
    }

    private fun contextOf(response: CredentialResponse, proofKeys: List<KeyHandle>, dpopKey: KeyHandle, policy: CredentialPolicy, configurationId: String) = FollowUpContext(
        credentialIssuer = response.credentialIssuer ?: "",
        configurationId = response.configurationId ?: configurationId,
        requestedFormat = response.requestedFormat,
        accessToken = response.accessToken,
        refreshToken = response.refreshToken,
        transactionId = response.transactionId,
        notificationId = response.notificationId,
        proofKeys = proofKeys,
        dpopKey = dpopKey,
        policy = policy,
    )

    private suspend fun loadFollowUp(id: CredentialId): FollowUpContext? =
        storage.get("followup", id.value)?.let { FollowUpContext.decode(it) }

    /** Captures issuer/display metadata at issuance so the app renders cards without re-fetching. Best-effort. */
    private suspend fun captureMetadata(response: CredentialResponse): CredentialMetadata? {
        val issuer = response.credentialIssuer ?: return null
        val configId = response.configurationId ?: return null
        return runCatching {
            val metadata = vci.loadIssuerMetadata(issuer)
            val config = metadata.credentialConfigurationsSupported[configId]
            CredentialMetadata(
                issuerUrl = issuer,
                issuerDisplayName = metadata.issuerDisplayName,
                configurationId = configId,
                displayName = config?.displayName,
                logoUri = config?.logoUri,
                backgroundColor = config?.backgroundColor,
            )
        }.getOrNull()
    }

    private suspend fun autoNotify(response: CredentialResponse, dpopKey: KeyHandle) {
        if (response.notificationId == null) return
        runCatching {
            val signer = SecureAreaJwsSigner(secureArea, dpopKey, SigningAlgorithm.ES256)
            val pub = secureArea.publicKey(dpopKey)
            vci.sendNotification(response, NotificationEvent.CREDENTIAL_ACCEPTED, IssuanceKeys(signer, pub, signer, pub))
        }
    }

    private fun newId(): CredentialId = CredentialId("cred-" + Base64Url.encode(rng.nextBytes(12)))

    /**
     * RFC 9901 §7.2: the Holder must reject an SD-JWT the Issuer delivered already carrying a KB-JWT — the
     * KB-JWT is the Holder's to add at presentation. Enforced here, at ingestion, before anything is stored.
     */
    private fun rejectIssuerBoundKb(credential: IssuedCredential) {
        if (credential.format == "mso_mdoc") return
        try {
            SdJwt.parseFromIssuer(credential.credential)
        } catch (e: SdJwtException) {
            throw WalletError.Issuance.CredentialRequestFailed(e.message ?: "invalid issued SD-JWT", e)
        }
    }

    /** Determines the format + raw payload bytes for storage (SD-JWT compact string / mdoc IssuerSigned CBOR). */
    private fun decode(credential: IssuedCredential): Pair<CredentialFormat, ByteArray> = when (credential.format) {
        "mso_mdoc" -> {
            val bytes = Base64Url.decode(credential.credential)
            CredentialFormat.MsoMdoc(IssuerSigned.decode(bytes).parseMso().docType) to bytes
        }
        else -> {
            val vct = (SdJwtHolder.processedClaims(SdJwt.parse(credential.credential))["vct"] as? JsonValue.Str)?.value ?: ""
            CredentialFormat.SdJwtVc(vct) to credential.credential.encodeToByteArray()
        }
    }

    /** Extracts and URL-decodes the `code` from an authorization redirect (it is re-encoded for the token request). */
    private fun extractCode(redirectUri: String): String? {
        val raw = redirectUri.substringAfter("code=", "").substringBefore("&").ifEmpty { return null }
        return runCatching { java.net.URLDecoder.decode(raw, "UTF-8") }.getOrDefault(raw)
    }

    private suspend fun <T> catchingVci(block: suspend () -> T): T = try {
        block()
    } catch (e: VciException) {
        throw when (e) {
            is VciException.InvalidOffer -> WalletError.Issuance.InvalidOffer(e.message ?: "")
            is VciException.OAuthError -> WalletError.Issuance.AuthorizationFailed(e.oauthError, e.message ?: "")
            else -> WalletError.Issuance.CredentialRequestFailed(e.message ?: "", e)
        }
    }
}
