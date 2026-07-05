package com.hopae.eudi.wallet.store

import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeyHandle
import java.time.Instant

/*
 * Storage envelope: the format-agnostic persistence layer (M1).
 * Claims/validity parsing belongs to the format modules (M2+) — here payloads are opaque.
 * Public Credential facade model is assembled on top of this in M2.
 */

/** One issued credential instance: payload bound to a device key (HAIP batch → N instances). */
class CredentialInstance(
    val key: KeyHandle,
    val payload: ByteArray,
    val useCount: Int = 0,
)

sealed interface EnvelopeLifecycle {
    /** Issuance started but paused on user authorization (dynamic issuance resume). */
    class Pending(val authorizationUrl: String?, val resumeContext: ByteArray?) : EnvelopeLifecycle

    /** Issuer accepted but credential not ready yet (deferred issuance). */
    class Deferred(val transactionContext: ByteArray, val retryAfter: Instant?) : EnvelopeLifecycle

    class Issued(val policy: CredentialPolicy, val instances: List<CredentialInstance>) : EnvelopeLifecycle
}

class CredentialEnvelope(
    val id: CredentialId,
    val format: CredentialFormat,
    val createdAt: Instant,
    val lifecycle: EnvelopeLifecycle,
    /** Issuer/display metadata captured at issuance (from issuer metadata). */
    val metadata: CredentialMetadata? = null,
)

/** Display/issuer metadata captured at issuance so the app renders cards without re-fetching. */
class CredentialMetadata(
    val issuerUrl: String,
    val issuerDisplayName: String?,
    val configurationId: String,
    val displayName: String?,
    val logoUri: String?,
    val backgroundColor: String?,
)
