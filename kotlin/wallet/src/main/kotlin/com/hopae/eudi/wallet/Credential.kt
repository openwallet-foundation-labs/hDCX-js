package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.KeyUse
import java.time.Instant

/**
 * Format-agnostic credential view, assembled from the storage envelope.
 * Issuer/display metadata is captured at issuance; claims/validity are parsed from the payload.
 */
class Credential(
    val id: CredentialId,
    val format: CredentialFormat,
    val lifecycle: Lifecycle,
    val issuer: IssuerInfo?,
    val display: CredentialDisplay?,
    val configurationId: String?,
    val createdAt: Instant,
)

/** Where the credential came from (captured from issuer metadata at issuance). */
data class IssuerInfo(val url: String, val displayName: String? = null)

/** Display metadata for a credential type (issuer-metadata derived). */
data class CredentialDisplay(val name: String? = null, val logoUri: String? = null, val backgroundColor: String? = null)

sealed interface Lifecycle {
    data class Issued(val claims: List<Claim>, val validity: ValidityInfo?, val instances: CredentialInstances) : Lifecycle
    data class Deferred(val retryAfter: Instant?) : Lifecycle
    data class Pending(val authorizationUrl: String?) : Lifecycle
}

/** A disclosed claim, path-addressed (namespace+element for mdoc, JSON path for SD-JWT VC). */
data class Claim(val path: List<String>, val value: ClaimValue)

/** A claim value with a format-agnostic rendering. */
class ClaimValue internal constructor(val raw: Any?) {
    fun display(): String = raw?.toString() ?: ""
    override fun toString(): String = display()
}

data class ValidityInfo(val validFrom: Instant?, val validUntil: Instant?)

/** Batch instance accounting (HAIP one-time-use / rotate). */
data class CredentialInstances(val remaining: Int, val use: KeyUse)
