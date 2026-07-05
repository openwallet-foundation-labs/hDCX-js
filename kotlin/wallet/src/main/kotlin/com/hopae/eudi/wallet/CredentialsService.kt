package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.status.StatusListClient
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.CredentialStoreChange
import com.hopae.eudi.wallet.vp.DcqlEngine
import com.hopae.eudi.wallet.vp.DcqlQuery
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import com.hopae.eudi.wallet.status.CredentialStatus as StatusListStatus

/** Stored-credential management (API-CONTRACT.md §6.5). Reads are local; `status` hits the network. */
class CredentialsService internal constructor(
    private val store: CredentialStore,
    private val statusClient: StatusListClient,
) {

    suspend fun list(filter: CredentialFilter = CredentialFilter.All): List<Credential> =
        store.list().map { it.toCredential() }.filter { filter.matches(it) }

    suspend fun get(id: CredentialId): Credential? = store.get(id)?.toCredential()

    suspend fun delete(id: CredentialId) = store.delete(id)

    /** Reactive list changes (Added/Updated/Removed) for UI refresh. */
    val changes: Flow<CredentialChange> = store.changes.map { it.toCredentialChange() }

    /**
     * Revocation status via IETF Token Status List (network fetch, cached). Valid when the credential
     * carries no status reference. (SD-JWT VC; mdoc CWT status is a follow-up.)
     */
    suspend fun status(id: CredentialId): CredentialStatus {
        val claims = store.get(id)?.claimsTree() ?: return CredentialStatus.Unknown
        return when (statusClient.check(claims)) {
            StatusListStatus.VALID -> CredentialStatus.Valid
            StatusListStatus.INVALID -> CredentialStatus.Invalid
            StatusListStatus.SUSPENDED -> CredentialStatus.Suspended
            StatusListStatus.UNKNOWN -> CredentialStatus.Unknown
        }
    }

    /**
     * Matches stored credentials against a DCQL query (OpenID4VP §6) — presentation-independent.
     * Uses the same engine the presentation flow uses (credential_sets, claim_sets, null-wildcard).
     */
    suspend fun match(dcqlJson: String): CredentialMatch {
        val envelopes = store.list()
        val held = envelopes.mapNotNull { it.toQueryable() }
        val query = DcqlQuery.parse(JsonValue.parse(dcqlJson) as JsonValue.Obj)
        val result = DcqlEngine.match(query, held)
        val byId = envelopes.associateBy { it.id.value }
        return CredentialMatch(
            satisfiable = result.isSatisfiable(),
            byQuery = result.candidatesByQuery.mapValues { (_, candidates) ->
                candidates.mapNotNull { candidate ->
                    byId[candidate.credential.credentialId]?.let { MatchedCredential(it.toCredential(), candidate.disclosedPaths) }
                }
            },
        )
    }
}

/** Result of [CredentialsService.match]: which held credentials satisfy each query, and disclosed paths. */
class CredentialMatch(
    val satisfiable: Boolean,
    val byQuery: Map<String, List<MatchedCredential>>,
)

class MatchedCredential(val credential: Credential, val disclosedPaths: List<List<String>>)

/** Credential revocation status (IETF Token Status List). */
enum class CredentialStatus { Valid, Invalid, Suspended, Unknown }

sealed interface CredentialChange {
    val id: CredentialId

    data class Added(override val id: CredentialId) : CredentialChange
    data class Updated(override val id: CredentialId) : CredentialChange
    data class Removed(override val id: CredentialId) : CredentialChange
}

internal fun CredentialStoreChange.toCredentialChange(): CredentialChange = when (this) {
    is CredentialStoreChange.Added -> CredentialChange.Added(id)
    is CredentialStoreChange.Updated -> CredentialChange.Updated(id)
    is CredentialStoreChange.Removed -> CredentialChange.Removed(id)
}
