package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.vp.DcqlMatchResult
import com.hopae.eudi.wallet.vp.ResolvedRequest

/**
 * A resolved verifier request, ready for the consent screen: who is asking, what they want, and which
 * stored credentials can satisfy each query. The raw resolved request + match are carried for [respond].
 */
class PresentationRequest internal constructor(
    val verifier: VerifierInfo,
    val queries: List<QueryPresentation>,
    val transactionData: List<String>?,
    val satisfiable: Boolean,
    internal val resolved: ResolvedRequest,
    internal val matches: DcqlMatchResult,
)

/** Who is requesting, and whether trust was established (signed request verified to a reader anchor). */
class VerifierInfo(
    val clientId: String,
    val clientIdScheme: String,
    val commonName: String?,
    val trusted: Boolean,
)

/** One DCQL query with the stored credentials that can answer it. */
class QueryPresentation(
    val queryId: String,
    val required: Boolean,
    val candidates: List<PresentationCandidate>,
)

/** A stored credential that satisfies a query, with the claim paths it would disclose. */
class PresentationCandidate(
    val credentialId: CredentialId,
    val disclosedPaths: List<List<String>>,
)

/** The user's choice of which credential answers each query. */
class PresentationSelection(val chosen: Map<String, CredentialId>) {
    companion object {
        /** Auto-pick the first candidate for every required query. */
        fun auto(request: PresentationRequest): PresentationSelection =
            PresentationSelection(
                request.queries.filter { it.required }
                    .mapNotNull { q -> q.candidates.firstOrNull()?.let { q.queryId to it.credentialId } }
                    .toMap(),
            )
    }
}

/** Presentation session state. */
sealed interface PresentationState {
    data object ResolvingRequest : PresentationState
    data class RequestResolved(val request: PresentationRequest) : PresentationState
    data object Submitting : PresentationState

    /**
     * Success. [redirectUri] is the verifier redirect for the remote (URL/QR) flow; [dcApiResponse] is
     * the JSON object to hand back to the platform for the Digital Credentials API flow. Exactly one is set.
     */
    data class Completed(val redirectUri: String?, val dcApiResponse: String? = null) : PresentationState
    data object Declined : PresentationState
    data class Failed(val error: WalletError.Presentation) : PresentationState

    val isTerminal: Boolean get() = this is Completed || this is Declined || this is Failed
}
