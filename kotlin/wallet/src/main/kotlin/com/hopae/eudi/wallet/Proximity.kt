package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.DeviceRequest
import com.hopae.eudi.wallet.proximity.SessionEncryption
import com.hopae.eudi.wallet.spi.CredentialId

/**
 * What an in-person reader asked for (ISO 18013-5 device retrieval), ready for the consent screen: the
 * requested documents/elements and which stored credential answers each. Raw request + session carried for the reply.
 */
class ProximityRequest internal constructor(
    val documents: List<RequestedDocumentView>,
    val satisfiable: Boolean,
    internal val deviceRequest: DeviceRequest,
    internal val transcript: Cbor,
    internal val session: SessionEncryption,
)

/** One requested document: the doctype, the elements the reader wants, and the matching stored credential. */
class RequestedDocumentView(
    val docType: String,
    val requestedElements: Map<String, List<String>>,
    val candidate: CredentialId?,
)

/** The user's choice of which stored credential answers each requested doctype. */
class ProximitySelection(val chosen: Map<String, CredentialId>) {
    companion object {
        fun auto(request: ProximityRequest): ProximitySelection =
            ProximitySelection(request.documents.mapNotNull { doc -> doc.candidate?.let { doc.docType to it } }.toMap())
    }
}

/** Proximity presentation session state (API-CONTRACT.md §6.3). */
sealed interface ProximityState {
    data object GeneratingEngagement : ProximityState

    /** Engagement is ready and the wallet is waiting for the reader — the app renders it as a QR / NFC tag. */
    data class EngagementReady(val deviceEngagement: ByteArray) : ProximityState
    data class RequestReceived(val request: ProximityRequest) : ProximityState
    data object Submitting : ProximityState
    data object Completed : ProximityState
    data object Declined : ProximityState
    data class Failed(val error: WalletError.Proximity) : ProximityState

    val isTerminal: Boolean get() = this is Completed || this is Declined || this is Failed
}
