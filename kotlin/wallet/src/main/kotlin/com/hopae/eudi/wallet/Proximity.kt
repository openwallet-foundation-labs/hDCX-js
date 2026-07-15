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
    /** Who is asking — from verified reader authentication (ISO 18013-5 §9.1.4), if present and trusted. */
    val reader: ProximityReaderInfo,
    internal val deviceRequest: DeviceRequest,
    internal val transcript: Cbor,
    internal val session: SessionEncryption,
)

/**
 * The in-person reader's identity. [trusted] is true only when the request was reader-authenticated
 * and the reader certificate chained to a configured reader anchor (config.trust.readerAnchorsDer).
 */
class ProximityReaderInfo(
    val trusted: Boolean,
    val commonName: String?,
    val certificateChainDer: List<ByteArray>,
)

/** One requested document: the doctype, the elements the reader wants, and the matching stored credential. */
class RequestedDocumentView(
    val docType: String,
    val requestedElements: Map<String, List<String>>,
    /** Stored credentials that can answer this doctype; the holder chooses one when there is more than one. */
    val candidates: List<CredentialId>,
)

/** The user's choice of which stored credential answers each requested doctype. */
class ProximitySelection(val chosen: Map<String, CredentialId>) {
    companion object {
        fun auto(request: ProximityRequest): ProximitySelection =
            ProximitySelection(request.documents.mapNotNull { doc -> doc.candidates.firstOrNull()?.let { doc.docType to it } }.toMap())
    }
}

/** Proximity presentation session state. */
sealed interface ProximityState {
    data object GeneratingEngagement : ProximityState

    /**
     * Engagement is ready and the wallet is waiting for the reader. [deviceEngagement] is rendered as a QR
     * code (`mdoc:` + base64url); [handoverNdef], when non-null, is the NFC Handover Select message the app
     * should serve over HCE (NFC static handover) instead of / alongside the QR.
     */
    data class EngagementReady(val deviceEngagement: ByteArray, val handoverNdef: ByteArray? = null) : ProximityState
    data class RequestReceived(val request: ProximityRequest) : ProximityState
    data object Submitting : ProximityState
    data object Completed : ProximityState
    data object Declined : ProximityState
    data class Failed(val error: WalletError.Proximity) : ProximityState

    val isTerminal: Boolean get() = this is Completed || this is Declined || this is Failed
}
