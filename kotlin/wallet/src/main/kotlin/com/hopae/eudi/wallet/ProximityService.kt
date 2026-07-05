package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.DeviceRequest
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocPresenter
import com.hopae.eudi.wallet.mdoc.MdocReaderTrust
import com.hopae.eudi.wallet.mdoc.ReaderAuth
import com.hopae.eudi.wallet.proximity.DeviceEngagement
import com.hopae.eudi.wallet.proximity.EphemeralKeyPair
import com.hopae.eudi.wallet.proximity.ProximityException
import com.hopae.eudi.wallet.proximity.ProximitySessionTranscript
import com.hopae.eudi.wallet.proximity.SessionEncryption
import com.hopae.eudi.wallet.proximity.SessionMessages
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.ProximityTransport
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SecureAreaCoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.EnvelopeLifecycle
import com.hopae.eudi.wallet.txlog.LoggedClaim
import com.hopae.eudi.wallet.txlog.LoggedDocument
import com.hopae.eudi.wallet.txlog.RelyingParty
import com.hopae.eudi.wallet.txlog.TransactionLog
import com.hopae.eudi.wallet.txlog.TransactionStatus
import kotlinx.coroutines.CoroutineScope
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * ISO 18013-5 proximity presentation (API-CONTRACT.md §6.3). Generates device engagement, establishes the
 * encrypted session over the app-provided [ProximityTransport], and replies with a device-signed DeviceResponse.
 */
class ProximityService internal constructor(
    private val store: CredentialStore,
    private val txlog: TransactionLog,
    private val secureAreas: List<SecureArea>,
    private val scope: CoroutineScope,
    /** Verifies reader authentication against configured reader anchors; null = no anchors, readers stay untrusted. */
    private val readerTrust: MdocReaderTrust?,
) {
    /** Starts a proximity session over [transport]: engage → session → reader request → consent → reply. */
    fun present(transport: ProximityTransport): ProximitySession {
        val session = ProximitySession(scope) {
            emit(ProximityState.GeneratingEngagement)
            val eDevice = EphemeralKeyPair.generate()
            val engagement = DeviceEngagement.qr(eDevice.publicKey)
            // EngagementReady stays the current state while blocked on receive() — the reader-waiting state.
            emit(ProximityState.EngagementReady(engagement))
            val establishment = catchingProximity { SessionMessages.decodeEstablishment(transport.receive()) }
            val transcript = ProximitySessionTranscript.build(engagement, establishment.eReaderKey)
            val enc = SessionEncryption.forMdoc(eDevice, establishment.eReaderKey, ProximitySessionTranscript.encode(transcript))
            val deviceRequest = catchingProximity { DeviceRequest.decode(enc.decrypt(establishment.encryptedDeviceRequest)) }

            val request = buildRequest(deviceRequest, transcript, enc)
            when (val selection = awaitDecision(request)) {
                null -> {
                    recordDeclined(request)
                    transport.close()
                    emit(ProximityState.Declined)
                }
                else -> {
                    emit(ProximityState.Submitting)
                    val deviceResponse = buildDeviceResponse(deviceRequest, transcript, selection)
                    transport.send(SessionMessages.encodeData(enc.encrypt(deviceResponse)))
                    recordSuccess(request, selection)
                    transport.close()
                    emit(ProximityState.Completed)
                }
            }
        }
        session.launch()
        return session
    }

    private suspend fun buildRequest(deviceRequest: DeviceRequest, transcript: Cbor, session: SessionEncryption): ProximityRequest {
        val documents = deviceRequest.docRequests.map { dr ->
            RequestedDocumentView(
                docType = dr.docType,
                requestedElements = dr.requested.mapValues { (_, elems) -> elems.map { it.identifier } },
                candidate = findMdoc(dr.docType),
            )
        }
        val reader = verifyReader(deviceRequest, transcript)
        return ProximityRequest(documents, satisfiable = documents.all { it.candidate != null }, reader, deviceRequest, transcript, session)
    }

    /** Verifies reader authentication (ISO 18013-5 §9.1.4) against the configured reader anchors. */
    private suspend fun verifyReader(deviceRequest: DeviceRequest, transcript: Cbor): ProximityReaderInfo {
        val trust = readerTrust ?: return ProximityReaderInfo(trusted = false, commonName = null, certificateChainDer = emptyList())
        val docRequest = deviceRequest.docRequests.firstOrNull { it.readerAuth != null }
            ?: return ProximityReaderInfo(trusted = false, commonName = null, certificateChainDer = emptyList())
        return runCatching {
            val info = ReaderAuth.verify(docRequest, transcript, trust)
            ProximityReaderInfo(info.trusted, commonNameOf(info.certificateChain), info.certificateChain ?: emptyList())
        }.getOrElse { ProximityReaderInfo(trusted = false, commonName = null, certificateChainDer = emptyList()) }
    }

    private fun commonNameOf(chainDer: List<ByteArray>?): String? {
        val leaf = chainDer?.firstOrNull() ?: return null
        return runCatching {
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(leaf.inputStream()) as X509Certificate
            Regex("CN=([^,]+)").find(cert.subjectX500Principal.name)?.groupValues?.get(1)
        }.getOrNull()
    }

    private suspend fun findMdoc(docType: String): CredentialId? =
        store.list().firstOrNull { envelope ->
            envelope.lifecycle is EnvelopeLifecycle.Issued &&
                (envelope.format as? CredentialFormat.MsoMdoc)?.docType == docType
        }?.id

    /** Builds the DeviceResponse for the first requested document (single-document retrieval; multi-doc is a follow-up). */
    private suspend fun buildDeviceResponse(deviceRequest: DeviceRequest, transcript: Cbor, selection: ProximitySelection): ByteArray {
        val docRequest = deviceRequest.docRequests.firstOrNull { selection.chosen.containsKey(it.docType) }
            ?: throw WalletError.Proximity.NoMatchingCredential("no chosen document")
        val credentialId = selection.chosen.getValue(docRequest.docType)
        val consumed = store.consumeInstance(credentialId)
            ?: throw WalletError.Proximity.NoMatchingCredential(docRequest.docType)
        val area = secureAreas.firstOrNull { it.id == consumed.instance.key.secureArea } ?: secureAreas.first()
        val issuerSigned = IssuerSigned.decode(consumed.instance.payload)
        return MdocPresenter.deviceResponse(
            issuerSigned = issuerSigned,
            docType = docRequest.docType,
            disclosed = docRequest.disclosable(issuerSigned),
            sessionTranscript = transcript,
            deviceSigner = SecureAreaCoseSigner(area, consumed.instance.key, SigningAlgorithm.ES256),
        )
    }

    private suspend fun recordSuccess(request: ProximityRequest, selection: ProximitySelection) {
        val documents = request.documents.filter { selection.chosen.containsKey(it.docType) }.map { doc ->
            LoggedDocument(
                format = "mso_mdoc", type = doc.docType, queryId = null,
                claims = doc.requestedElements.flatMap { (ns, els) -> els.map { LoggedClaim(listOf(ns, it), null) } },
            )
        }
        txlog.recordPresentation(proximityReader(request), documents, TransactionStatus.SUCCESS)
    }

    private suspend fun recordDeclined(request: ProximityRequest) {
        txlog.recordPresentation(proximityReader(request), documents = emptyList(), status = TransactionStatus.INCOMPLETE)
    }

    /** The in-person reader, from verified reader authentication (unauthenticated readers stay untrusted). */
    private fun proximityReader(request: ProximityRequest): RelyingParty = RelyingParty(
        id = request.reader.commonName ?: "proximity-reader",
        name = request.reader.commonName,
        trusted = request.reader.trusted,
        certificateChainDer = request.reader.certificateChainDer,
    )

    private suspend fun <T> catchingProximity(block: suspend () -> T): T = try {
        block()
    } catch (e: ProximityException) {
        throw WalletError.Proximity.SessionFailed(e.message ?: "session error", e)
    }
}
