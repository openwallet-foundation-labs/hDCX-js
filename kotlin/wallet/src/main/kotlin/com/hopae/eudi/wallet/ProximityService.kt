package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseKey
import com.hopae.eudi.wallet.mdoc.DeviceRequest
import com.hopae.eudi.wallet.mdoc.Hpke
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocPresenter
import com.hopae.eudi.wallet.mdoc.MdocReaderTrust
import com.hopae.eudi.wallet.mdoc.MdocSessionTranscript
import com.hopae.eudi.wallet.mdoc.ReaderAuth
import com.hopae.eudi.wallet.sdjwt.Base64Url
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
import com.hopae.eudi.wallet.trust.X509Support
import com.hopae.eudi.wallet.txlog.LoggedClaim
import com.hopae.eudi.wallet.txlog.LoggedDocument
import com.hopae.eudi.wallet.txlog.RelyingParty
import com.hopae.eudi.wallet.txlog.TransactionLog
import com.hopae.eudi.wallet.txlog.TransactionStatus
import kotlinx.coroutines.CoroutineScope

/**
 * ISO 18013-5 proximity presentation. Generates device engagement, establishes the
 * encrypted session over the app-provided [ProximityTransport], and replies with a device-signed DeviceResponse.
 */
class ProximityService internal constructor(
    private val store: CredentialStore,
    private val txlog: TransactionLog,
    private val secureAreas: List<SecureArea>,
    private val scope: CoroutineScope,
    /** Verifies reader authentication against configured reader anchors; null = no anchors, readers stay untrusted. */
    private val readerTrust: MdocReaderTrust?,
    /** When true, a failed final submission is recorded with ERROR status (opt-in via config). */
    private val recordFailures: Boolean = false,
) {
    /** Starts a proximity session over [transport]: engage → session → reader request → consent → reply. */
    fun present(transport: ProximityTransport): ProximitySession {
        val session = ProximitySession(scope) {
            emit(ProximityState.GeneratingEngagement)
            val eDevice = EphemeralKeyPair.generate()
            val engagement = DeviceEngagement.qr(eDevice.publicKey, transport.retrievalMethods())
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
                    try {
                        val deviceResponse = buildDeviceResponse(deviceRequest, transcript, selection)
                        transport.send(SessionMessages.encodeData(enc.encrypt(deviceResponse)))
                    } catch (e: Throwable) {
                        // Only the final submission failed — record the attempt with ERROR status (opt-in).
                        if (recordFailures) runCatching { recordError(request, selection) }
                        transport.close()
                        throw e
                    }
                    recordSuccess(request, selection)
                    transport.close()
                    emit(ProximityState.Completed)
                }
            }
        }
        session.launch()
        return session
    }

    /**
     * ISO/IEC 18013-7:2025 Annex C `org-iso-mdoc` Digital Credentials API: builds the mdoc DeviceResponse for
     * [deviceRequestBase64], HPKE-encrypts it to the verifier's `recipientPublicKey` (from [encryptionInfoBase64]),
     * and returns the base64url of `["dcapi", {enc, cipherText}]`. No transport — the platform mediates.
     */
    suspend fun respondDcApiMdoc(deviceRequestBase64: String, encryptionInfoBase64: String, origin: String): String {
        val deviceRequest = catchingProximity { DeviceRequest.decode(Base64Url.decode(deviceRequestBase64)) }
        val encInfo = CborDecoder.decode(Base64Url.decode(encryptionInfoBase64)) as? Cbor.Array
            ?: throw WalletError.Proximity.SessionFailed("malformed EncryptionInfo")
        if ((encInfo.items.getOrNull(0) as? Cbor.Text)?.value != "dcapi") {
            throw WalletError.Proximity.SessionFailed("EncryptionInfo is not a dcapi array")
        }
        val recipientKeyCbor = (encInfo.items.getOrNull(1) as? Cbor.CborMap)?.entries
            ?.firstOrNull { (it.first as? Cbor.Text)?.value == "recipientPublicKey" }?.second as? Cbor.CborMap
            ?: throw WalletError.Proximity.SessionFailed("EncryptionInfo missing recipientPublicKey")
        val recipientKey = CoseKey.decode(recipientKeyCbor)

        val transcript = MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64, origin)
        val chosen = deviceRequest.docRequests.mapNotNull { dr -> findMdoc(dr.docType)?.let { dr.docType to it } }.toMap()
        if (chosen.isEmpty()) throw WalletError.Proximity.NoMatchingCredential("no stored mdoc for the DC API request")

        val deviceResponse = buildDeviceResponse(deviceRequest, transcript, ProximitySelection(chosen))
        val sealed = Hpke.sealBaseP256(recipientKey, CborEncoder.encode(transcript), ByteArray(0), deviceResponse)
        val envelope = Cbor.Array(
            listOf(
                Cbor.Text("dcapi"),
                Cbor.CborMap(listOf(Cbor.Text("enc") to Cbor.Bytes(sealed.enc), Cbor.Text("cipherText") to Cbor.Bytes(sealed.ciphertext))),
            ),
        )
        recordDcApiMdocSuccess(deviceRequest, transcript, chosen.keys, origin)
        return Base64Url.encode(CborEncoder.encode(envelope))
    }

    private suspend fun recordDcApiMdocSuccess(deviceRequest: DeviceRequest, transcript: Cbor, docTypes: Set<String>, origin: String) {
        val reader = verifyReader(deviceRequest, transcript)
        val documents = deviceRequest.docRequests.filter { it.docType in docTypes }.map { dr ->
            LoggedDocument(
                format = "mso_mdoc", type = dr.docType, queryId = null,
                claims = dr.requested.flatMap { (ns, els) -> els.map { LoggedClaim(listOf(ns, it.identifier), null) } },
            )
        }
        val rp = RelyingParty(reader.commonName ?: origin, reader.commonName ?: origin, reader.trusted, reader.certificateChainDer)
        txlog.recordPresentation(rp, documents, TransactionStatus.SUCCESS)
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
            val commonName = info.certificateChain?.firstOrNull()?.let { X509Support.commonNameFromDer(it) }
            ProximityReaderInfo(info.trusted, commonName, info.certificateChain ?: emptyList())
        }.getOrElse { ProximityReaderInfo(trusted = false, commonName = null, certificateChainDer = emptyList()) }
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
        txlog.recordPresentation(proximityReader(request), loggedDocuments(request, selection), TransactionStatus.SUCCESS)
    }

    private suspend fun recordError(request: ProximityRequest, selection: ProximitySelection) {
        txlog.recordPresentation(proximityReader(request), loggedDocuments(request, selection), TransactionStatus.ERROR)
    }

    private suspend fun recordDeclined(request: ProximityRequest) {
        txlog.recordPresentation(proximityReader(request), documents = emptyList(), status = TransactionStatus.INCOMPLETE)
    }

    private fun loggedDocuments(request: ProximityRequest, selection: ProximitySelection): List<LoggedDocument> =
        request.documents.filter { selection.chosen.containsKey(it.docType) }.map { doc ->
            LoggedDocument(
                format = "mso_mdoc", type = doc.docType, queryId = null,
                claims = doc.requestedElements.flatMap { (ns, els) -> els.map { LoggedClaim(listOf(ns, it), null) } },
            )
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
