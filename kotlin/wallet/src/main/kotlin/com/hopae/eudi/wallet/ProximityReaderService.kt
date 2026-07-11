package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.DeviceResponse
import com.hopae.eudi.wallet.mdoc.MdocIssuerTrust
import com.hopae.eudi.wallet.mdoc.MdocReader
import com.hopae.eudi.wallet.mdoc.ReaderAuthSigner
import com.hopae.eudi.wallet.mdoc.RequestedDocument
import com.hopae.eudi.wallet.mdoc.VerifiedDocument
import com.hopae.eudi.wallet.proximity.DeviceEngagement
import com.hopae.eudi.wallet.proximity.EphemeralKeyPair
import com.hopae.eudi.wallet.proximity.ProximitySessionTranscript
import com.hopae.eudi.wallet.proximity.ProximityException
import com.hopae.eudi.wallet.proximity.SessionEncryption
import com.hopae.eudi.wallet.proximity.SessionMessages
import com.hopae.eudi.wallet.spi.ProximityTransport

/**
 * The reader/verifier side of ISO 18013-5 proximity: drives a [ProximityTransport] to request documents
 * from a wallet and verify the returned `DeviceResponse`. Symmetric to [ProximityService.present]; the
 * host supplies the transport (BLE central) and the scanned QR [DeviceEngagement].
 */
class ProximityReaderService internal constructor(
    private val issuerTrust: MdocIssuerTrust?,
    private val readerAuth: ReaderAuthSigner? = null,
) {
    /**
     * Requests [documents] from a wallet over [transport] (the reader is the BLE central) and verifies the
     * response against [engagement] (the scanned QR). Fully verified when issuer trust + holder binding
     * check out (`deviceAuthenticated = true`); otherwise the disclosed elements are still returned, unverified.
     */
    suspend fun read(
        transport: ProximityTransport,
        engagement: ByteArray,
        documents: List<RequestedDocument>,
        /** The NFC Handover Select message when the engagement was delivered by NFC handover (else null = QR). */
        handoverNdef: ByteArray? = null,
        /**
         * The NFC Handover Request the reader sent for **negotiated** handover (§8.2.2.1); binds the
         * SessionTranscript as `[Hs, Hr]` (§9.1.5.1). Null = static handover (`[Hs, null]`). The host performs
         * the NFC exchange and supplies both messages; the SDK only binds them.
         */
        handoverRequestNdef: ByteArray? = null,
    ): List<VerifiedDocument> {
        // Session setup runs before the try: if it throws there is no session yet to terminate.
        val eDeviceKey = DeviceEngagement.parseEDeviceKey(engagement)
        // §9.1.5.2: the reader's ephemeral key must be on the same curve as the mdoc's EDeviceKey.
        val eReader = EphemeralKeyPair.generate(eDeviceKey.curve)
        val handover = if (handoverNdef != null) ProximitySessionTranscript.nfcHandover(handoverNdef, handoverRequestNdef) else Cbor.Null
        val transcript = ProximitySessionTranscript.build(engagement, eReader.publicKey, handover)
        val transcriptBytes = ProximitySessionTranscript.encode(transcript)
        val enc = SessionEncryption.forReader(eReader, eDeviceKey, transcriptBytes)
        val reader = MdocReader(readerAuth, issuerTrust)

        try {
            val deviceRequest = reader.buildDeviceRequest(documents, transcript)
            transport.send(SessionMessages.encodeEstablishment(eReader.publicKey, enc.encrypt(deviceRequest)))

            // ISO 18013-5 Table 20: the mdoc may answer with an error/termination status instead of data.
            val frame = SessionMessages.decodeSessionData(transport.receive())
            val encryptedResponse = frame.data
                ?: throw ProximityException("mdoc returned status ${frame.status} without a DeviceResponse")
            val deviceResponse = enc.decrypt(encryptedResponse)

            // §8.3.2.1.2.3: a non-zero DeviceResponse status means no documents were returned, with a reason.
            // Surface it here — otherwise the verify/unverified fallback below reports an empty list silently.
            val responseStatus = DeviceResponse.decode(deviceResponse).status
            if (responseStatus != 0L) throw ProximityException("mdoc returned DeviceResponse status $responseStatus")

            return try {
                if (issuerTrust != null) {
                    // Verify deviceSignature or deviceMac (EMacKey via the reader's EReaderKey ↔ mdoc DeviceKey ECDH).
                    reader.verifyDeviceResponse(deviceResponse, transcript) { deviceKey ->
                        SessionEncryption.deriveEMacKey(eReader, deviceKey, transcriptBytes)
                    }
                } else {
                    parseUnverified(deviceResponse)
                }
            } catch (e: Throwable) {
                // Untrusted issuer or holder-binding failure — still surface what the wallet disclosed, marked unverified.
                parseUnverified(deviceResponse)
            }
        } finally {
            // §9.1.1.4: signal termination, destroy session keys, close. Best-effort on the wire.
            runCatching { transport.send(SessionMessages.encodeStatus(SessionMessages.Status.SESSION_TERMINATION)) }
            enc.destroy()
            runCatching { transport.close() }
        }
    }

    private fun parseUnverified(deviceResponse: ByteArray): List<VerifiedDocument> =
        DeviceResponse.decode(deviceResponse).documents.map { doc ->
            val elements = doc.issuerSigned.nameSpaces.mapValues { (_, items) ->
                items.associate { it.item.elementIdentifier to it.item.elementValue }
            }
            VerifiedDocument(doc.docType, elements, deviceAuthenticated = false)
        }
}
