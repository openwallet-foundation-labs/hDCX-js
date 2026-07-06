package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.mdoc.DeviceResponse
import com.hopae.eudi.wallet.mdoc.MdocIssuerTrust
import com.hopae.eudi.wallet.mdoc.MdocReader
import com.hopae.eudi.wallet.mdoc.ReaderAuthSigner
import com.hopae.eudi.wallet.mdoc.RequestedDocument
import com.hopae.eudi.wallet.mdoc.VerifiedDocument
import com.hopae.eudi.wallet.proximity.DeviceEngagement
import com.hopae.eudi.wallet.proximity.EphemeralKeyPair
import com.hopae.eudi.wallet.proximity.ProximitySessionTranscript
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
    ): List<VerifiedDocument> {
        try {
            val eDeviceKey = DeviceEngagement.parseEDeviceKey(engagement)
            val eReader = EphemeralKeyPair.generate()
            val transcript = ProximitySessionTranscript.build(engagement, eReader.publicKey)
            val enc = SessionEncryption.forReader(eReader, eDeviceKey, ProximitySessionTranscript.encode(transcript))
            val reader = MdocReader(readerAuth, issuerTrust)

            val deviceRequest = reader.buildDeviceRequest(documents, transcript)
            transport.send(SessionMessages.encodeEstablishment(eReader.publicKey, enc.encrypt(deviceRequest)))
            val deviceResponse = enc.decrypt(SessionMessages.decodeData(transport.receive()))

            return try {
                if (issuerTrust != null) reader.verifyDeviceResponse(deviceResponse, transcript) else parseUnverified(deviceResponse)
            } catch (e: Throwable) {
                // Untrusted issuer or holder-binding failure — still surface what the wallet disclosed, marked unverified.
                parseUnverified(deviceResponse)
            }
        } finally {
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
