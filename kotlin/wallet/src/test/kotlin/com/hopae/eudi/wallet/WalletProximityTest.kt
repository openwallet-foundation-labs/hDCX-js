package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseAlgorithm
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.cbor.cose.CoseSigner
import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocReader
import com.hopae.eudi.wallet.mdoc.MdocTestIssuer
import com.hopae.eudi.wallet.mdoc.ReaderAuthSigner
import com.hopae.eudi.wallet.mdoc.RequestedDocument
import com.hopae.eudi.wallet.proximity.DeviceEngagement
import com.hopae.eudi.wallet.proximity.EphemeralKeyPair
import com.hopae.eudi.wallet.proximity.ProximitySessionTranscript
import com.hopae.eudi.wallet.proximity.SessionEncryption
import com.hopae.eudi.wallet.proximity.SessionMessages
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.ProximityTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.store.CredentialEnvelope
import com.hopae.eudi.wallet.store.CredentialInstance
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.EnvelopeLifecycle
import com.hopae.eudi.wallet.testkit.InMemoryStorageDriver
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import com.hopae.eudi.wallet.trust.TestCerts
import com.hopae.eudi.wallet.txlog.InMemoryTransactionLogStore
import com.hopae.eudi.wallet.txlog.TransactionStatus
import kotlinx.coroutines.channels.Channel
import java.security.PrivateKey
import java.security.Signature
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Phase D: ISO 18013-5 proximity presentation over an in-memory transport (BLE/NFC stand-in). */
class WalletProximityTest {

    private val now: Instant = Instant.parse("2026-06-01T00:00:00Z")
    private val noHttp = object : HttpTransport {
        override suspend fun execute(request: HttpRequest): HttpResponse = HttpResponse(404, emptyList(), ByteArray(0))
    }

    /** In-memory duplex channel: the wallet drives [deviceSide]; the test plays the reader. */
    private class TransportPair {
        private val toDevice = Channel<ByteArray>(Channel.UNLIMITED)
        private val toReader = Channel<ByteArray>(Channel.UNLIMITED)
        val deviceSide = object : ProximityTransport {
            override suspend fun send(message: ByteArray) { toReader.send(message) }
            override suspend fun receive(): ByteArray = toDevice.receive()
            override suspend fun close() {}
        }
        suspend fun readerSend(message: ByteArray) { toDevice.send(message) }
        suspend fun readerReceive(): ByteArray = toReader.receive()
    }

    private fun field(c: Cbor, key: String): Cbor =
        (c as Cbor.CborMap).entries.first { (k, _) -> (k as? Cbor.Text)?.value == key }.second

    @Test
    fun proximityDeviceRetrievalRoundTrip() = runBlocking {
        val docType = "org.iso.18013.5.1.mDL"
        val namespace = "org.iso.18013.5.1"
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mdocBytes = MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey.publicKey, docType = docType, namespace = namespace,
            elements = listOf("family_name" to Cbor.Text("Han"), "given_name" to Cbor.Text("Jongho"), "age_over_18" to Cbor.Bool(true)),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = now, validFrom = now, validUntil = now.plusSeconds(31_536_000),
        )
        CredentialStore(storage).save(
            CredentialEnvelope(
                CredentialId("mdl-1"), CredentialFormat.MsoMdoc(docType), now,
                EnvelopeLifecycle.Issued(CredentialPolicy(), listOf(CredentialInstance(deviceKey.handle, mdocBytes))),
            ),
        )

        val logStore = InMemoryTransactionLogStore()
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, noHttp, transactionLogStore = logStore))
        val transport = TransportPair()
        val session = wallet.proximity.present(transport.deviceSide)

        // reader: read the device engagement QR
        val engagementState = withTimeout(15_000) { session.state.first { it is ProximityState.EngagementReady || it is ProximityState.Failed } }
        assertTrue(engagementState is ProximityState.EngagementReady, "engagement: $engagementState")
        val engagement = engagementState.deviceEngagement

        // reader: establish the encrypted session and send a DeviceRequest for family_name + given_name
        val eReader = EphemeralKeyPair.generate()
        val eDeviceKey = DeviceEngagement.parseEDeviceKey(engagement)
        val transcript = ProximitySessionTranscript.build(engagement, eReader.publicKey)
        val readerSession = SessionEncryption.forReader(eReader, eDeviceKey, ProximitySessionTranscript.encode(transcript))
        val deviceRequest = MdocReader().buildDeviceRequest(
            listOf(RequestedDocument(docType, mapOf(namespace to listOf("family_name", "given_name")))),
            transcript,
        )
        transport.readerSend(SessionMessages.encodeEstablishment(eReader.publicKey, readerSession.encrypt(deviceRequest)))

        // wallet: the request resolves against the stored mDL; approve
        val requestState = withTimeout(15_000) { session.state.first { it is ProximityState.RequestReceived || it is ProximityState.Failed } }
        assertTrue(requestState is ProximityState.RequestReceived, "request: $requestState")
        assertTrue(requestState.request.satisfiable, "mDL request satisfiable")
        assertEquals(CredentialId("mdl-1"), requestState.request.documents.single().candidate)
        session.respond(ProximitySelection.auto(requestState.request))

        // reader: decrypt the DeviceResponse over the session and verify selective disclosure + device signature
        val deviceResponse = readerSession.decrypt(SessionMessages.decodeData(transport.readerReceive()))
        val document = (field(CborDecoder.decode(deviceResponse), "documents") as Cbor.Array).items.single()
        val disclosed = IssuerSigned.fromCbor(field(document, "issuerSigned")).nameSpaces[namespace]!!.map { it.item.elementIdentifier }.toSet()
        assertEquals(setOf("family_name", "given_name"), disclosed, "age_over_18 must be withheld")

        val deviceSignature = CoseSign1.fromCbor(field(field(document, "deviceSigned"), "deviceAuth").let { field(it, "deviceSignature") })
        val deviceNsBytes = Cbor.Tagged(24uL, Cbor.Bytes(CborEncoder.encode(Cbor.CborMap(emptyList()))))
        val deviceAuth = Cbor.Array(listOf(Cbor.Text("DeviceAuthentication"), transcript, Cbor.Text(docType), deviceNsBytes))
        val deviceAuthBytes = CborEncoder.encode(Cbor.Tagged(24uL, Cbor.Bytes(CborEncoder.encode(deviceAuth))))
        assertTrue(deviceSignature.verify(deviceKey.publicKey, detachedPayload = deviceAuthBytes), "device signature over proximity transcript")

        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is ProximityState.Completed, "terminal: $terminal")
        assertEquals(TransactionStatus.SUCCESS, logStore.all().single().status)
    }

    private fun readerCoseSigner(priv: PrivateKey): CoseSigner = object : CoseSigner {
        override val algorithm = CoseAlgorithm.ES256
        override suspend fun sign(toBeSigned: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(priv); update(toBeSigned); Der.derSignatureToRaw(sign(), 32) }
    }

    @Test
    fun proximityAuthenticatesTrustedReader() = runBlocking {
        val docType = "org.iso.18013.5.1.mDL"
        val namespace = "org.iso.18013.5.1"
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mdocBytes = MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey.publicKey, docType = docType, namespace = namespace,
            elements = listOf("family_name" to Cbor.Text("Han"), "given_name" to Cbor.Text("Jongho")),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = now, validFrom = now, validUntil = now.plusSeconds(31_536_000),
        )
        CredentialStore(storage).save(
            CredentialEnvelope(
                CredentialId("mdl-1"), CredentialFormat.MsoMdoc(docType), now,
                EnvelopeLifecycle.Issued(CredentialPolicy(), listOf(CredentialInstance(deviceKey.handle, mdocBytes))),
            ),
        )

        // reader authentication material: a leaf chaining to the wallet's configured reader anchor
        val readerCa = TestCerts.makeCa("Reader Root CA")
        val readerLeaf = TestCerts.makeLeaf(readerCa, cn = "EUDI Reader")
        val logStore = InMemoryTransactionLogStore()
        val wallet = Wallet.create(
            WalletConfig(trust = TrustConfig(readerAnchorsDer = listOf(readerCa.der))),
            WalletPorts(listOf(area), storage, noHttp, transactionLogStore = logStore),
        )
        val transport = TransportPair()
        val session = wallet.proximity.present(transport.deviceSide)

        val engagement = (withTimeout(15_000) { session.state.first { it is ProximityState.EngagementReady || it is ProximityState.Failed } } as ProximityState.EngagementReady).deviceEngagement

        // reader signs the DeviceRequest with readerAuth (leaf + chain)
        val eReader = EphemeralKeyPair.generate()
        val transcript = ProximitySessionTranscript.build(engagement, eReader.publicKey)
        val readerSession = SessionEncryption.forReader(eReader, DeviceEngagement.parseEDeviceKey(engagement), ProximitySessionTranscript.encode(transcript))
        val mdocReader = MdocReader(readerAuth = ReaderAuthSigner(readerCoseSigner(readerLeaf.keyPair.private), listOf(readerLeaf.der)))
        val deviceRequest = mdocReader.buildDeviceRequest(listOf(RequestedDocument(docType, mapOf(namespace to listOf("family_name")))), transcript)
        transport.readerSend(SessionMessages.encodeEstablishment(eReader.publicKey, readerSession.encrypt(deviceRequest)))

        // wallet: the reader is authenticated and trusted, with its identity surfaced for consent
        val requestState = withTimeout(15_000) { session.state.first { it is ProximityState.RequestReceived || it is ProximityState.Failed } }
        assertTrue(requestState is ProximityState.RequestReceived, "request: $requestState")
        assertTrue(requestState.request.reader.trusted, "reader chaining to the anchor must be trusted")
        assertEquals("EUDI Reader", requestState.request.reader.commonName)
        session.respond(ProximitySelection.auto(requestState.request))

        readerSession.decrypt(SessionMessages.decodeData(transport.readerReceive()))
        withTimeout(15_000) { session.state.first { it.isTerminal } }

        // audit records the trusted reader identity + certificate chain
        val entry = logStore.all().single()
        assertEquals(true, entry.relyingParty?.trusted)
        assertEquals("EUDI Reader", entry.relyingParty?.name)
        assertTrue((entry.relyingParty?.certificateChainDer?.size ?: 0) >= 1)
    }
}
