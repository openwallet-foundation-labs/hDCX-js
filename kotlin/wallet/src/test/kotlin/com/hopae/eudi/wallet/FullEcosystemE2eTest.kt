package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeyUse
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.testkit.InMemoryStorageDriver
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import com.hopae.eudi.wallet.trustlist.TrustedListClient
import com.hopae.eudi.wallet.txlog.InMemoryTransactionLogStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest as JdkRequest
import java.net.http.HttpResponse as JdkResponse
import java.time.Duration
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Full-ecosystem live e2e: **one wallet run** exercises every piece — trust anchors pulled from our JAdES
 * Trusted Lists ([TrustedListClient]), a credential **issued** by the live issuer, then **presented** to the
 * deployed verifier which authenticates itself with a registrar-issued WRPAC + WRPRC and returns an
 * **encrypted** response the wallet produces. Env-gated (`EUDI_E2E=1`) — it hits live infrastructure.
 *
 *   ./gradlew :wallet:test --tests '*FullEcosystemE2eTest*' -DEUDI_E2E=1   (or EUDI_E2E=1 env)
 */
class FullEcosystemE2eTest {
    private val verifierBase = env("EUDI_VERIFIER", "https://dev.api.hopae.com/trp")
    private val issuerBase = env("EUDI_ISSUER", "https://tiss.api.hopae.com/eudi-issuer")
    private val tlBase = env("EUDI_TL", "https://trusted-list.vercel.app/tl")

    /** mDL (mdoc) is offered pre-authorized, so the whole loop runs headless (no browser/interaction). */
    @Test
    fun fullLoopMdl() = runBlocking {
        assumeTrue(env("EUDI_E2E", "") == "1", "set EUDI_E2E=1 to run the live full-ecosystem e2e")
        val http = JdkHttp()

        // 1) Trust anchors — pull the CA certificates from our JAdES-signed Trusted Lists.
        val soDer = pemToDer(String(http.get("$tlBase/scheme-operator.pem")))
        val tl = TrustedListClient(http)
        val pidCAs = tl.fetchCACerts("$tlBase/pid-issuers.jades.json", soDer)
        val attCAs = tl.fetchCACerts("$tlBase/attestation-issuers.jades.json", soDer)
        val regCAs = tl.fetchCACerts("$tlBase/registrar.jades.json", soDer)
        println("[e2e] trusted-list CAs: pid=${pidCAs.size} attestation=${attCAs.size} registrar=${regCAs.size}")

        val wallet = Wallet.create(
            WalletConfig(
                trust = TrustConfig(
                    issuerAnchorsDer = pidCAs + attCAs,
                    readerAnchorsDer = regCAs,
                    registrarAnchorsDer = regCAs,
                ),
            ),
            WalletPorts(listOf(SoftwareSecureArea()), InMemoryStorageDriver(), http, transactionLogStore = InMemoryTransactionLogStore()),
        )

        // 2) Issue mDL (pre-authorized code) from the live issuer → wallet holds it.
        val offerResp = json(http.post("$issuerBase/credential-offer/create", """{"credential_configuration_id":"org.iso.18013.5.1.mDL"}"""))
        val offerJson = (offerResp["credential_offer"] as JsonValue.Obj).serialize()
        val offerUri = "openid-credential-offer://?credential_offer=${URLEncoder.encode(offerJson, "UTF-8")}"
        val offer = wallet.issuance.resolveOffer(offerUri)
        val issuance = wallet.issuance.start(IssuanceRequest.fromOffer(offer, "org.iso.18013.5.1.mDL"))
        val issued = withTimeout(90_000) { issuance.state.first { it is IssuanceState.Completed || it is IssuanceState.Failed } }
        assertTrue(issued is IssuanceState.Completed, "issuance did not complete: $issued")
        println("[e2e] issued mDL: ${(issued as IssuanceState.Completed).result.issued}")

        // 3) Ask the deployed verifier for an mDL presentation (QR / direct_post.jwt).
        val created = json(http.post("$verifierBase/presentations", """{"credentials":["mdl"],"mode":"qr"}"""))
        val txnId = (created["transaction_id"] as JsonValue.Str).value
        val qr = (created["qr"] as JsonValue.Str).value
        println("[e2e] verifier request: client_id=${(created["client_id"] as JsonValue.Str).value}")

        // 4) Present: the wallet resolves the request (WRPAC + WRPRC verified), then submits the encrypted response.
        val session = wallet.presentation.start(qr)
        val resolved = withTimeout(45_000) {
            session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed }
        }
        assertTrue(resolved is PresentationState.RequestResolved, "request not resolved: $resolved")
        val request = (resolved as PresentationState.RequestResolved).request
        println("[e2e] resolved verifier=${request.verifier.clientId} trusted=${request.verifier.trusted} registration=${request.verifier.registration?.subject}")
        assertTrue(request.satisfiable, "verifier's mDL query not satisfiable by the held credential")

        session.respond(PresentationSelection.auto(request))
        val terminal = withTimeout(45_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Completed, "presentation failed: $terminal")

        // 5) Confirm the verifier verified the encrypted mdoc presentation.
        val result = pollResult(http, "$verifierBase/presentations/$txnId")
        val status = (result["status"] as? JsonValue.Str)?.value
        assertEquals("verified", status, "verifier result: ${result.serialize()}")
        println("[e2e] VERIFIED ✓  ${result.serialize()}")
        wallet.close()
    }

    /**
     * The issuer's `enc-batch` profile exercises the wallet honouring the offer/profile metadata: the offer's
     * `credential_issuer` selects a profile whose metadata sets `encryption_required` + `batch_size:3`, and the
     * pre-auth grant carries a `tx_code`. The wallet must send the tx_code at the token endpoint, encrypt the
     * Credential Request (and JWE-decrypt the response), and request 3 credentials — one per proof key.
     */
    @Test
    fun encryptedBatchTxCodeLoop() = runBlocking {
        assumeTrue(env("EUDI_E2E", "") == "1", "set EUDI_E2E=1 to run the live full-ecosystem e2e")
        val http = JdkHttp()

        val soDer = pemToDer(String(http.get("$tlBase/scheme-operator.pem")))
        val tl = TrustedListClient(http)
        val issuerCAs = tl.fetchCACerts("$tlBase/pid-issuers.jades.json", soDer) + tl.fetchCACerts("$tlBase/attestation-issuers.jades.json", soDer)
        val regCAs = tl.fetchCACerts("$tlBase/registrar.jades.json", soDer)
        val wallet = Wallet.create(
            WalletConfig(trust = TrustConfig(issuerAnchorsDer = issuerCAs, readerAnchorsDer = regCAs, registrarAnchorsDer = regCAs)),
            WalletPorts(listOf(SoftwareSecureArea()), InMemoryStorageDriver(), http, transactionLogStore = InMemoryTransactionLogStore()),
        )

        // Offer with the encryption-required + batch(3) profile AND a transaction code.
        val offerResp = json(http.post("$issuerBase/credential-offer/create", """{"credential_configuration_id":"org.iso.18013.5.1.mDL","encrypted":true,"batch_size":3,"tx_code":true}"""))
        val pin = (offerResp["tx_code"] as JsonValue.Str).value
        val offerJson = (offerResp["credential_offer"] as JsonValue.Obj).serialize()
        val offerUri = "openid-credential-offer://?credential_offer=${URLEncoder.encode(offerJson, "UTF-8")}"
        println("[e2e] enc-batch offer: credential_issuer=${((offerResp["credential_offer"] as JsonValue.Obj)["credential_issuer"] as JsonValue.Str).value} tx_code=$pin")

        val offer = wallet.issuance.resolveOffer(offerUri)
        assertTrue(offer.requiresTxCode, "offer should require a tx_code")

        val session = wallet.issuance.start(
            IssuanceRequest.fromOffer(offer, "org.iso.18013.5.1.mDL", txCode = pin, policy = CredentialPolicy(batchSize = 3, use = KeyUse.OneTime)),
        )
        val terminal = withTimeout(90_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is IssuanceState.Completed, "issuance did not complete (encrypted/batch/tx_code): $terminal")

        val issued = wallet.credentials.list().single().lifecycle as Lifecycle.Issued
        assertEquals(3, issued.instances.remaining, "batchSize=3 + encrypted response → 3 decrypted instances")
        println("[e2e] ENCRYPTED + BATCH(3) + TX_CODE ✓  instances=${issued.instances.remaining}")
        wallet.close()
    }

    // --- helpers --------------------------------------------------------------

    private fun pollResult(http: JdkHttp, url: String): JsonValue.Obj = runBlocking {
        repeat(20) {
            val r = json(http.get(url))
            if ((r["status"] as? JsonValue.Str)?.value != "pending") return@runBlocking r
            Thread.sleep(1000)
        }
        json(http.get(url))
    }

    private fun json(bytes: ByteArray): JsonValue.Obj = JsonValue.parse(bytes.decodeToString()) as JsonValue.Obj

    private fun pemToDer(pem: String): ByteArray =
        Base64.getMimeDecoder().decode(pem.replace(Regex("-----(BEGIN|END) CERTIFICATE-----"), "").replace(Regex("\\s"), ""))

    private fun env(k: String, default: String): String = System.getenv(k) ?: System.getProperty(k) ?: default

    private class JdkHttp : HttpTransport {
        private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(15)).build()

        suspend fun get(url: String): ByteArray = execute(HttpRequest(HttpMethod.GET, url, emptyList())).body
        suspend fun post(url: String, jsonBody: String): ByteArray =
            execute(HttpRequest(HttpMethod.POST, url, listOf("Content-Type" to "application/json"), jsonBody.encodeToByteArray())).body

        override suspend fun execute(request: HttpRequest): HttpResponse {
            val builder = JdkRequest.newBuilder(URI.create(request.url)).timeout(Duration.ofSeconds(20))
            val body = request.body?.let { JdkRequest.BodyPublishers.ofByteArray(it) } ?: JdkRequest.BodyPublishers.noBody()
            when (request.method) {
                HttpMethod.GET -> builder.GET()
                HttpMethod.POST -> builder.POST(body)
                HttpMethod.PUT -> builder.PUT(body)
                HttpMethod.PATCH -> builder.method("PATCH", body)
                HttpMethod.DELETE -> builder.DELETE()
            }
            request.headers.forEach { (k, v) -> builder.header(k, v) }
            val resp = client.send(builder.build(), JdkResponse.BodyHandlers.ofByteArray())
            return HttpResponse(resp.statusCode(), resp.headers().map().entries.flatMap { (k, vs) -> vs.map { k to it } }, resp.body())
        }
    }
}
