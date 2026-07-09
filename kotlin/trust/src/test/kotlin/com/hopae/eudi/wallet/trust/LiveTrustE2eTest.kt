package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.cbor.cose.CoseSigner
import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocVerifier
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.sdjwt.JwtTimeValidator
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtVcVerifier
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm
import com.hopae.eudi.wallet.vp.HeldMdoc
import com.hopae.eudi.wallet.vp.HeldSdJwtVc
import com.hopae.eudi.wallet.vp.Openid4VpClient
import com.hopae.eudi.wallet.vp.PresentationSelection
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest as JdkRequest
import java.net.http.HttpResponse as JdkResponse
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Live trust e2e against the real EUDI infrastructure, using the production trust module
 * (X.509 chain validation to the bundled EUDI IACA `PID Issuer CA - UT 02`).
 *   - verifyRealPidWithChain: EUDI_LIVE=x — verify the captured PID's issuer x5c chains to the anchor.
 *   - presentWithTrust: EUDI_VP=1, EUDI_VP_REQUEST=<url> — verify the verifier request (x509_hash)
 *     against the anchor, then present.
 */
class LiveTrustE2eTest {

    private fun anchor(): TrustAnchors = anchor("/pid_issuer_ca_ut_02.der")

    private fun anchor(resource: String): TrustAnchors {
        val der = javaClass.getResourceAsStream(resource)!!.readBytes()
        return TrustAnchors(listOf(X509Support.parse(der)))
    }

    /**
     * Live proof of OpenID4VCI §12.2.2/§12.2.3 signed metadata: `dev.issuer-backend.eudiw.dev` serves the
     * whole metadata document as an `application/jwt` JWS (`typ=openidvci-issuer-metadata+jwt`) whose x5c
     * leaf chains to `PID Issuer CA 02` (EU). `RequireSigned` must negotiate it, verify the chain, and
     * enforce `sub` / `iat`. (`issuer.eudiw.dev` does not sign — it only serves `application/json`.)
     */
    @Test
    fun verifySignedIssuerMetadata() = runBlocking {
        assumeTrue(System.getenv("EUDI_SIGNED_METADATA") == "1", "set EUDI_SIGNED_METADATA=1 for the live signed-metadata check")
        val issuer = "https://dev.issuer-backend.eudiw.dev"
        val validator = X509ChainValidator(anchor("/pid_issuer_ca_eu_02.der"))
        val client = com.hopae.eudi.wallet.vci.Openid4VciClient(
            JdkHttp(), { size -> ByteArray(size) }, clock = { Instant.now().epochSecond },
            metadataPolicy = com.hopae.eudi.wallet.vci.IssuerMetadataPolicy.RequireSigned(X5cSignedMetadataVerifier(validator)),
        )

        val meta = client.loadIssuerMetadata(issuer)
        println("\n*** LIVE SIGNED ISSUER METADATA VERIFIED (x5c -> PID Issuer CA 02 EU) ***")
        println("credential_issuer: ${meta.credentialIssuer}")
        println("credential_endpoint: ${meta.credentialEndpoint}")
        println("configurations: ${meta.credentialConfigurationsSupported.size}")
        assertEquals(issuer, meta.credentialIssuer)
        assertTrue(meta.credentialConfigurationsSupported.isNotEmpty(), "signed metadata carries the configurations")
    }

    /** The same issuer must still serve unsigned JSON — and `IgnoreSigned` must take that branch. */
    @Test
    fun unsignedMetadataStillWorks() = runBlocking {
        assumeTrue(System.getenv("EUDI_SIGNED_METADATA") == "1", "set EUDI_SIGNED_METADATA=1 for the live signed-metadata check")
        val issuer = "https://dev.issuer-backend.eudiw.dev"
        val client = com.hopae.eudi.wallet.vci.Openid4VciClient(JdkHttp(), { size -> ByteArray(size) }, clock = { Instant.now().epochSecond })

        val meta = client.loadIssuerMetadata(issuer)
        assertEquals(issuer, meta.credentialIssuer)
        println("*** unsigned application/json branch OK — ${meta.credentialConfigurationsSupported.size} configurations ***")
    }

    /** Validation instant: EUDI_AT (epoch seconds) overrides now — used to prove logic vs a lapsed issuer cert. */
    private fun validationInstant(): Instant =
        System.getenv("EUDI_AT")?.let { Instant.ofEpochSecond(it.toLong()) } ?: Instant.now()

    @Test
    fun verifyRealPidWithChain() = runBlocking {
        assumeTrue(System.getenv("EUDI_LIVE") == "x", "set EUDI_LIVE=x with a captured credential")
        val credential = File(System.getProperty("java.io.tmpdir"), "eudi-credential.txt").readText().trim()

        val at = validationInstant()
        val verifier = SdJwtVcVerifier(
            issuerKeyResolver = X5cIssuerKeyResolver(X509ChainValidator(anchor(), at = { java.util.Date.from(at) })),
            timeValidator = JwtTimeValidator(now = { at }),
        )
        val verified = verifier.verify(SdJwt.parse(credential))
        println("\n*** REAL PID VERIFIED WITH FULL X.509 CHAIN TO EUDI IACA ***")
        println("vct: ${verified.vct}, issuer: ${verified.issuer}, holder-bound: ${verified.holderKey != null}")
        verified.claims.entries.forEach { (k, v) -> println("  $k = ${v.serialize()}") }
        assertEquals("urn:eudi:pid:1", verified.vct)
    }

    @Test
    fun presentWithTrust() = runBlocking {
        assumeTrue(System.getenv("EUDI_VP") == "1", "set EUDI_VP=1 and EUDI_VP_REQUEST")
        val requestUrl = System.getenv("EUDI_VP_REQUEST") ?: error("set EUDI_VP_REQUEST")
        val tmp = System.getProperty("java.io.tmpdir")
        val credential = File(tmp, "eudi-credential.txt").readText().trim()
        val holder = LoadedKey.fromJson(JsonValue.parse(File(tmp, "eudi-holder-key.json").readText()) as JsonValue.Obj)

        val transport = JdkHttp()
        val held = HeldSdJwtVc("pid", SdJwt.parse(credential), holder.signer())
        val client = Openid4VpClient(
            transport, clock = { System.currentTimeMillis() / 1000 },
            trust = X509RequestVerifier(X509ChainValidator(anchor())),
        )

        val request = client.resolveRequest(requestUrl)
        println("verifier: client_id=${request.clientId} scheme=${request.verifier.clientIdScheme} trusted=${request.verifier.trusted} cn=${request.verifier.commonName}")
        assertTrue(request.verifier.trusted, "verifier request must chain to the EUDI IACA")

        val matches = client.match(request, listOf(held))
        assertTrue(matches.isSatisfiable())
        val result = client.respond(request, matches, PresentationSelection.auto(matches), listOf(held))
        println("*** PRESENTED TO TRUSTED VERIFIER — redirect_uri: ${result.redirectUri} ***")
    }

    @Test
    fun verifyRealMdocWithChain() = runBlocking {
        assumeTrue(System.getenv("EUDI_MDOC") == "verify", "set EUDI_MDOC=verify with a captured mdoc credential")
        val credential = File(System.getProperty("java.io.tmpdir"), "eudi-credential.txt").readText().trim()
        val issuerSigned = IssuerSigned.decode(Base64Url.decode(credential))

        val verified = MdocVerifier(X5cMdocIssuerTrust(X509ChainValidator(anchor()))).verify(issuerSigned)
        println("\n*** REAL mdoc PID VERIFIED WITH FULL X.509 CHAIN TO EUDI IACA ***")
        println("docType: ${verified.docType}, holder-bound: true, valid ${verified.validFrom}..${verified.validUntil}")
        verified.elements.forEach { (ns, els) -> els.forEach { (k, v) -> println("  $ns / $k = $v") } }
        assertEquals("eu.europa.ec.eudi.pid.1", verified.docType)
    }

    @Test
    fun presentMdocWithTrust() = runBlocking {
        assumeTrue(System.getenv("EUDI_MDOC") == "present", "set EUDI_MDOC=present and EUDI_VP_REQUEST")
        val requestUrl = System.getenv("EUDI_VP_REQUEST") ?: error("set EUDI_VP_REQUEST")
        val tmp = System.getProperty("java.io.tmpdir")
        val credential = File(tmp, "eudi-credential.txt").readText().trim()
        val holder = LoadedKey.fromJson(JsonValue.parse(File(tmp, "eudi-holder-key.json").readText()) as JsonValue.Obj)

        val held = HeldMdoc("pid-mdoc", IssuerSigned.decode(Base64Url.decode(credential)), holder.coseSigner())
        val client = Openid4VpClient(
            JdkHttp(), clock = { System.currentTimeMillis() / 1000 },
            trust = X509RequestVerifier(X509ChainValidator(anchor())),
        )

        val request = client.resolveRequest(requestUrl)
        println("verifier: client_id=${request.clientId} scheme=${request.verifier.clientIdScheme} trusted=${request.verifier.trusted}")
        assertTrue(request.verifier.trusted, "verifier request must chain to the EUDI IACA")

        val matches = client.match(request, listOf(held))
        matches.candidatesByQuery.forEach { (q, c) -> println("  $q -> ${c.size} candidate(s), disclose ${c.firstOrNull()?.disclosedPaths}") }
        assertTrue(matches.isSatisfiable())
        val result = client.respond(request, matches, PresentationSelection.auto(matches), listOf(held))
        println("*** mdoc DeviceResponse PRESENTED TO TRUSTED VERIFIER — redirect_uri: ${result.redirectUri} ***")
    }

    private class JdkHttp : HttpTransport {
        private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(15)).build()
        override suspend fun execute(request: HttpRequest): HttpResponse {
            val builder = JdkRequest.newBuilder(URI.create(request.url)).timeout(Duration.ofSeconds(20))
            val body = request.body?.let { JdkRequest.BodyPublishers.ofByteArray(it) } ?: JdkRequest.BodyPublishers.noBody()
            when (request.method) {
                HttpMethod.GET -> builder.GET(); HttpMethod.POST -> builder.POST(body)
                HttpMethod.PUT -> builder.PUT(body); HttpMethod.PATCH -> builder.method("PATCH", body); HttpMethod.DELETE -> builder.DELETE()
            }
            request.headers.forEach { (k, v) -> builder.header(k, v) }
            val resp = client.send(builder.build(), JdkResponse.BodyHandlers.ofByteArray())
            return HttpResponse(resp.statusCode(), resp.headers().map().entries.flatMap { (k, vs) -> vs.map { k to it } }, resp.body())
        }
    }

    private class LoadedKey(private val pkcs8: ByteArray, val publicKey: EcPublicKey) {
        private val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        private fun rawSign(bytes: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(priv); update(bytes); Der.derSignatureToRaw(sign(), 32) }

        fun signer(): JwsSigner = object : JwsSigner {
            override val algorithm = SigningAlgorithm.ES256
            override suspend fun sign(signingInput: ByteArray): ByteArray = rawSign(signingInput)
        }

        /** COSE signer over the same device key, for the mdoc DeviceResponse `deviceSignature`. */
        fun coseSigner(): CoseSigner = object : CoseSigner {
            override val algorithm = SigningAlgorithm.ES256.coseAlgorithm
            override suspend fun sign(toBeSigned: ByteArray): ByteArray = rawSign(toBeSigned)
        }
        companion object {
            fun fromJson(o: JsonValue.Obj) = LoadedKey(
                Base64.getDecoder().decode((o["pkcs8"] as JsonValue.Str).value),
                EcPublicKey(EcCurve.P256, Base64Url.decode((o["x"] as JsonValue.Str).value), Base64Url.decode((o["y"] as JsonValue.Str).value)),
            )
        }
    }
}
