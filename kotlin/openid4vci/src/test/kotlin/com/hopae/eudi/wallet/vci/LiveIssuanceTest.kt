package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.sdjwt.JwtTimeValidator
import com.hopae.eudi.wallet.sdjwt.JwtVcMetadataKeyResolver
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtVcVerifier
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import kotlin.test.Test

/**
 * Manual two-step live PID issuance from issuer.eudiw.dev.
 *
 *   Step 1 (get the URL):  EUDI_LIVE=prepare ./gradlew :openid4vci:test --tests '*LiveIssuanceTest*'
 *   -> open the printed URL in a browser, authenticate, copy the `code` from the redirect.
 *   Step 2 (complete):     EUDI_LIVE=finish EUDI_CODE=<code> ./gradlew ... (same filter)
 *
 * State + holder keys are persisted between the two runs. Uses the authorization code grant.
 */
class LiveIssuanceTest {

    private val issuer = "https://issuer.eudiw.dev"
    private val configId = "eu.europa.ec.eudi.pid_vc_sd_jwt"
    private val redirectUri = "https://example.org/cb"
    private val stateFile = File(System.getProperty("java.io.tmpdir"), "eudi-live-issuance.json")

    private fun secureRng(): Rng {
        val sr = SecureRandom()
        return Rng { size -> ByteArray(size).also(sr::nextBytes) }
    }

    private fun client() = Openid4VciClient(
        JdkHttpTransport(), secureRng(),
        clock = { System.currentTimeMillis() / 1000 },
        clientId = "wallet-dev",
    )

    @Test
    fun step1_prepare() = runBlocking {
        assumeTrue(System.getenv("EUDI_LIVE") == "prepare", "run with EUDI_LIVE=prepare")

        val proof = LocalEcKey.generate()
        val dpop = LocalEcKey.generate()
        val client = client()

        // If a credential offer (deep link) is provided, use its issuer/config/issuer_state.
        val offerInput = System.getenv("EUDI_OFFER")
        val offer = offerInput?.let { client.resolveCredentialOffer(it) }
        val useIssuer = offer?.credentialIssuer ?: issuer
        val useConfig = offer?.credentialConfigurationIds?.first() ?: configId
        val issuerState = offer?.authorizationCodeIssuerState
        if (offer != null) println("resolved offer: issuer=$useIssuer config=$useConfig issuer_state=$issuerState")

        val prepared = client.prepareAuthorizationCodeIssuance(
            credentialIssuer = useIssuer,
            configurationId = useConfig,
            redirectUri = redirectUri,
            issuerState = issuerState,
        )

        val state = JsonValue.Obj(
            listOf(
                "credentialIssuer" to JsonValue.Str(useIssuer),
                "configurationId" to JsonValue.Str(useConfig),
                "codeVerifier" to JsonValue.Str(prepared.pkce.codeVerifier),
                "redirectUri" to JsonValue.Str(redirectUri),
                "proof" to proof.toJson(),
                "dpop" to dpop.toJson(),
            )
        )
        stateFile.writeText(state.serialize())

        println("\n================ OPEN THIS URL IN A BROWSER ================\n")
        println(prepared.authorizationUrl)
        println("\nAfter authenticating, you'll be redirected to:")
        println("  $redirectUri?code=<CODE>&state=...")
        println("Copy the <CODE> value, then run step 2 with EUDI_LIVE=finish EUDI_CODE=<CODE>.")
        println("(state saved to ${stateFile.absolutePath})\n")
    }

    /**
     * Pre-authorized code flow — fully headless, no authorization endpoint or browser.
     * Reads a pre-auth offer (EUDI_OFFER) + transaction code (EUDI_TXCODE) captured from the
     * portal and redeems them directly at the token endpoint.
     */
    @Test
    fun preAuthIssue() = runBlocking {
        assumeTrue(System.getenv("EUDI_LIVE") == "preauth", "run with EUDI_LIVE=preauth")
        val offerInput = System.getenv("EUDI_OFFER") ?: error("set EUDI_OFFER=<pre-auth offer link>")
        val txCode = System.getenv("EUDI_TXCODE") ?: error("set EUDI_TXCODE=<transaction code>")
        val transport = JdkHttpTransport()

        val proof = LocalEcKey.generate()
        val dpop = LocalEcKey.generate()
        val keys = IssuanceKeys(proof.signer(), proof.publicKey, dpop.signer(), dpop.publicKey)

        val client = Openid4VciClient(
            transport, secureRng(), clock = { System.currentTimeMillis() / 1000 }, clientId = "wallet-dev",
        )
        val offer = client.resolveCredentialOffer(offerInput)
        println("pre-auth offer: config=${offer.credentialConfigurationIds.first()} txCodeRequired=${offer.txCode != null}")

        val response = client.issueWithPreAuthorizedCode(
            offer = offer,
            configurationId = offer.credentialConfigurationIds.first(),
            keys = keys,
            txCode = txCode,
        )
        println("credentials received: ${response.credentials.size}")
        val credential = response.credentials.first().credential
        File(System.getProperty("java.io.tmpdir"), "eudi-credential.txt").writeText(credential)
        println("credential saved (${credential.length} chars) — verify with VerifySavedPidTest")
    }

    @Test
    fun step2_finish() = runBlocking {
        assumeTrue(System.getenv("EUDI_LIVE") == "finish", "run with EUDI_LIVE=finish")
        // Prefer a redirect-URL file (no manual transcription): write the full redirect to
        // /tmp/eudi-redirect.txt, we extract and URL-decode the `code` ourselves.
        val redirectFile = File(System.getProperty("java.io.tmpdir"), "eudi-redirect.txt")
        val code = when {
            redirectFile.exists() -> {
                val url = redirectFile.readText().trim()
                val raw = url.substringAfter("code=").substringBefore('&')
                java.net.URLDecoder.decode(raw, "UTF-8")
            }
            else -> System.getenv("EUDI_CODE") ?: error("write redirect to ${redirectFile.absolutePath} or set EUDI_CODE")
        }
        println("using authorization code (len=${code.length})")
        val transport = JdkHttpTransport()

        val state = JsonValue.parse(stateFile.readText()) as JsonValue.Obj
        val proof = LocalEcKey.fromJson(state["proof"] as JsonValue.Obj)
        val dpop = LocalEcKey.fromJson(state["dpop"] as JsonValue.Obj)
        val codeVerifier = (state["codeVerifier"] as JsonValue.Str).value
        val redirect = (state["redirectUri"] as JsonValue.Str).value
        val useIssuer = (state["credentialIssuer"] as? JsonValue.Str)?.value ?: issuer
        val useConfig = (state["configurationId"] as? JsonValue.Str)?.value ?: configId

        val keys = IssuanceKeys(proof.signer(), proof.publicKey, dpop.signer(), dpop.publicKey)

        val client = Openid4VciClient(
            transport, secureRng(), clock = { System.currentTimeMillis() / 1000 }, clientId = "wallet-dev",
        )
        val response = client.exchangeAuthorizationCode(
            credentialIssuer = useIssuer,
            configurationId = useConfig,
            authorizationCode = code,
            redirectUri = redirect,
            codeVerifier = codeVerifier,
            keys = keys,
        )

        println("\n================ LIVE ISSUANCE RESULT ================")
        println("credentials received: ${response.credentials.size}")
        val credential = response.credentials.first().credential

        // Save the real credential FIRST — never lose it to a later verification error.
        val credFile = File(System.getProperty("java.io.tmpdir"), "eudi-credential.txt")
        credFile.writeText(credential)
        println("credential saved to ${credFile.absolutePath} (${credential.length} chars)")

        // Show the issuer JWS header + payload (unverified) for diagnostics.
        val parsed = SdJwt.parse(credential)
        val jws = com.hopae.eudi.wallet.sdjwt.Jws.parse(parsed.jwt)
        println("JWS header: ${jws.header.serialize()}")
        val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as JsonValue.Obj
        println("payload keys: ${payload.entries.map { it.first }}")
        println("disclosures: ${parsed.disclosures.size}")

        try {
            val verified = SdJwtVcVerifier(
                JwtVcMetadataKeyResolver(transport),
                JwtTimeValidator(now = { Instant.now() }),
            ).verify(parsed)
            println("\n*** VERIFIED SD-JWT VC ***")
            println("vct:    ${verified.vct}")
            println("issuer: ${verified.issuer}")
            println("claims:")
            verified.claims.entries.forEach { (k, v) -> println("  $k = ${v.serialize()}") }
            println("holder-bound: ${verified.holderKey != null}")
        } catch (e: Exception) {
            println("\n[verification failed: ${e.message}] — credential is saved; diagnosing resolver path")
            val x5c = jws.x5c
            println("issuer JWS has x5c: ${x5c != null} (${x5c?.size ?: 0} certs)")
        }
        println("=====================================================\n")
    }
}

/** Local JCA-backed EC key for the manual live test (persists across the two runs). */
private class LocalEcKey(val privateKey: PrivateKey, val publicKey: EcPublicKey, val pkcs8: ByteArray) {

    fun signer(): JwsSigner = object : JwsSigner {
        override val algorithm = SigningAlgorithm.ES256
        override suspend fun sign(signingInput: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(signingInput)
                Der.derSignatureToRaw(sign(), 32)
            }
    }

    fun toJson(): JsonValue = JsonValue.Obj(
        listOf(
            "pkcs8" to JsonValue.Str(Base64.getEncoder().encodeToString(pkcs8)),
            "x" to JsonValue.Str(Base64Url.encode(publicKey.x)),
            "y" to JsonValue.Str(Base64Url.encode(publicKey.y)),
        )
    )

    companion object {
        fun generate(): LocalEcKey {
            val kp = KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            val pub = kp.public as ECPublicKey
            fun fixed(b: BigInteger): ByteArray {
                val s = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
                return ByteArray(32 - s.size) + s
            }
            val ec = EcPublicKey(EcCurve.P256, fixed(pub.w.affineX), fixed(pub.w.affineY))
            return LocalEcKey(kp.private, ec, kp.private.encoded)
        }

        fun fromJson(o: JsonValue.Obj): LocalEcKey {
            val pkcs8 = Base64.getDecoder().decode((o["pkcs8"] as JsonValue.Str).value)
            val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
            val x = Base64Url.decode((o["x"] as JsonValue.Str).value)
            val y = Base64Url.decode((o["y"] as JsonValue.Str).value)
            return LocalEcKey(priv, EcPublicKey(EcCurve.P256, x, y), pkcs8)
        }
    }
}
