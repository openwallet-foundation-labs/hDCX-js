package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwkEc
import com.hopae.eudi.wallet.sdjwt.Jwe
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtIssuer
import com.hopae.eudi.wallet.sdjwt.SdJwtVerifier
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.math.BigInteger
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

class VpE2eTest {

    private val now = 1_700_000_000L

    /** Verifier: holds an EC encryption key, builds the request, receives & verifies the response. */
    private companion object { const val ENC_KID = "verifier-enc-key-1" }

    private class MockVerifier(
        val area: SoftwareSecureArea,
        val issuerPublic: EcPublicKey,
        /** §7.3(5.e) judges the KB-JWT `iat` against the verifier's clock — pin it to the wallet's. */
        val clock: () -> Long = { 1_700_000_000L },
    ) : HttpTransport {
        val clientId = "verifier.example"
        val nonce = "vp-nonce-123"
        val responseUri = "https://verifier.example/response"

        // encryption key for direct_post.jwt
        private val encKp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        private val encPubJwk: JsonValue.Obj
        private val encPrivD: ByteArray

        var verifiedClaims: JsonValue.Obj? = null; private set

        init {
            val pub = encKp.public as ECPublicKey
            fun fixed(b: BigInteger): ByteArray { val s = b.toByteArray().dropWhile { it == 0.toByte() }.toByteArray(); return ByteArray(32 - s.size) + s }
            val ec = EcPublicKey(EcCurve.P256, fixed(pub.w.affineX), fixed(pub.w.affineY))
            encPubJwk = JwkEc.toJson(ec).let {
            // §8.3: `alg` MUST be present on the JWK; the wallet echoes `kid` into the JWE header.
            JsonValue.Obj(it.entries + ("use" to JsonValue.Str("enc")) + ("alg" to JsonValue.Str("ECDH-ES")) + ("kid" to JsonValue.Str(ENC_KID)))
        }
            encPrivD = fixed((encKp.private as ECPrivateKey).s)
        }

        fun requestUri(responseMode: String): String {
            val dcql = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
                "claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}"""
            val clientMetadata = JsonValue.Obj(
                listOf(
                    "jwks" to JsonValue.Obj(listOf("keys" to JsonValue.Arr(listOf(encPubJwk)))),
                    "encrypted_response_enc_values_supported" to JsonValue.Arr(listOf(JsonValue.Str("A256GCM"))),
                )
            ).serialize()
            return "openid4vp://?client_id=${enc(clientId)}&nonce=${enc(nonce)}" +
                "&response_mode=$responseMode&response_uri=${enc(responseUri)}&state=xyz" +
                "&dcql_query=${enc(dcql)}&client_metadata=${enc(clientMetadata)}"
        }

        override suspend fun execute(request: HttpRequest): HttpResponse {
            if (request.url != responseUri || request.method != HttpMethod.POST) {
                return HttpResponse(404, emptyList(), ByteArray(0))
            }
            val form = request.body!!.decodeToString().split('&').associate {
                URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('='), "UTF-8")
            }
            val vpTokenJson = when {
                form["response"] != null -> Jwe.decryptEcdhEs(form["response"]!!, encPrivD, EcCurve.P256).decodeToString()
                    .let { JsonValue.parse(it) as JsonValue.Obj }.let { it["vp_token"] as JsonValue.Obj }
                form["vp_token"] != null -> JsonValue.parse(form["vp_token"]!!) as JsonValue.Obj
                else -> error("no vp_token in response")
            }
            // verify the SD-JWT VC presentation for query "pid"
            val presentation = ((vpTokenJson["pid"] as JsonValue.Arr).items.first() as JsonValue.Str).value
            val verified = SdJwtVerifier.verify(
                SdJwt.parse(presentation), issuerPublic, SigningAlgorithm.ES256,
                keyBinding = SdJwtVerifier.KbRequirement(clientId, nonce, now = clock),
            )
            verifiedClaims = verified.claims
            return HttpResponse(200, listOf("Content-Type" to "application/json"), """{"redirect_uri":"https://verifier.example/done"}""".encodeToByteArray())
        }
    }

    private fun issuePid(area: SoftwareSecureArea, issuerKey: KeyInfo, holderKey: KeyInfo): SdJwt = runBlocking {
        var n = 0
        SdJwtIssuer({ "salt-${++n}" }).issue(
            signer = SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256),
            holderKey = holderKey.publicKey,
        ) {
            claim("iss", "https://issuer.example")
            claim("vct", "urn:eudi:pid:1")
            sd("family_name", "Han")
            sd("given_name", "Jongho")
            sd("birthdate", "1990-05-15")
        }
    }

    private fun runFlow(responseMode: String) = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val holderKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val pid = issuePid(area, issuerKey, holderKey)
        val held = HeldSdJwtVc("pid-1", pid, SecureAreaJwsSigner(area, holderKey.handle, SigningAlgorithm.ES256))

        val verifier = MockVerifier(area, issuerKey.publicKey)
        val client = Openid4VpClient(verifier, clock = { now })

        val request = client.resolveRequest(verifier.requestUri(responseMode))
        assertEquals(verifier.clientId, request.clientId)
        val matches = client.match(request, listOf(held))
        assertTrue(matches.isSatisfiable())

        val result = client.respond(request, matches, PresentationSelection.auto(matches), listOf(held))
        assertEquals("https://verifier.example/done", result.redirectUri)

        // verifier-side: only requested claims disclosed, holder+nonce bound
        val claims = verifier.verifiedClaims!!
        assertEquals(JsonValue.Str("Han"), claims["family_name"])
        assertEquals(JsonValue.Str("Jongho"), claims["given_name"])
        assertNull(claims["birthdate"], "unrequested claim must not be disclosed")
    }

    @Test
    fun directPostJwtEncryptedResponse() = runFlow("direct_post.jwt")

    @Test
    fun directPostPlainResponse() = runFlow("direct_post")

    @Test
    fun sessionStateMachine() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val holderKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val pid = issuePid(area, issuerKey, holderKey)
        val held = HeldSdJwtVc("pid-1", pid, SecureAreaJwsSigner(area, holderKey.handle, SigningAlgorithm.ES256))
        val verifier = MockVerifier(area, issuerKey.publicKey)
        val client = Openid4VpClient(verifier, clock = { now })

        val session = PresentationSession(client, listOf(held))
        session.start(verifier.requestUri("direct_post.jwt"))
        val resolved = session.state.value as PresentationState.RequestResolved
        assertTrue(resolved.request.satisfiable)
        assertEquals("pid", resolved.request.queries.single().queryId)

        session.respond(PresentationSelection.auto(client.match(client.resolveRequest(verifier.requestUri("direct_post.jwt")), listOf(held))))
        assertTrue(session.state.value is PresentationState.Completed)
    }
}
