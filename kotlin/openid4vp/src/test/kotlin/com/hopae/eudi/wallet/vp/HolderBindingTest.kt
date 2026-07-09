package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtIssuer
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.net.URLDecoder
import java.net.URLEncoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * OpenID4VP DCQL `require_cryptographic_holder_binding` (§6.1): default true — the SD-JWT VC is presented
 * with a KB-JWT. When the verifier sets it false, the credential is presented without one.
 */
class HolderBindingTest {

    private val now = 1_700_000_000L
    private val clientId = "verifier.example"

    private class Capturing : HttpTransport {
        var vpToken: JsonValue.Obj? = null; private set
        override suspend fun execute(request: HttpRequest): HttpResponse {
            val form = request.body!!.decodeToString().split('&').associate {
                URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('='), "UTF-8")
            }
            vpToken = JsonValue.parse(form["vp_token"]!!) as JsonValue.Obj
            return HttpResponse(200, listOf("Content-Type" to "application/json"), "{}".encodeToByteArray())
        }
    }

    private fun requestUri(requireBinding: Boolean?): String {
        val bind = requireBinding?.let { ""","require_cryptographic_holder_binding":$it""" } ?: ""
        val dcql = """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
            "claims":[{"path":["family_name"]}]$bind}]}"""
        return "openid4vp://?client_id=${enc(clientId)}&nonce=vp-nonce-123" +
            "&response_mode=direct_post&response_uri=${enc("https://verifier.example/response")}&state=x&dcql_query=${enc(dcql)}"
    }

    private fun fixture(): Triple<Openid4VpClient, Capturing, List<PresentableCredential>> = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val holderKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        var n = 0
        val pid = SdJwtIssuer({ "salt-${++n}" }).issue(
            signer = SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256), holderKey = holderKey.publicKey,
        ) {
            claim("iss", "https://issuer.example"); claim("vct", "urn:eudi:pid:1")
            sd("family_name", "Han"); sd("given_name", "Jongho")
        }
        val held = listOf(HeldSdJwtVc("pid-1", pid, SecureAreaJwsSigner(area, holderKey.handle, SigningAlgorithm.ES256)))
        val http = Capturing()
        Triple(Openid4VpClient(http, clock = { now }), http, held)
    }

    private suspend fun presentFor(requireBinding: Boolean?): SdJwt {
        val (client, http, held) = fixture()
        val request = client.resolveRequest(requestUri(requireBinding))
        val matches = client.match(request, held)
        client.respond(request, matches, PresentationSelection.auto(matches), held)
        val str = ((http.vpToken!!["pid"] as JsonValue.Arr).items.first() as JsonValue.Str).value
        return SdJwt.parse(str)
    }

    @Test
    fun bindsWithKbJwtByDefault() = runBlocking {
        val presented = presentFor(requireBinding = null) // default true
        assertTrue(presented.serialize().let { !it.endsWith("~") }, "a KB-JWT is appended by default")
        assertEquals("Han", disclosed(presented, "family_name"))
    }

    @Test
    fun omitsKbJwtWhenBindingNotRequired() = runBlocking {
        val presented = presentFor(requireBinding = false)
        assertNull(presented.kbJwt, "no KB-JWT when require_cryptographic_holder_binding is false")
        assertTrue(presented.serialize().endsWith("~"), "serialization ends with a bare '~' (no key binding)")
        // the selective disclosure still works — the requested claim is present
        assertEquals("Han", disclosed(presented, "family_name"))
    }

    @Test
    fun stillBindsWhenExplicitlyRequired() = runBlocking {
        val presented = presentFor(requireBinding = true)
        assertTrue(presented.kbJwt != null, "explicit true keeps the KB-JWT")
    }

    private fun disclosed(sdJwt: SdJwt, name: String): String? =
        sdJwt.disclosures.firstOrNull { it.claimName == name }?.value?.let { (it as? JsonValue.Str)?.value }

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
}
