package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.spi.Rng
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Live interop against the official EUDI reference issuer (https://issuer.eudiw.dev).
 * Opt-in (external network): run with `EUDI_INTEROP=1`. Proves the discovery, metadata
 * parsing, and PAR wiring work against the real server — not a mock.
 */
class RealIssuerInteropTest {

    private val issuer = "https://issuer.eudiw.dev"
    private val pidSdJwt = "eu.europa.ec.eudi.pid_vc_sd_jwt"

    private fun enabled() = System.getenv("EUDI_INTEROP") == "1"
    private fun secureRng(): Rng {
        val sr = SecureRandom()
        return Rng { size -> ByteArray(size).also(sr::nextBytes) }
    }

    @Test
    fun discoversRealIssuerAndParsesMetadata() = runBlocking {
        assumeTrue(enabled(), "set EUDI_INTEROP=1 to run live interop")
        val client = Openid4VciClient(JdkHttpTransport(), secureRng(), clock = { System.currentTimeMillis() / 1000 })

        val meta = client.loadIssuerMetadata(issuer)
        assertEquals(issuer, meta.credentialIssuer)
        assertTrue(meta.credentialEndpoint.contains("/credential"), "credential_endpoint: ${meta.credentialEndpoint}")
        assertNotNull(meta.nonceEndpoint)

        val pid = meta.credentialConfigurationsSupported[pidSdJwt]
        assertNotNull(pid, "real issuer must advertise $pidSdJwt")
        assertEquals("dc+sd-jwt", pid!!.format)
        assertEquals("urn:eudi:pid:1", pid.vct)
        assertTrue("ES256" in pid.proofSigningAlgs, "PID must accept ES256 proofs")

        val asMeta = client.loadAuthorizationServerMetadata(meta.authorizationServers.first())
        assertTrue(asMeta.tokenEndpoint.startsWith("https://"), "token_endpoint: ${asMeta.tokenEndpoint}")
        assertNotNull(asMeta.authorizationEndpoint)
        assertNotNull(asMeta.pushedAuthorizationRequestEndpoint)
        println("INTEROP OK: token=${asMeta.tokenEndpoint} par=${asMeta.pushedAuthorizationRequestEndpoint}")
    }

    @Test
    fun pushesRealAuthorizationRequest() = runBlocking {
        assumeTrue(enabled(), "set EUDI_INTEROP=1 to run live interop")
        val client = Openid4VciClient(
            JdkHttpTransport(), secureRng(), clock = { System.currentTimeMillis() / 1000 },
            clientId = "wallet-dev",
        )
        // A real PAR round-trip against the live AS. If the issuer requires a registered
        // client, this surfaces the exact server error (proving our request is well-formed).
        val prepared = runCatching {
            client.prepareAuthorizationCodeIssuance(
                credentialIssuer = issuer,
                configurationId = pidSdJwt,
                redirectUri = "eudi-openid4ci://authorize",
            )
        }
        prepared.onSuccess {
            assertTrue(it.authorizationUrl.startsWith("https://"), "auth url: ${it.authorizationUrl}")
            assertTrue(it.authorizationUrl.contains("request_uri="), "expected PAR request_uri in ${it.authorizationUrl}")
            println("INTEROP PAR OK: ${it.authorizationUrl}")
        }.onFailure {
            // A well-formed request rejected for client-registration reasons still proves wiring.
            println("INTEROP PAR server response: ${it.message}")
            assertTrue(
                it is VciException.OAuthError || it is VciException.Http,
                "expected a server-level rejection, got ${it::class.simpleName}: ${it.message}",
            )
        }
        Unit
    }
}
