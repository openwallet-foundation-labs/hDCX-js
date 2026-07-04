package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwtTimeValidator
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtVcException
import com.hopae.eudi.wallet.sdjwt.SdJwtVcVerifier
import com.hopae.eudi.wallet.sdjwt.JwtVcMetadataKeyResolver
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class VciE2eTest {

    private val now = 1_700_000_000L
    private fun counterRng(): Rng {
        var n = 0
        return Rng { size -> ByteArray(size) { ((n++ and 0x7f) + 1).toByte() } }
    }

    @Test
    fun preAuthorizedFlowIssuesAndVerifiesSdJwtVc() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)

        // holder keys: one for the credential proof-of-possession, one for DPoP
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val keys = IssuanceKeys(
            proofSigner = SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256),
            proofPublicKey = proofKey.publicKey,
            dpopSigner = SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256),
            dpopPublicKey = dpopKey.publicKey,
        )

        val client = Openid4VciClient(mock, counterRng(), clock = { now })
        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        assertEquals("eu.europa.ec.eudi.pid.1", offer.credentialConfigurationIds.single())
        assertNotNull(offer.txCode)

        val response = client.issueWithPreAuthorizedCode(
            offer = offer,
            configurationId = "eu.europa.ec.eudi.pid.1",
            keys = keys,
            txCode = "1234",
        )

        assertTrue(mock.seenDpopNonceRetry, "DPoP-Nonce retry path must be exercised")
        assertEquals(1, response.credentials.size)
        val credential = response.credentials.single().credential

        // verify the issued SD-JWT VC through the full profile verifier + metadata key resolution
        val verifier = SdJwtVcVerifier(
            issuerKeyResolver = JwtVcMetadataKeyResolver(mock),
            timeValidator = JwtTimeValidator(now = { Instant.ofEpochSecond(now) }),
        )
        val verified = verifier.verify(SdJwt.parse(credential))

        assertEquals("eu.europa.ec.eudi.pid.1", verified.vct)
        assertEquals("https://issuer.example", verified.issuer)
        assertEquals(JsonValue.Str("Doe"), verified.claims["family_name"])
        assertEquals(JsonValue.Str("John"), verified.claims["given_name"])
        assertNotNull(verified.holderKey, "cnf holder key must be present")
        assertEquals(proofKey.publicKey.x.toList(), verified.holderKey!!.x.toList())
    }

    @Test
    fun authorizationCodeFlowWithParIssuesCredential() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val keys = IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
        val client = Openid4VciClient(mock, counterRng(), clock = { now })

        // Step 1: prepare (PAR pushed, authorization URL built)
        val prepared = client.prepareAuthorizationCodeIssuance(
            credentialIssuer = "https://issuer.example",
            configurationId = "eu.europa.ec.eudi.pid.1",
            redirectUri = "wallet://cb",
        )
        assertTrue(mock.seenPar, "PAR endpoint must be used when the AS advertises it")
        assertTrue(prepared.authorizationUrl.startsWith("https://issuer.example/authorize?"))
        assertTrue(prepared.authorizationUrl.contains("request_uri="))

        // Step 2: emulate the browser hitting the authorization URL → redirect carrying the code
        val redirect = mock.execute(
            com.hopae.eudi.wallet.spi.HttpRequest(
                com.hopae.eudi.wallet.spi.HttpMethod.GET, prepared.authorizationUrl,
            )
        )
        assertEquals(302, redirect.status)
        val location = redirect.headers.first { it.first == "Location" }.second
        val code = location.substringAfter("code=").substringBefore('&')

        // Step 3: finish (token via authorization_code + PKCE, then credential)
        val response = client.finishAuthorizationCodeIssuance(prepared, code, keys)
        assertEquals(1, response.credentials.size)

        val verifier = SdJwtVcVerifier(
            JwtVcMetadataKeyResolver(mock),
            JwtTimeValidator(now = { Instant.ofEpochSecond(now) }),
        )
        val verified = verifier.verify(SdJwt.parse(response.credentials.single().credential))
        assertEquals("eu.europa.ec.eudi.pid.1", verified.vct)
        assertEquals(JsonValue.Str("John"), verified.claims["given_name"])
        assertEquals(proofKey.publicKey.x.toList(), verified.holderKey!!.x.toList())
    }

    @Test
    fun expiredCredentialIsRejected(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val keys = IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
        val client = Openid4VciClient(mock, counterRng(), clock = { now })
        val credential = client.issueWithPreAuthorizedCode(
            CredentialOffer.parse(mock.credentialOfferJson), "eu.europa.ec.eudi.pid.1", keys, "1234",
        ).credentials.single().credential

        // verify far in the future → exp exceeded
        val verifier = SdJwtVcVerifier(
            JwtVcMetadataKeyResolver(mock),
            JwtTimeValidator(now = { Instant.ofEpochSecond(now + 200_000) }),
        )
        assertFailsWith<com.hopae.eudi.wallet.sdjwt.JwtTimeException> {
            verifier.verify(SdJwt.parse(credential))
        }
    }

    @Test
    fun txCodeRequiredWhenMissing(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val keys = IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
        val client = Openid4VciClient(mock, counterRng(), clock = { now })
        assertFailsWith<VciException.TxCodeRequired> {
            client.issueWithPreAuthorizedCode(
                CredentialOffer.parse(mock.credentialOfferJson), "eu.europa.ec.eudi.pid.1", keys, txCode = null,
            )
        }
    }

    @Test
    fun unknownConfigurationRejected(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val keys = IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
        val client = Openid4VciClient(mock, counterRng(), clock = { now })
        assertFailsWith<VciException.InvalidOffer> {
            client.issueWithPreAuthorizedCode(
                CredentialOffer.parse(mock.credentialOfferJson), "unknown.config", keys, "1234",
            )
        }
    }
}
