package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** HAIP tail: deferred issuance (§9) and issuance notifications (§10). */
class DeferredNotificationTest {

    private val now = 1_700_000_000L
    private fun rng() = Rng { size -> ByteArray(size) { (it + 1).toByte() } }

    private suspend fun keys(area: SoftwareSecureArea): IssuanceKeys {
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        return IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
    }

    @Test
    fun deferredIssuancePollsUntilReady() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now).apply { deferMode = true }
        val keys = keys(area)
        val client = Openid4VciClient(mock, rng(), clock = { now })

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        val deferred = client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys, txCode = "1234")

        assertTrue(deferred.isDeferred, "issuer deferred issuance")
        assertEquals(0, deferred.credentials.size)
        assertNotNull(deferred.transactionId)

        // first poll: not ready yet
        assertFailsWith<VciException.IssuancePending> { client.fetchDeferredCredential(deferred, keys) }
        // second poll: credential is ready
        val ready = client.fetchDeferredCredential(deferred, keys)
        assertEquals(1, ready.credentials.size)
    }

    @Test
    fun issuanceNotificationSent() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        val keys = keys(area)
        val client = Openid4VciClient(mock, rng(), clock = { now })

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        val response = client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys, txCode = "1234")
        assertEquals(1, response.credentials.size)
        assertEquals("n-1", response.notificationId)

        client.sendNotification(response, NotificationEvent.CREDENTIAL_ACCEPTED, keys)
        assertEquals("n-1" to "credential_accepted", mock.seenNotification)
    }
}
