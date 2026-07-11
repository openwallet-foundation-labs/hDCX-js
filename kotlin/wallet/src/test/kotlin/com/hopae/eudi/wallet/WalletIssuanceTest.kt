package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.KeyUse
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.InMemoryStorageDriver
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import com.hopae.eudi.wallet.vci.MockIssuer
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Phase B slice 1: pre-authorized code issuance through the facade session → stored credential. */
class WalletIssuanceTest {

    @Test
    fun preAuthorizedIssuanceStoresCredential() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now = 1_700_000_000L)
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), InMemoryStorageDriver(), mock))

        val offer = wallet.issuance.resolveOffer(mock.credentialOfferJson)
        assertTrue(offer.requiresTxCode)

        val session = wallet.issuance.start(
            IssuanceRequest.fromOffer(offer, "eu.europa.ec.eudi.pid.1", txCode = "1234", policy = CredentialPolicy(batchSize = 2, use = KeyUse.OneTime)),
        )
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is IssuanceState.Completed, "expected Completed, got $terminal")
        val result = (terminal as IssuanceState.Completed).result
        assertEquals(1, result.issued.size)

        // the credential is now stored and visible via the credentials service
        val creds = wallet.credentials.list()
        assertEquals(1, creds.size)
        assertEquals(result.issued.single(), creds.single().id)
        val issued = creds.single().lifecycle as Lifecycle.Issued
        assertEquals(2, issued.instances.remaining, "batchSize=2 → 2 one-time instances")
        assertEquals(KeyUse.OneTime, issued.instances.use)
        assertTrue(issued.claims.any { it.path == listOf("given_name") && it.value.display() == "John" }, "PID given_name")

        // metadata captured at issuance
        val credential = creds.single()
        assertEquals("Hopae Test Issuer", credential.issuer?.displayName)
        assertEquals("Personal ID", credential.display?.name)
        assertEquals("https://logo.example/pid.png", credential.display?.logoUri)
        assertEquals("eu.europa.ec.eudi.pid.1", credential.configurationId)

        // ARF/GDPR audit trail: the issuance was recorded as an ISSUANCE transaction
        val issuanceLog = wallet.transactions.query(type = com.hopae.eudi.wallet.txlog.TransactionType.ISSUANCE)
        assertEquals(1, issuanceLog.size, "one issuance recorded")
        val entry = issuanceLog.single()
        assertEquals(com.hopae.eudi.wallet.txlog.TransactionStatus.SUCCESS, entry.status)
        assertTrue(entry.issuer!!.isNotBlank(), "issuer recorded")
        assertEquals("dc+sd-jwt", entry.documents.single().format, "PID is an SD-JWT VC")

        wallet.close()
    }

    @Test
    fun failedIssuanceRecordsError() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now = 1_700_000_000L)
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), InMemoryStorageDriver(), mock))

        val offer = wallet.issuance.resolveOffer(mock.credentialOfferJson)
        // The mock requires tx_code "1234"; a wrong code fails the token request → the issuance fails.
        val session = wallet.issuance.start(IssuanceRequest.fromOffer(offer, "eu.europa.ec.eudi.pid.1", txCode = "0000"))
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is IssuanceState.Failed, "expected Failed, got $terminal")
        assertEquals(0, wallet.credentials.list().size, "nothing stored on failure")

        // ARF/GDPR: the failed attempt was recorded as an ERROR issuance transaction
        val log = wallet.transactions.query(type = com.hopae.eudi.wallet.txlog.TransactionType.ISSUANCE)
        assertEquals(1, log.size, "one issuance attempt recorded")
        assertEquals(com.hopae.eudi.wallet.txlog.TransactionStatus.ERROR, log.single().status)
        assertTrue(log.single().issuer!!.isNotBlank(), "issuer captured from the offer even on failure")

        wallet.close()
    }

    @Test
    fun authorizationCodeIssuanceWithBrowserStep() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now = 1_700_000_000L)
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), InMemoryStorageDriver(), mock))

        val session = wallet.issuance.start(IssuanceRequest.fromIssuer("https://issuer.example", "eu.europa.ec.eudi.pid.1"))

        // session pauses for the browser step
        val authState = withTimeout(15_000) { session.state.first { it is IssuanceState.AuthorizationRequired || it is IssuanceState.Failed } }
        assertTrue(authState is IssuanceState.AuthorizationRequired, "expected AuthorizationRequired, got $authState")

        // emulate the browser hitting the authorization URL on the mock issuer → redirect carrying the code
        val redirect = mock.execute(HttpRequest(HttpMethod.GET, (authState as IssuanceState.AuthorizationRequired).authorizationUrl))
        val location = redirect.headers.first { it.first == "Location" }.second
        session.completeAuthorization(location)

        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is IssuanceState.Completed, "expected Completed, got $terminal")
        assertEquals(1, wallet.credentials.list().size)
        wallet.close()
    }

    @Test
    fun txCodeSuppliedInteractively() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now = 1_700_000_000L)
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), InMemoryStorageDriver(), mock))

        val offer = wallet.issuance.resolveOffer(mock.credentialOfferJson)
        // no txCode in the request → session must ask for it
        val session = wallet.issuance.start(IssuanceRequest.fromOffer(offer, "eu.europa.ec.eudi.pid.1"))

        val txState = withTimeout(15_000) { session.state.first { it is IssuanceState.TxCodeRequired || it.isTerminal } }
        assertTrue(txState is IssuanceState.TxCodeRequired, "expected TxCodeRequired, got $txState")

        // §4.1.1: the input hints reach the host so it can render + warn (advisory, never blocking).
        val spec = txState.txCode
        assertEquals(4, spec?.length)
        assertEquals("numeric", spec?.inputMode)
        assertTrue(spec!!.validate("12").any { "4 characters" in it }, "short code warns")
        assertTrue(spec.validate("abcd").any { "digits" in it }, "non-numeric warns")
        assertTrue(spec.validate("1234").isEmpty(), "a conformant code is clean")

        session.submitTxCode("1234")

        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is IssuanceState.Completed, "expected Completed, got $terminal")
        assertEquals(1, wallet.credentials.list().size)
        wallet.close()
    }

    private suspend fun IssuanceSession.awaitTerminal(): IssuanceState = withTimeout(15_000) { state.first { it.isTerminal } }

    /**
     * OpenID4VCI §9.2 deferred issuance: an unready issuer defers (HTTP 202 + interval + transaction_id).
     * The wallet reports Deferred with the retry instant — not a failure — and resuming after a still-
     * deferred response reports Deferred again, until the credential is finally issued.
     */
    @Test
    fun deferredIssuanceReportsDeferredUntilReady() = runBlocking {
        val now = 1_700_000_000L
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now = now).apply { deferMode = true }
        val fixedClock = com.hopae.eudi.wallet.spi.WalletClock { java.time.Instant.ofEpochSecond(now) }
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), InMemoryStorageDriver(), mock, clock = fixedClock))

        val offer = wallet.issuance.resolveOffer(mock.credentialOfferJson)

        // start: the issuer defers immediately (interval 300 → retryAfter = now + 300s), not Completed.
        val started = wallet.issuance.start(IssuanceRequest.fromOffer(offer, "eu.europa.ec.eudi.pid.1", txCode = "1234")).awaitTerminal()
        assertTrue(started is IssuanceState.Deferred, "expected Deferred, got $started")
        val id = started.credentialId
        assertEquals(java.time.Instant.ofEpochSecond(now + 300), started.retryAfter)
        assertTrue(wallet.credentials.get(id)!!.lifecycle is Lifecycle.Deferred, "credential is deferred")

        // first poll: still deferred (interval 42 → fresh retryAfter), still Deferred not Failed.
        val t1 = wallet.issuance.resumeDeferred(id).awaitTerminal()
        assertTrue(t1 is IssuanceState.Deferred, "expected Deferred, got $t1")
        assertEquals(java.time.Instant.ofEpochSecond(now + 42), t1.retryAfter)

        // second poll: ready
        val t2 = wallet.issuance.resumeDeferred(id).awaitTerminal()
        assertTrue(t2 is IssuanceState.Completed, "expected Completed, got $t2")
        assertTrue(wallet.credentials.get(id)!!.lifecycle is Lifecycle.Issued, "credential now issued")
        wallet.close()
    }

    @Test
    fun reissueRenewsCredential() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now = 1_700_000_000L)
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), InMemoryStorageDriver(), mock))

        val offer = wallet.issuance.resolveOffer(mock.credentialOfferJson)
        val id = (wallet.issuance.start(IssuanceRequest.fromOffer(offer, "eu.europa.ec.eudi.pid.1", txCode = "1234")).awaitTerminal() as IssuanceState.Completed).result.issued.single()

        val renewed = wallet.issuance.reissue(id).awaitTerminal()
        assertTrue(renewed is IssuanceState.Completed, "reissue: $renewed")
        assertEquals(id, renewed.result.issued.single(), "renewed in place")
        assertEquals(1, wallet.credentials.list().size, "not duplicated")
        wallet.close()
    }

    @Test
    fun issuanceNotifiesIssuer() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now = 1_700_000_000L)
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), InMemoryStorageDriver(), mock))

        val offer = wallet.issuance.resolveOffer(mock.credentialOfferJson)
        wallet.issuance.start(IssuanceRequest.fromOffer(offer, "eu.europa.ec.eudi.pid.1", txCode = "1234")).awaitTerminal()

        assertEquals("n-1" to "credential_accepted", mock.seenNotification)
        wallet.close()
    }
}
