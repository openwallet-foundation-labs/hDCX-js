package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.status.StatusListClient
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.trust.TrustAnchorSource
import com.hopae.eudi.wallet.trust.TrustAnchors
import com.hopae.eudi.wallet.trust.X509ChainValidator
import com.hopae.eudi.wallet.trust.X509RequestVerifier
import com.hopae.eudi.wallet.trust.X5cIssuerKeyResolver
import com.hopae.eudi.wallet.trust.X5cMdocReaderTrust
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.txlog.TransactionLog
import com.hopae.eudi.wallet.vci.Openid4VciClient
import com.hopae.eudi.wallet.vp.Openid4VpClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

/**
 * The unified EUDI Wallet SDK facade (API-CONTRACT.md §5). Multi-instance, thread-safe; no global
 * state. [close] cancels in-flight sessions and is idempotent.
 *
 * Phases A–C wire credential storage, DCQL retrieval, status, issuance, and remote presentation; proximity follows.
 */
class Wallet private constructor(
    val credentials: CredentialsService,
    val issuance: IssuanceService,
    val presentation: PresentationService,
    val proximity: ProximityService,
    /** Audit history of presentations/issuances (ARF/GDPR) — query with [TransactionLog.history]/[TransactionLog.query]. */
    val transactions: TransactionLog,
    private val scope: CoroutineScope,
) : AutoCloseable {

    @Volatile
    private var closed = false

    override fun close() {
        if (closed) return
        closed = true
        scope.cancel()
    }

    companion object {
        fun create(config: WalletConfig, ports: WalletPorts): Wallet {
            val clockSeconds: () -> Long = { ports.clock.now().epochSecond }
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val store = CredentialStore(ports.storage)

            // Lazy issuer anchors: only required when a status token is actually verified.
            val issuerAnchors = TrustAnchorSource {
                require(config.trust.issuerAnchorsDer.isNotEmpty()) { "no issuer trust anchors configured for status verification" }
                TrustAnchors.ofDer(config.trust.issuerAnchorsDer)
            }
            val issuerValidator = X509ChainValidator(issuerAnchors, at = { java.util.Date.from(ports.clock.now()) })
            val statusClient = StatusListClient(ports.http, X5cIssuerKeyResolver(issuerValidator), clockSeconds)

            val vci = Openid4VciClient(ports.http, ports.rng, clockSeconds, config.issuance.clientId)
            val issuance = IssuanceService(vci, store, ports.storage, ports.defaultSecureArea, scope, ports.rng, ports.clock, config.issuance.redirectUri)

            // Reader trust: one validator over the configured reader anchors, shared by remote (signed OpenID4VP
            // request objects) and proximity (mdoc reader authentication). No anchors → readers stay untrusted.
            val readerValidator = config.trust.readerAnchorsDer.takeIf { it.isNotEmpty() }?.let { anchors ->
                X509ChainValidator(TrustAnchorSource { TrustAnchors.ofDer(anchors) }, at = { java.util.Date.from(ports.clock.now()) })
            }
            val vp = Openid4VpClient(ports.http, clockSeconds, readerValidator?.let { X509RequestVerifier(it) })
            val txlog = TransactionLog(
                store = ports.transactionLogStore,
                idGenerator = { "txn-" + Base64Url.encode(ports.rng.nextBytes(12)) },
                clock = clockSeconds,
            )
            val presentation = PresentationService(vp, store, txlog, ports.secureAreas, scope)
            val proximity = ProximityService(store, txlog, ports.secureAreas, scope, readerValidator?.let { X5cMdocReaderTrust(it) })

            return Wallet(
                credentials = CredentialsService(store, statusClient),
                issuance = issuance,
                presentation = presentation,
                proximity = proximity,
                transactions = txlog,
                scope = scope,
            )
        }
    }
}
