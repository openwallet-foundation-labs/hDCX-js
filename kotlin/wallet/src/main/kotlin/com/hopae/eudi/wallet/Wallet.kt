package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.status.StatusListClient
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.trust.TrustAnchorSource
import com.hopae.eudi.wallet.trust.TrustAnchors
import com.hopae.eudi.wallet.trust.X509ChainValidator
import com.hopae.eudi.wallet.trust.X5cIssuerKeyResolver

/**
 * The unified EUDI Wallet SDK facade (API-CONTRACT.md §5). Multi-instance, thread-safe; no global
 * state. [close] is idempotent.
 *
 * Phase A wires credential storage, DCQL retrieval, and status; issuance/presentation/proximity follow.
 */
class Wallet private constructor(
    val credentials: CredentialsService,
    private val ports: WalletPorts,
) : AutoCloseable {

    @Volatile
    private var closed = false

    override fun close() {
        closed = true
    }

    companion object {
        fun create(config: WalletConfig, ports: WalletPorts): Wallet {
            val clock: () -> Long = { ports.clock.now().epochSecond }
            val store = CredentialStore(ports.storage)

            // Trust fan-out (Phase A: issuer anchors → status-token signature verification).
            // Lazy source: anchors are only required when a status token is actually fetched/verified,
            // so a wallet without configured anchors can still read credentials with no status reference.
            val issuerAnchors = TrustAnchorSource {
                require(config.trust.issuerAnchorsDer.isNotEmpty()) { "no issuer trust anchors configured for status verification" }
                TrustAnchors.ofDer(config.trust.issuerAnchorsDer)
            }
            val issuerValidator = X509ChainValidator(issuerAnchors, at = { java.util.Date.from(ports.clock.now()) })
            val statusClient = StatusListClient(ports.http, X5cIssuerKeyResolver(issuerValidator), clock)

            return Wallet(
                credentials = CredentialsService(store, statusClient),
                ports = ports,
            )
        }
    }
}
