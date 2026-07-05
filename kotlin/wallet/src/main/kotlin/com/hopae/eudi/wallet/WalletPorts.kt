package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.spi.WalletAttestationProvider
import com.hopae.eudi.wallet.spi.WalletClock
import com.hopae.eudi.wallet.spi.WalletLogger
import com.hopae.eudi.wallet.txlog.InMemoryTransactionLogStore
import com.hopae.eudi.wallet.txlog.TransactionLogStore

/**
 * Host-supplied adapters. The SDK owns credential/key/attestation lifecycle; the app injects thin
 * platform capabilities.
 */
class WalletPorts(
    /** At least one; the first is the default secure area. */
    val secureAreas: List<SecureArea>,
    val storage: StorageDriver,
    val http: HttpTransport,
    /** Wallet Provider backend link (WUA). Required for attestation-based client auth. */
    val walletAttestation: WalletAttestationProvider? = null,
    val clock: WalletClock = WalletClock.System,
    val rng: Rng = Rng.Default,
    val logger: WalletLogger? = null,
    /** Append-only persistence for the audit log (ARF/GDPR). Defaults to in-memory; production wallets persist. */
    val transactionLogStore: TransactionLogStore = InMemoryTransactionLogStore(),
) {
    init {
        require(secureAreas.isNotEmpty()) { "WalletPorts requires at least one SecureArea" }
    }

    val defaultSecureArea: SecureArea get() = secureAreas.first()
}
