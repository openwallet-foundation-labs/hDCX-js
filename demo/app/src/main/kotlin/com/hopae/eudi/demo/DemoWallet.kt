package com.hopae.eudi.demo

import android.content.Context
import com.hopae.eudi.demo.adapters.AndroidKeystoreSecureArea
import com.hopae.eudi.demo.adapters.FileStorageDriver
import com.hopae.eudi.demo.adapters.FileTransactionLogStore
import com.hopae.eudi.demo.adapters.LogWalletLogger
import com.hopae.eudi.demo.adapters.OkHttpTransport
import com.hopae.eudi.wallet.IssuanceConfig
import com.hopae.eudi.wallet.TransactionLogConfig
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.WalletConfig
import com.hopae.eudi.wallet.WalletPorts
import java.io.File

/**
 * Assembles the EUDI Wallet SDK with Android debug-grade adapters — one instance per app process.
 *
 * Debug notes:
 *  - [AndroidKeystoreSecureArea] holds hardware-bound holder keys that persist across restarts, so a
 *    credential issued in one session can still be presented after a restart.
 *  - [FileStorageDriver] persists credentials as plain files; production should encrypt at rest.
 *  - Debug log and transaction log are persisted to files under `filesDir/logs`.
 */
object DemoWallet {
    @Volatile private var instance: Wallet? = null

    /** Persistent transaction-log store — exposed so the UI can clear it. */
    lateinit var transactionStore: FileTransactionLogStore
        private set

    fun get(context: Context): Wallet = instance ?: synchronized(this) {
        instance ?: run {
            val filesDir = context.applicationContext.filesDir
            val logsDir = File(filesDir, "logs").apply { mkdirs() }
            LogStore.attach(File(logsDir, "debug.log"))
            transactionStore = FileTransactionLogStore(File(logsDir, "transactions.log"))
            Wallet.create(
                config = WalletConfig(
                    // Authorization-code redirect — matches the EUDI reference wallet's scheme.
                    issuance = IssuanceConfig(redirectUri = "eu.europa.ec.euidi://authorization"),
                    // Debug wallet: also log presentations that fail at final submission (opt-in).
                    transactionLog = TransactionLogConfig(recordFailures = true),
                ),
                ports = WalletPorts(
                    secureAreas = listOf(AndroidKeystoreSecureArea()),
                    storage = FileStorageDriver(File(filesDir, "wallet")),
                    http = OkHttpTransport(),
                    logger = LogWalletLogger(),
                    transactionLogStore = transactionStore,
                ),
            ).also {
                instance = it
                LogStore.log("Wallet assembled (AndroidKeystore · FileStorageDriver · OkHttp · persistent txlog)")
            }
        }
    }
}
