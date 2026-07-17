package com.hopae.eudi.demo

import android.content.Context
import android.util.Base64
import com.hopae.eudi.demo.adapters.LogWalletLogger
import com.hopae.eudi.wallet.android.AndroidKeystoreSecureArea
import com.hopae.eudi.wallet.android.EncryptedFileStorageDriver
import com.hopae.eudi.wallet.android.FileTransactionLogStore
import com.hopae.eudi.wallet.android.OkHttpTransport
import com.hopae.eudi.wallet.android.attestation.DevIntegrityTokenProvider
import com.hopae.eudi.wallet.android.attestation.PlayIntegrityTokenProvider
import com.hopae.eudi.wallet.android.attestation.WalletProviderAttestation
import com.hopae.eudi.wallet.IssuanceConfig
import com.hopae.eudi.wallet.TransactionLogConfig
import com.hopae.eudi.wallet.TrustConfig
import com.hopae.eudi.wallet.Wallet
import com.hopae.eudi.wallet.WalletConfig
import com.hopae.eudi.wallet.WalletPorts
import com.hopae.eudi.wallet.cbor.cose.CoseAlgorithm
import com.hopae.eudi.wallet.cbor.cose.CoseSigner
import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.mdoc.ReaderAuthSigner
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm
import com.hopae.eudi.wallet.spi.curve
import com.hopae.eudi.wallet.trustlist.TrustedListClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec

/**
 * Assembles the EUDI Wallet SDK with Android debug-grade adapters — one instance per app process.
 *
 * Trust: on first assembly the wallet pulls its CA anchors from the sandbox JAdES **trusted lists** (verified
 * against the pinned Scheme Operator cert) into [TrustConfig], so it can actually verify our issuer (credential
 * DSC / signed metadata), verifier (WRPAC + WRPRC), and registrar (WRPRC status, TS5 registry). Without these
 * anchors the wallet can hold credentials but cannot establish trust — so [get] is `suspend` (one network
 * fetch at startup).
 *
 * Debug notes:
 *  - [AndroidKeystoreSecureArea] holds hardware-bound holder keys that persist across restarts.
 *  - [EncryptedFileStorageDriver] encrypts credentials at rest under a hardware-bound Keystore key
 *    (the iOS keychain equivalent). Swap in `FileStorageDriver` for plain-file, debug-only storage.
 */
object DemoWallet {
    /** Base of the sandbox JAdES trusted lists (our Scheme Operator). */
    private const val TL_BASE = "https://trusted-list.vercel.app/tl"

    /** Our Wallet Provider backend (client-auth WUA + key attestation). */
    private const val WP_BASE = "https://dev.api.hopae.com/wp"

    /** Google Cloud project number for Play Integrity (sideloaded debug falls back to the dev token). */
    private const val PLAY_INTEGRITY_PROJECT = 1_048_824_403_731L

    /** Wallet client_id — must equal [IssuanceConfig.clientId] so the WUA `sub` matches at the issuer. */
    private const val CLIENT_ID = "wallet-dev"

    @Volatile private var instance: Wallet? = null
    private val buildLock = Mutex()

    /** Persistent transaction-log store — exposed so the UI can clear it. */
    lateinit var transactionStore: FileTransactionLogStore
        private set

    /** The assembled wallet, building (and fetching trust anchors) on first call. Cached thereafter. */
    suspend fun get(context: Context): Wallet =
        instance ?: buildLock.withLock {
            // build() does network (trusted lists) + disk I/O on first call → keep it off the main thread.
            instance ?: withContext(Dispatchers.IO) { build(context.applicationContext) }.also { instance = it }
        }

    /** How long a cached trusted-list snapshot is used before a re-fetch is attempted. */
    private const val TRUST_TTL_MS = 24L * 60 * 60 * 1000

    private suspend fun build(context: Context): Wallet {
        val filesDir = context.filesDir
        val logsDir = File(filesDir, "logs").apply { mkdirs() }
        LogStore.attach(File(logsDir, "debug.log"))
        transactionStore = FileTransactionLogStore(File(logsDir, "transactions.log"))
        val logger = LogWalletLogger() // routes SDK + adapter logs into the in-app LogStore
        val http = OkHttpTransport(logger = logger)
        val secureArea = AndroidKeystoreSecureArea()
        val storage = EncryptedFileStorageDriver(File(filesDir, "wallet"))

        val trust = resolveTrust(http, File(filesDir, "trust"))
        // Reader-auth identity for the Read-mDL role — the demo reuses the verifier's WRPAC (chains to the
        // registrar CA, which holders trust as a reader anchor). Optional: absent asset → no reader auth.
        val readerAuth = loadReaderAuth(context)

        // Wallet Provider backend: gives the client-auth WUA (attest_jwt_client_auth) and the per-issuance
        // key attestation the issuer requires for PID. Play Integrity attests the instance, falling back to the
        // dev token when side-loaded. The instance registration id is persisted via [storage].
        val walletAttestation = WalletProviderAttestation(
            baseUrl = WP_BASE,
            http = http,
            secureArea = secureArea,
            integrity = PlayIntegrityTokenProvider(context, PLAY_INTEGRITY_PROJECT, fallback = DevIntegrityTokenProvider(), logger = logger),
            clientId = CLIENT_ID,
            storage = storage,
        )

        return Wallet.create(
            config = WalletConfig(
                trust = trust,
                // Authorization-code redirect — matches the EUDI reference wallet's scheme.
                issuance = IssuanceConfig(clientId = CLIENT_ID, redirectUri = "eu.europa.ec.euidi://authorization"),
                // Debug wallet: also log presentations that fail at final submission (opt-in).
                transactionLog = TransactionLogConfig(recordFailures = true),
                readerAuth = readerAuth,
            ),
            ports = WalletPorts(
                secureAreas = listOf(secureArea),
                storage = storage,
                http = http,
                logger = logger,
                transactionLogStore = transactionStore,
                walletAttestation = walletAttestation,
            ),
        ).also {
            LogStore.log(
                "Wallet assembled — trust anchors: issuer=${trust.issuerAnchorsDer.size} " +
                    "reader=${trust.readerAnchorsDer.size} registrar=${trust.registrarAnchorsDer.size}",
            )
        }
    }

    /**
     * The trust anchors, from disk when a cached snapshot is still fresh ([TRUST_TTL_MS]) — instant + offline —
     * otherwise re-fetched from the trusted lists and re-cached. On a fetch failure we fall back to a stale
     * cache if one exists (so a server outage / no network doesn't strip the wallet of trust). Only the
     * extracted CA DERs are kept (a few small certs), never the list JSON.
     */
    private suspend fun resolveTrust(http: HttpTransport, cacheDir: File): TrustConfig {
        loadCachedTrust(cacheDir)?.let { (cached, ageMs) ->
            if (ageMs < TRUST_TTL_MS) {
                LogStore.log("trusted-list: using cached anchors (age ${ageMs / 1000}s)")
                return cached
            }
        }
        val fetched = fetchTrust(http)
        if (fetched.issuerAnchorsDer.isNotEmpty() || fetched.registrarAnchorsDer.isNotEmpty()) {
            saveCachedTrust(cacheDir, fetched)
            return fetched
        }
        // Fetch yielded nothing (offline / outage): keep using a stale cache if we have one.
        return loadCachedTrust(cacheDir)?.first?.also { LogStore.log("trusted-list: fetch failed, using stale cache") }
            ?: TrustConfig()
    }

    /** Pull the CA anchors from the trusted lists (best-effort per list). */
    private suspend fun fetchTrust(http: HttpTransport): TrustConfig {
        val tl = TrustedListClient(http)
        val soDer = runCatching { pemToDer(fetchText(http, "$TL_BASE/scheme-operator.pem")) }
            .onFailure { LogStore.log("trusted-list: scheme-operator fetch failed (${it.message})") }
            .getOrNull() ?: return TrustConfig()

        suspend fun anchors(slug: String): List<ByteArray> =
            runCatching { tl.fetchCACerts("$TL_BASE/$slug.jades.json", soDer) }
                .onFailure { LogStore.log("trusted-list: '$slug' fetch failed: ${it.message}") }
                .getOrDefault(emptyList())

        // issued credentials chain to the PID + attestation issuer CAs; the verifier's WRPAC (and its WRPRC /
        // status list / TS5 registry) chain to the registrar CA.
        val issuerCAs = anchors("pid-issuers") + anchors("attestation-issuers")
        val registrarCAs = anchors("registrar")
        return TrustConfig(
            issuerAnchorsDer = issuerCAs,
            readerAnchorsDer = registrarCAs,
            registrarAnchorsDer = registrarCAs,
        )
    }

    // --- disk cache: <cacheDir>/{fetchedAt, issuer/*.der, registrar/*.der} ---------------------------------

    private fun loadCachedTrust(cacheDir: File): Pair<TrustConfig, Long>? {
        val stamp = File(cacheDir, "fetchedAt").takeIf { it.exists() }?.readText()?.trim()?.toLongOrNull() ?: return null
        fun ders(sub: String): List<ByteArray> =
            File(cacheDir, sub).listFiles { f -> f.extension == "der" }?.sortedBy { it.name }?.map { it.readBytes() } ?: emptyList()
        val issuer = ders("issuer")
        val registrar = ders("registrar")
        if (issuer.isEmpty() && registrar.isEmpty()) return null
        val trust = TrustConfig(issuerAnchorsDer = issuer, readerAnchorsDer = registrar, registrarAnchorsDer = registrar)
        return trust to (System.currentTimeMillis() - stamp)
    }

    private fun saveCachedTrust(cacheDir: File, trust: TrustConfig) = runCatching {
        fun write(sub: String, ders: List<ByteArray>) {
            val dir = File(cacheDir, sub).apply { deleteRecursively(); mkdirs() }
            ders.forEachIndexed { i, der -> File(dir, "%03d.der".format(i)).writeBytes(der) }
        }
        cacheDir.mkdirs()
        write("issuer", trust.issuerAnchorsDer)
        write("registrar", trust.registrarAnchorsDer) // == readerAnchorsDer
        File(cacheDir, "fetchedAt").writeText(System.currentTimeMillis().toString())
    }.onFailure { LogStore.log("trusted-list: cache write failed: ${it.message}") }

    private suspend fun fetchText(http: HttpTransport, url: String): String {
        val resp = http.execute(HttpRequest(HttpMethod.GET, url, listOf("Accept" to "*/*")))
        if (resp.status !in 200..299) throw IllegalStateException("HTTP ${resp.status} for $url")
        return resp.body.decodeToString()
    }

    /**
     * The demo's ISO 18013-5 reader-auth identity, loaded from a gitignored `reader_wrpac.json` asset
     * ({privateKeyPem, certPem, caCertPem} — the verifier's WRPAC, which chains to the registrar CA). Absent
     * asset → null (Read mDL requests carry no reader auth; holders show the reader as unverified).
     */
    private fun loadReaderAuth(context: Context): ReaderAuthSigner? = runCatching {
        val json = context.assets.open("reader_wrpac.json").bufferedReader().use { it.readText() }
        val o = JSONObject(json)
        val x5c = listOf(pemToDer(o.getString("certPem")), pemToDer(o.getString("caCertPem")))
        val signer = PemEcCoseSigner(o.getString("privateKeyPem"))
        LogStore.log("Reader-auth identity loaded — Read mDL signs its requests")
        ReaderAuthSigner(signer, x5c, SigningAlgorithm.ES256)
    }.getOrElse {
        LogStore.log("Reader-auth identity not configured (reader_wrpac.json absent) — reads are unauthenticated")
        null
    }

    private fun pemToDer(pem: String): ByteArray = Base64.decode(
        pem.replace(Regex("-----(BEGIN|END) CERTIFICATE-----"), "").replace(Regex("\\s"), ""),
        Base64.DEFAULT,
    )

    /** COSE ES256 signer over an embedded PKCS#8 EC private key — the demo reader's WRPAC key. */
    private class PemEcCoseSigner(privateKeyPem: String) : CoseSigner {
        private val key: PrivateKey = KeyFactory.getInstance("EC").generatePrivate(
            PKCS8EncodedKeySpec(
                Base64.decode(privateKeyPem.replace(Regex("-----(BEGIN|END) PRIVATE KEY-----"), "").replace(Regex("\\s"), ""), Base64.DEFAULT),
            ),
        )
        override val algorithm: CoseAlgorithm = SigningAlgorithm.ES256.coseAlgorithm
        override suspend fun sign(toBeSigned: ByteArray): ByteArray {
            val der = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(toBeSigned); sign() }
            return Der.derSignatureToRaw(der, SigningAlgorithm.ES256.curve.coordinateSize)
        }
    }
}
