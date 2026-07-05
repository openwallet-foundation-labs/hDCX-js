package com.hopae.eudi.wallet.spi

/** Encrypted blob storage; no domain logic. */
interface StorageDriver {
    suspend fun put(collection: String, key: String, value: ByteArray)
    suspend fun get(collection: String, key: String): ByteArray?
    suspend fun delete(collection: String, key: String)
    suspend fun keys(collection: String): List<String>
    suspend fun transaction(block: suspend StorageTx.() -> Unit)
}

interface StorageTx {
    suspend fun put(collection: String, key: String, value: ByteArray)
    suspend fun get(collection: String, key: String): ByteArray?
    suspend fun delete(collection: String, key: String)
}

enum class HttpMethod { GET, POST, PUT, PATCH, DELETE }

class HttpRequest(
    val method: HttpMethod,
    val url: String,
    val headers: List<Pair<String, String>> = emptyList(),
    val body: ByteArray? = null,
    /** OpenID flows need redirect interception (e.g. capturing authorization responses). */
    val followRedirects: Boolean = true,
)

class HttpResponse(
    val status: Int,
    val headers: List<Pair<String, String>>,
    val body: ByteArray,
)

interface HttpTransport {
    suspend fun execute(request: HttpRequest): HttpResponse
}

// ISO 18013-5 proximity transport is the ProximityTransport port (send/receive/close).

/** Wallet-provider backend port: WUA and key attestations (HAIP wallet attestation). */
interface WalletAttestationProvider {
    suspend fun walletAttestation(keyInfo: KeyInfo): String
    suspend fun keyAttestation(keys: List<KeyInfo>, nonce: String?): String
}
