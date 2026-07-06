package com.hopae.eudi.wallet.spi

/**
 * Duplex message channel to an in-person reader for ISO 18013-5 proximity presentation. The host
 * implements it over BLE / NFC / Wi-Fi Aware; the SDK drives the device-retrieval message exchange.
 */
interface ProximityTransport {
    /** Sends one framed message (e.g. SessionData) to the reader. */
    suspend fun send(message: ByteArray)

    /** Suspends until the reader delivers the next framed message (e.g. SessionEstablishment). */
    suspend fun receive(): ByteArray

    /** Tears down the transport; idempotent. */
    suspend fun close()

    /**
     * ISO 18013-5 `DeviceRetrievalMethod` entries (CBOR-encoded) this transport advertises, embedded into the QR
     * `DeviceEngagement` so the reader knows how to connect (e.g. the BLE service UUID). Empty = engagement carries none.
     */
    fun retrievalMethods(): List<ByteArray> = emptyList()
}
