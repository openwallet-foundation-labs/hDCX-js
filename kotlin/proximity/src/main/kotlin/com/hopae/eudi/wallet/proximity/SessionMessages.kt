package com.hopae.eudi.wallet.proximity

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseKey
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey

/**
 * ISO/IEC 18013-5 device-retrieval message framing (§9.1.1):
 *  - `SessionEstablishment = {"eReaderKey": EReaderKeyBytes, "data": <encrypted DeviceRequest>}`
 *  - `SessionData = {"data": <encrypted DeviceResponse>, "status": uint?}`
 *
 * The encrypted `data` payloads are produced/consumed by [SessionEncryption]; this only wraps them.
 */
object SessionMessages {
    private const val TAG_ENCODED_CBOR = 24uL

    fun encodeEstablishment(eReaderKey: EcPublicKey, encryptedDeviceRequest: ByteArray): ByteArray {
        val eReaderKeyBytes = Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(CoseKey.encode(eReaderKey))))
        return CborEncoder.encode(
            Cbor.CborMap(
                listOf(
                    Cbor.Text("eReaderKey") to eReaderKeyBytes,
                    Cbor.Text("data") to Cbor.Bytes(encryptedDeviceRequest),
                ),
            ),
        )
    }

    fun decodeEstablishment(bytes: ByteArray): SessionEstablishment {
        val map = CborDecoder.decode(bytes).asMap("SessionEstablishment")
        val tagged = map.field("eReaderKey") as? Cbor.Tagged ?: throw ProximityException("missing eReaderKey")
        val eReaderKey = CoseKey.decode(CborDecoder.decode((tagged.value as Cbor.Bytes).value).asMap("EReaderKey"))
        val data = (map.field("data") as? Cbor.Bytes)?.value ?: throw ProximityException("missing data")
        return SessionEstablishment(eReaderKey, data)
    }

    fun encodeData(encryptedDeviceResponse: ByteArray, status: Long? = null): ByteArray {
        val entries = buildList {
            add(Cbor.Text("data") to Cbor.Bytes(encryptedDeviceResponse))
            if (status != null) add(Cbor.Text("status") to Cbor.int(status))
        }
        return CborEncoder.encode(Cbor.CborMap(entries))
    }

    fun decodeData(bytes: ByteArray): ByteArray {
        val map = CborDecoder.decode(bytes).asMap("SessionData")
        return (map.field("data") as? Cbor.Bytes)?.value ?: throw ProximityException("missing data")
    }

    private fun Cbor.asMap(what: String): Cbor.CborMap =
        this as? Cbor.CborMap ?: throw ProximityException("$what must be a map")

    private fun Cbor.CborMap.field(key: String): Cbor? =
        entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == key }?.second
}

class SessionEstablishment(val eReaderKey: EcPublicKey, val encryptedDeviceRequest: ByteArray)
