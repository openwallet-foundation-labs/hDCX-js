package com.hopae.eudi.wallet.proximity

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseKey
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey

private const val TAG_ENCODED_CBOR: ULong = 24u

/**
 * The mdoc proximity `SessionTranscript` (ISO/IEC 18013-5 §9.1.5.1):
 * `[DeviceEngagementBytes, EReaderKeyBytes, Handover]`, where the first two are `#6.24(bstr)`
 * and Handover is `null` for QR-code engagement. Also builds a minimal QR `DeviceEngagement`.
 */
object ProximitySessionTranscript {

    fun build(deviceEngagement: ByteArray, eReaderKey: EcPublicKey, handover: Cbor = Cbor.Null): Cbor {
        val deviceEngagementBytes = Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(deviceEngagement))
        val eReaderKeyBytes = Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(CoseKey.encode(eReaderKey))))
        return Cbor.Array(listOf(deviceEngagementBytes, eReaderKeyBytes, handover))
    }

    /** SessionTranscript bytes fed to session-key derivation (HKDF salt = SHA-256 of these). */
    fun encode(sessionTranscript: Cbor): ByteArray = CborEncoder.encode(sessionTranscript)
}

/** A minimal QR-code `DeviceEngagement` (ISO/IEC 18013-5 §8.2.1.1): version + EDeviceKey. */
object DeviceEngagement {

    fun qr(eDeviceKey: EcPublicKey, retrievalMethods: List<ByteArray> = emptyList()): ByteArray {
        val eDeviceKeyBytes = Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(CoseKey.encode(eDeviceKey))))
        val security = Cbor.Array(listOf(Cbor.int(1), eDeviceKeyBytes)) // [cipher-suite 1, EDeviceKeyBytes]
        val entries = mutableListOf<Pair<Cbor, Cbor>>(
            Cbor.int(0) to Cbor.Text("1.0"), // version
            Cbor.int(1) to security,          // Security
        )
        if (retrievalMethods.isNotEmpty()) { // DeviceRetrievalMethods (ISO 18013-5 §8.2.1.1 key 2)
            entries.add(Cbor.int(2) to Cbor.Array(retrievalMethods.map { CborDecoder.decode(it) }))
        }
        return CborEncoder.encode(Cbor.CborMap(entries))
    }

    /**
     * An ISO/IEC 18013-5 §8.3.3.1.1 BLE **mdoc peripheral server mode** `DeviceRetrievalMethod`:
     * `[2, 1, {0: true, 10: <16-byte service UUID>}]`. Advertise it in [qr] so the reader connects over BLE.
     */
    fun bleRetrievalMethod(serviceUuid: ByteArray): ByteArray = CborEncoder.encode(
        Cbor.Array(
            listOf(
                Cbor.int(2), Cbor.int(1), // type 2 = BLE, version 1
                Cbor.CborMap(listOf(Cbor.int(0) to Cbor.Bool(true), Cbor.int(10) to Cbor.Bytes(serviceUuid))),
            ),
        ),
    )

    /** The BLE peripheral-server-mode service UUID (16 bytes) from a QR `DeviceEngagement`, or null — the reader side. */
    fun parseBleUuid(engagement: ByteArray): ByteArray? {
        val map = CborDecoder.decode(engagement) as? Cbor.CborMap ?: return null
        val methods = map.entries.firstOrNull { (k, _) -> (k as? Cbor.UInt)?.value == 2uL }?.second as? Cbor.Array ?: return null
        for (m in methods.items) {
            val arr = m as? Cbor.Array ?: continue
            if ((arr.items.getOrNull(0) as? Cbor.UInt)?.value != 2uL) continue // BLE
            val opts = arr.items.getOrNull(2) as? Cbor.CborMap ?: continue
            (opts.entries.firstOrNull { (k, _) -> (k as? Cbor.UInt)?.value == 10uL }?.second as? Cbor.Bytes)?.let { return it.value }
        }
        return null
    }

    /** Extracts the mdoc's ephemeral public key (EDeviceKey) from a QR `DeviceEngagement` — the reader side. */
    fun parseEDeviceKey(engagement: ByteArray): EcPublicKey {
        val map = CborDecoder.decode(engagement) as? Cbor.CborMap ?: throw ProximityException("DeviceEngagement must be a map")
        val security = map.entries.firstOrNull { (k, _) -> (k as? Cbor.UInt)?.value == 1uL }?.second as? Cbor.Array
            ?: throw ProximityException("missing Security")
        val eDeviceKeyBytes = security.items.getOrNull(1) as? Cbor.Tagged ?: throw ProximityException("missing EDeviceKeyBytes")
        val coseKey = CborDecoder.decode((eDeviceKeyBytes.value as Cbor.Bytes).value) as? Cbor.CborMap
            ?: throw ProximityException("EDeviceKey not a COSE_Key")
        return CoseKey.decode(coseKey)
    }
}
