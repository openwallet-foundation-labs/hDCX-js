package com.hopae.eudi.wallet.proximity

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.Hkdf
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

    /**
     * The NFC `Handover` for the SessionTranscript (ISO 18013-5 §9.1.5.1):
     * `[HandoverSelectMessage, HandoverRequestMessage / null]`. Static handover passes no request message
     * (the second element is `null`, §8.2.2.1); negotiated handover passes the reader's Handover Request
     * Message so both messages are bound into the transcript.
     */
    fun nfcHandover(handoverSelectMessage: ByteArray, handoverRequestMessage: ByteArray? = null): Cbor =
        Cbor.Array(listOf(Cbor.Bytes(handoverSelectMessage), handoverRequestMessage?.let { Cbor.Bytes(it) } ?: Cbor.Null))
}

/** BLE connection UUIDs offered in a `DeviceEngagement`; the reader picks a mode it supports (either may be null). */
class BleRetrieval(val peripheralServerUuid: ByteArray?, val centralClientUuid: ByteArray?)

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
     * An ISO/IEC 18013-5 §8.3.3.1.1 BLE `DeviceRetrievalMethod` `[2, 1, {…}]`. Both mode flags (keys 0 and 1)
     * are mandatory; the UUID goes at key 10 (peripheral server mode) and/or 11 (central client mode). Pass the
     * UUID(s) for the mode(s) offered; advertise the result in [qr] so the reader connects over BLE.
     */
    fun bleRetrievalMethod(peripheralServerUuid: ByteArray? = null, centralClientUuid: ByteArray? = null): ByteArray {
        val opts = mutableListOf<Pair<Cbor, Cbor>>(
            Cbor.int(0) to Cbor.Bool(peripheralServerUuid != null), // mdoc peripheral server mode supported
            Cbor.int(1) to Cbor.Bool(centralClientUuid != null),    // mdoc central client mode supported
        )
        peripheralServerUuid?.let { opts.add(Cbor.int(10) to Cbor.Bytes(it)) }
        centralClientUuid?.let { opts.add(Cbor.int(11) to Cbor.Bytes(it)) }
        return CborEncoder.encode(Cbor.Array(listOf(Cbor.int(2), Cbor.int(1), Cbor.CborMap(opts))))
    }

    /** The BLE connection UUIDs (peripheral server / central client mode) from a QR `DeviceEngagement`, or null — reader side. */
    fun parseBle(engagement: ByteArray): BleRetrieval? {
        val map = CborDecoder.decode(engagement) as? Cbor.CborMap ?: return null
        val methods = map.entries.firstOrNull { (k, _) -> (k as? Cbor.UInt)?.value == 2uL }?.second as? Cbor.Array ?: return null
        for (m in methods.items) {
            val arr = m as? Cbor.Array ?: continue
            if ((arr.items.getOrNull(0) as? Cbor.UInt)?.value != 2uL) continue // BLE
            val opts = arr.items.getOrNull(2) as? Cbor.CborMap ?: continue
            fun uuid(key: ULong) = (opts.entries.firstOrNull { (k, _) -> (k as? Cbor.UInt)?.value == key }?.second as? Cbor.Bytes)?.value
            return BleRetrieval(uuid(10uL), uuid(11uL))
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

    /**
     * The raw `EDeviceKeyBytes` (`#6.24(bstr .cbor COSE_Key)`, §9.1.1.4) taken verbatim from a QR
     * `DeviceEngagement` — the IKM for the BLE `Ident` characteristic. Verbatim (not re-encoded) so both
     * sides derive the same bytes regardless of map-key ordering.
     */
    fun eDeviceKeyBytes(engagement: ByteArray): ByteArray {
        val map = CborDecoder.decode(engagement) as? Cbor.CborMap ?: throw ProximityException("DeviceEngagement must be a map")
        val security = map.entries.firstOrNull { (k, _) -> (k as? Cbor.UInt)?.value == 1uL }?.second as? Cbor.Array
            ?: throw ProximityException("missing Security")
        val bytes = security.items.getOrNull(1) as? Cbor.Tagged ?: throw ProximityException("missing EDeviceKeyBytes")
        return CborEncoder.encode(bytes)
    }

    /**
     * ISO/IEC 18013-5 §8.3.3.1.1.4 BLE `Ident` characteristic value:
     * `HKDF-SHA256(IKM = EDeviceKeyBytes, salt = ∅, info = "BLEIdent", L = 16)`. In central client mode the
     * mdoc **reader** (GATT server) exposes it on characteristic `…00000008`; the mdoc (GATT client) reads and
     * verifies it to confirm it connected to the reader that scanned this engagement, and terminates on mismatch.
     */
    fun bleIdent(eDeviceKeyBytes: ByteArray): ByteArray =
        Hkdf.deriveSha256(eDeviceKeyBytes, ByteArray(0), "BLEIdent".encodeToByteArray(), 16)
}
