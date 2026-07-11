package com.hopae.eudi.wallet.android.proximity

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.ByteArrayOutputStream
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The reader side of ISO 18013-5 NFC engagement: puts the phone in NFC reader mode, reads the mdoc's
 * NFC Forum Type 4 Tag, and returns the raw Handover Select NDEF message (which the SDK then parses).
 */
object NfcReader {
    private val NDEF_AID = hex("D2760000850101")

    /** Suspends until an mdoc tag is tapped, then returns its Handover Select NDEF message. */
    suspend fun readHandover(activity: Activity): ByteArray = suspendCancellableCoroutine { cont ->
        val adapter = NfcAdapter.getDefaultAdapter(activity)
            ?: return@suspendCancellableCoroutine cont.resumeWithException(IllegalStateException("NFC unavailable"))
        val callback = NfcAdapter.ReaderCallback { tag ->
            val iso = IsoDep.get(tag) ?: return@ReaderCallback
            try {
                iso.connect()
                iso.timeout = 5000
                val ndef = readType4(iso)
                runCatching { iso.close() }
                runCatching { adapter.disableReaderMode(activity) }
                if (cont.isActive) cont.resume(ndef)
            } catch (e: Exception) {
                if (cont.isActive) cont.resumeWithException(e)
            }
        }
        val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
        adapter.enableReaderMode(activity, callback, flags, null)
        cont.invokeOnCancellation { runCatching { adapter.disableReaderMode(activity) } }
    }

    // ---- NFC Forum Type 4 Tag read ----

    private fun readType4(iso: IsoDep): ByteArray {
        transceive(iso, byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, NDEF_AID.size.toByte()) + NDEF_AID + byteArrayOf(0x00)) // SELECT AID
        transceive(iso, hex("00A4000C02E103")) // SELECT Capability Container
        val cc = readBinary(iso, 0, 15)
        val ndefFileId = byteArrayOf(cc[9], cc[10]) // NDEF File Control TLV → file id (E104)
        transceive(iso, byteArrayOf(0x00, 0xA4.toByte(), 0x00, 0x0C, 0x02) + ndefFileId) // SELECT NDEF file
        val nlen = readBinary(iso, 0, 2)
        val len = ((nlen[0].toInt() and 0xFF) shl 8) or (nlen[1].toInt() and 0xFF)
        val out = ByteArrayOutputStream()
        var offset = 2
        var remaining = len
        while (remaining > 0) {
            val chunk = minOf(remaining, 0xF0)
            out.write(readBinary(iso, offset, chunk))
            offset += chunk
            remaining -= chunk
        }
        return out.toByteArray()
    }

    private fun readBinary(iso: IsoDep, offset: Int, length: Int): ByteArray =
        transceive(iso, byteArrayOf(0x00, 0xB0.toByte(), (offset shr 8).toByte(), offset.toByte(), length.toByte()))

    /** Sends an APDU and returns the response data (without the trailing 0x9000 status word). */
    private fun transceive(iso: IsoDep, apdu: ByteArray): ByteArray {
        val r = iso.transceive(apdu)
        if (r.size < 2 || r[r.size - 2] != 0x90.toByte() || r[r.size - 1] != 0x00.toByte()) {
            throw IllegalStateException("APDU failed: sw=${if (r.size >= 2) "%02x%02x".format(r[r.size - 2], r[r.size - 1]) else "?"}")
        }
        return r.copyOfRange(0, r.size - 2)
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }
}
