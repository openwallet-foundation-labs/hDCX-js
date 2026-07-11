package com.hopae.eudi.wallet.android.proximity

import android.nfc.cardemulation.HostApduService
import android.os.Bundle

/**
 * NFC Forum **Type 4 Tag** emulation (Host Card Emulation) that serves the SDK-built ISO 18013-5 NFC
 * Handover Select message. The holder arms it with [ndefMessage] (from `EngagementReady.handoverNdef`);
 * a reader in NFC reader mode reads the NDEF, extracts the engagement + BLE UUID, and connects over BLE.
 */
class NfcEngagementService : HostApduService() {
    private var selected: ByteArray? = null
    private var cachedFor: ByteArray? = null
    private var ndefFile: ByteArray = ByteArray(0)

    override fun processCommandApdu(apdu: ByteArray, extras: Bundle?): ByteArray {
        val msg = ndefMessage ?: return SW_NOT_FOUND
        if (cachedFor !== msg) { // NDEF file = 2-byte length prefix + the Handover Select message
            ndefFile = byteArrayOf((msg.size shr 8).toByte(), (msg.size and 0xFF).toByte()) + msg
            cachedFor = msg
        }
        if (apdu.size < 2) return SW_NOT_FOUND
        return when (apdu[1]) {
            0xA4.toByte() -> handleSelect(apdu)
            0xB0.toByte() -> handleRead(apdu)
            else -> SW_NOT_FOUND
        }
    }

    private fun handleSelect(apdu: ByteArray): ByteArray {
        if (apdu.size >= 5 && apdu[2] == 0x04.toByte()) return SW_OK // SELECT by AID (NDEF application)
        if (apdu.size >= 7 && apdu[2] == 0x00.toByte()) { // SELECT by file id
            val fid = apdu.copyOfRange(5, 7)
            selected = when {
                fid.contentEquals(CC_FILE_ID) -> CC_FILE
                fid.contentEquals(NDEF_FILE_ID) -> ndefFile
                else -> null
            }
            return if (selected != null) SW_OK else SW_NOT_FOUND
        }
        return SW_NOT_FOUND
    }

    private fun handleRead(apdu: ByteArray): ByteArray {
        val file = selected ?: return SW_NOT_FOUND
        val offset = ((apdu[2].toInt() and 0xFF) shl 8) or (apdu[3].toInt() and 0xFF)
        val le = if (apdu.size >= 5) (apdu[4].toInt() and 0xFF).let { if (it == 0) 256 else it } else 0
        if (offset > file.size) return SW_NOT_FOUND
        return file.copyOfRange(offset, minOf(offset + le, file.size)) + SW_OK
    }

    override fun onDeactivated(reason: Int) {
        selected = null
    }

    companion object {
        /** The Handover Select NDEF message to serve over NFC; armed by the holder screen while presenting. */
        @Volatile
        var ndefMessage: ByteArray? = null

        private val SW_OK = byteArrayOf(0x90.toByte(), 0x00)
        private val SW_NOT_FOUND = byteArrayOf(0x6A, 0x82.toByte())
        private val CC_FILE_ID = byteArrayOf(0xE1.toByte(), 0x03)
        private val NDEF_FILE_ID = byteArrayOf(0xE1.toByte(), 0x04)

        // Capability Container: NDEF file E104, max 0x7FFF, read-only.
        private val CC_FILE = byteArrayOf(
            0x00, 0x0F, 0x20, 0x7F, 0xFF.toByte(), 0x7F, 0xFF.toByte(),
            0x04, 0x06, 0xE1.toByte(), 0x04, 0x7F, 0xFF.toByte(), 0x00, 0xFF.toByte(),
        )
    }
}
