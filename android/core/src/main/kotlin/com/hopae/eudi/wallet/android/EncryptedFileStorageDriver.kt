package com.hopae.eudi.wallet.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.spi.StorageTx
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Persistent [StorageDriver] that encrypts every value **at rest** with AES-256-GCM under a key held in the
 * **Android Keystore** — the production-grade counterpart of [FileStorageDriver] (which stores plain files).
 *
 * The AES key is hardware-bound (TEE/StrongBox): it never leaves the secure hardware and cannot be exported,
 * so a file copied off the device — or read from a backup — is useless without it. This mirrors what iOS gets
 * for free from the keychain-backed `KeychainStorageDriver`: OS/hardware encryption at rest, keyed to the app.
 *
 * On-disk layout matches [FileStorageDriver] — one file per `(collection, key)` under `baseDir`, names
 * base64url-encoded — but each file holds `iv (12 bytes) ‖ ciphertext‖tag` instead of the raw value. The
 * Keystore generates a fresh random IV per write (GCM must never reuse an IV under one key).
 *
 * Migration: a value written by the plain [FileStorageDriver] fails GCM authentication, so [get] treats an
 * undecryptable file as absent (returns `null`) rather than throwing — an old plaintext store degrades to
 * "empty" and the wallet re-issues, instead of crashing. For a residue-free upgrade, clear app data.
 *
 * Still debug-grade in one respect: like [FileStorageDriver] it offers no atomic transaction/rollback. It does
 * not require device unlock or user authentication for access; add `setUnlockedDeviceRequired(true)` or
 * `setUserAuthenticationRequired(true)` to [keySpec] if your threat model needs it (note: that would block
 * access from a background provider on a locked device).
 */
class EncryptedFileStorageDriver(
    private val baseDir: File,
    keyAlias: String = "eudi-storage-aead",
) : StorageDriver {

    private val key: SecretKey = loadOrCreateKey(keyAlias)

    private fun collectionDir(collection: String) = File(baseDir, enc(collection)).apply { mkdirs() }
    private fun file(collection: String, key: String) = File(collectionDir(collection), enc(key))

    override suspend fun put(collection: String, key: String, value: ByteArray) {
        file(collection, key).writeBytes(seal(value))
    }

    override suspend fun get(collection: String, key: String): ByteArray? =
        file(collection, key).takeIf { it.exists() }?.readBytes()?.let(::open)

    override suspend fun delete(collection: String, key: String) {
        file(collection, key).delete()
    }

    override suspend fun keys(collection: String): List<String> =
        collectionDir(collection).listFiles()?.map { dec(it.name) } ?: emptyList()

    override suspend fun transaction(block: suspend StorageTx.() -> Unit) {
        // Debug-grade: no rollback (matches FileStorageDriver). Production should batch writes atomically.
        object : StorageTx {
            override suspend fun put(collection: String, key: String, value: ByteArray) = this@EncryptedFileStorageDriver.put(collection, key, value)
            override suspend fun get(collection: String, key: String) = this@EncryptedFileStorageDriver.get(collection, key)
            override suspend fun delete(collection: String, key: String) = this@EncryptedFileStorageDriver.delete(collection, key)
        }.block()
    }

    /** AES-GCM seal → `iv ‖ ciphertext‖tag`. The Keystore picks a fresh 12-byte IV each call. */
    private fun seal(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
        return cipher.iv + cipher.doFinal(plaintext) // cipher.iv is IV_LEN bytes
    }

    /** Inverse of [seal]; returns `null` for anything this key can't authenticate (e.g. legacy plaintext). */
    private fun open(sealed: ByteArray): ByteArray? {
        if (sealed.size <= IV_LEN) return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed, 0, IV_LEN))
            }
            cipher.doFinal(sealed, IV_LEN, sealed.size - IV_LEN)
        } catch (_: GeneralSecurityException) {
            null
        }
    }

    private fun enc(s: String) = Base64.encodeToString(s.toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun dec(s: String) = String(Base64.decode(s, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING))

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12   // 96-bit nonce — the GCM standard, and the length the Keystore emits
        const val TAG_BITS = 128

        /** The Keystore AES-256-GCM key, created on first use and reused thereafter (persists across restarts). */
        fun loadOrCreateKey(alias: String): SecretKey {
            val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            (keystore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(keySpec(alias))
            }.generateKey()
        }

        private fun keySpec(alias: String) = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
    }
}
