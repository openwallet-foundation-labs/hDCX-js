package com.hopae.eudi.wallet.spi

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey

/**
 * Private-key custody port.
 *
 * Crypto boundary rule: every operation that touches a private key goes through this port.
 * Public-key verification, hashing and encoding stay in core and run anywhere (incl. Linux CI).
 *
 * Adapters: AndroidKeystore/StrongBox, SecureEnclave, SoftwareSecureArea (testkit),
 * remote WSCD/HSM later. Adapter qualification = passing the shared contract test suite.
 */
interface SecureArea {
    val id: SecureAreaId
    val capabilities: SecureAreaCapabilities

    /** Creates a key and returns its handle plus public key (always needed for proofs). */
    suspend fun createKey(spec: KeySpec): KeyInfo

    suspend fun publicKey(key: KeyHandle): EcPublicKey

    /** Raw r||s signature; the adapter shows the user-auth prompt when the key requires it. */
    suspend fun sign(
        key: KeyHandle,
        algorithm: SigningAlgorithm,
        data: ByteArray,
        hint: AuthorizationHint? = null,
    ): ByteArray

    /** ECDH shared secret (18013-5 session encryption, JWE ECDH-ES). */
    suspend fun keyAgreement(
        key: KeyHandle,
        peerPublicKey: EcPublicKey,
        hint: AuthorizationHint? = null,
    ): ByteArray

    /** Null when the area cannot attest (e.g. software area without attestation). */
    suspend fun attestation(key: KeyHandle, challenge: ByteArray): KeyAttestation?

    suspend fun deleteKey(key: KeyHandle)
}
