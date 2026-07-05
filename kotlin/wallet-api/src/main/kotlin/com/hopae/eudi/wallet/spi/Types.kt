package com.hopae.eudi.wallet.spi

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import kotlin.time.Duration

/*
 * Shared value types for the port SPI.
 * Naming is the cross-platform contract: Swift mirrors these 1:1.
 */

@JvmInline
value class SecureAreaId(val value: String) {
    companion object {
        val Default = SecureAreaId("default")
    }
}

enum class SigningAlgorithm { ES256, ES384, ES512 }

/** Opaque reference to a key inside a specific secure area. */
data class KeyHandle(val secureArea: SecureAreaId, val alias: String)

sealed interface UserAuthPolicy {
    data object NotRequired : UserAuthPolicy
    data class Required(val timeout: Duration? = null) : UserAuthPolicy
}

enum class HardwarePolicy { Preferred, Required, Software }

class KeySpec(
    val secureArea: SecureAreaId = SecureAreaId.Default,
    val algorithm: SigningAlgorithm = SigningAlgorithm.ES256,
    val userAuthentication: UserAuthPolicy = UserAuthPolicy.NotRequired,
    val hardware: HardwarePolicy = HardwarePolicy.Preferred,
    val attestationChallenge: ByteArray? = null,
)

enum class KeyUse { Rotate, OneTime }

data class CredentialPolicy(
    val batchSize: Int = 1,
    val use: KeyUse = KeyUse.Rotate,
)

/** Text shown by the adapter's user-auth prompt (BiometricPrompt / LAContext). */
data class AuthorizationHint(val title: String, val subtitle: String? = null)

/** Opaque key attestation as produced by the secure area (format is adapter-specific). */
class KeyAttestation(val format: String, val data: ByteArray)

class KeyInfo(
    val handle: KeyHandle,
    val algorithm: SigningAlgorithm,
    val publicKey: EcPublicKey,
)

data class SecureAreaCapabilities(
    val algorithms: Set<SigningAlgorithm>,
    val hardwareBacked: Boolean,
    val userAuthentication: Boolean,
    val keyAttestation: Boolean,
    val keyAgreement: Boolean,
)

/* ---- credential model identifiers ---- */

@JvmInline
value class CredentialId(val value: String)

sealed interface CredentialFormat {
    data class MsoMdoc(val docType: String) : CredentialFormat
    data class SdJwtVc(val vct: String) : CredentialFormat
}

/* ---- algorithm mappings (SigningAlgorithm <-> COSE/curve) ---- */

val SigningAlgorithm.curve: com.hopae.eudi.wallet.cbor.cose.EcCurve
    get() = when (this) {
        SigningAlgorithm.ES256 -> com.hopae.eudi.wallet.cbor.cose.EcCurve.P256
        SigningAlgorithm.ES384 -> com.hopae.eudi.wallet.cbor.cose.EcCurve.P384
        SigningAlgorithm.ES512 -> com.hopae.eudi.wallet.cbor.cose.EcCurve.P521
    }

val SigningAlgorithm.coseAlgorithm: com.hopae.eudi.wallet.cbor.cose.CoseAlgorithm
    get() = when (this) {
        SigningAlgorithm.ES256 -> com.hopae.eudi.wallet.cbor.cose.CoseAlgorithm.ES256
        SigningAlgorithm.ES384 -> com.hopae.eudi.wallet.cbor.cose.CoseAlgorithm.ES384
        SigningAlgorithm.ES512 -> com.hopae.eudi.wallet.cbor.cose.CoseAlgorithm.ES512
    }
