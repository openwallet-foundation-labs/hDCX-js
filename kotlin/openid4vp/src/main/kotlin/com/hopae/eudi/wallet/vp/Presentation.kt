package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey

/** Everything a held credential needs to build its OpenID4VP presentation for one query. */
class PresentationContext(
    /** Concrete leaf paths DCQL selected for disclosure (SD-JWT VC claim paths / mdoc [ns, element]). */
    val disclosedPaths: List<List<String>>,
    val clientId: String,
    val nonce: String,
    val responseUri: String?,
    val issuedAt: Long,
    val transactionData: List<String>?,
    /** RFC 7638 thumbprint of the verifier's encryption key, for the mdoc OpenID4VP handover (null if unencrypted). */
    val verifierJwkThumbprint: ByteArray?,
    /** Caller web origin for a Digital Credentials API presentation; non-null selects the DC API handover. */
    val origin: String? = null,
    /**
     * The verifier's response-encryption public key, doubling as the `EReaderKey` for mdoc `deviceMac`
     * (ISO 18013-7 B.4.5 / OpenID4VP §B.2.2). Null when the response is unencrypted — then only
     * `deviceSignature` is possible, as there is no reader key to run ECDH against.
     */
    val verifierEncryptionKey: EcPublicKey? = null,
    /**
     * COSE algorithm identifiers from the verifier's `deviceauth_alg_values` (OpenID4VP §B.2.2), stating
     * which `deviceSignature` / `deviceMac` algorithms it accepts. Null when the verifier did not constrain it.
     */
    val deviceAuthAlgValues: List<Long>? = null,
    /**
     * §6.1 `require_cryptographic_holder_binding`. When false the verifier accepts an unbound credential, so an
     * SD-JWT VC may be presented without a KB-JWT. Default true (bind). mdoc always binds via DeviceAuth.
     */
    val requireHolderBinding: Boolean = true,
)

/**
 * A held credential that can produce an OpenID4VP `vp_token` entry. Both SD-JWT VC
 * ([HeldSdJwtVc]) and mdoc ([HeldMdoc]) implement this so [Openid4VpClient] presents either.
 */
interface PresentableCredential : QueryableCredential {
    suspend fun present(ctx: PresentationContext): String
}
