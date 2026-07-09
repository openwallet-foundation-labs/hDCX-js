package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtHolder
import java.security.MessageDigest

/** An SD-JWT VC the wallet holds, usable as a DCQL match target and presentable over OpenID4VP. */
class HeldSdJwtVc(
    override val credentialId: String,
    val sdJwt: SdJwt,
    private val holderSigner: JwsSigner,
) : PresentableCredential {

    override val format: String = "dc+sd-jwt"
    override val claims: JsonValue.Obj = SdJwtHolder.processedClaims(sdJwt)
    override val vct: String? = (claims["vct"] as? JsonValue.Str)?.value
    override val docType: String? = null

    /**
     * Builds a presentation: selects the disclosed disclosures and, unless the verifier waived it, appends a
     * KB-JWT bound to the verifier client_id + nonce (optionally with transaction-data hashes).
     *
     * §6.1 `require_cryptographic_holder_binding=false` lets the verifier accept an unbound credential — then
     * no KB-JWT is produced, which also drops replay protection (the presentation is not tied to this verifier
     * or nonce). Transaction data can only be conveyed inside the KB-JWT, so its presence forces binding.
     */
    override suspend fun present(ctx: PresentationContext): String {
        val pathSet = ctx.disclosedPaths.toSet()
        if (!ctx.requireHolderBinding && ctx.transactionData.isNullOrEmpty()) {
            return SdJwtHolder.present(sdJwt, select = { it in pathSet }).serialize()
        }
        val extra = buildList {
            if (!ctx.transactionData.isNullOrEmpty()) {
                add("transaction_data_hashes" to JsonValue.Arr(ctx.transactionData.map { JsonValue.Str(sha256B64(it)) }))
                add("transaction_data_hashes_alg" to JsonValue.Str("sha-256"))
            }
        }
        val presented = SdJwtHolder.presentWithKeyBinding(
            issued = sdJwt,
            select = { it in pathSet },
            audience = ctx.clientId,
            nonce = ctx.nonce,
            issuedAt = ctx.issuedAt,
            signer = holderSigner,
            extraClaims = extra,
        )
        return presented.serialize()
    }

    private fun sha256B64(s: String): String =
        Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(s.encodeToByteArray()))
}
