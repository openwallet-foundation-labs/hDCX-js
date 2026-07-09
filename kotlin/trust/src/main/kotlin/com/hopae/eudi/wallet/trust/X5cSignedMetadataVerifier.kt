package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.vci.SignedMetadataVerifier
import java.util.Base64

/**
 * Verifies signed Credential Issuer Metadata (OpenID4VCI §12.2.3): resolves the signer's key from the
 * JWS `x5c` header and validates that chain to a trust anchor. The spec leaves "establish trust in the
 * signer" out of scope; this is the x5c form, and how the EUDI reference issuer signs — a leaf chaining
 * to `PID Issuer CA`. The `typ` / `alg` / `sub` / `iat` / `exp` rules are enforced by `Openid4VciClient`.
 */
class X5cSignedMetadataVerifier(private val validator: X509ChainValidator) : SignedMetadataVerifier {

    override suspend fun verify(signedMetadataJws: String): JsonValue.Obj {
        val jws = Jws.parse(signedMetadataJws)
        val x5c = (jws.header["x5c"] as? JsonValue.Arr)?.items?.map { el ->
            Base64.getDecoder().decode((el as? JsonValue.Str)?.value ?: throw TrustException("x5c entries must be strings"))
        } ?: throw TrustException("signed metadata JWS has no x5c header")

        val leaf = validator.validate(x5c).first() // throws if the chain does not reach an anchor
        if (!jws.verify(X509Support.ecPublicKey(leaf), X509Support.signingAlgorithm(leaf))) {
            throw TrustException("signed metadata signature invalid")
        }
        return JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw TrustException("signed metadata payload is not a JSON object")
    }
}
