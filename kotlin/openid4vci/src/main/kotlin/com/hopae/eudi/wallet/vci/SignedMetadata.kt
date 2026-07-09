package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.JsonValue

/** The JOSE `typ` every signed Credential Issuer Metadata JWT carries (OpenID4VCI §12.2.3). */
const val SIGNED_METADATA_TYP: String = "openidvci-issuer-metadata+jwt"

/**
 * Proves the signature of the issuer's signed metadata JWT and establishes trust in its signer,
 * returning the verified payload claims (OpenID4VCI §12.2.3). The spec leaves key resolution and
 * trust out of scope, so the adapter reads `x5c` / `kid` / `trust_chain` and chains the key to a
 * trust anchor — keeping `openid4vci` decoupled from the trust module. The client itself enforces
 * the spec's `typ`, `alg`, `sub`, `iat` and `exp` rules.
 */
fun interface SignedMetadataVerifier {
    suspend fun verify(signedMetadataJws: String): JsonValue.Obj
}

/**
 * How the wallet negotiates Credential Issuer Metadata (OpenID4VCI §12.2.2). The `Accept` header
 * signals whether the wallet supports signed metadata: issuers MUST be able to serve unsigned
 * `application/json` and MAY serve a signed `application/jwt`. There is no `signed_metadata` JSON
 * member — the signed form is the whole response body.
 */
sealed interface IssuerMetadataPolicy {
    /** Ask for unsigned `application/json` only (default). */
    data object IgnoreSigned : IssuerMetadataPolicy

    /** Prefer signed `application/jwt`; accept unsigned JSON when the issuer does not sign. */
    data class PreferSigned(val verifier: SignedMetadataVerifier) : IssuerMetadataPolicy

    /** Require signed `application/jwt`; fail when the issuer answers with unsigned JSON. */
    data class RequireSigned(val verifier: SignedMetadataVerifier) : IssuerMetadataPolicy
}

/** The `Accept` header this policy sends on the metadata GET (§12.2.2). */
internal fun IssuerMetadataPolicy.acceptHeader(): String = when (this) {
    is IssuerMetadataPolicy.IgnoreSigned -> "application/json"
    is IssuerMetadataPolicy.PreferSigned -> "application/jwt, application/json;q=0.9"
    is IssuerMetadataPolicy.RequireSigned -> "application/jwt"
}

internal val IssuerMetadataPolicy.verifierOrNull: SignedMetadataVerifier?
    get() = when (this) {
        is IssuerMetadataPolicy.IgnoreSigned -> null
        is IssuerMetadataPolicy.PreferSigned -> verifier
        is IssuerMetadataPolicy.RequireSigned -> verifier
    }
