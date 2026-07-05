package com.hopae.eudi.wallet.vci

/**
 * Typed OpenID4VCI errors. [oauthError] preserves the server's RFC 6749/OpenID4VCI
 * error code verbatim (e.g. "invalid_grant") for diagnostics and caller handling.
 */
sealed class VciException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    class InvalidOffer(message: String) : VciException("invalid credential offer: $message")

    class MetadataError(message: String) : VciException("metadata error: $message")

    class Http(val status: Int, val endpoint: String, val body: String?) :
        VciException("HTTP $status from $endpoint${body?.let { ": $it" } ?: ""}")

    class OAuthError(val oauthError: String, val description: String?, val endpoint: String) :
        VciException("OAuth error '$oauthError' from $endpoint${description?.let { ": $it" } ?: ""}")

    class ProtocolError(message: String) : VciException("protocol error: $message")

    class TxCodeRequired(val length: Int?, val inputMode: String?) :
        VciException("transaction code required (length=$length, mode=$inputMode)")

    /** Deferred issuance: the credential is not ready yet — retry the deferred endpoint later. */
    object IssuancePending : VciException("issuance pending — retry the deferred credential endpoint later")
}

/** Issuance notification event (OpenID4VCI §10). */
enum class NotificationEvent(val wire: String) {
    CREDENTIAL_ACCEPTED("credential_accepted"),
    CREDENTIAL_DELETED("credential_deleted"),
    CREDENTIAL_FAILURE("credential_failure"),
}
