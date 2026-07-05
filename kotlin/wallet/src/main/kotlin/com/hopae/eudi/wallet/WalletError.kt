package com.hopae.eudi.wallet

/** Typed wallet errors (API-CONTRACT.md §8). Spec error codes are preserved on the relevant cases. */
sealed class WalletError(message: String, cause: Throwable? = null) : Exception(message, cause) {

    sealed class Issuance(message: String, cause: Throwable? = null) : WalletError(message, cause) {
        class InvalidOffer(message: String) : Issuance("invalid offer: $message")
        class AuthorizationFailed(val oauthError: String?, message: String) : Issuance("authorization failed: $message")
        class CredentialRequestFailed(message: String, cause: Throwable? = null) : Issuance("credential request failed: $message", cause)
        class DeferredNotReady : Issuance("deferred credential not ready")
        class Unexpected(cause: Throwable) : Issuance("unexpected issuance error: ${cause.message}", cause)
    }

    sealed class Presentation(message: String, cause: Throwable? = null) : WalletError(message, cause) {
        class InvalidRequest(message: String, cause: Throwable? = null) : Presentation("invalid presentation request: $message", cause)
        class VerifierNotTrusted(message: String) : Presentation("verifier not trusted: $message")
        class QueryNotSatisfiable(message: String) : Presentation("request not satisfiable: $message")
        class SelectionIncomplete(message: String) : Presentation("selection incomplete: $message")
        class ResponseRejected(message: String, cause: Throwable? = null) : Presentation("verifier rejected the response: $message", cause)
        class Unexpected(cause: Throwable) : Presentation("unexpected presentation error: ${cause.message}", cause)
    }

    sealed class Proximity(message: String, cause: Throwable? = null) : WalletError(message, cause) {
        class SessionFailed(message: String, cause: Throwable? = null) : Proximity("proximity session failed: $message", cause)
        class NoMatchingCredential(message: String) : Proximity("no credential for the reader request: $message")
        class Unexpected(cause: Throwable) : Proximity("unexpected proximity error: ${cause.message}", cause)
    }
}
