package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.JsonValue

/* OpenID4VCI 1.0 wire models, parsed from the SDK's own JsonValue. */

private fun JsonValue.Obj.str(name: String): String? = (this[name] as? JsonValue.Str)?.value
private fun JsonValue.Obj.requireStr(name: String, where: String): String =
    str(name) ?: throw VciException.ProtocolError("$where: missing '$name'")
private fun JsonValue.Obj.arrStr(name: String): List<String>? =
    (this[name] as? JsonValue.Arr)?.items?.map { (it as? JsonValue.Str)?.value ?: return null }

/** Credential offer (OpenID4VCI §4.1). */
class CredentialOffer(
    val credentialIssuer: String,
    val credentialConfigurationIds: List<String>,
    val preAuthorizedCode: String?,
    val txCode: TxCodeSpec?,
    val authorizationCodeIssuerState: String?,
) {
    class TxCodeSpec(val length: Int?, val inputMode: String?, val description: String?)

    companion object {
        fun parse(json: String): CredentialOffer =
            fromObj(JsonValue.parse(json) as? JsonValue.Obj ?: throw VciException.InvalidOffer("not an object"))

        fun fromObj(o: JsonValue.Obj): CredentialOffer {
            val issuer = o.str("credential_issuer") ?: throw VciException.InvalidOffer("missing credential_issuer")
            val ids = o.arrStr("credential_configuration_ids")
                ?: throw VciException.InvalidOffer("missing credential_configuration_ids")
            if (ids.isEmpty()) throw VciException.InvalidOffer("credential_configuration_ids is empty")

            val grants = o["grants"] as? JsonValue.Obj
            val preAuth = grants?.get("urn:ietf:params:oauth:grant-type:pre-authorized_code") as? JsonValue.Obj
            val authCode = grants?.get("authorization_code") as? JsonValue.Obj

            val txCode = (preAuth?.get("tx_code") as? JsonValue.Obj)?.let {
                TxCodeSpec(
                    length = (it["length"] as? JsonValue.NumInt)?.value?.toInt(),
                    inputMode = (it["input_mode"] as? JsonValue.Str)?.value,
                    description = (it["description"] as? JsonValue.Str)?.value,
                )
            }

            return CredentialOffer(
                credentialIssuer = issuer,
                credentialConfigurationIds = ids,
                preAuthorizedCode = preAuth?.str("pre-authorized_code"),
                txCode = txCode,
                authorizationCodeIssuerState = authCode?.str("issuer_state"),
            )
        }
    }
}

/** Credential issuer metadata (OpenID4VCI §11.2). */
class CredentialIssuerMetadata(
    val credentialIssuer: String,
    val credentialEndpoint: String,
    val nonceEndpoint: String?,
    val deferredCredentialEndpoint: String?,
    val notificationEndpoint: String?,
    val authorizationServers: List<String>,
    val credentialConfigurationsSupported: Map<String, CredentialConfiguration>,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj): CredentialIssuerMetadata {
            val issuer = o.requireStr("credential_issuer", "issuer metadata")
            val configs = (o["credential_configurations_supported"] as? JsonValue.Obj)?.entries
                ?.associate { (id, v) ->
                    id to CredentialConfiguration.fromObj(
                        v as? JsonValue.Obj ?: throw VciException.MetadataError("config '$id' not an object")
                    )
                } ?: emptyMap()
            return CredentialIssuerMetadata(
                credentialIssuer = issuer,
                credentialEndpoint = o.requireStr("credential_endpoint", "issuer metadata"),
                nonceEndpoint = o.str("nonce_endpoint"),
                deferredCredentialEndpoint = o.str("deferred_credential_endpoint"),
                notificationEndpoint = o.str("notification_endpoint"),
                authorizationServers = o.arrStr("authorization_servers") ?: listOf(issuer),
                credentialConfigurationsSupported = configs,
            )
        }
    }
}

class CredentialConfiguration(
    val format: String,
    val vct: String?,
    val docType: String?,
    val proofSigningAlgs: List<String>,
    val scope: String?,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj): CredentialConfiguration {
            val proofAlgs = ((o["proof_types_supported"] as? JsonValue.Obj)
                ?.get("jwt") as? JsonValue.Obj)
                ?.let { (it["proof_signing_alg_values_supported"] as? JsonValue.Arr) }
                ?.items?.mapNotNull { (it as? JsonValue.Str)?.value } ?: emptyList()
            return CredentialConfiguration(
                format = (o["format"] as? JsonValue.Str)?.value ?: "",
                vct = (o["vct"] as? JsonValue.Str)?.value,
                docType = (o["doctype"] as? JsonValue.Str)?.value,
                proofSigningAlgs = proofAlgs,
                scope = (o["scope"] as? JsonValue.Str)?.value,
            )
        }
    }
}

/** Authorization server metadata (RFC 8414) — the fields we use. */
class AuthorizationServerMetadata(
    val issuer: String,
    val tokenEndpoint: String,
    val pushedAuthorizationRequestEndpoint: String?,
    val authorizationEndpoint: String?,
    val dpopSigningAlgValuesSupported: List<String>,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj): AuthorizationServerMetadata = AuthorizationServerMetadata(
            issuer = o.requireStr("issuer", "AS metadata"),
            tokenEndpoint = o.requireStr("token_endpoint", "AS metadata"),
            pushedAuthorizationRequestEndpoint = o.str("pushed_authorization_request_endpoint"),
            authorizationEndpoint = o.str("authorization_endpoint"),
            dpopSigningAlgValuesSupported = o.arrStr("dpop_signing_alg_values_supported") ?: emptyList(),
        )
    }
}

class TokenResponse(
    val accessToken: String,
    val tokenType: String,
    val cNonce: String?,
    val expiresIn: Long?,
    val authorizationDetails: JsonValue?,
) {
    companion object {
        fun fromObj(o: JsonValue.Obj): TokenResponse = TokenResponse(
            accessToken = o.requireStr("access_token", "token response"),
            tokenType = o.requireStr("token_type", "token response"),
            cNonce = o.str("c_nonce"),
            expiresIn = (o["expires_in"] as? JsonValue.NumInt)?.value,
            authorizationDetails = o["authorization_details"],
        )
    }
}

/** One issued credential plus optional deferral. */
class IssuedCredential(val format: String, val credential: String)

class CredentialResponse(
    val credentials: List<IssuedCredential>,
    val transactionId: String?,
    val notificationId: String?,
    /** Context for follow-ups (deferred poll, notification) — set by the client, not parsed. */
    val accessToken: String? = null,
    val credentialIssuer: String? = null,
    val requestedFormat: String = "dc+sd-jwt",
) {
    /** True when the issuer deferred issuance (returned a transaction_id, no credential yet). */
    val isDeferred: Boolean get() = credentials.isEmpty() && transactionId != null

    internal fun withContext(accessToken: String?, credentialIssuer: String?, requestedFormat: String) =
        CredentialResponse(credentials, transactionId, notificationId, accessToken, credentialIssuer, requestedFormat)

    companion object {
        fun fromObj(o: JsonValue.Obj, requestedFormat: String): CredentialResponse {
            // OpenID4VCI 1.0: "credentials" is an array of objects each with a "credential" member.
            val creds = (o["credentials"] as? JsonValue.Arr)?.items?.mapNotNull { item ->
                val c = (item as? JsonValue.Obj)?.get("credential")
                when (c) {
                    is JsonValue.Str -> IssuedCredential(requestedFormat, c.value)
                    else -> null
                }
            } ?: emptyList()
            return CredentialResponse(
                credentials = creds,
                transactionId = o.str("transaction_id"),
                notificationId = o.str("notification_id"),
            )
        }
    }
}
