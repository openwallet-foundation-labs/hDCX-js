package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue

class DcqlException(message: String) : Exception(message)

/** A single element of a DCQL claims path (OpenID4VP §6.4): key, array index, or wildcard (JSON null). */
sealed interface PathElement {
    data class Key(val name: String) : PathElement
    data class Index(val index: Int) : PathElement

    /** JSON `null`: selects every element of an array (the null array-wildcard). */
    data object Wildcard : PathElement
}

data class ClaimQuery(
    val id: String?,
    val path: List<PathElement>,
    /** If present, the claim matches only when its value is one of these. */
    val values: List<JsonValue>?,
)

/** DCQL meta constraints — vct for SD-JWT VC, doctype for mdoc. */
data class CredentialMeta(
    val vctValues: List<String>?,
    val doctypeValue: String?,
)

data class CredentialQuery(
    val id: String,
    val format: String,
    val meta: CredentialMeta?,
    val claims: List<ClaimQuery>,
    /** Alternative sets of claim ids; at least one set must be fully satisfiable. */
    val claimSets: List<List<String>>?,
    /** §6.1: whether more than one Credential may be returned for this query. Default false (exactly one). */
    val multiple: Boolean = false,
    /**
     * §6.1: whether the Verifier requires a Cryptographic Holder Binding proof. Default true. When false the
     * Verifier accepts a Credential without holder binding, so an SD-JWT VC may be presented with no KB-JWT.
     */
    val requireCryptographicHolderBinding: Boolean = true,
)

data class CredentialSetQuery(
    val options: List<List<String>>,
    val required: Boolean,
)

data class DcqlQuery(
    val credentials: List<CredentialQuery>,
    val credentialSets: List<CredentialSetQuery>?,
) {
    companion object {
        fun parse(obj: JsonValue.Obj): DcqlQuery {
            val creds = (obj["credentials"] as? JsonValue.Arr)?.items?.map { parseCredentialQuery(it.asObj("credential")) }
                ?: throw DcqlException("dcql: missing 'credentials'")
            if (creds.isEmpty()) throw DcqlException("dcql: 'credentials' is empty")
            val sets = (obj["credential_sets"] as? JsonValue.Arr)?.items?.map { parseCredentialSet(it.asObj("credential_set")) }
            return DcqlQuery(creds, sets)
        }

        private fun parseCredentialQuery(o: JsonValue.Obj): CredentialQuery {
            val id = o.str("id") ?: throw DcqlException("credential query: missing 'id'")
            val format = o.str("format") ?: throw DcqlException("credential query '$id': missing 'format'")
            val metaObj = o["meta"] as? JsonValue.Obj
            val meta = metaObj?.let {
                CredentialMeta(
                    vctValues = (it["vct_values"] as? JsonValue.Arr)?.items?.mapNotNull { v -> (v as? JsonValue.Str)?.value },
                    doctypeValue = (it["doctype_value"] as? JsonValue.Str)?.value,
                )
            }
            val claims = (o["claims"] as? JsonValue.Arr)?.items?.map { parseClaimQuery(it.asObj("claim")) } ?: emptyList()
            val claimSets = (o["claim_sets"] as? JsonValue.Arr)?.items?.map { set ->
                (set as? JsonValue.Arr)?.items?.map { id2 -> (id2 as? JsonValue.Str)?.value ?: throw DcqlException("claim_sets entries must be strings") }
                    ?: throw DcqlException("claim_sets must be arrays")
            }
            // mdoc (ISO 18013-5): a claim path addresses [namespace, data element], both strings.
            // Require the first two segments to be string keys (>=2, not strictly ==2 — a deeper
            // path may index into a structured element value).
            if (format == "mso_mdoc") {
                claims.forEach { c ->
                    if (c.path.size < 2 || c.path[0] !is PathElement.Key || c.path[1] !is PathElement.Key) {
                        throw DcqlException("credential query '$id': mso_mdoc claim path must start with [namespace, element] (two strings)")
                    }
                }
            }
            val multiple = (o["multiple"] as? JsonValue.Bool)?.value ?: false
            val requireBinding = (o["require_cryptographic_holder_binding"] as? JsonValue.Bool)?.value ?: true
            return CredentialQuery(id, format, meta, claims, claimSets, multiple, requireBinding)
        }

        private fun parseClaimQuery(o: JsonValue.Obj): ClaimQuery {
            val pathArr = o["path"] as? JsonValue.Arr ?: throw DcqlException("claim: missing 'path'")
            val path = pathArr.items.map { el ->
                when (el) {
                    is JsonValue.Str -> PathElement.Key(el.value)
                    is JsonValue.NumInt -> PathElement.Index(el.value.toInt())
                    JsonValue.Null -> PathElement.Wildcard
                    else -> throw DcqlException("path element must be string, int, or null")
                }
            }
            val values = (o["values"] as? JsonValue.Arr)?.items
            return ClaimQuery(o.str("id"), path, values)
        }

        private fun parseCredentialSet(o: JsonValue.Obj): CredentialSetQuery {
            val options = (o["options"] as? JsonValue.Arr)?.items?.map { opt ->
                (opt as? JsonValue.Arr)?.items?.map { (it as? JsonValue.Str)?.value ?: throw DcqlException("option ids must be strings") }
                    ?: throw DcqlException("options must be arrays")
            } ?: throw DcqlException("credential_set: missing 'options'")
            val required = (o["required"] as? JsonValue.Bool)?.value ?: true
            return CredentialSetQuery(options, required)
        }

        private fun JsonValue.asObj(what: String): JsonValue.Obj =
            this as? JsonValue.Obj ?: throw DcqlException("$what must be an object")

        private fun JsonValue.Obj.str(name: String): String? = (this[name] as? JsonValue.Str)?.value
    }
}
