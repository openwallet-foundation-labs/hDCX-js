package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.sdjwt.JsonValue

/**
 * A held mdoc (ISO 18013-5) exposed to DCQL as a [QueryableCredential]. mdoc claims are a
 * two-level tree `{ namespace: { elementIdentifier: value } }`, so a DCQL claim path is
 * `[namespace, element]` (both strings) — see [DcqlEngine] mdoc path handling.
 */
class HeldMdoc(
    override val credentialId: String,
    val issuerSigned: IssuerSigned,
) : QueryableCredential {

    override val format: String = "mso_mdoc"
    override val vct: String? = null
    override val docType: String = issuerSigned.parseMso().docType

    override val claims: JsonValue.Obj = JsonValue.Obj(
        issuerSigned.elements().map { (namespace, elements) ->
            namespace to JsonValue.Obj(elements.map { (id, value) -> id to CborJson.toJson(value) })
        }
    )
}
