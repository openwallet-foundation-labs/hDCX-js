package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue

/**
 * Projects a CBOR value into the JSON claim tree DCQL matches against. Byte strings become
 * base64url text and tags are unwrapped (mdoc element values are plain CBOR — text, ints,
 * bools, arrays, maps, and tdate/bstr for dates and portraits).
 */
object CborJson {
    fun toJson(c: Cbor): JsonValue = when (c) {
        is Cbor.Text -> JsonValue.Str(c.value)
        is Cbor.Bytes -> JsonValue.Str(Base64Url.encode(c.value))
        is Cbor.Bool -> JsonValue.Bool(c.value)
        is Cbor.UInt -> JsonValue.NumInt(c.value.toLong())
        is Cbor.NInt -> JsonValue.NumInt(-1L - c.n.toLong())
        is Cbor.Fp -> JsonValue.NumDouble(c.value)
        is Cbor.Array -> JsonValue.Arr(c.items.map { toJson(it) })
        is Cbor.CborMap -> JsonValue.Obj(c.entries.map { (k, v) -> keyString(k) to toJson(v) })
        is Cbor.Tagged -> toJson(c.value) // e.g. tdate (#6.0) -> its inner text
        Cbor.Null, Cbor.Undefined -> JsonValue.Null
        is Cbor.Simple -> JsonValue.Null
    }

    private fun keyString(k: Cbor): String = when (k) {
        is Cbor.Text -> k.value
        is Cbor.UInt -> k.value.toString()
        is Cbor.NInt -> (-1L - k.n.toLong()).toString()
        else -> k.toString()
    }
}
