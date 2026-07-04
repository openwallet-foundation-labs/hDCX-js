package com.hopae.eudi.wallet.sdjwt

import kotlin.test.Test
import kotlin.test.assertEquals

/** Cross-language golden vectors for SD-JWT (RFC 9901) disclosure encoding + digests — shared with Swift. */
class DisclosureGoldenTest {

    private fun buildValue(spec: JsonValue): JsonValue {
        val o = spec as JsonValue.Obj
        return when ((o["t"] as JsonValue.Str).value) {
            "str" -> JsonValue.Str((o["v"] as JsonValue.Str).value)
            "num" -> JsonValue.NumInt((o["v"] as JsonValue.NumInt).value)
            "bool" -> JsonValue.Bool((o["v"] as JsonValue.Bool).value)
            else -> error("unknown value type")
        }
    }

    private fun JsonValue.Obj.str(k: String) = (this[k] as JsonValue.Str).value

    @Test
    fun disclosureDigestsMatchGolden() {
        val root = GoldenVectors.load("sdjwt/disclosures.json")

        // 1) digest = base64url(SHA-256(disclosure bytes)) — SD-JWT spec authoritative
        for (v in (root["digest_of_string"] as JsonValue.Arr).items) {
            val o = v as JsonValue.Obj
            val digest = Base64Url.encode(sha256(o.str("disclosure").encodeToByteArray()))
            assertEquals(o.str("digest"), digest, "digest_of_string '${o.str("name")}'")
        }

        // 2) our object-property disclosure serialization + digest
        for (v in (root["object_property"] as JsonValue.Arr).items) {
            val o = v as JsonValue.Obj
            val d = Disclosure.objectProperty(o.str("salt"), o.str("key"), buildValue(o["value"]!!))
            assertEquals(o.str("disclosure"), d.encoded, "object_property encoded '${o.str("name")}'")
            assertEquals(o.str("digest"), d.digest, "object_property digest '${o.str("name")}'")
        }

        // 3) our array-element disclosure serialization + digest
        for (v in (root["array_element"] as JsonValue.Arr).items) {
            val o = v as JsonValue.Obj
            val d = Disclosure.arrayElement(o.str("salt"), buildValue(o["value"]!!))
            assertEquals(o.str("disclosure"), d.encoded, "array_element encoded '${o.str("name")}'")
            assertEquals(o.str("digest"), d.digest, "array_element digest '${o.str("name")}'")
        }
    }
}
