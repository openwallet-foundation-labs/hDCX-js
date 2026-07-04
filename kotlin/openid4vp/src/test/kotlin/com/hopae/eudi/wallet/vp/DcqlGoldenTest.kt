package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/** Cross-language golden vectors for DCQL matching (OpenID4VP §6, incl. null/values edges) — shared with Swift. */
class DcqlGoldenTest {

    private class VectorCred(
        override val credentialId: String,
        override val format: String,
        override val vct: String?,
        override val docType: String?,
        override val claims: JsonValue.Obj,
    ) : QueryableCredential

    private fun loadVectors(): JsonValue.Obj {
        var d = File(System.getProperty("user.dir")).absoluteFile
        repeat(8) {
            val v = File(d, "vectors/dcql/matching.json")
            if (v.isFile) return JsonValue.parse(v.readText()) as JsonValue.Obj
            d = d.parentFile ?: return@repeat
        }
        error("vectors/dcql/matching.json not found")
    }

    private fun JsonValue.Obj.str(k: String) = (this[k] as? JsonValue.Str)?.value

    @Test
    fun dcqlMatchingMatchesGolden() {
        val root = loadVectors()
        val c = root["credential"] as JsonValue.Obj
        val cred = VectorCred(c.str("credentialId")!!, c.str("format")!!, c.str("vct"), c.str("docType"), c["claims"] as JsonValue.Obj)

        for (case in (root["cases"] as JsonValue.Arr).items) {
            val o = case as JsonValue.Obj
            val name = o.str("name")!!
            val query = DcqlQuery.parse(o["query"] as JsonValue.Obj)
            val result = DcqlEngine.match(query, listOf(cred))
            val expected = o["expected"] as JsonValue.Obj

            assertEquals((expected["satisfiable"] as JsonValue.Bool).value, result.isSatisfiable(), "satisfiable '$name'")

            val expectedPaths = (expected["disclosedPaths"] as JsonValue.Arr).items.map { path ->
                (path as JsonValue.Arr).items.map { (it as JsonValue.Str).value }
            }.toSet()
            val actualPaths = result.candidatesByQuery["q"]?.firstOrNull()?.disclosedPaths?.toSet() ?: emptySet()
            assertEquals(expectedPaths, actualPaths, "disclosedPaths '$name'")
        }
    }
}
