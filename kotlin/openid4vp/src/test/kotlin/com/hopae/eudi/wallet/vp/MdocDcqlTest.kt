package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.mdoc.MdocTestIssuer
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class MdocDcqlTest {

    private val docType = "org.iso.18013.5.1.mDL"
    private val namespace = "org.iso.18013.5.1"

    private fun heldMdoc(): HeldMdoc = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256)).publicKey
        val bytes = MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey,
            docType = docType, namespace = namespace,
            elements = listOf("family_name" to Cbor.Text("Han"), "given_name" to Cbor.Text("Jongho"), "age_over_18" to Cbor.Bool(true)),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = Instant.parse("2026-01-01T00:00:00Z"),
            validFrom = Instant.parse("2026-01-01T00:00:00Z"),
            validUntil = Instant.parse("2027-01-01T00:00:00Z"),
        )
        HeldMdoc("mdl-1", IssuerSigned.decode(bytes))
    }

    private fun query(json: String): DcqlQuery = DcqlQuery.parse(JsonValue.parse(json) as JsonValue.Obj)

    @Test
    fun matchesMdocByDoctypeAndNamespacePath() {
        val held = heldMdoc()
        val q = query(
            """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"$docType"},
               "claims":[{"path":["$namespace","family_name"]},{"path":["$namespace","given_name"]}]}]}"""
        )
        val result = DcqlEngine.match(q, listOf(held))
        assertTrue(result.isSatisfiable())
        val candidate = result.candidatesByQuery["mdl"]!!.single()
        assertEquals(
            listOf(listOf(namespace, "family_name"), listOf(namespace, "given_name")),
            candidate.disclosedPaths,
        )
    }

    @Test
    fun wrongDoctypeExcludes() {
        val held = heldMdoc()
        val q = query(
            """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.other"},
               "claims":[{"path":["$namespace","family_name"]}]}]}"""
        )
        assertTrue(DcqlEngine.match(q, listOf(held)).candidatesByQuery["mdl"]!!.isEmpty())
    }

    @Test
    fun valueConstraintMatchesElement() {
        val held = heldMdoc()
        val q = query(
            """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"$docType"},
               "claims":[{"path":["$namespace","age_over_18"],"values":[true]}]}]}"""
        )
        assertTrue(DcqlEngine.match(q, listOf(held)).isSatisfiable())
    }

    @Test
    fun oneElementPathRejectedAtParse() {
        // [namespace] only — no data element — is a malformed mso_mdoc claim path.
        assertFailsWith<DcqlException> {
            query("""{"credentials":[{"id":"mdl","format":"mso_mdoc","claims":[{"path":["$namespace"]}]}]}""")
        }
    }

    @Test
    fun nonStringSecondElementRejectedAtParse() {
        assertFailsWith<DcqlException> {
            query("""{"credentials":[{"id":"mdl","format":"mso_mdoc","claims":[{"path":["$namespace",0]}]}]}""")
        }
    }
}
