package com.hopae.eudi.wallet.sdjwt

import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Issue → present (subset + KB-JWT) → verify, over the SecureArea port end to end. */
class SdJwtE2eTest {

    /** The instant the KB-JWT is created; §7.3(5.e) judges it against the verifier's clock. */
    private val presentedAt = 1_700_000_100L

    private fun fixedSalts(): () -> String {
        var n = 0
        return { "salt-%02d".format(++n) }
    }

    private fun issueSample(
        issuerSigner: JwsSigner,
        holderKey: com.hopae.eudi.wallet.cbor.cose.EcPublicKey,
    ): SdJwt = runBlocking {
        SdJwtIssuer(fixedSalts()).issue(signer = issuerSigner, holderKey = holderKey) {
            claim("iss", "https://issuer.example")
            claim("iat", 1_700_000_000L)
            claim("vct", "urn:eudi:pid:1")
            sd("given_name", "John")
            sd("family_name", "Doe")
            sd("email", JsonValue.Str("john@example.com"))
            obj("address") {
                sd("street_address", JsonValue.Str("Main St 1"))
                claim("country", "DE")
            }
            arr(
                "nationalities",
                listOf(
                    SdArrayElement.sd(JsonValue.Str("DE")),
                    SdArrayElement.plain(JsonValue.Str("US")),
                )
            )
            sdObj("secret_box") {
                sd("inner", JsonValue.Str("treasure"))
            }
        }
    }

    @Test
    fun issuePresentVerify() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val holderKeyInfo = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val issuerSigner = SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256)
        val holderSigner = SecureAreaJwsSigner(area, holderKeyInfo.handle, SigningAlgorithm.ES256)

        val issued = issueSample(issuerSigner, holderKeyInfo.publicKey)

        // serialization roundtrip
        val reparsed = SdJwt.parse(issued.serialize())
        assertEquals(issued.disclosures.map { it.encoded }, reparsed.disclosures.map { it.encoded })
        assertNull(reparsed.kbJwt)

        // full verification (all disclosures, no KB)
        val full = SdJwtVerifier.verify(reparsed, issuerKey.publicKey, SigningAlgorithm.ES256)
        assertEquals(JsonValue.Str("John"), full.claims["given_name"])
        assertEquals(JsonValue.Str("Doe"), full.claims["family_name"])
        val address = full.claims["address"] as JsonValue.Obj
        assertEquals(JsonValue.Str("Main St 1"), address["street_address"])
        assertEquals(
            listOf(JsonValue.Str("DE"), JsonValue.Str("US")),
            (full.claims["nationalities"] as JsonValue.Arr).items,
        )
        assertEquals(
            JsonValue.Str("treasure"),
            ((full.claims["secret_box"] as JsonValue.Obj)["inner"]),
        )
        assertNull(full.claims["_sd_alg"])
        assertNull(full.claims["_sd"])

        // subset presentation with key binding: given_name + street + secret_box.inner
        val wanted = setOf(
            listOf("given_name"),
            listOf("address", "street_address"),
            listOf("secret_box", "inner"),
        )
        val presented = SdJwtHolder.presentWithKeyBinding(
            issued = issued,
            select = { path -> path in wanted },
            audience = "https://verifier.example",
            nonce = "nonce-123",
            issuedAt = presentedAt,
            signer = holderSigner,
        )

        val verified = SdJwtVerifier.verify(
            SdJwt.parse(presented.serialize()),
            issuerKey.publicKey,
            SigningAlgorithm.ES256,
            keyBinding = SdJwtVerifier.KbRequirement("https://verifier.example", "nonce-123", now = { presentedAt }),
        )
        assertEquals(JsonValue.Str("John"), verified.claims["given_name"])
        assertNull(verified.claims["family_name"], "family_name must stay undisclosed")
        assertNull(verified.claims["email"])
        assertEquals(
            JsonValue.Str("Main St 1"),
            (verified.claims["address"] as JsonValue.Obj)["street_address"],
        )
        // parent of secret_box.inner auto-included (recursive disclosure)
        assertEquals(
            JsonValue.Str("treasure"),
            ((verified.claims["secret_box"] as JsonValue.Obj)["inner"]),
        )
        // undisclosed sd array element omitted
        assertEquals(
            listOf(JsonValue.Str("US")),
            (verified.claims["nationalities"] as JsonValue.Arr).items,
        )
    }

    @Test
    fun negativeCases(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val holderKeyInfo = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val wrongKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val issuerSigner = SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256)
        val holderSigner = SecureAreaJwsSigner(area, holderKeyInfo.handle, SigningAlgorithm.ES256)

        val issued = issueSample(issuerSigner, holderKeyInfo.publicKey)

        // wrong issuer key
        assertFailsWith<SdJwtException> {
            SdJwtVerifier.verify(issued, wrongKey.publicKey, SigningAlgorithm.ES256)
        }

        // tampered disclosure: value swapped -> digest no longer referenced -> unused disclosure
        val forged = Disclosure.objectProperty("salt-99", "given_name", JsonValue.Str("Mallory"))
        val tampered = SdJwt(issued.jwt, issued.disclosures.dropLast(1) + forged)
        assertFailsWith<SdJwtException> {
            SdJwtVerifier.verify(tampered, issuerKey.publicKey, SigningAlgorithm.ES256)
        }

        val presented = SdJwtHolder.presentWithKeyBinding(
            issued = issued,
            select = { true },
            audience = "https://verifier.example",
            nonce = "nonce-123",
            issuedAt = presentedAt,
            signer = holderSigner,
        )

        // nonce mismatch
        assertFailsWith<SdJwtException> {
            SdJwtVerifier.verify(
                presented, issuerKey.publicKey, SigningAlgorithm.ES256,
                keyBinding = SdJwtVerifier.KbRequirement("https://verifier.example", "other-nonce", now = { presentedAt }),
            )
        }

        // sd_hash mismatch: drop a disclosure after KB was bound
        val stripped = SdJwt(presented.jwt, presented.disclosures.drop(1), presented.kbJwt)
        assertFailsWith<SdJwtException> {
            SdJwtVerifier.verify(
                stripped, issuerKey.publicKey, SigningAlgorithm.ES256,
                keyBinding = SdJwtVerifier.KbRequirement("https://verifier.example", "nonce-123", now = { presentedAt }),
            )
        }

        // KB required but missing
        assertFailsWith<SdJwtException> {
            SdJwtVerifier.verify(
                issued, issuerKey.publicKey, SigningAlgorithm.ES256,
                keyBinding = SdJwtVerifier.KbRequirement("https://verifier.example", "nonce-123", now = { presentedAt }),
            )
        }
        Unit
    }

    @Test
    fun decoysAndX5cHeader() = runBlocking {
        val area = SoftwareSecureArea()
        val k = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val signer = SecureAreaJwsSigner(area, k.handle, SigningAlgorithm.ES256)

        val issued = SdJwtIssuer(fixedSalts()).issue(signer = signer, decoysPerSdStruct = 3) {
            sd("given_name", "John")
        }
        val v = SdJwtVerifier.verify(issued, k.publicKey, SigningAlgorithm.ES256)
        assertEquals(JsonValue.Str("John"), v.claims["given_name"])
        assertEquals(4, (v.payload["_sd"] as JsonValue.Arr).items.size, "1 real + 3 decoy digests")

        val certBytes = byteArrayOf(0x30, 0x01, 0x02)
        val header = JsonValue.Obj(
            listOf(
                "alg" to JsonValue.Str("ES256"),
                "x5c" to JsonValue.Arr(listOf(JsonValue.Str(java.util.Base64.getEncoder().encodeToString(certBytes)))),
            )
        )
        assertEquals(certBytes.toList(), Jws(header, "h", "p", ByteArray(0)).x5c!!.single().toList())
    }

    @Test
    fun jsonSerializerBasics() {
        val obj = JsonValue.Obj(
            listOf(
                "b" to JsonValue.Str("q\"\\\n"),
                "a" to JsonValue.NumInt(-42),
                "c" to JsonValue.Arr(listOf(JsonValue.Bool(true), JsonValue.Null)),
            )
        )
        val text = obj.serialize()
        assertEquals("""{"b":"q\"\\\n","a":-42,"c":[true,null]}""", text)
        assertEquals(obj, JsonValue.parse(text), "parse(serialize()) must be identity")
        assertEquals(JsonValue.Str("😀ü水"), JsonValue.parse("\"\\ud83d\\ude00ü水\""))
        assertFailsWith<JsonException> { JsonValue.parse("{} trailing") }
        assertFailsWith<JsonException> { JsonValue.parse("{\"a\":1,\"a\":2}") }
        assertFailsWith<JsonException> { JsonValue.parse("{\"a\":}") }
        assertTrue(JsonValue.parse("9007199254740993") is JsonValue.NumInt, "big integers stay exact")
    }
}
