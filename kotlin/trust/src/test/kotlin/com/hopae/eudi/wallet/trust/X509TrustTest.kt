package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.cbor.cose.Der
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JwsSigner
import com.hopae.eudi.wallet.sdjwt.JwtTimeValidator
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.vp.VpException
import kotlinx.coroutines.runBlocking
import java.security.PrivateKey
import java.security.Signature
import java.util.Base64
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class X509TrustTest {

    private val validAt = { Date(1_700_000_000_000L) }

    private fun leafSigner(priv: PrivateKey): JwsSigner = object : JwsSigner {
        override val algorithm = SigningAlgorithm.ES256
        override suspend fun sign(signingInput: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(priv); update(signingInput); Der.derSignatureToRaw(sign(), 32) }
    }

    private fun signedRequest(leaf: TestCerts.Cert, payload: String): Jws = runBlocking {
        val header = JsonValue.Obj(
            listOf(
                "alg" to JsonValue.Str("ES256"),
                "typ" to JsonValue.Str("oauth-authz-req+jwt"),
                "x5c" to JsonValue.Arr(listOf(JsonValue.Str(Base64.getEncoder().encodeToString(leaf.der)))),
            )
        )
        Jws.sign(header, payload.encodeToByteArray(), leafSigner(leaf.keyPair.private))
    }

    // ---- chain validation ----

    @Test
    fun chainValidatesToAnchor() = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Leaf")
        val validator = X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)
        val chain = validator.validate(listOf(leaf.der))
        assertEquals(leaf.certificate, chain.first())
    }

    @Test
    fun untrustedCaRejected(): Unit = runBlocking {
        val ca = TestCerts.makeCa("Real CA")
        val otherCa = TestCerts.makeCa("Rogue CA")
        val leaf = TestCerts.makeLeaf(ca, "Leaf")
        val validator = X509ChainValidator(TrustAnchors(listOf(otherCa.certificate)), at = validAt)
        assertFailsWith<TrustException> { validator.validate(listOf(leaf.der)) }
    }

    @Test
    fun expiredLeafRejected(): Unit = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Leaf", notAfter = 1_700_000_000_000L - 1000L) // already expired at validAt
        val validator = X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)
        assertFailsWith<TrustException> { validator.validate(listOf(leaf.der)) }
    }

    @Test
    fun dynamicAnchorSourceRefreshes() = runBlocking {
        // The source starts trusting only a rogue CA, then updates to the real one — the
        // validator picks up the new anchors on the next validate() with no rebuild.
        val realCa = TestCerts.makeCa("Real CA")
        val rogueCa = TestCerts.makeCa("Rogue CA")
        val leaf = TestCerts.makeLeaf(realCa, "Leaf")

        var current = TrustAnchors(listOf(rogueCa.certificate))
        val validator = X509ChainValidator(TrustAnchorSource { current }, at = validAt)

        assertFailsWith<TrustException> { validator.validate(listOf(leaf.der)) } // rogue-only: rejected
        current = TrustAnchors(listOf(realCa.certificate))                        // trust list "refreshes"
        val chain = validator.validate(listOf(leaf.der))                          // now trusted
        assertEquals(leaf.certificate, chain.first())
    }

    // ---- OpenID4VP request verification ----

    @Test
    fun x509SanDnsRequestTrusted() = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Verifier", dnsName = "verifier.example.com")
        val verifier = X509RequestVerifier(X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt))
        val jws = signedRequest(leaf, """{"nonce":"n"}""")
        val info = verifier.verifyRequestObject(jws, "x509_san_dns:verifier.example.com", "x509_san_dns")
        assertTrue(info.trusted)
        assertEquals("Verifier", info.commonName)
    }

    @Test
    fun x509SanDnsMismatchRejected(): Unit = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Verifier", dnsName = "verifier.example.com")
        val verifier = X509RequestVerifier(X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt))
        val jws = signedRequest(leaf, """{"nonce":"n"}""")
        assertFailsWith<VpException.VerifierNotTrusted> {
            verifier.verifyRequestObject(jws, "x509_san_dns:evil.example.com", "x509_san_dns")
        }
    }

    @Test
    fun x509HashRequestTrusted() = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Verifier")
        val validator = X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)
        val thumbprint = X509Support.sha256Thumbprint(leaf.certificate)
        val jws = signedRequest(leaf, """{"nonce":"n"}""")
        val info = X509RequestVerifier(validator).verifyRequestObject(jws, "x509_hash:$thumbprint", "x509_hash")
        assertTrue(info.trusted)
    }

    @Test
    fun x509HashMismatchRejected(): Unit = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Verifier")
        val validator = X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)
        val jws = signedRequest(leaf, """{"nonce":"n"}""")
        assertFailsWith<VpException.VerifierNotTrusted> {
            X509RequestVerifier(validator).verifyRequestObject(jws, "x509_hash:WRONGHASH", "x509_hash")
        }
    }

    @Test
    fun tamperedRequestSignatureRejected(): Unit = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Verifier", dnsName = "verifier.example.com")
        val validator = X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)
        val jws = signedRequest(leaf, """{"nonce":"n"}""")
        val tampered = Jws(jws.header, jws.headerB64, Base64Url.encode("""{"nonce":"evil"}"""), jws.signature)
        assertFailsWith<VpException.VerifierNotTrusted> {
            X509RequestVerifier(validator).verifyRequestObject(tampered, "x509_san_dns:verifier.example.com", "x509_san_dns")
        }
    }

    // ---- verifier_info: registrar_dataset (ETSI TS 119 472-2 §6.3) ----

    private fun registrarVerifier() =
        WRPRCVerifier(X509ChainValidator(TrustAnchors(listOf(TestCerts.makeCa("Registrar CA").certificate)), at = validAt),
            JwtTimeValidator(now = { validAt().toInstant() }))

    /** A `registrar_dataset` (self-declared, no WRPRC) is parsed and surfaced, attested = false. */
    @Test
    fun verifierInfoDatasetParsed() = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Verifier", dnsName = "verifier.example.com")
        val validator = X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)
        val payload = """{"nonce":"n","verifier_info":[{"format":"registrar_dataset","data":{""" +
            """"identifier":[{"type":"LEI","identifier":"HOPAE-TEST-RP"}],""" +
            """"registryURI":"https://registrar.example/registrar","policyURI":"https://rp.example/privacy",""" +
            """"intendedUseIdentifier":"use-1","srvDescription":[{"lang":"en","content":"Test RP"}],""" +
            """"purpose":[{"lang":"en","content":"Age check"}],""" +
            """"credential":[{"format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claim":[{"path":["org.iso.18013.5.1","given_name"]}]}]}}]}"""
        val jws = signedRequest(leaf, payload)
        val info = X509RequestVerifier(validator, registrarVerifier())
            .verifyRequestObject(jws, "x509_san_dns:verifier.example.com", "x509_san_dns")
        val reg = info.registration!!
        assertEquals(false, reg.attested, "a dataset-only registration is not registrar-attested")
        assertEquals("HOPAE-TEST-RP", reg.dataset?.identifier)
        assertEquals("https://registrar.example/registrar", reg.dataset?.registryURI)
        assertEquals("https://rp.example/privacy", reg.dataset?.policyURI)
        assertEquals(1, reg.registeredCredentials.size)
        assertEquals(listOf(listOf("org.iso.18013.5.1", "given_name")), reg.registeredCredentials.first().claims)
    }

    /** A malformed `verifier_info` (registration_cert without the mandatory dataset) is best-effort: it yields
     *  no registration rather than failing the request — the signature is still authentic and the chain trusted. */
    @Test
    fun registrationCertWithoutDatasetIgnored() = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Verifier", dnsName = "verifier.example.com")
        val validator = X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)
        val fakeCert = Base64Url.encode("not-a-real-wrprc".encodeToByteArray())
        val payload = """{"nonce":"n","verifier_info":[{"format":"registration_cert","data":"$fakeCert"}]}"""
        val jws = signedRequest(leaf, payload)
        val info = X509RequestVerifier(validator, registrarVerifier())
            .verifyRequestObject(jws, "x509_san_dns:verifier.example.com", "x509_san_dns")
        assertTrue(info.trusted, "signature + chain are fine")
        assertEquals(null, info.registration, "a registration_cert without the mandatory dataset → no registration (soft)")
    }

    /** Trust is informational: a request signed by a cert that does NOT chain to a trusted reader anchor still
     *  resolves — with `trusted = false` — so the wallet can show "not trusted" and let the User decide. */
    @Test
    fun untrustedVerifierResolvesAsNotTrusted() = runBlocking {
        val rogue = TestCerts.makeCa("Rogue CA")
        val leaf = TestCerts.makeLeaf(rogue, "Verifier", dnsName = "verifier.example.com")
        val validator = X509ChainValidator(TrustAnchors(listOf(TestCerts.makeCa("Real CA").certificate)), at = validAt)
        val jws = signedRequest(leaf, """{"nonce":"n"}""")
        val info = X509RequestVerifier(validator).verifyRequestObject(jws, "x509_san_dns:verifier.example.com", "x509_san_dns")
        assertEquals(false, info.trusted, "an untrusted chain surfaces as trusted=false, not an error")
        assertEquals("Verifier", info.commonName)
    }

    /** But authenticity is still enforced: a tampered signature is rejected even in the soft-trust model. */
    @Test
    fun tamperedSignatureStillRejected(): Unit = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Verifier", dnsName = "verifier.example.com")
        val validator = X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)
        val jws = signedRequest(leaf, """{"nonce":"n"}""")
        val tampered = Jws(jws.header, jws.headerB64, Base64Url.encode("""{"nonce":"evil"}"""), jws.signature)
        assertFailsWith<VpException.VerifierNotTrusted> {
            X509RequestVerifier(validator).verifyRequestObject(tampered, "x509_san_dns:verifier.example.com", "x509_san_dns")
        }
    }

    /** No `verifier_info` at all → registration stays null even with registrar trust configured (interop). */
    @Test
    fun verifierInfoAbsentRegistrationNull() = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "Verifier", dnsName = "verifier.example.com")
        val validator = X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt)
        val jws = signedRequest(leaf, """{"nonce":"n"}""")
        val info = X509RequestVerifier(validator, registrarVerifier())
            .verifyRequestObject(jws, "x509_san_dns:verifier.example.com", "x509_san_dns")
        assertEquals(null, info.registration)
    }

    // ---- issuer key resolution ----

    @Test
    fun x5cIssuerKeyResolves() = runBlocking {
        val ca = TestCerts.makeCa()
        val leaf = TestCerts.makeLeaf(ca, "PID DS")
        val resolver = X5cIssuerKeyResolver(X509ChainValidator(TrustAnchors(listOf(ca.certificate)), at = validAt))
        val header = JsonValue.Obj(listOf("x5c" to JsonValue.Arr(listOf(JsonValue.Str(Base64.getEncoder().encodeToString(leaf.der))))))
        val key = resolver.resolve("https://issuer.example", header)
        assertContentEquals(X509Support.ecPublicKey(leaf.certificate).x, key.publicKey.x)
    }

    @Test
    fun x5cIssuerUntrustedRejected(): Unit = runBlocking {
        val ca = TestCerts.makeCa()
        val rogue = TestCerts.makeCa("Rogue")
        val leaf = TestCerts.makeLeaf(ca, "PID DS")
        val resolver = X5cIssuerKeyResolver(X509ChainValidator(TrustAnchors(listOf(rogue.certificate)), at = validAt))
        val header = JsonValue.Obj(listOf("x5c" to JsonValue.Arr(listOf(JsonValue.Str(Base64.getEncoder().encodeToString(leaf.der))))))
        assertFailsWith<TrustException> { resolver.resolve("https://issuer.example", header) }
    }

    // ---- real EUDI trust anchor ----

    @Test
    fun realEudiCaLoadsAsSelfSignedAnchor() {
        val der = X509TrustTest::class.java.getResourceAsStream("/pid_issuer_ca_ut_02.der")!!.readBytes()
        val ca = X509Support.parse(der)
        assertEquals(ca.subjectX500Principal, ca.issuerX500Principal, "IACA is a self-signed root")
        assertTrue(ca.basicConstraints >= 0, "must be a CA certificate")
        assertContentEquals(der, ca.encoded)
    }
}
