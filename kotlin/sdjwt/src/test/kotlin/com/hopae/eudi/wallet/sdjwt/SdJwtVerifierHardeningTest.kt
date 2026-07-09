package com.hopae.eudi.wallet.sdjwt

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * RFC 9901 verification rules that had no test:
 *  - §7.1(2.a) / §7.3(5.b): "The `none` algorithm MUST NOT be accepted."
 *  - §7.3(5.e): the KB-JWT's `iat` must fall "within an acceptable window" — presence is not enough,
 *    or a KB-JWT minted long ago would still authorise a presentation today.
 */
class SdJwtVerifierHardeningTest {

    private val audience = "https://verifier.example"
    private val nonce = "nonce-123"
    private val presentedAt = 1_700_000_100L

    private class Party(val area: SoftwareSecureArea, val issuer: EcPublicKey, val issued: SdJwt, val holderSigner: JwsSigner)

    private suspend fun party(): Party {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val holderKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        var n = 0
        val issued = SdJwtIssuer({ "salt-${++n}" }).issue(
            SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256),
            holderKey = holderKey.publicKey,
        ) {
            claim("iss", "https://issuer.example")
            sd("family_name", "Han")
        }
        return Party(area, issuerKey.publicKey, issued, SecureAreaJwsSigner(area, holderKey.handle, SigningAlgorithm.ES256))
    }

    private suspend fun present(p: Party, issuedAt: Long): SdJwt = SdJwtHolder.presentWithKeyBinding(
        issued = p.issued, select = { true }, audience = audience, nonce = nonce,
        issuedAt = issuedAt, signer = p.holderSigner,
    )

    private fun kb(now: Long, maxAge: Long = 300, skew: Long = 60) =
        SdJwtVerifier.KbRequirement(audience, nonce, now = { now }, maxAgeSeconds = maxAge, skewSeconds = skew)

    /* ---- §7.3(5.e): the iat window ---- */

    @Test
    fun acceptsAFreshKeyBindingJwt() = runBlocking {
        val p = party()
        val presented = present(p, presentedAt)
        SdJwtVerifier.verify(presented, p.issuer, SigningAlgorithm.ES256, keyBinding = kb(now = presentedAt + 10))
        Unit
    }

    /** The gap this closes: presence alone let a months-old KB-JWT through. */
    @Test
    fun rejectsAStaleKeyBindingJwt() = runBlocking<Unit> {
        val p = party()
        val presented = present(p, presentedAt)

        val error = assertFailsWith<SdJwtException> {
            SdJwtVerifier.verify(presented, p.issuer, SigningAlgorithm.ES256, keyBinding = kb(now = presentedAt + 301))
        }
        assertTrue("old" in error.message!!, "the error explains the window: ${error.message}")
    }

    @Test
    fun rejectsAKeyBindingJwtFromTheFuture() = runBlocking<Unit> {
        val p = party()
        val presented = present(p, presentedAt + 3600) // holder clock an hour fast

        assertFailsWith<SdJwtException> {
            SdJwtVerifier.verify(presented, p.issuer, SigningAlgorithm.ES256, keyBinding = kb(now = presentedAt))
        }
    }

    /** A holder clock slightly ahead is tolerated — that is what `skewSeconds` is for. */
    @Test
    fun toleratesSmallClockSkew() = runBlocking {
        val p = party()
        val presented = present(p, presentedAt + 30)
        SdJwtVerifier.verify(presented, p.issuer, SigningAlgorithm.ES256, keyBinding = kb(now = presentedAt, skew = 60))
        Unit
    }

    /* ---- §7.1(2.a) / §7.3(5.b): alg=none ---- */

    /**
     * Re-headers a compact JWS as `alg: none` while keeping the original signature bytes, so it survives
     * `Jws.parse` (which rejects an *empty* signature segment) and reaches the algorithm check — the
     * `none`-downgrade an attacker actually attempts.
     */
    private fun forgeNoneAlg(compact: String, typ: String?): String {
        val parts = compact.split(".")
        val headerJson = if (typ != null) """{"alg":"none","typ":"$typ"}""" else """{"alg":"none"}"""
        return "${Base64Url.encode(headerJson.encodeToByteArray())}.${parts[1]}.${parts[2]}"
    }

    @Test
    fun rejectsNoneAlgOnTheIssuerSignedJwt() = runBlocking<Unit> {
        val p = party()
        val forgedJwt = forgeNoneAlg(p.issued.jwt, typ = null)
        val forged = SdJwt(forgedJwt, p.issued.disclosures, null)

        val error = assertFailsWith<SdJwtException> { SdJwtVerifier.verify(forged, p.issuer, SigningAlgorithm.ES256) }
        assertTrue("none" in error.message!!, "the refusal names the algorithm: ${error.message}")
    }

    @Test
    fun rejectsNoneAlgOnTheKeyBindingJwt() = runBlocking<Unit> {
        val p = party()
        val presented = present(p, presentedAt)
        val forged = SdJwt(presented.jwt, presented.disclosures, forgeNoneAlg(presented.kbJwt!!, typ = "kb+jwt"))

        val error = assertFailsWith<SdJwtException> {
            SdJwtVerifier.verify(forged, p.issuer, SigningAlgorithm.ES256, keyBinding = kb(now = presentedAt))
        }
        assertTrue("none" in error.message!!, "the refusal names the algorithm: ${error.message}")
    }
}
