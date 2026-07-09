package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Minor HAIP gaps: refresh-token reissuance (RFC 6749 §6) and signed issuer metadata
 * (OpenID4VCI §12.2.2 content negotiation + §12.2.3 signed-metadata rules).
 */
class RefreshSignedMetadataTest {

    private val now = 1_700_000_000L
    private val issuer = "https://issuer.example"
    private fun rng() = Rng { size -> ByteArray(size) { (it + 1).toByte() } }

    private suspend fun keys(area: SoftwareSecureArea): IssuanceKeys {
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        return IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
    }

    @Test
    fun reissueWithRefreshToken() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        val client = Openid4VciClient(mock, rng(), clock = { now })

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        val first = client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys(area), txCode = "1234")
        assertEquals(1, first.credentials.size)
        assertTrue(first.canReissue, "issuer granted a refresh token")

        // renew with rotated holder keys — no browser re-authorization
        val renewed = client.reissue(first, keys(area))
        assertEquals(1, renewed.credentials.size)
        assertTrue(renewed.canReissue, "renewed response carries a fresh refresh token")
    }

    /** Verifier: proves the JWS signature against the issuer key and returns its claims (trust is the adapter's job). */
    private fun verifier(issuerKey: KeyInfo) = SignedMetadataVerifier { jws ->
        val parsed = Jws.parse(jws)
        require(parsed.verify(issuerKey.publicKey, SigningAlgorithm.ES256)) { "bad signed metadata signature" }
        JsonValue.parse(parsed.payloadBytes.decodeToString()) as JsonValue.Obj
    }

    /** A §12.2.3 payload: the metadata parameters as top-level claims, plus sub/iat (and optionally exp). */
    private fun metadataClaims(
        sub: String = issuer,
        iat: Long? = now,
        exp: Long? = null,
        nonceEndpoint: String = "$issuer/signed-nonce",
    ): JsonValue.Obj = JsonValue.Obj(
        buildList {
            add("credential_issuer" to JsonValue.Str(issuer))
            add("credential_endpoint" to JsonValue.Str("$issuer/credential"))
            add("nonce_endpoint" to JsonValue.Str(nonceEndpoint))
            add("sub" to JsonValue.Str(sub))
            iat?.let { add("iat" to JsonValue.NumInt(it)) }
            exp?.let { add("exp" to JsonValue.NumInt(it)) }
        }
    )

    private suspend fun signMetadata(
        area: SoftwareSecureArea,
        key: KeyInfo,
        payload: JsonValue.Obj = metadataClaims(),
        typ: String = SIGNED_METADATA_TYP,
    ): String {
        val header = JsonValue.Obj(listOf("alg" to JsonValue.Str("ES256"), "typ" to JsonValue.Str(typ)))
        val signer = SecureAreaJwsSigner(area, key.handle, SigningAlgorithm.ES256)
        return Jws.sign(header, payload.serialize().encodeToByteArray(), signer).compact()
    }

    private suspend fun clientFor(
        area: SoftwareSecureArea,
        issuerKey: KeyInfo,
        mock: MockIssuer,
        require: Boolean = true,
    ) = Openid4VciClient(
        mock, rng(), clock = { now },
        metadataPolicy = if (require) IssuerMetadataPolicy.RequireSigned(verifier(issuerKey))
        else IssuerMetadataPolicy.PreferSigned(verifier(issuerKey)),
    )

    @Test
    fun requireSignedUsesVerifiedMetadata() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        mock.signedMetadata = signMetadata(area, issuerKey) // pins the nonce endpoint authoritatively

        val meta = clientFor(area, issuerKey, mock).loadIssuerMetadata(issuer)

        assertEquals(issuer, meta.credentialIssuer)
        assertEquals("$issuer/signed-nonce", meta.nonceEndpoint) // came from the JWT payload, not the JSON
        assertEquals("application/jwt", mock.lastMetadataAccept) // §12.2.2: signalled signed-only
    }

    @Test
    fun ignoreSignedAsksForJsonOnly() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        mock.signedMetadata = signMetadata(area, issuerKey)

        val meta = Openid4VciClient(mock, rng(), clock = { now }).loadIssuerMetadata(issuer)

        assertEquals("application/json", mock.lastMetadataAccept)
        assertEquals("$issuer/nonce", meta.nonceEndpoint) // the unsigned JSON, signed metadata never requested
    }

    @Test
    fun preferSignedUsesSignedThenFallsBackToJson() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))

        val signing = MockIssuer(area, issuerKey, now)
        signing.signedMetadata = signMetadata(area, issuerKey)
        assertEquals("$issuer/signed-nonce", clientFor(area, issuerKey, signing, require = false).loadIssuerMetadata(issuer).nonceEndpoint)
        assertTrue(signing.lastMetadataAccept!!.contains("application/jwt"))

        val unsigned = MockIssuer(area, issuerKey, now) // does not sign — must not fail
        assertEquals("$issuer/nonce", clientFor(area, issuerKey, unsigned, require = false).loadIssuerMetadata(issuer).nonceEndpoint)
    }

    @Test
    fun requireSignedRejectsUnsignedMetadata() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now) // no signedMetadata set

        assertFailsWith<VciException.MetadataError> { clientFor(area, issuerKey, mock).loadIssuerMetadata(issuer) }
    }

    @Test
    fun requireSignedRejectsBadSignature() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val rogue = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        mock.signedMetadata = signMetadata(area, rogue)

        assertFailsWith<IllegalArgumentException> { clientFor(area, issuerKey, mock).loadIssuerMetadata(issuer) }
    }

    @Test
    fun rejectsWrongTyp() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        mock.signedMetadata = signMetadata(area, issuerKey, typ = "jwt") // §12.2.3: typ MUST be the metadata type

        assertFailsWith<VciException.MetadataError> { clientFor(area, issuerKey, mock).loadIssuerMetadata(issuer) }
    }

    @Test
    fun rejectsSymmetricAlg() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        // §12.2.3: alg MUST NOT be `none` or a MAC — rejected on the header, before any signature check.
        val header = """{"alg":"HS256","typ":"$SIGNED_METADATA_TYP"}"""
        mock.signedMetadata = "${Base64Url.encode(header.encodeToByteArray())}." +
            "${Base64Url.encode(metadataClaims().serialize().encodeToByteArray())}.c2ln"

        assertFailsWith<VciException.MetadataError> { clientFor(area, issuerKey, mock).loadIssuerMetadata(issuer) }
    }

    @Test
    fun rejectsSubMismatch() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        mock.signedMetadata = signMetadata(area, issuerKey, metadataClaims(sub = "https://evil.example"))

        assertFailsWith<VciException.MetadataError> { clientFor(area, issuerKey, mock).loadIssuerMetadata(issuer) }
    }

    @Test
    fun rejectsMissingIat() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        mock.signedMetadata = signMetadata(area, issuerKey, metadataClaims(iat = null))

        assertFailsWith<VciException.MetadataError> { clientFor(area, issuerKey, mock).loadIssuerMetadata(issuer) }
    }

    @Test
    fun rejectsExpiredMetadata() = runBlocking<Unit> {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)
        mock.signedMetadata = signMetadata(area, issuerKey, metadataClaims(exp = now - 1))

        assertFailsWith<VciException.MetadataError> { clientFor(area, issuerKey, mock).loadIssuerMetadata(issuer) }
    }
}
