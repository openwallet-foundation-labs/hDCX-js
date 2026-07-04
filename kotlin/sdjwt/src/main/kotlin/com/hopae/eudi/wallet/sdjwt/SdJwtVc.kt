package com.hopae.eudi.wallet.sdjwt

import com.hopae.eudi.wallet.cbor.cose.EcCurve
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import java.time.Instant

class SdJwtVcException(message: String) : Exception(message)

/** Resolved issuer signing key (SD-JWT VC §3.5). */
class IssuerSigningKey(val publicKey: EcPublicKey, val algorithm: SigningAlgorithm)

/**
 * Resolves the issuer key for an SD-JWT VC from its `iss` and JWS header.
 * Implementations: metadata (.well-known/jwt-vc-issuer), x509 (trust module, M3), or pinned.
 */
fun interface IssuerKeyResolver {
    suspend fun resolve(iss: String, header: JsonValue.Obj): IssuerSigningKey
}

/** A verified SD-JWT VC: profile-validated claims plus the fields callers act on. */
class VerifiedSdJwtVc(
    val vct: String,
    val issuer: String,
    val claims: JsonValue.Obj,
    val holderKey: EcPublicKey?,
    /** Status list reference (`status.status_list`) if present, for the status module. */
    val status: JsonValue.Obj?,
    val disclosedPaths: Map<String, List<String>>,
)

/**
 * SD-JWT VC verifier (draft-ietf-oauth-sd-jwt-vc): the profile layer over RFC 9901.
 *
 * Enforces: `typ` ∈ {dc+sd-jwt, vc+sd-jwt}; required `iss` and `vct`; time claims
 * (iat/exp/nbf) via [JwtTimeValidator]; issuer key resolution via [IssuerKeyResolver];
 * optional holder key binding. Fail-closed throughout.
 */
class SdJwtVcVerifier(
    private val issuerKeyResolver: IssuerKeyResolver,
    private val timeValidator: JwtTimeValidator,
) {
    companion object {
        // draft-ietf-oauth-sd-jwt-vc §3.1: typ MUST be dc+sd-jwt. (vc+sd-jwt was the
        // pre-2024-11 value, dropped over a conflict with W3C's vc media type.)
        private const val REQUIRED_TYP = "dc+sd-jwt"
    }

    suspend fun verify(
        sdJwtVc: SdJwt,
        keyBinding: SdJwtVerifier.KbRequirement? = null,
    ): VerifiedSdJwtVc {
        val jws = Jws.parse(sdJwtVc.jwt)

        val typ = (jws.header["typ"] as? JsonValue.Str)?.value
            ?: throw SdJwtVcException("missing 'typ' header")
        if (typ != REQUIRED_TYP) throw SdJwtVcException("unexpected typ '$typ' for SD-JWT VC (expected $REQUIRED_TYP)")

        // Peek issuer before signature verification only to resolve the key; the resolved
        // key then authenticates the payload, and iss is re-read from verified claims below.
        val unverifiedPayload = runCatching { JsonValue.parse(jws.payloadBytes.decodeToString()) }
            .getOrElse { throw SdJwtVcException("issuer payload is not JSON") } as? JsonValue.Obj
            ?: throw SdJwtVcException("issuer payload must be an object")
        val issForResolve = (unverifiedPayload["iss"] as? JsonValue.Str)?.value
            ?: throw SdJwtVcException("missing 'iss'")

        val issuerKey = issuerKeyResolver.resolve(issForResolve, jws.header)

        val verified = SdJwtVerifier.verify(sdJwtVc, issuerKey.publicKey, issuerKey.algorithm, keyBinding)
        val payload = verified.payload

        val iss = (payload["iss"] as? JsonValue.Str)?.value
            ?: throw SdJwtVcException("missing 'iss' in verified payload")
        val vct = (payload["vct"] as? JsonValue.Str)?.value
            ?: throw SdJwtVcException("missing 'vct'")

        timeValidator.validate(payload)

        return VerifiedSdJwtVc(
            vct = vct,
            issuer = iss,
            claims = verified.claims,
            holderKey = SdJwtVerifier.holderKeyFromCnf(payload),
            status = (payload["status"] as? JsonValue.Obj),
            disclosedPaths = verified.disclosedPaths,
        )
    }
}

/**
 * Resolver using the SD-JWT VC issuer metadata endpoint (draft §5):
 * `https://<host>/.well-known/jwt-vc-issuer/<path>`. Selects the JWK by `kid` header,
 * or the sole key when no `kid`. Cross-language and testable over [HttpTransport].
 */
class JwtVcMetadataKeyResolver(private val http: HttpTransport) : IssuerKeyResolver {

    override suspend fun resolve(iss: String, header: JsonValue.Obj): IssuerSigningKey {
        val metadata = fetchJson(metadataUrl(iss))
        if ((metadata["issuer"] as? JsonValue.Str)?.value != iss) {
            throw SdJwtVcException("issuer metadata 'issuer' does not match '$iss'")
        }
        val jwks = when {
            metadata["jwks"] is JsonValue.Obj -> metadata["jwks"] as JsonValue.Obj
            metadata["jwks_uri"] is JsonValue.Str ->
                fetchJson((metadata["jwks_uri"] as JsonValue.Str).value)
            else -> throw SdJwtVcException("issuer metadata has neither jwks nor jwks_uri")
        }
        val keys = (jwks["keys"] as? JsonValue.Arr)?.items?.filterIsInstance<JsonValue.Obj>()
            ?: throw SdJwtVcException("jwks.keys missing")

        val kid = (header["kid"] as? JsonValue.Str)?.value
        val jwk = when {
            kid != null -> keys.firstOrNull { (it["kid"] as? JsonValue.Str)?.value == kid }
                ?: throw SdJwtVcException("no JWK with kid '$kid'")
            keys.size == 1 -> keys.single()
            else -> throw SdJwtVcException("multiple JWKs but no kid in header")
        }

        val publicKey = JwkEc.fromJson(jwk) ?: throw SdJwtVcException("issuer JWK is not a supported EC key")
        val algorithm = (jwk["alg"] as? JsonValue.Str)?.value?.let { signingAlgorithmFromJwsName(it) }
            ?: defaultAlgFor(publicKey.curve)
        return IssuerSigningKey(publicKey, algorithm)
    }

    private fun defaultAlgFor(curve: EcCurve): SigningAlgorithm = when (curve) {
        EcCurve.P256 -> SigningAlgorithm.ES256
        EcCurve.P384 -> SigningAlgorithm.ES384
        EcCurve.P521 -> SigningAlgorithm.ES512
    }

    private suspend fun fetchJson(url: String): JsonValue.Obj {
        val response = http.execute(HttpRequest(HttpMethod.GET, url, listOf("Accept" to "application/json")))
        if (response.status !in 200..299) throw SdJwtVcException("GET $url failed: HTTP ${response.status}")
        return JsonValue.parse(response.body.decodeToString()) as? JsonValue.Obj
            ?: throw SdJwtVcException("$url did not return a JSON object")
    }

    private fun metadataUrl(iss: String): String {
        if (!iss.startsWith("https://")) throw SdJwtVcException("issuer must be https")
        val rest = iss.removePrefix("https://")
        val slash = rest.indexOf('/')
        return if (slash < 0) {
            "https://$rest/.well-known/jwt-vc-issuer"
        } else {
            val host = rest.substring(0, slash)
            val path = rest.substring(slash) // begins with '/'
            "https://$host/.well-known/jwt-vc-issuer$path"
        }
    }
}
