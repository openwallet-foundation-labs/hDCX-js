package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.JwkEc
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.SdJwtIssuer
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import java.security.MessageDigest

/**
 * A mock OpenID4VCI issuer that actually verifies DPoP + key proofs and issues a real
 * SD-JWT VC. Not a stub: signatures, htu/htm/ath, aud and c_nonce are checked, and the
 * first token request is answered with a DPoP-Nonce challenge to exercise the retry path.
 */
class MockIssuer(
    private val area: SoftwareSecureArea,
    private val issuerKey: KeyInfo,
    private val now: Long,
) : HttpTransport {

    private val issuer = "https://issuer.example"
    private val preAuthCode = "PRE-AUTH-123"
    private var expectedNonce: String? = null
    private var cNonce: String? = null
    private var accessToken: String? = null
    var seenDpopNonceRetry = false; private set

    // authorization code flow state
    private var parRequestUri: String? = null
    private var parChallenge: String? = null
    private val authCode = "AUTH-CODE-XYZ"
    private var authCodeChallenge: String? = null
    var seenPar = false; private set

    val credentialOfferJson = """
        {"credential_issuer":"$issuer",
         "credential_configuration_ids":["eu.europa.ec.eudi.pid.1"],
         "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":
           {"pre-authorized_code":"$preAuthCode","tx_code":{"length":4,"input_mode":"numeric"}}}}
    """.trimIndent()

    override suspend fun execute(request: HttpRequest): HttpResponse {
        val path = request.url.removePrefix(issuer)
        return when {
            path == "/.well-known/openid-credential-issuer" -> ok(issuerMetadata())
            path == "/.well-known/oauth-authorization-server" -> ok(asMetadata())
            path == "/.well-known/jwt-vc-issuer" -> ok(jwtVcIssuerMetadata())
            path == "/token" -> handleToken(request)
            path == "/nonce" -> handleNonce()
            path == "/credential" -> handleCredential(request)
            path == "/par" -> handlePar(request)
            path.startsWith("/authorize") -> handleAuthorize(request)
            else -> HttpResponse(404, emptyList(), "not found".encodeToByteArray())
        }
    }

    /** PAR endpoint: validate the pushed request and return a request_uri. */
    private fun handlePar(request: HttpRequest): HttpResponse {
        seenPar = true
        val form = parseForm(request.body!!.decodeToString())
        require(form["response_type"] == "code") { "PAR: response_type must be code" }
        require(form["code_challenge_method"] == "S256") { "PAR: expected S256 PKCE" }
        require(form["redirect_uri"] != null) { "PAR: missing redirect_uri" }
        val details = JsonValue.parse(form["authorization_details"]!!) as JsonValue.Arr
        require(((details.items[0] as JsonValue.Obj)["type"] as JsonValue.Str).value == "openid_credential")
        authCodeChallenge = form["code_challenge"]
        parRequestUri = "urn:ietf:params:oauth:request_uri:mock-${form["state"]}"
        return HttpResponse(
            201,
            listOf("Content-Type" to "application/json"),
            """{"request_uri":"$parRequestUri","expires_in":90}""".encodeToByteArray(),
        )
    }

    /** Authorization endpoint: a browser would land here; the mock just checks the request_uri. */
    private fun handleAuthorize(request: HttpRequest): HttpResponse {
        val query = request.url.substringAfter('?', "")
        val params = parseForm(query)
        require(params["client_id"] != null) { "authorize: missing client_id" }
        require(params["request_uri"] == parRequestUri) { "authorize: unknown request_uri" }
        // emulate the redirect the browser would follow (host extracts code from Location)
        return HttpResponse(302, listOf("Location" to "wallet://cb?code=$authCode&state=..."), ByteArray(0))
    }

    private suspend fun handleToken(request: HttpRequest): HttpResponse {
        val form = parseForm(request.body!!.decodeToString())
        val dpopNonce = verifyDpop(request, "POST", "$issuer/token", accessToken = null)

        when (form["grant_type"]) {
            GRANT_PRE_AUTHORIZED -> {
                require(form["pre-authorized_code"] == preAuthCode) { "wrong pre-auth code" }
                require(form["tx_code"] == "1234") { "wrong tx_code" }
            }
            "authorization_code" -> {
                require(form["code"] == authCode) { "wrong authorization code" }
                // PKCE verification: SHA256(verifier) must equal the pushed challenge
                val verifier = form["code_verifier"] ?: error("missing code_verifier")
                val computed = Base64Url.encode(sha256(verifier.encodeToByteArray()))
                require(computed == authCodeChallenge) { "PKCE verification failed" }
            }
            else -> error("unsupported grant_type ${form["grant_type"]}")
        }

        if (dpopNonce == null) {
            // demand a nonce on the first attempt
            val serverNonce = "dpop-nonce-token"
            expectedNonce = serverNonce
            return HttpResponse(
                400,
                listOf("DPoP-Nonce" to serverNonce, "Content-Type" to "application/json"),
                """{"error":"use_dpop_nonce"}""".encodeToByteArray(),
            )
        }
        seenDpopNonceRetry = true
        accessToken = "ACCESS-" + Base64Url.encode(byteArrayOf(1, 2, 3, 4))
        cNonce = "c-nonce-xyz"
        return ok("""{"access_token":"$accessToken","token_type":"DPoP","expires_in":3600}""")
    }

    private fun handleNonce(): HttpResponse = ok("""{"c_nonce":"${cNonce ?: "c-nonce-xyz"}"}""")

    private suspend fun handleCredential(request: HttpRequest): HttpResponse {
        val token = accessToken ?: return HttpResponse(401, emptyList(), "no token".encodeToByteArray())
        require(request.headers.any { it.first == "Authorization" && it.second == "DPoP $token" }) { "bad auth" }
        verifyDpop(request, "POST", "$issuer/credential", accessToken = token) // asserts ath binding internally

        val body = JsonValue.parse(request.body!!.decodeToString()) as JsonValue.Obj
        val proofJwt = (((body["proofs"] as JsonValue.Obj)["jwt"] as JsonValue.Arr).items[0] as JsonValue.Str).value
        val holderKey = verifyKeyProof(proofJwt)

        val credential = issueSdJwtVc(holderKey)
        return ok("""{"credentials":[{"credential":"$credential"}],"notification_id":"n-1"}""")
    }

    /** Verifies a DPoP proof; returns its `nonce` claim (null if absent). Throws on any invalidity. */
    private suspend fun verifyDpop(request: HttpRequest, htm: String, htu: String, accessToken: String?): String? {
        val dpop = request.headers.firstOrNull { it.first == "DPoP" }?.second ?: error("missing DPoP header")
        val jws = Jws.parse(dpop)
        require((jws.header["typ"] as JsonValue.Str).value == "dpop+jwt")
        val jwk = jws.header["jwk"] as JsonValue.Obj
        val key = JwkEc.fromJson(jwk) ?: error("bad DPoP jwk")
        require(jws.verify(key, SigningAlgorithm.ES256)) { "DPoP signature invalid" }

        val claims = JsonValue.parse(jws.payloadBytes.decodeToString()) as JsonValue.Obj
        require((claims["htm"] as JsonValue.Str).value == htm) { "DPoP htm mismatch" }
        require((claims["htu"] as JsonValue.Str).value == htu) { "DPoP htu mismatch" }
        require(claims["jti"] is JsonValue.Str) { "DPoP jti missing" }
        if (accessToken != null) {
            val expectedAth = Base64Url.encode(sha256(accessToken.encodeToByteArray()))
            require((claims["ath"] as JsonValue.Str).value == expectedAth) { "DPoP ath mismatch" }
        }
        return (claims["nonce"] as? JsonValue.Str)?.value
    }

    private suspend fun verifyKeyProof(proofJwt: String): EcPublicKey {
        val jws = Jws.parse(proofJwt)
        require((jws.header["typ"] as JsonValue.Str).value == "openid4vci-proof+jwt") { "wrong proof typ" }
        val key = JwkEc.fromJson(jws.header["jwk"] as JsonValue.Obj) ?: error("bad proof jwk")
        require(jws.verify(key, SigningAlgorithm.ES256)) { "proof signature invalid" }
        val claims = JsonValue.parse(jws.payloadBytes.decodeToString()) as JsonValue.Obj
        require((claims["aud"] as JsonValue.Str).value == issuer) { "proof aud mismatch" }
        require((claims["nonce"] as JsonValue.Str).value == cNonce) { "proof nonce mismatch" }
        return key
    }

    private suspend fun issueSdJwtVc(holderKey: EcPublicKey): String {
        val signer = SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256)
        var n = 0
        val sdJwt = SdJwtIssuer({ "salt-${++n}" }).issue(
            signer = signer,
            holderKey = holderKey,
            typ = "dc+sd-jwt",
            decoysPerSdStruct = 2,
        ) {
            claim("iss", issuer)
            claim("vct", "eu.europa.ec.eudi.pid.1")
            claim("iat", now)
            claim("exp", now + 86_400)
            sd("family_name", "Doe")
            sd("given_name", "John")
            sd("birthdate", "1990-01-01")
        }
        return sdJwt.serialize()
    }

    private fun issuerMetadata(): String = """
        {"credential_issuer":"$issuer",
         "credential_endpoint":"$issuer/credential",
         "nonce_endpoint":"$issuer/nonce",
         "authorization_servers":["$issuer"],
         "credential_configurations_supported":{
           "eu.europa.ec.eudi.pid.1":{"format":"dc+sd-jwt","vct":"eu.europa.ec.eudi.pid.1",
             "proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}}}}
    """.trimIndent()

    private fun asMetadata(): String = """
        {"issuer":"$issuer","token_endpoint":"$issuer/token",
         "authorization_endpoint":"$issuer/authorize",
         "pushed_authorization_request_endpoint":"$issuer/par",
         "code_challenge_methods_supported":["S256"],
         "dpop_signing_alg_values_supported":["ES256"]}
    """.trimIndent()

    private fun jwtVcIssuerMetadata(): String {
        val jwk = JwkEc.toJson(issuerKey.publicKey).serialize()
        return """{"issuer":"$issuer","jwks":{"keys":[$jwk]}}"""
    }

    private fun ok(body: String): HttpResponse =
        HttpResponse(200, listOf("Content-Type" to "application/json"), body.encodeToByteArray())

    private fun parseForm(form: String): Map<String, String> =
        form.split('&').filter { it.isNotEmpty() }.associate {
            val (k, v) = it.split('=', limit = 2)
            java.net.URLDecoder.decode(k, "UTF-8") to java.net.URLDecoder.decode(v, "UTF-8")
        }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
}
