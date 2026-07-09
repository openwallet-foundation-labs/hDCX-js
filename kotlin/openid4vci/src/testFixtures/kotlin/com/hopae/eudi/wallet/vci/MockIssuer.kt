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
            path == "/.well-known/openid-credential-issuer" -> handleIssuerMetadata(request)
            path == "/.well-known/oauth-authorization-server" -> ok(asMetadata())
            path == "/.well-known/jwt-vc-issuer" -> ok(jwtVcIssuerMetadata())
            path == "/token" -> handleToken(request)
            path == "/nonce" -> handleNonce()
            path == "/credential" -> handleCredential(request)
            path == "/deferred_credential" -> handleDeferred(request)
            path == "/notification" -> handleNotification(request)
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
            "refresh_token" -> require(form["refresh_token"] == issuedRefreshToken) { "wrong refresh_token" }
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
        issuedRefreshToken = "REFRESH-" + Base64Url.encode(byteArrayOf(5, 6, 7, 8))
        return ok("""{"access_token":"$accessToken","token_type":"DPoP","expires_in":3600,"refresh_token":"$issuedRefreshToken","c_nonce":"$cNonce"}""")
    }

    private var issuedRefreshToken: String? = null

    /** When set, the issuer serves this JWT (as `application/jwt`) to wallets whose Accept allows it. */
    var signedMetadata: String? = null

    /** The `Accept` the wallet sent on the last metadata GET — lets tests assert §12.2.2 negotiation. */
    var lastMetadataAccept: String? = null
        private set

    /**
     * Content-negotiated metadata (OpenID4VCI §12.2.2): a signed JWT when the wallet accepts
     * `application/jwt` and this issuer signs; otherwise the unsigned JSON document.
     */
    private fun handleIssuerMetadata(request: HttpRequest): HttpResponse {
        val accept = request.headers.firstOrNull { it.first.equals("Accept", ignoreCase = true) }?.second ?: "application/json"
        lastMetadataAccept = accept
        val jwt = signedMetadata
        return if (jwt != null && accept.contains("application/jwt")) {
            HttpResponse(200, listOf("Content-Type" to "application/jwt"), jwt.encodeToByteArray())
        } else {
            ok(issuerMetadata())
        }
    }

    private fun handleNonce(): HttpResponse = ok("""{"c_nonce":"${cNonce ?: "c-nonce-xyz"}"}""")

    /** Test-observable: the key_attestation header from the first proof (null if none), and proof count. */
    var seenKeyAttestation: String? = null
        private set
    var seenProofCount: Int = 0
        private set

    /** When true, /credential defers (returns a transaction_id); the credential comes from /deferred_credential. */
    var deferMode: Boolean = false
    private var deferredHolderKey: EcPublicKey? = null
    private var deferredPollCount = 0
    /** Test-observable: (notification_id, event) of the last notification received. */
    var seenNotification: Pair<String, String>? = null
        private set

    private suspend fun handleDeferred(request: HttpRequest): HttpResponse {
        val token = accessToken ?: return HttpResponse(401, emptyList(), "no token".encodeToByteArray())
        require(request.headers.any { it.first == "Authorization" && it.second == "DPoP $token" }) { "bad auth" }
        verifyDpop(request, "POST", "$issuer/deferred_credential", accessToken = token)
        val body = JsonValue.parse(request.body!!.decodeToString()) as JsonValue.Obj
        require((body["transaction_id"] as JsonValue.Str).value == "tx-1") { "unknown transaction_id" }
        deferredPollCount++
        // First poll: not ready yet; second poll: issue.
        if (deferredPollCount < 2) {
            return HttpResponse(400, listOf("Content-Type" to "application/json"), """{"error":"issuance_pending"}""".encodeToByteArray())
        }
        return ok("""{"credentials":[{"credential":"${issueSdJwtVc(deferredHolderKey!!)}"}]}""")
    }

    private fun handleNotification(request: HttpRequest): HttpResponse {
        val token = accessToken ?: return HttpResponse(401, emptyList(), "no token".encodeToByteArray())
        require(request.headers.any { it.first == "Authorization" && it.second == "DPoP $token" }) { "bad auth" }
        val body = JsonValue.parse(request.body!!.decodeToString()) as JsonValue.Obj
        seenNotification = (body["notification_id"] as JsonValue.Str).value to (body["event"] as JsonValue.Str).value
        return HttpResponse(204, emptyList(), ByteArray(0))
    }

    private suspend fun handleCredential(request: HttpRequest): HttpResponse {
        val token = accessToken ?: return HttpResponse(401, emptyList(), "no token".encodeToByteArray())
        require(request.headers.any { it.first == "Authorization" && it.second == "DPoP $token" }) { "bad auth" }
        verifyDpop(request, "POST", "$issuer/credential", accessToken = token) // asserts ath binding internally

        val body = JsonValue.parse(request.body!!.decodeToString()) as JsonValue.Obj
        val proofs = ((body["proofs"] as JsonValue.Obj)["jwt"] as JsonValue.Arr).items.map { (it as JsonValue.Str).value }
        seenProofCount = proofs.size
        seenKeyAttestation = (Jws.parse(proofs.first()).header["key_attestation"] as? JsonValue.Str)?.value

        if (deferMode) {
            // Defer: verify the proof, remember the holder key, return a transaction_id (no credential yet).
            deferredHolderKey = verifyKeyProof(proofs.first())
            return ok("""{"transaction_id":"tx-1","notification_id":"n-1"}""")
        }

        // One credential per proof (batch issuance), each bound to that proof's holder key.
        val credentials = proofs.map { proof -> """{"credential":"${issueSdJwtVc(verifyKeyProof(proof))}"}""" }.joinToString(",")
        return ok("""{"credentials":[$credentials],"notification_id":"n-1"}""")
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
         "deferred_credential_endpoint":"$issuer/deferred_credential",
         "notification_endpoint":"$issuer/notification",
         "authorization_servers":["$issuer"],
         "display":[{"name":"Hopae Test Issuer"}],
         "credential_configurations_supported":{
           "eu.europa.ec.eudi.pid.1":{"format":"dc+sd-jwt","vct":"eu.europa.ec.eudi.pid.1",
             "display":[{"name":"Personal ID","logo":{"uri":"https://logo.example/pid.png"},"background_color":"#123456"}],
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
