package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.Jws
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.signingAlgorithmFromJwsName
import com.hopae.eudi.wallet.vp.RegistrarDataset
import com.hopae.eudi.wallet.vp.RegistrationInfo
import com.hopae.eudi.wallet.vp.RegistrationLocalizedText
import com.hopae.eudi.wallet.vp.RequestTrustVerifier
import com.hopae.eudi.wallet.vp.VerifierInfo
import com.hopae.eudi.wallet.vp.VpException

/**
 * Verifies an OpenID4VP signed request object (OpenID4VP §5.10): the JWS signature against the
 * x5c leaf key, the certificate chain to a trust anchor, and the client_id scheme —
 * `x509_san_dns` (leaf SAN dNSName == client_id host) or `x509_hash`
 * (base64url(SHA-256(leaf DER)) == client_id value). The live EUDI verifier uses `x509_hash`.
 *
 * When a [wrprcVerifier] (built over the registrar CA) is supplied, a `registration_cert` carried in the
 * request's `verifier_info` is validated and bound to the WRPAC leaf; the result rides on [VerifierInfo].
 */
class X509RequestVerifier(
    private val validator: X509ChainValidator,
    private val wrprcVerifier: WRPRCVerifier? = null,
) : RequestTrustVerifier {

    override suspend fun verifyRequestObject(jws: Jws, clientId: String, scheme: String): VerifierInfo {
        val x5c = jws.x5c ?: throw VpException.VerifierNotTrusted("x509 request without x5c")
        val leaf = X509Support.parse(x5c.first()) // the request's signing cert — not yet trusted

        // --- Authenticity (HARD fail) --- a request whose signature does not verify, or whose client_id does
        // not identify this exact certificate, is forged / spoofed (not merely "untrusted") and is rejected.
        val alg = signingAlgorithmFromJwsName((jws.header["alg"] as? JsonValue.Str)?.value ?: "")
            ?: throw VpException.InvalidRequest("unsupported request alg")
        if (!jws.verify(X509Support.ecPublicKey(leaf), alg)) {
            throw VpException.VerifierNotTrusted("request signature invalid")
        }
        when (scheme) {
            "x509_san_dns" -> {
                val expected = clientId.substringAfter("x509_san_dns:", clientId)
                if (X509Support.dnsNames(leaf).none { it.equals(expected, ignoreCase = true) }) {
                    throw VpException.VerifierNotTrusted("client_id '$expected' not in certificate SAN dNSName")
                }
            }
            "x509_hash" -> {
                val expected = clientId.substringAfter("x509_hash:", clientId)
                if (X509Support.sha256Thumbprint(leaf) != expected) {
                    throw VpException.VerifierNotTrusted("client_id hash does not match the certificate")
                }
            }
            else -> throw VpException.Unsupported("client_id scheme '$scheme' for x509 verification")
        }

        // --- Trust (SOFT) --- whether the certificate chains to a trusted reader anchor. A failure is NOT an
        // error: it surfaces as `trusted = false` so the wallet can show "not trusted" and let the User decide
        // (ARF informed consent). Registration (WRPRC / registrar_dataset) is likewise best-effort — any problem
        // yields no registration rather than failing the whole request.
        val trusted = runCatching { validator.validate(x5c) }.isSuccess
        val registration = runCatching { buildRegistration(jws, x5c) }.getOrNull()

        return VerifierInfo(clientId, scheme, x5c, X509Support.commonName(leaf), trusted = trusted, registration = registration)
    }

    /**
     * The RP's registration from the request's `verifier_info` array (ETSI TS 119 472-2 §6.3): the WRPRC
     * (registrar-sealed, authoritative) when present, else the self-declared `registrar_dataset`. Only built
     * when registrar trust is configured. Throws on a verification problem; the caller treats that as
     * "no registration" (soft) so an untrusted/invalid registration does not block the presentation.
     */
    private suspend fun buildRegistration(jws: Jws, x5c: List<ByteArray>): RegistrationInfo? {
        val verifier = wrprcVerifier ?: return null
        val (dataset, wrprc) = extractVerifierInfo(jws)
        return when {
            // Presence matrix (§2): a WRPRC without the mandatory dataset is malformed.
            wrprc != null && dataset == null ->
                throw VpException.InvalidRequest("verifier_info carries a registration_cert but no registrar_dataset (REQ-RO-02)")
            wrprc != null -> {
                // Both present → the WRPRC wins (registrar-attested, offline-verifiable); dataset is for display/log.
                val verified = verifier.verify(wrprc, x5c.first())
                RegistrationInfo(
                    subject = verified.subject,
                    entitlements = verified.entitlements,
                    purpose = verified.purpose.map { RegistrationLocalizedText(it.lang, it.value) },
                    intermediarySub = verified.intermediary?.sub,
                    intermediaryName = verified.intermediary?.name,
                    status = verified.status,
                    attested = true,
                    dataset = dataset,
                    registeredCredentials = verified.registeredCredentials,
                )
            }
            // Dataset only → self-declared registration (not registrar-attested). The wallet layer may upgrade
            // it via the registrar's TS5 API when the User opts in (RPRC_16/18); until then `attested = false`.
            dataset != null -> RegistrationInfo(
                subject = dataset.identifier ?: "",
                entitlements = emptyList(),
                purpose = dataset.purpose.map { RegistrationLocalizedText(it.lang, it.value) },
                intermediarySub = null,
                intermediaryName = null,
                status = null,
                attested = false,
                dataset = dataset,
                registeredCredentials = dataset.credentials,
            )
            else -> null
        }
    }

    /**
     * Reads the request object's `verifier_info` array (ETSI TS 119 472-2 §6.3): the self-declared
     * `registrar_dataset` element and the optional `registration_cert` (the WRPRC as `base64url(serialized
     * WRPRC)`, REQ-RO-13/15). Returns (dataset, wrprcCompactJws); either is null when its element is absent
     * or undecodable, and both are null when there is no `verifier_info` at all.
     */
    private fun extractVerifierInfo(jws: Jws): Pair<RegistrarDataset?, String?> {
        val claims = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj ?: return null to null
        val infos = (claims["verifier_info"] as? JsonValue.Arr)?.items ?: return null to null
        var dataset: RegistrarDataset? = null
        var wrprc: String? = null
        for (info in infos) {
            val obj = info as? JsonValue.Obj ?: continue
            when ((obj["format"] as? JsonValue.Str)?.value) {
                "registrar_dataset" -> (obj["data"] as? JsonValue.Obj)?.let { dataset = RegistrarDataset.fromData(it) }
                "registration_cert" -> (obj["data"] as? JsonValue.Str)?.value?.let {
                    wrprc = runCatching { Base64Url.decode(it).decodeToString() }.getOrNull()
                }
            }
        }
        return dataset to wrprc
    }
}
