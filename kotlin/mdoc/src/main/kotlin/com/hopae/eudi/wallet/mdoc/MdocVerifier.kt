package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import java.security.MessageDigest
import java.time.Instant

/**
 * Resolves the mdoc issuer's public key from the `issuerAuth` x5chain, validating the chain to
 * a trust anchor. Implemented by the `trust` module (mirrors SD-JWT VC's IssuerKeyResolver).
 */
fun interface MdocIssuerTrust {
    suspend fun issuerKey(x5chain: List<ByteArray>): EcPublicKey
}

/** A verified mdoc: integrity-checked disclosed elements plus the holder (device) binding. */
class VerifiedMdoc(
    val docType: String,
    val deviceKey: EcPublicKey,
    /** namespace -> (elementIdentifier -> value). */
    val elements: Map<String, Map<String, Cbor>>,
    val signed: Instant,
    val validFrom: Instant,
    val validUntil: Instant,
)

/**
 * Verifies an mdoc `IssuerSigned` (ISO 18013-5 §9.1.2): resolves + trusts the issuer key from
 * the COSE x5chain, verifies the `issuerAuth` COSE_Sign1 over the MSO, checks every disclosed
 * element's digest against the MSO `valueDigests`, and enforces `validityInfo`.
 */
class MdocVerifier(
    private val trust: MdocIssuerTrust,
    private val now: () -> Instant = { Instant.now() },
) {
    suspend fun verify(issuerSigned: IssuerSigned): VerifiedMdoc {
        val x5chain = issuerSigned.issuerCertChain ?: throw MdocException("issuerAuth has no x5chain")
        val issuerKey = trust.issuerKey(x5chain)

        val cose = issuerSigned.issuerAuth
        if (!cose.verify(issuerKey)) throw MdocException("issuerAuth signature invalid")

        val mso = issuerSigned.parseMso()

        if (!mso.digestAlgorithm.equals("SHA-256", ignoreCase = true)) {
            throw MdocException("unsupported MSO digest algorithm ${mso.digestAlgorithm}")
        }

        val instant = now()
        if (instant.isBefore(mso.validFrom)) throw MdocException("mdoc not yet valid (validFrom=${mso.validFrom})")
        if (instant.isAfter(mso.validUntil)) throw MdocException("mdoc expired (validUntil=${mso.validUntil})")

        val elements = mutableMapOf<String, MutableMap<String, Cbor>>()
        for ((namespace, items) in issuerSigned.nameSpaces) {
            val nsDigests = mso.valueDigests[namespace]
                ?: throw MdocException("MSO has no digests for namespace '$namespace'")
            for (entry in items) {
                val expected = nsDigests[entry.item.digestId]
                    ?: throw MdocException("no MSO digest for ${namespace}/${entry.item.digestId}")
                val actual = sha256(entry.itemBytes)
                if (!actual.contentEquals(expected)) {
                    throw MdocException("digest mismatch for ${namespace}/${entry.item.elementIdentifier}")
                }
                elements.getOrPut(namespace) { mutableMapOf() }[entry.item.elementIdentifier] = entry.item.elementValue
            }
        }

        return VerifiedMdoc(
            docType = mso.docType,
            deviceKey = mso.deviceKey,
            elements = elements,
            signed = mso.signed,
            validFrom = mso.validFrom,
            validUntil = mso.validUntil,
        )
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
