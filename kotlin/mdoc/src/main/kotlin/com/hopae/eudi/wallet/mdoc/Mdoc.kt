package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborDecoder
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseKey
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import java.time.Instant

class MdocException(message: String) : Exception(message)

/** CBOR tag 24: an embedded CBOR data item carried as a byte string (RFC 8949 §3.4.5.1). */
internal const val TAG_ENCODED_CBOR: ULong = 24u
internal const val TAG_TDATE: ULong = 0u

/** One data element inside an mdoc namespace (ISO 18013-5 §8.3.2.1.2.2). */
class IssuerSignedItem(
    val digestId: Long,
    val random: ByteArray,
    val elementIdentifier: String,
    val elementValue: Cbor,
)

/** An item plus the exact `#6.24(bstr)` bytes the issuer digested (`IssuerSignedItemBytes`). */
class IssuerSignedItemEntry(val item: IssuerSignedItem, val itemBytes: ByteArray)

/** Mobile Security Object (ISO 18013-5 §9.1.2.4) — the issuer-signed integrity structure. */
class MobileSecurityObject(
    val version: String,
    val digestAlgorithm: String,
    /** namespace -> (digestID -> digest bytes). */
    val valueDigests: Map<String, Map<Long, ByteArray>>,
    val deviceKey: EcPublicKey,
    val docType: String,
    val signed: Instant,
    val validFrom: Instant,
    val validUntil: Instant,
)

/** IssuerSigned (ISO 18013-5 §8.3.2.1.2.2): the disclosable items + the issuer's COSE_Sign1. */
class IssuerSigned(
    val nameSpaces: Map<String, List<IssuerSignedItemEntry>>,
    val issuerAuth: CoseSign1,
) {
    /** The x5chain (COSE header 33) presented by the issuer, leaf-first DER. */
    val issuerCertChain: List<ByteArray>? get() = issuerAuth.protected.x5chain ?: issuerAuth.unprotected.x5chain

    /** Parses the MSO from the `issuerAuth` payload. Trust the result only after verifying the signature. */
    fun parseMso(): MobileSecurityObject =
        MsoCodec.parse(unwrapTag24(issuerAuth.payload ?: throw MdocException("issuerAuth has no payload")))

    /** namespace -> (elementIdentifier -> value) across all issuer-signed items. */
    fun elements(): Map<String, Map<String, Cbor>> = nameSpaces.mapValues { (_, items) ->
        items.associate { it.item.elementIdentifier to it.item.elementValue }
    }

    companion object {
        fun decode(bytes: ByteArray): IssuerSigned = fromCbor(CborDecoder.decode(bytes))

        fun fromCbor(cbor: Cbor): IssuerSigned {
            val map = cbor as? Cbor.CborMap ?: throw MdocException("IssuerSigned must be a map")
            val issuerAuth = CoseSign1.fromCbor(map.get("issuerAuth") ?: throw MdocException("missing issuerAuth"))
            val nsMap = map.get("nameSpaces") as? Cbor.CborMap ?: throw MdocException("missing nameSpaces")
            val nameSpaces = nsMap.entries.associate { (nsKey, arr) ->
                val ns = (nsKey as? Cbor.Text)?.value ?: throw MdocException("namespace key must be text")
                val items = (arr as? Cbor.Array ?: throw MdocException("namespace value must be an array")).items.map { entry ->
                    val tagged = entry as? Cbor.Tagged ?: throw MdocException("item must be #6.24")
                    if (tagged.tag != TAG_ENCODED_CBOR) throw MdocException("item must be tag 24")
                    val inner = (tagged.value as? Cbor.Bytes)?.value ?: throw MdocException("tag 24 value must be bstr")
                    IssuerSignedItemEntry(parseItem(CborDecoder.decode(inner)), CborEncoder.encode(tagged))
                }
                ns to items
            }
            return IssuerSigned(nameSpaces, issuerAuth)
        }

        private fun parseItem(cbor: Cbor): IssuerSignedItem {
            val m = cbor as? Cbor.CborMap ?: throw MdocException("IssuerSignedItem must be a map")
            return IssuerSignedItem(
                digestId = (m.get("digestID") as? Cbor.UInt)?.value?.toLong() ?: throw MdocException("missing digestID"),
                random = (m.get("random") as? Cbor.Bytes)?.value ?: throw MdocException("missing random"),
                elementIdentifier = (m.get("elementIdentifier") as? Cbor.Text)?.value ?: throw MdocException("missing elementIdentifier"),
                elementValue = m.get("elementValue") ?: throw MdocException("missing elementValue"),
            )
        }

        internal fun Cbor.CborMap.get(name: String): Cbor? =
            entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == name }?.second
    }
}

/** issuerAuth payload is MobileSecurityObjectBytes = #6.24(bstr .cbor MSO); unwrap to the MSO bytes. */
internal fun unwrapTag24(payload: ByteArray): ByteArray {
    val decoded = CborDecoder.decode(payload)
    return when {
        decoded is Cbor.Tagged && decoded.tag == TAG_ENCODED_CBOR ->
            (decoded.value as? Cbor.Bytes)?.value ?: throw MdocException("tag 24 payload must be bstr")
        decoded is Cbor.CborMap -> payload // already the bare MSO
        else -> throw MdocException("unexpected issuerAuth payload shape")
    }
}

internal object MsoCodec {

    fun parse(msoBytes: ByteArray): MobileSecurityObject {
        val m = CborDecoder.decode(msoBytes) as? Cbor.CborMap ?: throw MdocException("MSO must be a map")
        fun field(name: String): Cbor? = m.entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == name }?.second

        val valueDigests = (field("valueDigests") as? Cbor.CborMap ?: throw MdocException("missing valueDigests"))
            .entries.associate { (nsKey, digestsCbor) ->
                val ns = (nsKey as? Cbor.Text)?.value ?: throw MdocException("valueDigests namespace must be text")
                val digests = (digestsCbor as? Cbor.CborMap ?: throw MdocException("digests must be a map"))
                    .entries.associate { (idKey, digest) ->
                        val id = (idKey as? Cbor.UInt)?.value?.toLong() ?: throw MdocException("digestID must be uint")
                        id to ((digest as? Cbor.Bytes)?.value ?: throw MdocException("digest must be bstr"))
                    }
                ns to digests
            }

        val deviceKeyInfo = field("deviceKeyInfo") as? Cbor.CborMap ?: throw MdocException("missing deviceKeyInfo")
        val deviceKeyCbor = deviceKeyInfo.entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == "deviceKey" }?.second
            as? Cbor.CborMap ?: throw MdocException("missing deviceKey")

        val validity = field("validityInfo") as? Cbor.CborMap ?: throw MdocException("missing validityInfo")
        fun tdate(name: String): Instant {
            val v = validity.entries.firstOrNull { (k, _) -> (k as? Cbor.Text)?.value == name }?.second
                ?: throw MdocException("validityInfo missing $name")
            val text = when (v) {
                is Cbor.Tagged -> (v.value as? Cbor.Text)?.value
                is Cbor.Text -> v.value
                else -> null
            } ?: throw MdocException("$name must be a tdate")
            return Instant.parse(text)
        }

        return MobileSecurityObject(
            version = (field("version") as? Cbor.Text)?.value ?: throw MdocException("missing version"),
            digestAlgorithm = (field("digestAlgorithm") as? Cbor.Text)?.value ?: throw MdocException("missing digestAlgorithm"),
            valueDigests = valueDigests,
            deviceKey = CoseKey.decode(deviceKeyCbor),
            docType = (field("docType") as? Cbor.Text)?.value ?: throw MdocException("missing docType"),
            signed = tdate("signed"),
            validFrom = tdate("validFrom"),
            validUntil = tdate("validUntil"),
        )
    }
}
