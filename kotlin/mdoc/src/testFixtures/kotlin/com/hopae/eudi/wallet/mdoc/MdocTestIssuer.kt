package com.hopae.eudi.wallet.mdoc

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.cbor.CborEncoder
import com.hopae.eudi.wallet.cbor.cose.CoseHeaders
import com.hopae.eudi.wallet.cbor.cose.CoseKey
import com.hopae.eudi.wallet.cbor.cose.CoseSign1
import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SecureAreaCoseSigner
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.coseAlgorithm
import java.security.MessageDigest
import java.time.Instant

/** Builds a signed mdoc `IssuerSigned` for tests (the wallet only ever consumes these). */
object MdocTestIssuer {

    suspend fun issue(
        area: SecureArea,
        issuerKey: KeyInfo,
        deviceKey: EcPublicKey,
        docType: String,
        namespace: String,
        elements: List<Pair<String, Cbor>>,
        x5chain: List<ByteArray>,
        signed: Instant,
        validFrom: Instant,
        validUntil: Instant,
    ): ByteArray {
        // IssuerSignedItems + their #6.24 bytes + digests
        val itemEntries = mutableListOf<Cbor>()
        val digests = mutableListOf<Pair<Cbor, Cbor>>()
        elements.forEachIndexed { index, (elementId, value) ->
            val digestId = index.toLong()
            val itemMap = Cbor.CborMap(
                listOf(
                    Cbor.Text("digestID") to Cbor.int(digestId),
                    Cbor.Text("random") to Cbor.Bytes(ByteArray(16) { (index + it).toByte() }),
                    Cbor.Text("elementIdentifier") to Cbor.Text(elementId),
                    Cbor.Text("elementValue") to value,
                )
            )
            val tagged = Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(itemMap)))
            val itemBytes = CborEncoder.encode(tagged)
            itemEntries.add(tagged)
            digests.add(Cbor.int(digestId) to Cbor.Bytes(sha256(itemBytes)))
        }

        val mso = Cbor.CborMap(
            listOf(
                Cbor.Text("version") to Cbor.Text("1.0"),
                Cbor.Text("digestAlgorithm") to Cbor.Text("SHA-256"),
                Cbor.Text("valueDigests") to Cbor.CborMap(listOf(Cbor.Text(namespace) to Cbor.CborMap(digests))),
                Cbor.Text("deviceKeyInfo") to Cbor.CborMap(listOf(Cbor.Text("deviceKey") to CoseKey.encode(deviceKey))),
                Cbor.Text("docType") to Cbor.Text(docType),
                Cbor.Text("validityInfo") to Cbor.CborMap(
                    listOf(
                        Cbor.Text("signed") to tdate(signed),
                        Cbor.Text("validFrom") to tdate(validFrom),
                        Cbor.Text("validUntil") to tdate(validUntil),
                    )
                ),
            )
        )
        val msoBytes = CborEncoder.encode(Cbor.Tagged(TAG_ENCODED_CBOR, Cbor.Bytes(CborEncoder.encode(mso))))

        val unprotected = CoseHeaders(Cbor.CborMap(listOf(Cbor.int(33) to Cbor.Array(x5chain.map { Cbor.Bytes(it) }))))
        val issuerAuth = CoseSign1.sign(
            protected = CoseHeaders.of(algorithm = SigningAlgorithm.ES256.coseAlgorithm),
            unprotected = unprotected,
            payload = msoBytes,
            signer = SecureAreaCoseSigner(area, issuerKey.handle, SigningAlgorithm.ES256),
        )

        val issuerSigned = Cbor.CborMap(
            listOf(
                Cbor.Text("nameSpaces") to Cbor.CborMap(listOf(Cbor.Text(namespace) to Cbor.Array(itemEntries))),
                Cbor.Text("issuerAuth") to issuerAuth.toCbor(),
            )
        )
        return CborEncoder.encode(issuerSigned)
    }

    private fun tdate(instant: Instant): Cbor = Cbor.Tagged(TAG_TDATE, Cbor.Text(instant.toString()))

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
}
