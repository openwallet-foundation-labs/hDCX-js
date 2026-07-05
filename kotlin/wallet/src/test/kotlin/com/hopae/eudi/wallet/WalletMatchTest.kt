package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.MdocTestIssuer
import com.hopae.eudi.wallet.sdjwt.SdJwtIssuer
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.store.CredentialEnvelope
import com.hopae.eudi.wallet.store.CredentialInstance
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.EnvelopeLifecycle
import com.hopae.eudi.wallet.testkit.InMemoryStorageDriver
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.test.runTest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Phase A: parsed claims view + DCQL credential retrieval over real SD-JWT VC and mdoc payloads. */
class WalletMatchTest {

    private val noHttp = object : HttpTransport {
        override suspend fun execute(request: HttpRequest): HttpResponse = error("http not used")
    }
    private val now: Instant = Instant.parse("2026-06-01T00:00:00Z")

    private suspend fun seedSdJwtPid(area: SecureArea, storage: StorageDriver): CredentialId {
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val holderKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        var n = 0
        val sdJwt = SdJwtIssuer({ "salt-${++n}" }).issue(SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256)) {
            claim("vct", "urn:eudi:pid:1")
            sd("family_name", "Han")
            sd("given_name", "Jongho")
        }
        val id = CredentialId("pid-1")
        CredentialStore(storage).save(
            CredentialEnvelope(id, CredentialFormat.SdJwtVc("urn:eudi:pid:1"), now,
                EnvelopeLifecycle.Issued(CredentialPolicy(), listOf(CredentialInstance(holderKey.handle, sdJwt.serialize().encodeToByteArray())))),
        )
        return id
    }

    private suspend fun seedMdocMdl(area: SecureArea, storage: StorageDriver): CredentialId {
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val bytes = MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey.publicKey,
            docType = "org.iso.18013.5.1.mDL", namespace = "org.iso.18013.5.1",
            elements = listOf("family_name" to Cbor.Text("Kim"), "given_name" to Cbor.Text("Minsu")),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = now, validFrom = now, validUntil = now.plusSeconds(31_536_000),
        )
        val id = CredentialId("mdl-1")
        CredentialStore(storage).save(
            CredentialEnvelope(id, CredentialFormat.MsoMdoc("org.iso.18013.5.1.mDL"), now,
                EnvelopeLifecycle.Issued(CredentialPolicy(), listOf(CredentialInstance(deviceKey.handle, bytes)))),
        )
        return id
    }

    @Test
    fun parsedClaimsAndDcqlMatch() = runTest {
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val pidId = seedSdJwtPid(area, storage)
        val mdlId = seedMdocMdl(area, storage)
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, noHttp))

        // claims view — parsed from payload (SD-JWT disclosures / mdoc namespaces)
        val pidClaims = (wallet.credentials.get(pidId)!!.lifecycle as Lifecycle.Issued).claims
        assertTrue(pidClaims.any { it.path == listOf("family_name") && it.value.display() == "Han" }, "PID family_name")
        val mdlClaims = (wallet.credentials.get(mdlId)!!.lifecycle as Lifecycle.Issued).claims
        assertTrue(mdlClaims.any { it.path == listOf("org.iso.18013.5.1", "family_name") && it.value.display() == "Kim" }, "mDL family_name")

        // DCQL match — PID SD-JWT query matches only the PID
        val pidQuery = """{"credentials":[{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}"""
        val m = wallet.credentials.match(pidQuery)
        assertTrue(m.satisfiable)
        val cands = m.byQuery.getValue("q")
        assertEquals(1, cands.size)
        assertEquals(pidId, cands.single().credential.id)
        assertEquals(listOf(listOf("family_name")), cands.single().disclosedPaths)

        // DCQL match — mdoc query matches only the mDL
        val mdlQuery = """{"credentials":[{"id":"q","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]}"""
        val m2 = wallet.credentials.match(mdlQuery)
        assertEquals(mdlId, m2.byQuery.getValue("q").single().credential.id)

        // status — no status_list claim → Valid (no network)
        assertEquals(CredentialStatus.Valid, wallet.credentials.status(pidId))
    }
}
