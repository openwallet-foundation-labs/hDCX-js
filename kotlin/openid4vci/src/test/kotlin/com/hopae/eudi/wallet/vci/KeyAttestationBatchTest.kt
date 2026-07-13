package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/** HAIP hardening: Key Attestation in the proof header, and batch issuance (proofs array). */
class KeyAttestationBatchTest {

    private val now = 1_700_000_000L
    private fun rng() = Rng { size -> ByteArray(size) { (it + 1).toByte() } }

    @Test
    fun keyAttestationCarriedInProofHeader() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now).apply { requiresKeyAttestation = true }
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val keys = IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
        val client = Openid4VciClient(
            mock, rng(), clock = { now },
            keyAttestation = KeyAttestationSource { "eyJ.key-attestation.jwt" },
        )

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        val response = client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys, txCode = "1234")

        assertEquals(1, response.credentials.size)
        // the issuer saw the key_attestation in the proof JWT header
        assertEquals("eyJ.key-attestation.jwt", mock.seenKeyAttestation)
    }

    /** Shape 2: attestation required + a batch → ONE jwt proof (first-key PoP) carrying the batch attestation,
     *  never one-jwt-per-key (the N×N shape the issuer rejects). */
    @Test
    fun batchWithAttestationSendsExactlyOneJwtProof() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now).apply { requiresKeyAttestation = true }
        suspend fun key() = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        fun signer(k: com.hopae.eudi.wallet.spi.KeyInfo) = SecureAreaJwsSigner(area, k.handle, SigningAlgorithm.ES256)
        val k1 = key(); val k2 = key(); val k3 = key(); val dpopKey = key()
        val keys = IssuanceKeys(
            signer(k1), k1.publicKey, signer(dpopKey), dpopKey.publicKey,
            additionalProofKeys = listOf(ProofKey(signer(k2), k2.publicKey), ProofKey(signer(k3), k3.publicKey)),
            keyAttestation = KeyAttestationSource { "eyJ.batch-key-attestation.jwt" },
        )
        val client = Openid4VciClient(mock, rng(), clock = { now })

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys, txCode = "1234")

        assertEquals(1, mock.seenProofCount, "the batch goes in attested_keys → exactly one jwt proof, not N")
        assertEquals("eyJ.batch-key-attestation.jwt", mock.seenKeyAttestation, "the batch attestation rides in that proof's header")
    }

    /** A config that mandates key attestation, with no attestation source available → the client refuses. */
    @Test
    fun attestationRequiredButNoSourceThrows(): Unit = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now).apply { requiresKeyAttestation = true }
        val proofKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val dpopKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val keys = IssuanceKeys(
            SecureAreaJwsSigner(area, proofKey.handle, SigningAlgorithm.ES256), proofKey.publicKey,
            SecureAreaJwsSigner(area, dpopKey.handle, SigningAlgorithm.ES256), dpopKey.publicKey,
        )
        val client = Openid4VciClient(mock, rng(), clock = { now }) // no keyAttestation source

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        kotlin.test.assertFailsWith<VciException.Unsupported> {
            client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys, txCode = "1234")
        }
    }

    @Test
    fun batchIssuanceYieldsOneCredentialPerProofKey() = runBlocking {
        val area = SoftwareSecureArea()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val mock = MockIssuer(area, issuerKey, now)

        suspend fun key() = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        fun signer(k: com.hopae.eudi.wallet.spi.KeyInfo) = SecureAreaJwsSigner(area, k.handle, SigningAlgorithm.ES256)
        val k1 = key(); val k2 = key(); val k3 = key(); val dpopKey = key()
        val keys = IssuanceKeys(
            signer(k1), k1.publicKey, signer(dpopKey), dpopKey.publicKey,
            additionalProofKeys = listOf(ProofKey(signer(k2), k2.publicKey), ProofKey(signer(k3), k3.publicKey)),
        )
        val client = Openid4VciClient(mock, rng(), clock = { now })

        val offer = CredentialOffer.parse(mock.credentialOfferJson)
        val response = client.issueWithPreAuthorizedCode(offer, "eu.europa.ec.eudi.pid.1", keys, txCode = "1234")

        assertEquals(3, mock.seenProofCount, "issuer received one proof per key")
        assertEquals(3, response.credentials.size, "one credential issued per proof")
        // each credential is bound to a distinct holder key
        assertEquals(3, response.credentials.map { it.credential }.toSet().size, "credentials are distinct")
    }
}
