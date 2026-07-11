package com.hopae.eudi.wallet.sdjwt

import com.hopae.eudi.wallet.cbor.cose.EcPublicKey
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import java.security.MessageDigest

class SdJwtException(message: String) : Exception(message)

internal fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/** RFC 9901 Disclosure: base64url(JSON array). Digest is over the base64url string bytes. */
class Disclosure private constructor(
    val encoded: String,
    val salt: String,
    /** null for array-element disclosures. */
    val claimName: String?,
    val value: JsonValue,
) {
    val digest: String by lazy { Base64Url.encode(sha256(encoded.encodeToByteArray())) }

    companion object {
        fun objectProperty(salt: String, name: String, value: JsonValue): Disclosure {
            require(name != "_sd" && name != "..." && name != "_sd_alg") { "reserved claim name '$name'" }
            val json = JsonValue.Arr(listOf(JsonValue.Str(salt), JsonValue.Str(name), value)).serialize()
            return Disclosure(Base64Url.encode(json), salt, name, value)
        }

        fun arrayElement(salt: String, value: JsonValue): Disclosure {
            val json = JsonValue.Arr(listOf(JsonValue.Str(salt), value)).serialize()
            return Disclosure(Base64Url.encode(json), salt, null, value)
        }

        fun parse(encoded: String): Disclosure {
            val arr = runCatching { JsonValue.parse(Base64Url.decodeToString(encoded)) }
                .getOrElse { throw SdJwtException("malformed disclosure") } as? JsonValue.Arr
                ?: throw SdJwtException("disclosure must be a JSON array")
            val salt = (arr.items.getOrNull(0) as? JsonValue.Str)?.value
                ?: throw SdJwtException("disclosure salt must be a string")
            return when (arr.items.size) {
                2 -> Disclosure(encoded, salt, null, arr.items[1])
                3 -> {
                    val name = (arr.items[1] as? JsonValue.Str)?.value
                        ?: throw SdJwtException("disclosure claim name must be a string")
                    if (name == "_sd" || name == "..." || name == "_sd_alg") {
                        throw SdJwtException("reserved claim name in disclosure")
                    }
                    Disclosure(encoded, salt, name, arr.items[2])
                }
                else -> throw SdJwtException("disclosure array must have 2 or 3 elements")
            }
        }
    }
}

/** `<issuer-jwt>~<disclosure>*~[<kb-jwt>]` (RFC 9901 §4). */
class SdJwt(
    val jwt: String,
    val disclosures: List<Disclosure>,
    val kbJwt: String? = null,
) {
    fun serialize(): String = presentationWithoutKb() + (kbJwt ?: "")

    /** The exact string the KB-JWT's sd_hash commits to (ends with '~'). */
    fun presentationWithoutKb(): String = buildString {
        append(jwt)
        disclosures.forEach { append('~').append(it.encoded) }
        append('~')
    }

    companion object {
        fun parse(text: String): SdJwt {
            val parts = text.split('~')
            if (parts.size < 2 || parts[0].isEmpty()) throw SdJwtException("malformed SD-JWT")
            val disclosures = parts.subList(1, parts.size - 1).map {
                if (it.isEmpty()) throw SdJwtException("empty disclosure segment")
                Disclosure.parse(it)
            }
            return SdJwt(parts[0], disclosures, kbJwt = parts.last().ifEmpty { null })
        }

        /**
         * Parses an SD-JWT received from an Issuer. RFC 9901 §7.2: an SD-JWT delivered by the Issuer MUST
         * NOT carry a Key Binding JWT — the KB-JWT is the Holder's to add at presentation time. An
         * SD-JWT+KB from the Issuer is rejected.
         */
        fun parseFromIssuer(text: String): SdJwt = parse(text).also {
            if (it.kbJwt != null) throw SdJwtException("issuer delivered an SD-JWT+KB (RFC 9901 §7.2)")
        }
    }
}

/**
 * Shared digest-resolution walker (RFC 9901 §7.3 processing): used by the verifier
 * and by the holder (to learn where each disclosure attaches for selection).
 */
internal class SdProcessor(disclosures: List<Disclosure>) {

    val byDigest: Map<String, Disclosure>
    val placements = mutableMapOf<String, List<String>>()          // digest -> path
    val parents = mutableMapOf<String, String>()                   // digest -> enclosing disclosure digest
    private val used = mutableSetOf<String>()
    private val referenced = mutableSetOf<String>()
    private val parentStack = ArrayDeque<String>()

    init {
        val map = mutableMapOf<String, Disclosure>()
        for (d in disclosures) {
            if (map.put(d.digest, d) != null) throw SdJwtException("duplicate disclosure")
        }
        byDigest = map
    }

    fun process(payload: JsonValue.Obj): JsonValue.Obj {
        val out = processObj(payload, emptyList(), topLevel = true)
        val unused = byDigest.keys - used
        if (unused.isNotEmpty()) throw SdJwtException("disclosure not referenced by any digest")
        return out
    }

    private fun reference(digest: String) {
        if (!referenced.add(digest)) throw SdJwtException("digest appears more than once")
    }

    private fun consume(digest: String, disclosure: Disclosure, path: List<String>): JsonValue {
        used.add(digest)
        placements[digest] = path
        parentStack.lastOrNull()?.let { parents[digest] = it }
        parentStack.addLast(digest)
        val processed = processValue(disclosure.value, path)
        parentStack.removeLast()
        return processed
    }

    private fun processObj(obj: JsonValue.Obj, path: List<String>, topLevel: Boolean = false): JsonValue.Obj {
        val entries = mutableListOf<Pair<String, JsonValue>>()
        val names = mutableSetOf<String>()

        fun add(name: String, value: JsonValue) {
            if (!names.add(name)) throw SdJwtException("duplicate claim name '$name'")
            entries.add(name to value)
        }

        for ((key, value) in obj.entries) {
            when (key) {
                "_sd" -> {
                    val digests = value as? JsonValue.Arr ?: throw SdJwtException("_sd must be an array")
                    for (item in digests.items) {
                        val digest = (item as? JsonValue.Str)?.value
                            ?: throw SdJwtException("_sd entries must be strings")
                        reference(digest)
                        val disclosure = byDigest[digest] ?: continue // undisclosed
                        if (disclosure.claimName == null) {
                            throw SdJwtException("array-element disclosure referenced from _sd")
                        }
                        add(disclosure.claimName, consume(digest, disclosure, path + disclosure.claimName))
                    }
                }
                "..." -> throw SdJwtException("'...' is only allowed inside arrays")
                "_sd_alg" -> {
                    if (!topLevel) throw SdJwtException("_sd_alg outside top level")
                    // validated by the caller; not part of processed claims
                }
                else -> add(key, processValue(value, path + key))
            }
        }
        return JsonValue.Obj(entries)
    }

    private fun processValue(value: JsonValue, path: List<String>): JsonValue = when (value) {
        is JsonValue.Obj -> processObj(value, path)
        is JsonValue.Arr -> processArr(value, path)
        else -> value
    }

    private fun processArr(arr: JsonValue.Arr, path: List<String>): JsonValue.Arr {
        val items = mutableListOf<JsonValue>()
        for ((index, element) in arr.items.withIndex()) {
            val sdRef = (element as? JsonValue.Obj)
                ?.takeIf { it.entries.size == 1 && it.entries[0].first == "..." }
            if (sdRef != null) {
                val digest = (sdRef.entries[0].second as? JsonValue.Str)?.value
                    ?: throw SdJwtException("'...' value must be a string")
                reference(digest)
                val disclosure = byDigest[digest] ?: continue // undisclosed element is omitted
                if (disclosure.claimName != null) {
                    throw SdJwtException("object-property disclosure referenced from array")
                }
                items.add(consume(digest, disclosure, path + index.toString()))
            } else {
                items.add(processValue(element, path + index.toString()))
            }
        }
        return JsonValue.Arr(items)
    }
}

object SdJwtVerifier {

    /**
     * What the verifier requires of a Key Binding JWT (RFC 9901 §7.3 step 5).
     *
     * The spec leaves the `iat` window to the verifier ("within an acceptable window", §7.3(5.e)), so it
     * is policy here: [maxAgeSeconds] bounds how stale a presentation may be — the replay window — and
     * [skewSeconds] tolerates a holder clock running slightly fast.
     */
    class KbRequirement(
        val audience: String,
        val nonce: String,
        /** Epoch seconds. Injectable so tests (and offline verification) can pin the moment of judgement. */
        val now: () -> Long = { System.currentTimeMillis() / 1000 },
        val maxAgeSeconds: Long = 300,
        val skewSeconds: Long = 60,
    )

    class VerifiedSdJwt(
        /** Processed claims: digests resolved, _sd/_sd_alg removed. */
        val claims: JsonValue.Obj,
        /** Raw issuer payload (incl. cnf) for callers that need it. */
        val payload: JsonValue.Obj,
        /** digest -> path of every disclosed claim. */
        val disclosedPaths: Map<String, List<String>>,
    )

    fun verify(
        sdJwt: SdJwt,
        issuerKey: EcPublicKey,
        algorithm: SigningAlgorithm,
        keyBinding: KbRequirement? = null,
    ): VerifiedSdJwt {
        val jws = Jws.parse(sdJwt.jwt)
        requireSecureAlg(jws, "issuer-signed JWT") // §7.1(2.a)
        if (!jws.verify(issuerKey, algorithm)) throw SdJwtException("issuer signature invalid")

        val payload = runCatching { JsonValue.parse(jws.payloadBytes.decodeToString()) }
            .getOrElse { throw SdJwtException("issuer payload is not JSON") } as? JsonValue.Obj
            ?: throw SdJwtException("issuer payload must be an object")

        val sdAlg = (payload["_sd_alg"] as? JsonValue.Str)?.value ?: "sha-256"
        if (sdAlg != "sha-256") throw SdJwtException("unsupported _sd_alg '$sdAlg'")

        val processor = SdProcessor(sdJwt.disclosures)
        val claims = processor.process(payload)

        if (keyBinding != null) {
            val kbJwt = sdJwt.kbJwt ?: throw SdJwtException("key binding required but missing")
            val holderKey = holderKeyFromCnf(payload) ?: throw SdJwtException("cnf.jwk missing or unsupported")
            verifyKeyBinding(kbJwt, holderKey, keyBinding, sdJwt)
        }

        return VerifiedSdJwt(claims, payload, processor.placements)
    }

    fun holderKeyFromCnf(payload: JsonValue.Obj): EcPublicKey? {
        val jwk = ((payload["cnf"] as? JsonValue.Obj)?.get("jwk")) as? JsonValue.Obj ?: return null
        return JwkEc.fromJson(jwk)
    }

    /**
     * RFC 9901 §7.1(2.a) and §7.3(5.b): "The `none` algorithm MUST NOT be accepted." [Jws.verify] would
     * already reject it, since the header `alg` must equal the algorithm the caller pinned — but only as
     * a signature failure. Naming the rule keeps the refusal explicit and the diagnostic honest.
     */
    private fun requireSecureAlg(jws: Jws, where: String) {
        val alg = (jws.header["alg"] as? JsonValue.Str)?.value ?: throw SdJwtException("$where has no alg")
        if (alg.equals("none", ignoreCase = true)) throw SdJwtException("$where must not use the 'none' algorithm")
    }

    private fun verifyKeyBinding(kbJwt: String, holderKey: EcPublicKey, req: KbRequirement, sdJwt: SdJwt) {
        val jws = Jws.parse(kbJwt)
        if ((jws.header["typ"] as? JsonValue.Str)?.value != "kb+jwt") throw SdJwtException("kb-jwt typ must be kb+jwt")
        requireSecureAlg(jws, "kb-jwt") // §7.3(5.b)
        val algName = (jws.header["alg"] as? JsonValue.Str)?.value ?: throw SdJwtException("kb-jwt alg missing")
        val algorithm = signingAlgorithmFromJwsName(algName) ?: throw SdJwtException("kb-jwt alg unsupported")
        if (!jws.verify(holderKey, algorithm)) throw SdJwtException("kb-jwt signature invalid")

        val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw SdJwtException("kb-jwt payload must be an object")
        if ((payload["nonce"] as? JsonValue.Str)?.value != req.nonce) throw SdJwtException("kb-jwt nonce mismatch")
        if ((payload["aud"] as? JsonValue.Str)?.value != req.audience) throw SdJwtException("kb-jwt aud mismatch")

        // §7.3(5.e): the KB-JWT's creation time must fall within the verifier's acceptable window. Presence
        // alone proves nothing — a KB-JWT minted months ago would otherwise still authorise a presentation.
        val iat = (payload["iat"] as? JsonValue.NumInt)?.value ?: throw SdJwtException("kb-jwt iat missing")
        val now = req.now()
        if (iat > now + req.skewSeconds) throw SdJwtException("kb-jwt iat is ${iat - now}s in the future")
        if (iat < now - req.maxAgeSeconds) {
            throw SdJwtException("kb-jwt is ${now - iat}s old; the acceptable window is ${req.maxAgeSeconds}s")
        }

        val expected = Base64Url.encode(sha256(sdJwt.presentationWithoutKb().encodeToByteArray()))
        if ((payload["sd_hash"] as? JsonValue.Str)?.value != expected) throw SdJwtException("kb-jwt sd_hash mismatch")
    }
}

object SdJwtHolder {

    /** Processed claim tree of a held credential (disclosures resolved), without verifying the issuer signature. */
    fun processedClaims(issued: SdJwt): JsonValue.Obj {
        val jws = Jws.parse(issued.jwt)
        val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw SdJwtException("issuer payload must be an object")
        return SdProcessor(issued.disclosures).process(payload)
    }

    /**
     * Selects disclosures by processed-claim path. Ancestors of a selected disclosure
     * (recursive disclosures) are included automatically.
     */
    fun present(issued: SdJwt, select: (path: List<String>) -> Boolean): SdJwt {
        val jws = Jws.parse(issued.jwt)
        val payload = JsonValue.parse(jws.payloadBytes.decodeToString()) as? JsonValue.Obj
            ?: throw SdJwtException("issuer payload must be an object")
        val processor = SdProcessor(issued.disclosures)
        processor.process(payload)

        val selected = mutableSetOf<String>()
        for ((digest, path) in processor.placements) {
            if (select(path)) {
                var current: String? = digest
                while (current != null && selected.add(current)) {
                    current = processor.parents[current]
                }
            }
        }
        return SdJwt(issued.jwt, issued.disclosures.filter { it.digest in selected })
    }

    suspend fun presentWithKeyBinding(
        issued: SdJwt,
        select: (path: List<String>) -> Boolean,
        audience: String,
        nonce: String,
        issuedAt: Long,
        signer: JwsSigner,
        /** Extra KB-JWT claims (e.g. OpenID4VP `transaction_data_hashes`). */
        extraClaims: List<Pair<String, JsonValue>> = emptyList(),
    ): SdJwt {
        val bare = present(issued, select)
        val sdHash = Base64Url.encode(sha256(bare.presentationWithoutKb().encodeToByteArray()))
        val header = JsonValue.Obj(
            listOf(
                "typ" to JsonValue.Str("kb+jwt"),
                "alg" to JsonValue.Str(signer.algorithm.jwsName),
            )
        )
        val payload = JsonValue.Obj(
            listOf(
                "iat" to JsonValue.NumInt(issuedAt),
                "aud" to JsonValue.Str(audience),
                "nonce" to JsonValue.Str(nonce),
                "sd_hash" to JsonValue.Str(sdHash),
            ) + extraClaims
        )
        val kb = Jws.sign(header, payload.serialize().encodeToByteArray(), signer).compact()
        return SdJwt(bare.jwt, bare.disclosures, kb)
    }
}

/* ---------- issuance ---------- */

class SdArrayElement private constructor(val value: JsonValue, val selectivelyDisclosable: Boolean) {
    companion object {
        fun plain(value: JsonValue) = SdArrayElement(value, false)
        fun sd(value: JsonValue) = SdArrayElement(value, true)
    }
}

class SdObjectBuilder internal constructor() {
    internal sealed interface Part
    internal class Plain(val name: String, val value: JsonValue) : Part
    internal class Sd(val name: String, val value: JsonValue) : Part
    internal class PlainObj(val name: String, val builder: SdObjectBuilder) : Part
    internal class SdObj(val name: String, val builder: SdObjectBuilder) : Part
    internal class ArrPart(val name: String, val elements: List<SdArrayElement>) : Part

    internal val parts = mutableListOf<Part>()

    fun claim(name: String, value: JsonValue) { parts.add(Plain(name, value)) }
    fun claim(name: String, value: String) = claim(name, JsonValue.Str(value))
    fun claim(name: String, value: Long) = claim(name, JsonValue.NumInt(value))
    fun sd(name: String, value: JsonValue) { parts.add(Sd(name, value)) }
    fun sd(name: String, value: String) = sd(name, JsonValue.Str(value))
    fun obj(name: String, block: SdObjectBuilder.() -> Unit) { parts.add(PlainObj(name, SdObjectBuilder().apply(block))) }
    fun sdObj(name: String, block: SdObjectBuilder.() -> Unit) { parts.add(SdObj(name, SdObjectBuilder().apply(block))) }
    fun arr(name: String, elements: List<SdArrayElement>) { parts.add(ArrPart(name, elements)) }

    internal fun build(salt: () -> String, out: MutableList<Disclosure>, decoys: Int = 0): JsonValue.Obj {
        val entries = mutableListOf<Pair<String, JsonValue>>()
        val sdDigests = mutableListOf<String>()

        fun disclose(name: String, value: JsonValue) {
            val d = Disclosure.objectProperty(salt(), name, value)
            out.add(d)
            sdDigests.add(d.digest)
        }

        for (part in parts) {
            when (part) {
                is Plain -> entries.add(part.name to part.value)
                is Sd -> disclose(part.name, part.value)
                is PlainObj -> entries.add(part.name to part.builder.build(salt, out, decoys))
                is SdObj -> disclose(part.name, part.builder.build(salt, out, decoys))
                is ArrPart -> entries.add(
                    part.name to JsonValue.Arr(
                        part.elements.map { element ->
                            if (element.selectivelyDisclosable) {
                                val d = Disclosure.arrayElement(salt(), element.value)
                                out.add(d)
                                JsonValue.Obj(listOf("..." to JsonValue.Str(d.digest)))
                            } else element.value
                        }
                    )
                )
            }
        }
        // decoy digests (RFC 9901 §4.2.5): hash of fresh salt — indistinguishable from real ones
        if (sdDigests.isNotEmpty() && decoys > 0) {
            repeat(decoys) { sdDigests.add(Base64Url.encode(sha256(salt().encodeToByteArray()))) }
        }
        // sorted for determinism (RFC allows any order; production may shuffle via Rng later)
        if (sdDigests.isNotEmpty()) {
            entries.add("_sd" to JsonValue.Arr(sdDigests.sorted().map { JsonValue.Str(it) }))
        }
        return JsonValue.Obj(entries)
    }
}

class SdJwtIssuer(private val saltProvider: () -> String) {

    companion object {
        fun randomSalts(rng: com.hopae.eudi.wallet.spi.Rng): () -> String =
            { Base64Url.encode(rng.nextBytes(16)) }
    }

    suspend fun issue(
        signer: JwsSigner,
        holderKey: EcPublicKey? = null,
        typ: String = "dc+sd-jwt",
        decoysPerSdStruct: Int = 0,
        block: SdObjectBuilder.() -> Unit,
    ): SdJwt {
        val disclosures = mutableListOf<Disclosure>()
        val body = SdObjectBuilder().apply(block).build(saltProvider, disclosures, decoysPerSdStruct)

        val entries = body.entries.toMutableList()
        entries.add("_sd_alg" to JsonValue.Str("sha-256"))
        holderKey?.let {
            entries.add("cnf" to JsonValue.Obj(listOf("jwk" to JwkEc.toJson(it))))
        }

        val header = JsonValue.Obj(
            listOf(
                "typ" to JsonValue.Str(typ),
                "alg" to JsonValue.Str(signer.algorithm.jwsName),
            )
        )
        val jws = Jws.sign(header, JsonValue.Obj(entries).serialize().encodeToByteArray(), signer)
        return SdJwt(jws.compact(), disclosures)
    }
}
