import CborCose
import Foundation
import SdJwt
import WalletAPI

/// Per-query choice: which held credential(s) to present for a DCQL credential-query id. A `multiple: false`
/// query (§6.1) takes exactly one credential; a `multiple: true` query may take several — the vp_token then
/// carries one Presentation per chosen credential (§8.1).
public struct PresentationSelection {
    public let chosen: [String: [String]]

    public init(chosen: [String: [String]]) {
        self.chosen = chosen
    }

    /// Auto-pick for every required query: all matching candidates when the query is `multiple`, else the
    /// first candidate only.
    public static func auto(_ matches: DcqlMatchResult) -> PresentationSelection {
        var chosen: [String: [String]] = [:]
        for qid in matches.requiredQueryIds {
            guard let candidates = matches.candidatesByQuery[qid], let first = candidates.first else { continue }
            chosen[qid] = first.query.multiple ? candidates.map { $0.credential.credentialId } : [first.credential.credentialId]
        }
        return PresentationSelection(chosen: chosen)
    }
}

/// The only JWE key-agreement `alg` this SDK implements; §8.3 requires the JWE `alg` to equal the chosen JWK's.
private let ecdhEs = "ECDH-ES"

public struct SubmitResult {
    public let redirectUri: String?
}

/// OpenID4VP 1.0 client (wallet/holder side) over the `HttpTransport` port.
public struct Openid4VpClient {
    private let http: any HttpTransport
    private let clock: () -> Int64
    private let resolver: AuthorizationRequestResolver

    /// `rng` enables the `wallet_nonce` replay mitigation on `request_uri_method=post` (§5.10); nil = don't send one.
    public init(http: any HttpTransport, clock: @escaping () -> Int64, trust: (any RequestTrustVerifier)? = nil,
                rng: (any Rng)? = nil) {
        self.http = http
        self.clock = clock
        self.resolver = AuthorizationRequestResolver(http: http, trust: trust, rng: rng)
    }

    public func resolveRequest(_ requestUri: String) async throws -> ResolvedRequest {
        try await resolver.resolve(requestUri)
    }

    /// Resolves an OpenID4VP request delivered over the Digital Credentials API (with the caller `origin`).
    public func resolveDcApiRequest(_ requestObject: String, origin: String) async throws -> ResolvedRequest {
        try await resolver.resolveDcApi(requestObject, origin: origin)
    }

    public func match(_ request: ResolvedRequest, held: [any PresentableCredential]) -> DcqlMatchResult {
        DcqlEngine.match(request.dcqlQuery, held: held)
    }

    public func respond(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: [any PresentableCredential]
    ) async throws -> SubmitResult {
        let vpToken = try await buildVpToken(request: request, matches: matches, selection: selection, held: held)
        switch request.responseMode {
        case "direct_post": return try await submitDirectPost(request, vpToken)
        case "direct_post.jwt": return try await submitDirectPostJwt(request, vpToken)
        default: throw VpError.unsupported("response_mode \(request.responseMode)")
        }
    }

    /// Builds the presentations for a Digital Credentials API request and returns the response object
    /// to hand back to the platform (no HTTP POST): `{vp_token}` for `dc_api`, `{response: <JWE>}` for
    /// `dc_api.jwt`. mdoc presentations bind the caller origin via the DC API handover.
    public func respondDcApi(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: [any PresentableCredential]
    ) async throws -> JsonValue {
        let vpToken = try await buildVpToken(request: request, matches: matches, selection: selection, held: held)
        switch request.responseMode {
        case "dc_api":
            return .obj([("vp_token", vpToken)])
        case "dc_api.jwt":
            guard let recipient = verifierEncryptionKey(request) else {
                throw VpError.invalidRequest("dc_api.jwt but no ECDH-ES verifier encryption key in client_metadata")
            }
            let jwe = try Jwe.encryptEcdhEs(
                plaintext: [UInt8](JsonValue.obj([("vp_token", vpToken)]).serialize().utf8),
                recipient: recipient.publicKey, enc: encValue(request), apv: apv(request), kid: recipient.kid)
            return .obj([("response", .str(jwe))])
        default:
            throw VpError.unsupported("respondDcApi requires a dc_api response_mode, got \(request.responseMode)")
        }
    }

    /// Sends an Authorization Error Response (§8.5) to the verifier's `response_uri`: a form POST of
    /// `error` / `error_description` / `state`, symmetric to the success submission. Returns the
    /// verifier's `redirect_uri` when it supplies one — which the wallet MUST then follow.
    ///
    /// Only defined for the `direct_post` response modes. Over the Digital Credentials API there is no
    /// `response_uri`; the error is handed back to the platform, and §15.9.2 warns that returning
    /// protocol errors there can itself reveal whether the wallet holds a matching credential.
    public func reportError(
        _ request: ResolvedRequest,
        code: VpErrorCode,
        description: String? = nil
    ) async throws -> SubmitResult {
        guard let responseUri = request.responseUri else {
            throw VpError.unsupported("error responses are only sent to a response_uri (direct_post)")
        }
        var form = "error=\(enc(code.code))"
        if let description { form += "&error_description=\(enc(description))" }
        if let state = request.state { form += "&state=\(enc(state))" }
        return try await post(responseUri, form)
    }

    private func buildVpToken(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: [any PresentableCredential]
    ) async throws -> JsonValue {
        let missing = matches.requiredQueryIds.filter { selection.chosen[$0] == nil }
        if !missing.isEmpty { throw VpError.queryNotSatisfiable(missing: Set(missing)) }

        var heldById: [String: any PresentableCredential] = [:]
        for h in held { heldById[h.credentialId] = h }
        let iat = clock()
        // Encrypted responses (direct_post.jwt / dc_api.jwt) carry a verifier encryption key: it binds the
        // mdoc handover (thumbprint) and doubles as the EReaderKey for mdoc deviceMac (ISO 18013-7 B.4.5).
        let encryptionKey = request.responseMode.hasSuffix(".jwt") ? verifierEncryptionKey(request) : nil
        let jwkThumbprint = encryptionKey.map { ecJwkThumbprint($0.publicKey) }
        let deviceAuthAlgValues = deviceAuthAlgValues(request)

        var vpEntries: [(String, JsonValue)] = []
        for (queryId, credentialIds) in selection.chosen {
            let queryCandidates = matches.candidatesByQuery[queryId] ?? []
            // §8.1: a query that is not `multiple` MUST return exactly one Presentation.
            if credentialIds.isEmpty { throw VpError.selectionIncomplete("no credential selected for query \(queryId)") }
            if queryCandidates.first?.query.multiple != true && credentialIds.count > 1 {
                throw VpError.invalidRequest("query '\(queryId)' is not 'multiple' but \(credentialIds.count) credentials were selected")
            }
            var presentations: [JsonValue] = []
            for credentialId in credentialIds {
                guard let candidate = queryCandidates.first(where: { $0.credential.credentialId == credentialId }) else {
                    throw VpError.selectionIncomplete("no candidate \(credentialId) for query \(queryId)")
                }
                guard let cred = heldById[credentialId] else {
                    throw VpError.selectionIncomplete("unknown credential \(credentialId)")
                }
                presentations.append(.str(try await cred.present(PresentationContext(
                    disclosedPaths: candidate.disclosedPaths,
                    clientId: request.clientId, nonce: request.nonce, responseUri: request.responseUri,
                    issuedAt: iat, transactionData: request.transactionData, verifierJwkThumbprint: jwkThumbprint, origin: request.origin,
                    verifierEncryptionKey: encryptionKey?.publicKey, deviceAuthAlgValues: deviceAuthAlgValues,
                    requireHolderBinding: candidate.query.requireCryptographicHolderBinding
                ))))
            }
            vpEntries.append((queryId, .arr(presentations)))
        }
        return .obj(vpEntries)
    }

    private func submitDirectPost(_ request: ResolvedRequest, _ vpToken: JsonValue) async throws -> SubmitResult {
        guard let responseUri = request.responseUri else { throw VpError.invalidRequest("direct_post needs response_uri") }
        var form = "vp_token=\(enc(vpToken.serialize()))"
        if let state = request.state { form += "&state=\(enc(state))" }
        return try await post(responseUri, form)
    }

    private func submitDirectPostJwt(_ request: ResolvedRequest, _ vpToken: JsonValue) async throws -> SubmitResult {
        guard let responseUri = request.responseUri else { throw VpError.invalidRequest("direct_post.jwt needs response_uri") }
        guard let recipient = verifierEncryptionKey(request) else {
            throw VpError.invalidRequest("direct_post.jwt but no ECDH-ES verifier encryption key in client_metadata")
        }
        var entries: [(String, JsonValue)] = [("vp_token", vpToken)]
        if let state = request.state { entries.append(("state", .str(state))) }
        let jwe = try Jwe.encryptEcdhEs(
            plaintext: [UInt8](JsonValue.obj(entries).serialize().utf8),
            recipient: recipient.publicKey, enc: encValue(request), apv: apv(request), kid: recipient.kid)
        return try await post(responseUri, "response=\(enc(jwe))")
    }

    private func post(_ url: String, _ form: String) async throws -> SubmitResult {
        let resp = try await http.execute(HttpRequest(
            method: .post, url: url,
            headers: [("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json")],
            body: [UInt8](form.utf8)
        ))
        guard (200...299).contains(resp.status) else {
            throw VpError.responseFailed("verifier returned HTTP \(resp.status)")
        }
        if let text = String(bytes: resp.body, encoding: .utf8), let body = try? JsonValue.parse(text),
           case let .str(redirect)? = body["redirect_uri"] {
            return SubmitResult(redirectUri: redirect)
        }
        return SubmitResult(redirectUri: nil)
    }

    /// The verifier's chosen encryption key, with the `kid` §8.3 makes the wallet echo back.
    private struct VerifierEncryptionKey {
        let publicKey: EcPublicKey
        let kid: String?
    }

    /// Selects the verifier's response-encryption key from `client_metadata.jwks` (OpenID4VP §8.3).
    /// The spec requires `alg` on every JWK and requires the JWE `alg` to equal the chosen key's, so we
    /// only consider `ECDH-ES` keys — the one key-agreement algorithm this SDK implements. `use: enc`
    /// keys win over unmarked ones.
    private func verifierEncryptionKey(_ request: ResolvedRequest) -> VerifierEncryptionKey? {
        guard let jwks = request.clientMetadata?["jwks"], case let .arr(keys)? = jwks["keys"] else { return nil }
        let usable = keys.filter { if case .str(ecdhEs)? = $0["alg"] { return true }; return false }
        let chosen = usable.first { if case .str("enc")? = $0["use"] { return true }; return false } ?? usable.first
        guard let chosen, let publicKey = JwkEc.fromJson(chosen) else { return nil }
        var kid: String?
        if case let .str(k)? = chosen["kid"] { kid = k }
        return VerifierEncryptionKey(publicKey: publicKey, kid: kid)
    }

    /// The verifier's accepted mdoc device-authentication algorithms (OpenID4VP §B.2.2): the
    /// `deviceauth_alg_values` array under `client_metadata.vp_formats_supported.mso_mdoc` (or the older
    /// `vp_formats`). Nil when the verifier did not constrain it — then `deviceSignature` is used.
    private func deviceAuthAlgValues(_ request: ResolvedRequest) -> [Int64]? {
        let formats = request.clientMetadata?["vp_formats_supported"] ?? request.clientMetadata?["vp_formats"]
        guard let mdoc = formats?["mso_mdoc"], case let .arr(values)? = mdoc["deviceauth_alg_values"] else { return nil }
        let ids: [Int64] = values.compactMap {
            switch $0 {
            case let .numInt(n): return n
            case let .numDouble(n): return Int64(n)
            default: return nil
            }
        }
        return ids.isEmpty ? nil : ids
    }

    /// ISO 18013-7 B.5.3: the mdoc sets `apv` to the base64url of the request `nonce`. `apu` would carry
    /// the `mdocGeneratedNonce` of the TS-literal B.4.4 handover, which OpenID4VP 1.0 Final replaced —
    /// so there is no `apu` to send. Both are ConcatKDF inputs and part of the AEAD tag either way.
    private func apv(_ request: ResolvedRequest) -> [UInt8] { [UInt8](request.nonce.utf8) }

    private func encValue(_ request: ResolvedRequest) -> JweEnc {
        if case let .arr(items)? = request.clientMetadata?["encrypted_response_enc_values_supported"],
           case let .str(id)? = items.first {
            return JweEnc.from(id) ?? .a128gcm
        }
        if case let .str(id)? = request.clientMetadata?["authorization_encrypted_response_enc"] {
            return JweEnc.from(id) ?? .a128gcm
        }
        return .a128gcm
    }

    private func enc(_ v: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return v.addingPercentEncoding(withAllowedCharacters: allowed) ?? v
    }
}
