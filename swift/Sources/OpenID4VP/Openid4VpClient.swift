import CborCose
import Foundation
import SdJwt
import WalletAPI

/// Per-query choice: which held credential to present for a DCQL credential-query id.
public struct PresentationSelection {
    public let chosen: [String: String]

    public init(chosen: [String: String]) {
        self.chosen = chosen
    }

    /// Auto-pick the first candidate for every required query.
    public static func auto(_ matches: DcqlMatchResult) -> PresentationSelection {
        var chosen: [String: String] = [:]
        for qid in matches.requiredQueryIds {
            if let first = matches.candidatesByQuery[qid]?.first {
                chosen[qid] = first.credential.credentialId
            }
        }
        return PresentationSelection(chosen: chosen)
    }
}

public struct SubmitResult {
    public let redirectUri: String?
}

/// OpenID4VP 1.0 client (wallet/holder side) over the `HttpTransport` port.
public struct Openid4VpClient {
    private let http: any HttpTransport
    private let clock: () -> Int64
    private let resolver: AuthorizationRequestResolver

    public init(http: any HttpTransport, clock: @escaping () -> Int64, trust: (any RequestTrustVerifier)? = nil) {
        self.http = http
        self.clock = clock
        self.resolver = AuthorizationRequestResolver(http: http, trust: trust)
    }

    public func resolveRequest(_ requestUri: String) async throws -> ResolvedRequest {
        try await resolver.resolve(requestUri)
    }

    public func match(_ request: ResolvedRequest, held: [HeldSdJwtVc]) -> DcqlMatchResult {
        DcqlEngine.match(request.dcqlQuery, held: held)
    }

    public func respond(
        request: ResolvedRequest,
        matches: DcqlMatchResult,
        selection: PresentationSelection,
        held: [HeldSdJwtVc]
    ) async throws -> SubmitResult {
        let missing = matches.requiredQueryIds.filter { selection.chosen[$0] == nil }
        if !missing.isEmpty { throw VpError.queryNotSatisfiable(missing: Set(missing)) }

        var heldById: [String: HeldSdJwtVc] = [:]
        for h in held { heldById[h.credentialId] = h }
        let iat = clock()

        var vpEntries: [(String, JsonValue)] = []
        for (queryId, credentialId) in selection.chosen {
            guard let candidate = matches.candidatesByQuery[queryId]?.first(where: { $0.credential.credentialId == credentialId }) else {
                throw VpError.selectionIncomplete("no candidate \(credentialId) for query \(queryId)")
            }
            guard let cred = heldById[credentialId] else {
                throw VpError.selectionIncomplete("unknown credential \(credentialId)")
            }
            let presentation = try await cred.present(
                disclosedPaths: candidate.disclosedPaths,
                audience: request.clientId, nonce: request.nonce, issuedAt: iat,
                transactionData: request.transactionData
            )
            vpEntries.append((queryId, .arr([.str(presentation)])))
        }
        let vpToken = JsonValue.obj(vpEntries)

        switch request.responseMode {
        case "direct_post": return try await submitDirectPost(request, vpToken)
        case "direct_post.jwt": return try await submitDirectPostJwt(request, vpToken)
        default: throw VpError.unsupported("response_mode \(request.responseMode)")
        }
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
            throw VpError.invalidRequest("direct_post.jwt but no verifier encryption key in client_metadata")
        }
        var entries: [(String, JsonValue)] = [("vp_token", vpToken)]
        if let state = request.state { entries.append(("state", .str(state))) }
        let jwe = try Jwe.encryptEcdhEs(plaintext: [UInt8](JsonValue.obj(entries).serialize().utf8), recipient: recipient, enc: encValue(request))
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

    private func verifierEncryptionKey(_ request: ResolvedRequest) -> EcPublicKey? {
        guard let jwks = request.clientMetadata?["jwks"], case let .arr(keys)? = jwks["keys"] else { return nil }
        let encKey = keys.first { if case .str("enc")? = $0["use"] { return true } else { return false } } ?? keys.first
        return encKey.flatMap { JwkEc.fromJson($0) }
    }

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
