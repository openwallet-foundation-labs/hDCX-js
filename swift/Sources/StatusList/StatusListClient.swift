import Foundation
import SdJwt
import WalletAPI

/// Fetches, verifies, caches and reads IETF Token Status Lists to resolve credential revocation
/// (draft-ietf-oauth-status-list). The `statuslist+jwt` is verified through an `IssuerKeyResolver`
/// — the same port the `Trust` module implements for x5c — so chain validation is reused. Lists
/// are cached until `ttl`/`exp`, so a batch of checks costs one fetch.
public actor StatusListClient {
    private let http: any HttpTransport
    private let keyResolver: any IssuerKeyResolver
    private let clock: () -> Int64
    private let defaultTtlSeconds: Int64
    private var cache: [String: (list: StatusList, expiresAt: Int64)] = [:]

    public init(
        http: any HttpTransport,
        keyResolver: any IssuerKeyResolver,
        clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970) },
        defaultTtlSeconds: Int64 = 300
    ) {
        self.http = http
        self.keyResolver = keyResolver
        self.clock = clock
        self.defaultTtlSeconds = defaultTtlSeconds
    }

    /// Resolves the status of the credential pointed at by `reference`.
    public func check(_ reference: StatusReference) async throws -> CredentialStatus {
        try await fetchList(reference.uri).statusAt(reference.index)
    }

    /// Convenience: resolve a credential's status from its claims, valid-by-default if unlisted.
    public func check(claims: JsonValue) async throws -> CredentialStatus {
        guard let reference = StatusReference.fromClaims(claims) else { return .valid }
        return try await check(reference)
    }

    private func fetchList(_ uri: String) async throws -> StatusList {
        let now = clock()
        if let cached = cache[uri], cached.expiresAt > now { return cached.list }

        let resp = try await http.execute(HttpRequest(method: .get, url: uri, headers: [("Accept", "application/statuslist+jwt")], body: nil))
        guard (200...299).contains(resp.status) else { throw StatusListError("status list fetch failed: HTTP \(resp.status)") }

        let jws = try Jws.parse(String(decoding: resp.body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        if case let .str(typ)? = jws.header["typ"], typ != "statuslist+jwt" {
            throw StatusListError("unexpected status list token typ '\(typ)'")
        }

        guard let payload = try? JsonValue.parse(String(decoding: jws.payloadBytes, as: UTF8.self)) else {
            throw StatusListError("status list token payload must be JSON")
        }
        var sub: String?
        if case let .str(s)? = payload["sub"] { sub = s }
        if let sub, sub != uri { throw StatusListError("status list token sub '\(sub)' does not match its URI") }
        if case let .numInt(exp)? = payload["exp"], exp <= now { throw StatusListError("status list token expired") }

        let iss: String = { if case let .str(s)? = payload["iss"] { return s }; return sub ?? uri }()
        let key = try await keyResolver.resolve(iss: iss, header: jws.header) // verifies x5c / throws if untrusted
        guard jws.verify(key: key.publicKey, expected: key.algorithm) else { throw StatusListError("status list token signature invalid") }

        let list = try StatusList.fromTokenPayload(payload)
        var expiresAt = now + defaultTtlSeconds
        if case let .numInt(ttl)? = payload["ttl"] { expiresAt = now + ttl }
        else if case let .numInt(exp)? = payload["exp"] { expiresAt = exp }
        cache[uri] = (list, expiresAt)
        return list
    }
}
