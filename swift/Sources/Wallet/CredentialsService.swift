import CredentialStore
import Foundation
import OpenID4VP
import SdJwt
import StatusList
import WalletAPI

/// Stored-credential management. Reads are local; `status` hits the network.
public struct CredentialsService {
    private let store: DefaultCredentialStore
    private let statusClient: StatusListClient

    init(store: DefaultCredentialStore, statusClient: StatusListClient) {
        self.store = store
        self.statusClient = statusClient
    }

    public func list(filter: CredentialFilter = .all) async throws -> [Credential] {
        try await store.list().map { $0.toCredential() }.filter { filter.matches($0) }
    }

    public func get(_ id: CredentialId) async throws -> Credential? {
        try await store.get(id)?.toCredential()
    }

    /// The raw serialized credential, for export / backup / inspection: the SD-JWT VC compact
    /// serialization for SD-JWT, or the base64url-encoded issuer-signed CBOR for mdoc. Nil if
    /// the credential is unknown or not yet issued.
    public func export(_ id: CredentialId) async throws -> String? {
        guard let envelope = try await store.get(id),
              case let .issued(_, instances) = envelope.lifecycle,
              let payload = instances.first?.payload else { return nil }
        switch envelope.format {
        case .sdJwtVc: return String(decoding: payload, as: UTF8.self)
        case .msoMdoc: return Base64Url.encode(payload)
        }
    }

    public func delete(_ id: CredentialId) async throws {
        try await store.delete(id)
    }

    /// Reactive list changes (added/updated/removed) for UI refresh.
    public func changes() async -> AsyncStream<CredentialChange> {
        let source = await store.changes()
        return AsyncStream { continuation in
            Task {
                for await change in source { continuation.yield(change.toFacade()) }
                continuation.finish()
            }
        }
    }

    /// Matches stored credentials against a DCQL query (OpenID4VP §6) — presentation-independent.
    public func match(_ dcqlJson: String) async throws -> CredentialMatch {
        let envelopes = try await store.list()
        let held = envelopes.compactMap { $0.toQueryable() }
        let query = try DcqlQuery.parse(JsonValue.parse(dcqlJson))
        let result = DcqlEngine.match(query, held: held)
        let byId = Dictionary(envelopes.map { ($0.id.value, $0) }, uniquingKeysWith: { first, _ in first })
        var byQuery: [String: [MatchedCredential]] = [:]
        for (queryId, candidates) in result.candidatesByQuery {
            byQuery[queryId] = candidates.compactMap { candidate in
                byId[candidate.credential.credentialId].map {
                    MatchedCredential(credential: $0.toCredential(), disclosedPaths: candidate.disclosedPaths)
                }
            }
        }
        return CredentialMatch(satisfiable: result.isSatisfiable(), byQuery: byQuery)
    }

    /// Revocation status via IETF Token Status List. Valid when the credential carries no status reference.
    public func status(_ id: CredentialId) async throws -> CredentialStatus {
        guard let claims = try await store.get(id)?.claimsTree() else { return .unknown }
        switch try await statusClient.check(claims: claims) {
        case .valid: return .valid
        case .invalid: return .invalid
        case .suspended: return .suspended
        case .unknown: return .unknown
        }
    }
}

/// Result of `CredentialsService.match`: which held credentials satisfy each query, and disclosed paths.
public struct CredentialMatch {
    public let satisfiable: Bool
    public let byQuery: [String: [MatchedCredential]]
}

public struct MatchedCredential {
    public let credential: Credential
    public let disclosedPaths: [[String]]
}

public enum CredentialChange {
    case added(CredentialId)
    case updated(CredentialId)
    case removed(CredentialId)
}

/// Credential revocation status (IETF Token Status List).
public enum CredentialStatus: Equatable { case valid, invalid, suspended, unknown }

extension CredentialStoreChange {
    func toFacade() -> CredentialChange {
        switch self {
        case let .added(id): return .added(id)
        case let .updated(id): return .updated(id)
        case let .removed(id): return .removed(id)
        }
    }
}
