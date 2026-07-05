import Foundation
import WalletAPI

/*
 * Storage envelope: the format-agnostic persistence layer (M1).
 * Claims/validity parsing belongs to the format modules (M2+) — here payloads are opaque.
 * Public Credential facade model is assembled on top of this in M2.
 */

/// One issued credential instance: payload bound to a device key (HAIP batch → N instances).
public struct CredentialInstance: Sendable {
    public let key: KeyHandle
    public let payload: [UInt8]
    public let useCount: Int

    public init(key: KeyHandle, payload: [UInt8], useCount: Int = 0) {
        self.key = key
        self.payload = payload
        self.useCount = useCount
    }
}

public enum EnvelopeLifecycle: Sendable {
    /// Issuance started but paused on user authorization (dynamic issuance resume).
    case pending(authorizationUrl: String?, resumeContext: [UInt8]?)
    /// Issuer accepted but credential not ready yet (deferred issuance).
    case deferred(transactionContext: [UInt8], retryAfter: Date?)
    case issued(policy: CredentialPolicy, instances: [CredentialInstance])
}

public struct CredentialMetadata: Sendable {
    public let issuerUrl: String
    public let issuerDisplayName: String?
    public let configurationId: String
    public let displayName: String?
    public let logoUri: String?
    public let backgroundColor: String?

    public init(issuerUrl: String, issuerDisplayName: String?, configurationId: String,
                displayName: String?, logoUri: String?, backgroundColor: String?) {
        self.issuerUrl = issuerUrl
        self.issuerDisplayName = issuerDisplayName
        self.configurationId = configurationId
        self.displayName = displayName
        self.logoUri = logoUri
        self.backgroundColor = backgroundColor
    }
}

public struct CredentialEnvelope: Sendable {
    public let id: CredentialId
    public let format: CredentialFormat
    public let createdAt: Date
    public let lifecycle: EnvelopeLifecycle
    /// Issuer/display metadata captured at issuance (from issuer metadata).
    public let metadata: CredentialMetadata?

    public init(id: CredentialId, format: CredentialFormat, createdAt: Date, lifecycle: EnvelopeLifecycle, metadata: CredentialMetadata? = nil) {
        self.id = id
        self.format = format
        self.createdAt = createdAt
        self.lifecycle = lifecycle
        self.metadata = metadata
    }
}
