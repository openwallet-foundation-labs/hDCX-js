import Foundation
import OpenID4VP
import WalletAPI

/// A resolved verifier request, ready for the consent screen: who is asking, what they want, and which
/// stored credentials can satisfy each query. The raw resolved request + match are carried for respond.
public struct PresentationRequest {
    public let verifier: VerifierInfo
    public let queries: [QueryPresentation]
    public let transactionData: [String]?
    public let satisfiable: Bool
    let resolved: ResolvedRequest
    let matches: DcqlMatchResult
}

/// Who is requesting, and whether trust was established (signed request verified to a reader anchor).
public struct VerifierInfo {
    public let clientId: String
    public let clientIdScheme: String
    public let commonName: String?
    public let trusted: Bool
}

/// One DCQL query with the stored credentials that can answer it.
public struct QueryPresentation {
    public let queryId: String
    public let required: Bool
    public let candidates: [PresentationCandidate]
}

/// A stored credential that satisfies a query, with the claim paths it would disclose.
public struct PresentationCandidate {
    public let credentialId: CredentialId
    public let disclosedPaths: [[String]]
}

/// The user's choice of which credential answers each query.
public struct PresentationSelection {
    public let chosen: [String: CredentialId]
    public init(chosen: [String: CredentialId]) { self.chosen = chosen }

    /// Auto-pick the first candidate for every required query.
    public static func auto(_ request: PresentationRequest) -> PresentationSelection {
        var chosen: [String: CredentialId] = [:]
        for query in request.queries where query.required {
            if let first = query.candidates.first { chosen[query.queryId] = first.credentialId }
        }
        return PresentationSelection(chosen: chosen)
    }
}

/// Presentation session state.
public enum PresentationState {
    case resolvingRequest
    case requestResolved(PresentationRequest)
    case submitting
    /// Success. `redirectUri` is the verifier redirect for the remote (URL/QR) flow; `dcApiResponse` is
    /// the JSON object to hand back to the platform for the Digital Credentials API flow. Exactly one is set.
    case completed(redirectUri: String?, dcApiResponse: String?)
    case declined
    case failed(PresentationError)

    public var isTerminal: Bool {
        switch self {
        case .completed, .declined, .failed: return true
        default: return false
        }
    }
}
