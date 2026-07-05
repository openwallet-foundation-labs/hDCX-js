import Foundation

/// Typed issuance errors (API-CONTRACT.md §8). Spec error codes are preserved on the relevant cases.
public enum IssuanceError: Error, Equatable {
    case invalidOffer(String)
    case authorizationFailed(oauthError: String?, message: String)
    case credentialRequestFailed(String)
    case deferredNotReady
    case unexpected(String)
}

/// Typed presentation errors (API-CONTRACT.md §8).
public enum PresentationError: Error, Equatable {
    case invalidRequest(String)
    case verifierNotTrusted(String)
    case queryNotSatisfiable(String)
    case selectionIncomplete(String)
    case responseRejected(String)
    case unexpected(String)
}

/// Typed ISO 18013-5 proximity errors (API-CONTRACT.md §8).
public enum ProximityError: Error, Equatable {
    case sessionFailed(String)
    case noMatchingCredential(String)
    case unexpected(String)
}
