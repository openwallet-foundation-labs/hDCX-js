import Foundation

/// Typed issuance errors. Spec error codes are preserved on the relevant cases.
public enum IssuanceError: Error, Equatable {
    case invalidOffer(String)
    case authorizationFailed(oauthError: String?, message: String)
    case credentialRequestFailed(String)
    case deferredNotReady
    case unexpected(String)
}

/// Typed presentation errors.
public enum PresentationError: Error, Equatable {
    case invalidRequest(String)
    case verifierNotTrusted(String)
    case queryNotSatisfiable(String)
    case selectionIncomplete(String)
    case responseRejected(String)
    case unexpected(String)
}

/// Typed ISO 18013-5 proximity errors.
public enum ProximityError: Error, Equatable {
    case sessionFailed(String)
    case noMatchingCredential(String)
    case unexpected(String)
}
