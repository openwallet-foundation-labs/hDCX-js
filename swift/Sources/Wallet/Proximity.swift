import CborCose
import MDoc
import Proximity
import WalletAPI

/// What an in-person reader asked for (ISO 18013-5 device retrieval), ready for the consent screen: the
/// requested documents/elements and which stored credential answers each. Raw request + session carried for the reply.
public struct ProximityRequest {
    public let documents: [RequestedDocumentView]
    public let satisfiable: Bool
    /// Who is asking — from verified reader authentication (ISO 18013-5 §9.1.4), if present and trusted.
    public let reader: ProximityReaderInfo
    let deviceRequest: DeviceRequest
    let transcript: Cbor
    let session: SessionEncryption
}

/// The in-person reader's identity. `trusted` is true only when the request was reader-authenticated and
/// the reader certificate chained to a configured reader anchor (config.trust.readerAnchorsDer).
public struct ProximityReaderInfo {
    public let trusted: Bool
    public let commonName: String?
    public let certificateChainDer: [[UInt8]]
}

/// One requested document: the doctype, the elements the reader wants, and the matching stored credential.
public struct RequestedDocumentView {
    public let docType: String
    public let requestedElements: [String: [String]]
    /// Stored credentials that can answer this doctype; the holder chooses one when there is more than one.
    public let candidates: [CredentialId]
}

/// An org-iso-mdoc (ISO 18013-7) Digital Credentials API request, resolved for the consent screen: the requested
/// documents/elements + matching credentials, and the verified reader identity. Unlike the proximity flow there is
/// no BLE session — the response is produced separately (on approval) via `ProximityService.respondDcApiMdoc`.
public struct DcApiMdocRequest {
    public let documents: [RequestedDocumentView]
    public let satisfiable: Bool
    /// Who is asking — from verified reader authentication (ISO 18013-5 §9.1.4), if present and trusted.
    public let reader: ProximityReaderInfo
}

/// The user's choice of which stored credential answers each requested doctype.
public struct ProximitySelection {
    public let chosen: [String: CredentialId]
    public init(chosen: [String: CredentialId]) { self.chosen = chosen }

    public static func auto(_ request: ProximityRequest) -> ProximitySelection {
        var chosen: [String: CredentialId] = [:]
        for doc in request.documents { if let candidate = doc.candidates.first { chosen[doc.docType] = candidate } }
        return ProximitySelection(chosen: chosen)
    }
}

/// Proximity presentation session state.
public enum ProximityState {
    case generatingEngagement
    /// Engagement is ready and the wallet is waiting for the reader — the app renders it as a QR / NFC tag.
    case engagementReady(deviceEngagement: [UInt8], handoverNdef: [UInt8]? = nil)
    case requestReceived(ProximityRequest)
    case submitting
    case completed
    case declined
    case failed(ProximityError)

    public var isTerminal: Bool {
        switch self {
        case .completed, .declined, .failed: return true
        default: return false
        }
    }
}
