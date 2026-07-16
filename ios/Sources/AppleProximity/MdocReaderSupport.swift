import CborCose
import Foundation // Data (image-claim base64 encoding)
import MDoc

/// Reader-side helpers that keep the `MDoc` / `CborCose` types out of the app: the app builds a request and
/// renders results through these, naming only `AppleProximity` types. Mirrors the android demo's
/// `readerRequest()` + `ReaderResultCard` rendering.

/// One document a proximity reader received, flattened for display.
public struct ReaderResultDoc: Sendable {
    public let docType: String
    public let deviceAuthenticated: Bool
    public let claims: [Claim]

    public struct Claim: Sendable {
        public let namespace: String
        public let element: String
        public let value: String
        /// Standard-base64 raw bytes for an image element (portrait etc.), so the app can render a thumbnail.
        public let imageBase64: String?
    }
}

/// The document types the demo reader can request — picked one at a time on the reader screen.
/// Mirrors the android demo's `ReaderDocKind`.
public enum ReaderDocKind: String, CaseIterable, Sendable {
    case pid = "Personal ID"
    case mdl = "Driving Licence"
    case age = "Proof of Age"
    case photoID = "Photo ID"

    /// The exact mdoc DocType this kind requests — shown under the friendly name in the picker.
    public var doctype: String {
        switch self {
        case .pid: return "eu.europa.ec.eudi.pid.1"
        case .mdl: return "org.iso.18013.5.1.mDL"
        case .age: return "eu.europa.ec.av.1"
        case .photoID: return "org.iso.23220.photoid.1"
        }
    }
}

public enum MdocReaderRequests {
    /// The request for one document kind (android demo `readerRequest(kind)`).
    public static func request(_ kind: ReaderDocKind) -> [RequestedDocument] {
        let elements: [(String, [String])]
        switch kind {
        case .pid:
            elements = [("eu.europa.ec.eudi.pid.1", ["family_name", "given_name", "birth_date", "nationality"])]
        // portrait is an ISO 18013-5 mandatory element — the reader verifies the holder's photo.
        case .mdl:
            elements = [("org.iso.18013.5.1", ["family_name", "given_name", "portrait", "driving_privileges"])]
        // AV Profile §A.4: age_over_18 is the only attribute a Proof of Age attestation carries.
        case .age:
            elements = [("eu.europa.ec.av.1", ["age_over_18"])]
        // ISO 23220-4 Annex C: identity claims live in the generic 23220-2 namespace.
        case .photoID:
            elements = [("org.iso.23220.1", ["family_name", "given_name", "birth_date", "portrait", "age_over_18"])]
        }
        return [RequestedDocument(docType: kind.doctype, elements: elements)]
    }

    /// Flattens verified documents into display rows, rendering each CBOR element value to a readable string.
    public static func flatten(_ documents: [VerifiedDocument]) -> [ReaderResultDoc] {
        documents.map { doc in
            var claims: [ReaderResultDoc.Claim] = []
            for (namespace, elements) in doc.elements {
                for (element, value) in elements {
                    var imageBase64: String?
                    if case let .bytes(b) = value, imageElements.contains(element.lowercased()) {
                        imageBase64 = Data(b).base64EncodedString()
                    }
                    claims.append(.init(namespace: namespace, element: element, value: cborString(value), imageBase64: imageBase64))
                }
            }
            return ReaderResultDoc(
                docType: doc.docType,
                deviceAuthenticated: doc.deviceAuthenticated,
                claims: claims.sorted { $0.element < $1.element }
            )
        }
    }
}

/// mdoc image-carrying elements (ISO 23220-2 / 18013-5) — surfaced with raw bytes for thumbnail rendering.
private let imageElements: Set<String> = ["portrait", "enrolment_portrait_image", "signature_usual_mark"]

/// Best-effort human rendering of a CBOR element value (dates unwrapped from their tag).
func cborString(_ value: Cbor) -> String {
    switch value {
    case let .text(s): return s
    case let .uint(u): return String(u)
    case let .bool(b): return b ? "Yes" : "No"
    case let .bytes(b): return "\(b.count) bytes"
    case let .array(a): return a.map(cborString).joined(separator: ", ")
    case let .tagged(_, inner): return cborString(inner)
    case .null: return "—"
    default: return String(describing: value)
    }
}
