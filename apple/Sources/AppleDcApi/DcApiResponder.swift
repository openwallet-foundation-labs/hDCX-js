import Foundation
import Wallet

/// Turns Apple's `IdentityDocumentWebPresentmentRawRequest` (its `requestData` JSON + the calling web origin) into
/// the raw CBOR `DeviceResponse` bytes for `ISO18013MobileDocumentResponse(responseData:)`.
///
/// All the cryptography — mdoc `DeviceResponse` build, HPKE seal to the verifier's key, ISO/IEC 18013-7:2025 Annex C
/// SessionTranscript — is the SDK's `proximity.respondDcApiMdoc`. This only marshals the wire shapes Apple's API
/// uses (base64url-JSON in, raw `Data` out) and normalizes the origin so its hash matches what the verifier signed.
/// Behaviour matches android's `GetCredentialActivity` mdoc branch: resolve (consent + reader badge) → respond.
public enum DcApiResponder {
    public enum Failure: Error, CustomStringConvertible {
        case missingOrigin
        case malformedRequest
        case responseEncoding
        public var description: String {
            switch self {
            case .missingOrigin: return "the web presentment request had no requesting origin"
            case .malformedRequest: return "request data was not the expected {deviceRequest, encryptionInfo} JSON"
            case .responseEncoding: return "the DeviceResponse was not valid base64url"
            }
        }
    }

    private struct RawRequest: Decodable { let deviceRequest: String; let encryptionInfo: String }

    /// Builds the encrypted `org-iso-mdoc` DeviceResponse for a raw web-presentment request. `wallet` must be built
    /// from the shared Secure Enclave + keychain group so it can read the app's credentials and sign with their
    /// device keys. Auto-discloses `requested ∩ held` (Apple's picker already chose the document; there is no
    /// per-claim consent in this path, matching `respondDcApiMdoc` and android).
    public static func responseData(rawRequestData: Data, origin: URL?, wallet: Wallet) async throws -> Data {
        guard let origin else { throw Failure.missingOrigin }
        guard let req = try? JSONDecoder().decode(RawRequest.self, from: rawRequestData) else { throw Failure.malformedRequest }
        let base64url = try await wallet.proximity.respondDcApiMdoc(
            deviceRequestBase64: req.deviceRequest,
            encryptionInfoBase64: req.encryptionInfo,
            origin: normalizedOrigin(origin))
        guard let data = dataFromBase64Url(base64url) else { throw Failure.responseEncoding }
        return data
    }

    /// The verifier hashes the *exact* origin string into the SessionTranscript; Apple's `URL.absoluteString` can
    /// carry a trailing `/` the web origin does not, which would silently change the hash and fail verification.
    static func normalizedOrigin(_ url: URL) -> String {
        var s = url.absoluteString
        while s.hasSuffix("/") { s.removeLast() }
        return s
    }

    static func dataFromBase64Url(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t.append("=") }
        return Data(base64Encoded: t)
    }
}
