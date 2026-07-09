import Crypto
import Foundation
import SdJwt

/// An SD-JWT VC the wallet holds, usable as a DCQL match target and presentable over OpenID4VP.
public struct HeldSdJwtVc: PresentableCredential {
    public let credentialId: String
    let sdJwt: SdJwt
    let holderSigner: any JwsSigner

    public let format = "dc+sd-jwt"
    public let claims: JsonValue
    public let docType: String? = nil

    public var vct: String? {
        if case let .str(v)? = claims["vct"] { return v }
        return nil
    }

    public init(credentialId: String, sdJwt: SdJwt, holderSigner: any JwsSigner) throws {
        self.credentialId = credentialId
        self.sdJwt = sdJwt
        self.holderSigner = holderSigner
        self.claims = try SdJwtHolder.processedClaims(sdJwt)
    }

    /// Selects the disclosed disclosures and, unless the verifier waived it, appends a KB-JWT bound to the
    /// verifier client_id + nonce.
    ///
    /// §6.1 `require_cryptographic_holder_binding=false` lets the verifier accept an unbound credential — then
    /// no KB-JWT is produced, which also drops replay protection (the presentation is not tied to this verifier
    /// or nonce). Transaction data can only be conveyed inside the KB-JWT, so its presence forces binding.
    public func present(_ ctx: PresentationContext) async throws -> String {
        let pathSet = Set(ctx.disclosedPaths)
        if !ctx.requireHolderBinding, ctx.transactionData?.isEmpty ?? true {
            return try SdJwtHolder.present(sdJwt, select: { pathSet.contains($0) }).serialize()
        }
        var extra: [(String, JsonValue)] = []
        if let td = ctx.transactionData, !td.isEmpty {
            extra.append(("transaction_data_hashes", .arr(td.map { .str(sha256B64($0)) })))
            extra.append(("transaction_data_hashes_alg", .str("sha-256")))
        }
        let presented = try await SdJwtHolder.presentWithKeyBinding(
            sdJwt, select: { pathSet.contains($0) },
            audience: ctx.clientId, nonce: ctx.nonce, issuedAt: ctx.issuedAt, signer: holderSigner, extraClaims: extra
        )
        return presented.serialize()
    }

    private func sha256B64(_ s: String) -> String {
        Base64Url.encode([UInt8](SHA256.hash(data: Data(s.utf8))))
    }
}
