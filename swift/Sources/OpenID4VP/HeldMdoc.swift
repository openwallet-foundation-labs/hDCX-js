import CborCose
import MDoc
import SdJwt

/// A held mdoc (ISO 18013-5) exposed to DCQL as a `QueryableCredential`. mdoc claims are a
/// two-level tree `{ namespace: { elementIdentifier: value } }`, so a DCQL claim path is
/// `[namespace, element]` (both strings) — see the mdoc path handling in Dcql parsing.
public struct HeldMdoc: QueryableCredential {
    public let credentialId: String
    public let issuerSigned: IssuerSigned
    public let format = "mso_mdoc"
    public let vct: String? = nil
    public let docType: String?
    public let claims: JsonValue

    public init(credentialId: String, issuerSigned: IssuerSigned) throws {
        self.credentialId = credentialId
        self.issuerSigned = issuerSigned
        self.docType = try issuerSigned.parseMso().docType
        self.claims = .obj(issuerSigned.elements().map { ns, elements in
            (ns, .obj(elements.map { ($0.0, CborJson.toJson($0.1)) }))
        })
    }
}
