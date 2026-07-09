import CborCose

/// Everything a held credential needs to build its OpenID4VP presentation for one query.
public struct PresentationContext {
    /// Concrete leaf paths DCQL selected (SD-JWT VC claim paths / mdoc [ns, element]).
    public let disclosedPaths: [[String]]
    public let clientId: String
    public let nonce: String
    public let responseUri: String?
    public let issuedAt: Int64
    public let transactionData: [String]?
    /// RFC 7638 thumbprint of the verifier's encryption key, for the mdoc OpenID4VP handover (nil if unencrypted).
    public let verifierJwkThumbprint: [UInt8]?
    /// Caller web origin for a Digital Credentials API presentation; non-nil selects the DC API handover.
    public let origin: String?
    /// The verifier's response-encryption public key, doubling as the `EReaderKey` for mdoc `deviceMac`
    /// (ISO 18013-7 B.4.5 / OpenID4VP §B.2.2). Nil when the response is unencrypted — then only
    /// `deviceSignature` is possible, as there is no reader key to run ECDH against.
    public let verifierEncryptionKey: EcPublicKey?
    /// COSE algorithm identifiers from the verifier's `deviceauth_alg_values` (OpenID4VP §B.2.2), stating
    /// which `deviceSignature` / `deviceMac` algorithms it accepts. Nil when the verifier did not constrain it.
    public let deviceAuthAlgValues: [Int64]?
    /// §6.1 `require_cryptographic_holder_binding`. When false the verifier accepts an unbound credential, so an
    /// SD-JWT VC may be presented without a KB-JWT. Default true (bind). mdoc always binds via DeviceAuth.
    public let requireHolderBinding: Bool

    public init(disclosedPaths: [[String]], clientId: String, nonce: String, responseUri: String?,
                issuedAt: Int64, transactionData: [String]?, verifierJwkThumbprint: [UInt8]?, origin: String? = nil,
                verifierEncryptionKey: EcPublicKey? = nil, deviceAuthAlgValues: [Int64]? = nil,
                requireHolderBinding: Bool = true) {
        self.disclosedPaths = disclosedPaths
        self.clientId = clientId
        self.nonce = nonce
        self.responseUri = responseUri
        self.issuedAt = issuedAt
        self.transactionData = transactionData
        self.verifierJwkThumbprint = verifierJwkThumbprint
        self.origin = origin
        self.verifierEncryptionKey = verifierEncryptionKey
        self.deviceAuthAlgValues = deviceAuthAlgValues
        self.requireHolderBinding = requireHolderBinding
    }
}

/// A held credential that can produce an OpenID4VP `vp_token` entry. Both SD-JWT VC
/// (`HeldSdJwtVc`) and mdoc (`HeldMdoc`) conform so `Openid4VpClient` presents either.
public protocol PresentableCredential: QueryableCredential {
    func present(_ ctx: PresentationContext) async throws -> String
}
