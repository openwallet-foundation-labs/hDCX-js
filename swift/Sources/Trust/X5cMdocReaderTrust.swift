import CborCose
import Foundation
import MDoc

/// Resolves an mdoc reader's key from the `readerAuth` x5chain, validating the chain to a **reader**
/// trust anchor (configure `validator` with the reader-CA anchors, distinct from issuer anchors).
/// This authenticates the verifier that is asking for data (ISO 18013-5 §9.1.4).
public struct X5cMdocReaderTrust: MdocReaderTrust {
    private let validator: X509ChainValidator

    public init(validator: X509ChainValidator) {
        self.validator = validator
    }

    public func readerKey(x5chain: [[UInt8]]) async throws -> EcPublicKey {
        let chain = try await validator.validate(x5chain) // throws if not trusted
        return try X509Support.ecPublicKey(chain[0])
    }
}
