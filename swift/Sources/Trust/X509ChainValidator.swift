import Foundation
import X509

/// Trust anchors (IACA / issuer-CA roots) the wallet is configured with — populated from the
/// EU LOTL / trust list by the host.
public struct TrustAnchors {
    let roots: [Certificate]

    public init(roots: [Certificate]) {
        precondition(!roots.isEmpty, "at least one trust anchor is required")
        self.roots = roots
    }

    public static func ofDer(_ ders: [[UInt8]]) throws -> TrustAnchors {
        TrustAnchors(roots: try ders.map { try X509Support.parse($0) })
    }
}

/// Validates an X.509 chain (leaf-first, excluding the anchor) to a configured `TrustAnchors`
/// via swift-certificates' `Verifier` with the RFC 5280 policy.
public struct X509ChainValidator {
    private let anchors: TrustAnchors
    private let validationTime: Date

    public init(anchors: TrustAnchors, validationTime: Date = Date()) {
        self.anchors = anchors
        self.validationTime = validationTime
    }

    /// Returns the parsed chain (leaf first) if it validates to an anchor, else throws.
    public func validate(_ chainDer: [[UInt8]]) async throws -> [Certificate] {
        guard let leafDer = chainDer.first else { throw TrustError("empty certificate chain") }
        let leaf = try X509Support.parse(leafDer)
        let intermediates = try chainDer.dropFirst().map { try X509Support.parse($0) }

        let time = validationTime
        var verifier = Verifier(rootCertificates: CertificateStore(anchors.roots)) {
            RFC5280Policy(validationTime: time)
        }
        let result = await verifier.validate(
            leafCertificate: leaf,
            intermediates: CertificateStore(intermediates)
        )
        switch result {
        case .validCertificate:
            return [leaf] + intermediates
        case let .couldNotValidate(failures):
            throw TrustError("chain does not validate to a trust anchor: \(failures)")
        }
    }
}
