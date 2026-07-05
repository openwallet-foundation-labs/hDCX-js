import CredentialStore
import Foundation
import OpenID4VCI
import OpenID4VP
import SdJwt
import StatusList
import TransactionLog
import Trust
import WalletAPI

/// The unified EUDI Wallet SDK facade. Multi-instance; no global state.
///
/// Phases A–C wire credential storage, DCQL retrieval, status, issuance, and remote presentation; proximity follows.
public struct Wallet {
    public let credentials: CredentialsService
    public let issuance: IssuanceService
    public let presentation: PresentationService
    public let proximity: ProximityService
    /// Audit history of presentations/issuances (ARF/GDPR) — query with `history()` / `query(...)`.
    public let transactions: TransactionLog
    private let ports: WalletPorts

    /// Idempotent; no resources held yet.
    public func close() {}

    public static func create(config: WalletConfig, ports: WalletPorts) -> Wallet {
        let clockSeconds: () -> Int64 = { Int64(ports.clock.now().timeIntervalSince1970) }
        let store = DefaultCredentialStore(driver: ports.storage)

        // Lazy anchor source: anchors are only required when a status token is actually verified, so a
        // wallet without configured anchors can still read credentials with no status reference.
        let anchorSource = LazyIssuerAnchorSource(ders: config.trust.issuerAnchorsDer)
        let validator = X509ChainValidator(anchorSource: anchorSource, validationTime: ports.clock.now())
        let statusClient = StatusListClient(http: ports.http, keyResolver: X5cIssuerKeyResolver(validator: validator), clock: clockSeconds)

        let vci = Openid4VciClient(http: ports.http, rng: ports.rng, clock: clockSeconds, clientId: config.issuance.clientId)
        let issuance = IssuanceService(vci: vci, store: store, storage: ports.storage, secureArea: ports.defaultSecureArea,
                                       rng: ports.rng, clock: ports.clock, redirectUri: config.issuance.redirectUri)

        // Reader trust: one validator over the configured reader anchors, shared by remote (signed OpenID4VP
        // request objects) and proximity (mdoc reader authentication). No anchors → readers stay untrusted.
        let readerValidator: X509ChainValidator? = config.trust.readerAnchorsDer.isEmpty ? nil :
            X509ChainValidator(anchorSource: LazyIssuerAnchorSource(ders: config.trust.readerAnchorsDer), validationTime: ports.clock.now())
        let vpTrust: (any RequestTrustVerifier)? = readerValidator.map { X509RequestVerifier(validator: $0) }
        let vp = Openid4VpClient(http: ports.http, clock: clockSeconds, trust: vpTrust)
        let txlog = TransactionLog(
            store: ports.transactionLogStore,
            idGenerator: { "txn-" + Base64Url.encode(ports.rng.nextBytes(12)) },
            clock: clockSeconds)
        let presentation = PresentationService(vp: vp, store: store, txlog: txlog, secureAreas: ports.secureAreas)
        let proximity = ProximityService(store: store, txlog: txlog, secureAreas: ports.secureAreas,
                                         readerTrust: readerValidator.map { X5cMdocReaderTrust(validator: $0) })

        return Wallet(credentials: CredentialsService(store: store, statusClient: statusClient),
                      issuance: issuance, presentation: presentation, proximity: proximity, transactions: txlog, ports: ports)
    }
}

struct LazyIssuerAnchorSource: TrustAnchorSource {
    let ders: [[UInt8]]
    func anchors() async throws -> TrustAnchors {
        guard !ders.isEmpty else { throw WalletFacadeError.noTrustAnchors }
        return try TrustAnchors.ofDer(ders)
    }
}

enum WalletFacadeError: Error { case noTrustAnchors }
