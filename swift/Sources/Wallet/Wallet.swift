import CredentialStore
import Foundation
import OpenID4VCI
import OpenID4VP
import StatusList
import Trust
import WalletAPI

/// The unified EUDI Wallet SDK facade (API-CONTRACT.md §5). Multi-instance; no global state.
///
/// Phases A–C wire credential storage, DCQL retrieval, status, issuance, and remote presentation; proximity follows.
public struct Wallet {
    public let credentials: CredentialsService
    public let issuance: IssuanceService
    public let presentation: PresentationService
    public let proximity: ProximityService
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

        // Reader trust: verify signed OpenID4VP request objects against the configured reader anchors.
        // Unsigned requests (or no anchors) resolve with verifier.trusted == false.
        let vpTrust: (any RequestTrustVerifier)? = config.trust.readerAnchorsDer.isEmpty ? nil :
            X509RequestVerifier(validator: X509ChainValidator(anchorSource: LazyIssuerAnchorSource(ders: config.trust.readerAnchorsDer), validationTime: ports.clock.now()))
        let vp = Openid4VpClient(http: ports.http, clock: clockSeconds, trust: vpTrust)
        let presentation = PresentationService(vp: vp, store: store, txlog: ports.transactionLog,
                                               secureAreas: ports.secureAreas, clock: ports.clock, rng: ports.rng)
        let proximity = ProximityService(store: store, txlog: ports.transactionLog,
                                         secureAreas: ports.secureAreas, clock: ports.clock, rng: ports.rng)

        return Wallet(credentials: CredentialsService(store: store, statusClient: statusClient),
                      issuance: issuance, presentation: presentation, proximity: proximity, ports: ports)
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
