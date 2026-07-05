import TransactionLog
import WalletAPI

/// Host-supplied adapters. The SDK owns credential/key/attestation lifecycle; the app injects thin
/// platform capabilities.
public struct WalletPorts {
    /// At least one; the first is the default secure area.
    public let secureAreas: [any SecureArea]
    public let storage: any StorageDriver
    public let http: any HttpTransport
    /// Wallet Provider backend link (WUA). Required for attestation-based client auth.
    public let walletAttestation: (any WalletAttestationProvider)?
    public let clock: any WalletClock
    public let rng: any Rng
    public let logger: (any WalletLogger)?
    /// Append-only persistence for the audit log (ARF/GDPR). Defaults to in-memory; production wallets persist.
    public let transactionLogStore: any TransactionLogStore

    public init(secureAreas: [any SecureArea], storage: any StorageDriver, http: any HttpTransport,
                walletAttestation: (any WalletAttestationProvider)? = nil,
                clock: any WalletClock = SystemClock(), rng: any Rng = SystemRng(),
                logger: (any WalletLogger)? = nil, transactionLogStore: any TransactionLogStore = InMemoryTransactionLogStore()) {
        precondition(!secureAreas.isEmpty, "WalletPorts requires at least one SecureArea")
        self.secureAreas = secureAreas
        self.storage = storage
        self.http = http
        self.walletAttestation = walletAttestation
        self.clock = clock
        self.rng = rng
        self.logger = logger
        self.transactionLogStore = transactionLogStore
    }

    var defaultSecureArea: any SecureArea { secureAreas[0] }
}
