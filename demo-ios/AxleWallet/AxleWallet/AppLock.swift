import Observation

/// App-lock gating state (onboarding + auto-lock) — the iOS counterpart of android `MainActivity`'s
/// `onboarded`/`locked` flags. The wallet re-locks whenever it returns from the background (see `RootView`);
/// unlike android, iOS sheets / covers / the auth browser stay foreground, so no per-launch suppression is needed.
@MainActor
@Observable
final class AppLock {
    private(set) var onboarded: Bool
    var locked: Bool

    init() {
        let isOnboarded = WalletSecurity.isOnboarded
        onboarded = isOnboarded
        locked = isOnboarded // cold start: require unlock if the wallet is already set up
    }

    func completeOnboarding() {
        onboarded = true
        locked = false
    }

    func unlock() { locked = false }

    func lock() { if onboarded { locked = true } }

    /// Factory reset: clear the PIN/flags and drop back to onboarding.
    func reset() {
        WalletSecurity.reset()
        onboarded = false
        locked = false
    }
}
