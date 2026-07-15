import SwiftUI

/// The app root — gates the wallet behind first-run onboarding and the auto-lock (android `MainActivity`).
/// `WalletHome` stays alive underneath once onboarded, so `LockView` overlays it (no reload on unlock) and
/// also masks wallet content in the app switcher. The wallet re-locks whenever it returns from the background.
struct RootView: View {
    @State private var appLock = AppLock()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ZStack {
            if appLock.onboarded {
                WalletHome()
            }
            if !appLock.onboarded {
                OnboardingView { appLock.completeOnboarding() }
            } else if appLock.locked {
                LockView { appLock.unlock() }
            }
        }
        .environment(appLock)
        .preferredColorScheme(.light)
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { appLock.lock() }
        }
    }
}
