import Foundation

/**
 * A single issuance run driven as a state machine. One-shot; the flow runs in
 * a Task and pauses at browser-authorization / tx-code interruptions until the app resumes.
 */
public final class IssuanceSession: @unchecked Sendable {
    private let lock = NSLock()
    private var _currentState: IssuanceState = .preparing
    public var currentState: IssuanceState { locked { _currentState } }

    public let states: AsyncStream<IssuanceState>
    private let continuation: AsyncStream<IssuanceState>.Continuation
    private var task: Task<Void, Never>?
    private var authContinuation: CheckedContinuation<String, Never>?
    private var txCodeContinuation: CheckedContinuation<String, Never>?
    private var _issuer: String?
    private let flow: (IssuanceSession) async throws -> Void

    /// The credential issuer, set by the flow as soon as it is known, so a failure can be logged against it.
    var issuer: String? {
        get { locked { _issuer } }
        set { locked { _issuer = newValue } }
    }

    init(_ flow: @escaping (IssuanceSession) async throws -> Void) {
        self.flow = flow
        var c: AsyncStream<IssuanceState>.Continuation!
        self.states = AsyncStream { c = $0 }
        self.continuation = c
    }

    func launch() {
        task = Task { [self] in
            do {
                try await flow(self)
            } catch let error as IssuanceError {
                emit(.failed(error))
            } catch {
                emit(.failed(.unexpected(String(describing: error))))
            }
        }
    }

    func emit(_ state: IssuanceState) {
        locked { _currentState = state }
        continuation.yield(state)
        if state.isTerminal { continuation.finish() }
    }

    /// Pauses the flow at `.authorizationRequired` until `completeAuthorization`.
    func awaitAuthorization(_ url: String) async -> String {
        await withCheckedContinuation { cont in
            locked { authContinuation = cont } // set before emitting to avoid a resume-before-suspend race
            emit(.authorizationRequired(url))
        }
    }

    /// Pauses the flow at `.txCodeRequired` until `submitTxCode`.
    func awaitTxCode(_ txCode: TxCodeSpec?) async -> String {
        await withCheckedContinuation { cont in
            locked { txCodeContinuation = cont }
            emit(.txCodeRequired(txCode))
        }
    }

    /// Resume after the browser authorization step (auth-code flow).
    public func completeAuthorization(_ redirectUri: String) {
        let cont = locked { () -> CheckedContinuation<String, Never>? in
            let c = authContinuation; authContinuation = nil; return c
        }
        cont?.resume(returning: redirectUri)
    }

    /// Provide the transaction code when the session is `.txCodeRequired`.
    public func submitTxCode(_ code: String) {
        let cont = locked { () -> CheckedContinuation<String, Never>? in
            let c = txCodeContinuation; txCodeContinuation = nil; return c
        }
        cont?.resume(returning: code)
    }

    public func cancel() {
        task?.cancel()
        continuation.finish()
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
