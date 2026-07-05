import Foundation

/**
 * A single presentation run driven as a state machine. One-shot; the flow runs
 * in a Task and pauses at `.requestResolved` for the user's consent until respond/decline.
 */
public final class PresentationSession: @unchecked Sendable {
    private let lock = NSLock()
    private var _currentState: PresentationState = .resolvingRequest
    public var currentState: PresentationState { locked { _currentState } }

    public let states: AsyncStream<PresentationState>
    private let continuation: AsyncStream<PresentationState>.Continuation
    private var task: Task<Void, Never>?
    private var decisionContinuation: CheckedContinuation<PresentationSelection?, Never>?
    private let flow: (PresentationSession) async throws -> Void

    init(_ flow: @escaping (PresentationSession) async throws -> Void) {
        self.flow = flow
        var c: AsyncStream<PresentationState>.Continuation!
        self.states = AsyncStream { c = $0 }
        self.continuation = c
    }

    func launch() {
        task = Task { [self] in
            do {
                try await flow(self)
            } catch let error as PresentationError {
                emit(.failed(error))
            } catch {
                emit(.failed(.unexpected(String(describing: error))))
            }
        }
    }

    func emit(_ state: PresentationState) {
        locked { _currentState = state }
        continuation.yield(state)
        if state.isTerminal { continuation.finish() }
    }

    /// Pauses at `.requestResolved` for consent; returns the selection or nil (declined).
    func awaitDecision(_ request: PresentationRequest) async -> PresentationSelection? {
        await withCheckedContinuation { cont in
            locked { decisionContinuation = cont } // set before emitting to avoid a resume-before-suspend race
            emit(.requestResolved(request))
        }
    }

    /// Approve with the chosen credentials — resumes the flow to submit the response.
    public func respond(_ selection: PresentationSelection) {
        resumeDecision(selection)
    }

    /// Decline the request — the flow terminates at `.declined`.
    public func decline() {
        resumeDecision(nil)
    }

    public func cancel() {
        task?.cancel()
        continuation.finish()
    }

    private func resumeDecision(_ value: PresentationSelection?) {
        let cont = locked { () -> CheckedContinuation<PresentationSelection?, Never>? in
            let c = decisionContinuation; decisionContinuation = nil; return c
        }
        cont?.resume(returning: value)
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
