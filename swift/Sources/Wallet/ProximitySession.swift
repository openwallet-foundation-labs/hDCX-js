import Foundation

/**
 * A single ISO 18013-5 proximity presentation run (API-CONTRACT.md §6.3). One-shot; the flow runs in a
 * Task, drives the device-retrieval exchange over the transport, and pauses at `.requestReceived` for consent.
 */
public final class ProximitySession: @unchecked Sendable {
    private let lock = NSLock()
    private var _currentState: ProximityState = .generatingEngagement
    public var currentState: ProximityState { locked { _currentState } }

    public let states: AsyncStream<ProximityState>
    private let continuation: AsyncStream<ProximityState>.Continuation
    private var task: Task<Void, Never>?
    private var decisionContinuation: CheckedContinuation<ProximitySelection?, Never>?
    private let flow: (ProximitySession) async throws -> Void

    init(_ flow: @escaping (ProximitySession) async throws -> Void) {
        self.flow = flow
        var c: AsyncStream<ProximityState>.Continuation!
        self.states = AsyncStream { c = $0 }
        self.continuation = c
    }

    func launch() {
        task = Task { [self] in
            do {
                try await flow(self)
            } catch let error as ProximityError {
                emit(.failed(error))
            } catch {
                emit(.failed(.unexpected(String(describing: error))))
            }
        }
    }

    func emit(_ state: ProximityState) {
        locked { _currentState = state }
        continuation.yield(state)
        if state.isTerminal { continuation.finish() }
    }

    /// Pauses at `.requestReceived` for consent; returns the selection or nil (declined).
    func awaitDecision(_ request: ProximityRequest) async -> ProximitySelection? {
        await withCheckedContinuation { cont in
            locked { decisionContinuation = cont } // set before emitting to avoid a resume-before-suspend race
            emit(.requestReceived(request))
        }
    }

    /// Approve with the chosen credentials — resumes the flow to build and send the DeviceResponse.
    public func respond(_ selection: ProximitySelection) { resumeDecision(selection) }

    /// Decline the request — the flow terminates at `.declined`.
    public func decline() { resumeDecision(nil) }

    public func cancel() {
        task?.cancel()
        continuation.finish()
    }

    private func resumeDecision(_ value: ProximitySelection?) {
        let cont = locked { () -> CheckedContinuation<ProximitySelection?, Never>? in
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
