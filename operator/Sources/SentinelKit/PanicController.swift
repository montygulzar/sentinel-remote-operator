import Foundation

/// PanicController is the state machine behind the hold-to-confirm PANIC
/// button. The SwiftUI view drives the hold animation and calls this; the
/// controller owns the rule that matters for safety: a request is sent only on
/// a completed hold, and exactly once (spec §7, THIRD ARTILLERY ORDER). A
/// cancelled hold sends nothing. A partial failure is surfaced as `.partial`,
/// never reported as SECURED.
@MainActor
public final class PanicController: ObservableObject {
    public enum State: Equatable {
        case idle
        case securing
        case secured(elapsedMs: Int64)
        case partial(failed: [String])
        case failed(String)
    }

    @Published public private(set) var state: State = .idle

    private let perform: () async throws -> PanicResult
    private var firing = false

    public init(perform: @escaping () async throws -> PanicResult) {
        self.perform = perform
    }

    /// Called when the hold completes. Fires PANIC exactly once: re-entrant or
    /// repeated calls while in flight (or after completion) are ignored until
    /// `reset()`.
    public func completeHold() async {
        guard !firing, !isTerminalOrSecuring else { return }
        firing = true
        state = .securing
        do {
            let result = try await perform()
            switch PanicOutcome(result: result) {
            case .secured(let ms):
                state = .secured(elapsedMs: ms)
            case .partial(let failed, _):
                state = .partial(failed: failed)
            case .failed(let msg):
                state = .failed(msg)
            }
        } catch {
            state = .failed(message(for: error))
        }
        firing = false
    }

    /// Called when the hold is released early. Does nothing once PANIC is in
    /// flight or finished, so it can never cancel a sent request.
    public func cancelHold() {
        guard !firing, !isTerminalOrSecuring else { return }
        state = .idle
    }

    /// Returns the button to its resting state after the user acknowledges a
    /// result.
    public func reset() {
        guard !firing else { return }
        state = .idle
    }

    private var isTerminalOrSecuring: Bool {
        switch state {
        case .idle:
            return false
        case .securing, .secured, .partial, .failed:
            return true
        }
    }

    private func message(for error: Error) -> String {
        if let e = error as? SentinelError {
            switch e {
            case .offline: return "Sentinel is offline"
            case .unauthorized: return "Not authorized"
            case .captureUnavailable: return "Unavailable"
            case .notConfigured: return "No paired device"
            case .badRequest(let m), .server(_, let m), .malformedResponse(let m): return m
            }
        }
        return "PANIC failed"
    }
}
