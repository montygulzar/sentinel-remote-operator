import Foundation

/// SentinelAPI is the typed surface the UI talks to. Defining it as a protocol
/// lets view models be tested against a fake without a live agent, keeping
/// networking cleanly separable from presentation.
public protocol SentinelAPI: Sendable {
    func status() async throws -> Status
    func activity() async throws -> Activity
    func grabScreen(display: String?, format: String?, quality: Int?) async throws -> ScreenCapture
    func panic() async throws -> PanicResult
    func logs(limit: Int?, class klass: String?) async throws -> [LogEvent]
}
