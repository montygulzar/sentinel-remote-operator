import Foundation
@testable import SentinelKit

/// FakeAPI is a configurable SentinelAPI for exercising view models without a
/// live agent.
final class FakeAPI: SentinelAPI, @unchecked Sendable {
    var statusResult: Result<Status, Error>
    var panicResult: Result<PanicResult, Error>
    var grabResult: Result<ScreenCapture, Error>

    private(set) var statusCalls = 0
    private(set) var panicCalls = 0
    private(set) var grabCalls = 0

    init(
        status: Result<Status, Error> = .failure(SentinelError.offline),
        panic: Result<PanicResult, Error> = .failure(SentinelError.offline),
        grab: Result<ScreenCapture, Error> = .failure(SentinelError.offline)
    ) {
        self.statusResult = status
        self.panicResult = panic
        self.grabResult = grab
    }

    func status() async throws -> Status {
        statusCalls += 1
        return try statusResult.get()
    }

    func activity() async throws -> Activity {
        Activity(session: .unlocked, activeApp: nil, idleSeconds: nil)
    }

    func grabScreen(display: String?, format: String?, quality: Int?) async throws -> ScreenCapture {
        grabCalls += 1
        return try grabResult.get()
    }

    func panic() async throws -> PanicResult {
        panicCalls += 1
        return try panicResult.get()
    }

    func logs(limit: Int?, class klass: String?) async throws -> [LogEvent] { [] }
}

extension Status {
    static func sample(online: Bool = true) -> Status {
        Status(
            deviceName: "BEEFCAKES", online: online, session: .unlocked,
            idleSeconds: 42, batteryPercent: 82, cpuPercent: 16, ramPercent: 41, uptimeSeconds: 15480
        )
    }
}
