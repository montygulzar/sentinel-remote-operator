import XCTest
@testable import SentinelKit

@MainActor
final class PanicControllerTests: XCTestCase {
    /// A reference counter the perform-closure bumps each time it is invoked,
    /// i.e. each time a PANIC request would be sent.
    final class Counter { var count = 0 }

    func makeController(_ counter: Counter, result: @escaping () -> Result<PanicResult, Error>) -> PanicController {
        PanicController(perform: {
            counter.count += 1
            return try result().get()
        })
    }

    func testCancelledHoldSendsNoRequest() {
        let counter = Counter()
        let c = makeController(counter) { .success(securedResult()) }

        c.cancelHold() // released early, before completion

        XCTAssertEqual(counter.count, 0, "a cancelled hold must send zero PANIC requests")
        XCTAssertEqual(c.state, .idle)
    }

    func testCompletedHoldSendsExactlyOneRequest() async {
        let counter = Counter()
        let c = makeController(counter) { .success(securedResult()) }

        await c.completeHold()

        XCTAssertEqual(counter.count, 1, "a completed hold must send exactly one PANIC request")
        XCTAssertEqual(c.state, .secured(elapsedMs: 1140))
    }

    func testRepeatedCompleteDoesNotResend() async {
        let counter = Counter()
        let c = makeController(counter) { .success(securedResult()) }

        await c.completeHold()
        await c.completeHold() // ignored: already secured
        c.cancelHold()         // cannot undo a sent request

        XCTAssertEqual(counter.count, 1, "PANIC must fire exactly once even on repeated completion")
        XCTAssertEqual(c.state, .secured(elapsedMs: 1140))
    }

    func testPartialFailureIsNotSecured() async {
        let counter = Counter()
        let partial = PanicResult(
            ok: false,
            actions: [
                PanicStep(name: "closeConfiguredApps", ok: false, error: "x", steps: [
                    PanicStep(name: "slack.exe", ok: false, error: "cannot close", steps: nil),
                ]),
                PanicStep(name: "mute", ok: true, error: nil, steps: nil),
                PanicStep(name: "lock", ok: true, error: nil, steps: nil),
            ],
            elapsedMs: 800
        )
        let c = makeController(counter) { .success(partial) }

        await c.completeHold()

        XCTAssertEqual(counter.count, 1)
        guard case let .partial(failed) = c.state else {
            return XCTFail("expected partial, got \(c.state)")
        }
        XCTAssertEqual(failed, ["slack.exe"])
    }

    func testTransportFailureSurfacesAsFailed() async {
        let counter = Counter()
        let c = makeController(counter) { .failure(SentinelError.offline) }

        await c.completeHold()

        if case .failed = c.state {} else {
            XCTFail("expected failed, got \(c.state)")
        }
    }
}

private func securedResult() -> PanicResult {
    PanicResult(
        ok: true,
        actions: [
            PanicStep(name: "closeConfiguredApps", ok: true, error: nil, steps: nil),
            PanicStep(name: "mute", ok: true, error: nil, steps: nil),
            PanicStep(name: "lock", ok: true, error: nil, steps: nil),
        ],
        elapsedMs: 1140
    )
}
