import XCTest
@testable import SentinelKit

final class ModelDecodingTests: XCTestCase {
    func testStatusDecodesRealValuesAndNulls() throws {
        let json = """
        {"deviceName":"BEEFCAKES","online":true,"session":"unlocked",
         "idleSeconds":42,"batteryPercent":null,"cpuPercent":16,
         "ramPercent":41,"uptimeSeconds":15480}
        """.data(using: .utf8)!
        let s = try JSONDecoder().decode(Status.self, from: json)
        XCTAssertEqual(s.deviceName, "BEEFCAKES")
        XCTAssertTrue(s.online)
        XCTAssertEqual(s.session, .unlocked)
        XCTAssertEqual(s.cpuPercent, 16)
        XCTAssertEqual(s.ramPercent, 41)
        XCTAssertEqual(s.idleSeconds, 42)
        XCTAssertEqual(s.uptimeSeconds, 15480)
        XCTAssertNil(s.batteryPercent, "null battery must decode as nil (UNAVAILABLE)")
    }

    func testPanicResultSecured() throws {
        let json = """
        {"ok":true,"actions":[{"name":"closeConfiguredApps","ok":true},
         {"name":"mute","ok":true},{"name":"lock","ok":true}],"elapsedMs":1140}
        """.data(using: .utf8)!
        let r = try JSONDecoder().decode(PanicResult.self, from: json)
        XCTAssertEqual(PanicOutcome(result: r), .secured(elapsedMs: 1140))
    }

    func testPanicResultPartialListsFailedSteps() throws {
        let json = """
        {"ok":false,"actions":[
          {"name":"closeConfiguredApps","ok":false,"error":"x","steps":[
             {"name":"chrome.exe","ok":true},
             {"name":"slack.exe","ok":false,"error":"cannot close"}]},
          {"name":"mute","ok":true},
          {"name":"lock","ok":false,"error":"lock failed"}],"elapsedMs":900}
        """.data(using: .utf8)!
        let r = try JSONDecoder().decode(PanicResult.self, from: json)
        let outcome = PanicOutcome(result: r)
        guard case let .partial(failed, elapsed) = outcome else {
            return XCTFail("expected partial, got \(outcome)")
        }
        XCTAssertEqual(elapsed, 900)
        XCTAssertEqual(Set(failed), Set(["slack.exe", "lock"]))
        XCTAssertNotEqual(outcome, .secured(elapsedMs: 900), "a partial failure must never read as SECURED")
    }

    func testLogEventDecodesClassKeyword() throws {
        let json = #"{"time":"2026-01-01T00:00:00Z","class":"SCREEN","message":"Grab Screen requested"}"#.data(using: .utf8)!
        let e = try JSONDecoder().decode(LogEvent.self, from: json)
        XCTAssertEqual(e.category, "SCREEN")
        XCTAssertEqual(e.message, "Grab Screen requested")
    }
}
