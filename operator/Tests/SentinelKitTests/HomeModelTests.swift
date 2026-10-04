import XCTest
@testable import SentinelKit

@MainActor
final class HomeModelTests: XCTestCase {
    func testRefreshOnlineSetsStatusAndConnection() async {
        let api = FakeAPI(status: .success(.sample()))
        let model = HomeModel(api: api)

        await model.refresh()

        XCTAssertEqual(model.status, Status.sample())
        XCTAssertTrue(model.connection.isOnline)
        XCTAssertNotNil(model.lastSeen)
        XCTAssertNil(model.lastError)
    }

    func testRefreshOfflineClearsStaleTelemetry() async {
        let api = FakeAPI(status: .success(.sample()))
        let model = HomeModel(api: api)
        await model.refresh()
        XCTAssertNotNil(model.status)
        let seenWhenOnline = model.lastSeen

        // Agent becomes unreachable.
        api.statusResult = .failure(SentinelError.offline)
        await model.refresh()

        XCTAssertNil(model.status, "offline must not keep stale live telemetry")
        if case .offline(let lastSeen) = model.connection {
            XCTAssertEqual(lastSeen, seenWhenOnline, "offline should report the last time we were online")
        } else {
            XCTFail("expected offline, got \(model.connection)")
        }
    }

    func testRefreshErrorSurfacesAndGoesOffline() async {
        let api = FakeAPI(status: .failure(SentinelError.unauthorized))
        let model = HomeModel(api: api)

        await model.refresh()

        XCTAssertEqual(model.lastError, .unauthorized)
        XCTAssertFalse(model.connection.isOnline)
        XCTAssertNil(model.status)
    }

    func testNilAPIIsOffline() async {
        let model = HomeModel(api: nil)
        XCTAssertEqual(model.connection, .offline(lastSeen: nil))
        await model.refresh()
        XCTAssertFalse(model.connection.isOnline)
    }
}
