import XCTest
@testable import SentinelKit

final class ScreenMetadataTests: XCTestCase {
    private func accessor(_ dict: [String: String]) -> (String) -> String? {
        // Case-insensitive lookup, like HTTPURLResponse.value(forHTTPHeaderField:).
        let lower = Dictionary(uniqueKeysWithValues: dict.map { ($0.key.lowercased(), $0.value) })
        return { lower[$0.lowercased()] }
    }

    func testParsesValidMetadata() throws {
        let headers = [
            "X-Sentinel-Capture-Display": "DISPLAY1",
            "X-Sentinel-Capture-Width": "1920",
            "X-Sentinel-Capture-Height": "1080",
            "X-Sentinel-Capture-Format": "jpeg",
            "X-Sentinel-Capture-Timestamp": "1700000000",
            "X-Sentinel-Capture-Ms": "12",
            "X-Sentinel-Encode-Ms": "5",
        ]
        let meta = try ScreenMetadataParser.parse(accessor(headers))
        XCTAssertEqual(meta.display, "DISPLAY1")
        XCTAssertEqual(meta.width, 1920)
        XCTAssertEqual(meta.height, 1080)
        XCTAssertEqual(meta.format, "jpeg")
        XCTAssertEqual(meta.captureMs, 12)
        XCTAssertEqual(meta.encodeMs, 5)
        XCTAssertEqual(meta.capturedAt, Date(timeIntervalSince1970: 1700000000))
    }

    func testMissingWidthIsMalformed() {
        let headers = [
            "X-Sentinel-Capture-Display": "DISPLAY1",
            "X-Sentinel-Capture-Height": "1080",
        ]
        XCTAssertThrowsError(try ScreenMetadataParser.parse(accessor(headers))) { err in
            guard case SentinelError.malformedResponse = err else {
                return XCTFail("expected malformedResponse, got \(err)")
            }
        }
    }

    func testMissingDisplayIsMalformed() {
        let headers = [
            "X-Sentinel-Capture-Width": "800",
            "X-Sentinel-Capture-Height": "600",
        ]
        XCTAssertThrowsError(try ScreenMetadataParser.parse(accessor(headers)))
    }
}
