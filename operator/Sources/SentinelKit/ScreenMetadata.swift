import Foundation

/// ScreenMetadataParser reads the Grab Screen capture metadata from response
/// headers (spec §15). It is a free function of a header accessor so it can be
/// unit-tested without a live HTTP response, including the malformed cases.
public enum ScreenMetadataParser {
    /// Parses metadata from a case-insensitive header accessor. `display`,
    /// `width` and `height` are required and must be well-formed; a missing or
    /// non-numeric required field is a malformed response. Timing fields are
    /// best-effort and default to zero when absent.
    public static func parse(_ header: (String) -> String?) throws -> ScreenCaptureMetadata {
        guard let display = header("X-Sentinel-Capture-Display"), !display.isEmpty else {
            throw SentinelError.malformedResponse("missing capture display header")
        }
        guard let widthStr = header("X-Sentinel-Capture-Width"), let width = Int(widthStr), width > 0 else {
            throw SentinelError.malformedResponse("missing or invalid capture width header")
        }
        guard let heightStr = header("X-Sentinel-Capture-Height"), let height = Int(heightStr), height > 0 else {
            throw SentinelError.malformedResponse("missing or invalid capture height header")
        }
        let format = header("X-Sentinel-Capture-Format") ?? "jpeg"

        var capturedAt = Date()
        if let ts = header("X-Sentinel-Capture-Timestamp"), let secs = TimeInterval(ts) {
            capturedAt = Date(timeIntervalSince1970: secs)
        }
        let captureMs = header("X-Sentinel-Capture-Ms").flatMap(Int.init) ?? 0
        let encodeMs = header("X-Sentinel-Encode-Ms").flatMap(Int.init) ?? 0

        return ScreenCaptureMetadata(
            display: display,
            width: width,
            height: height,
            format: format,
            capturedAt: capturedAt,
            captureMs: captureMs,
            encodeMs: encodeMs
        )
    }
}
