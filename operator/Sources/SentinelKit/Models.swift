import Foundation

/// Lock state of the Windows session, matching the agent's `SessionState`.
public enum SessionState: String, Codable, Sendable {
    case unlocked
    case locked
    case unknown
}

/// GET /v1/status (spec §19). Optional metrics are nil when the host reports
/// them unavailable, so the UI shows UNAVAILABLE rather than a misleading zero.
public struct Status: Codable, Sendable, Equatable {
    public let deviceName: String
    public let online: Bool
    public let session: SessionState
    public let idleSeconds: Int64?
    public let batteryPercent: Int?
    public let cpuPercent: Int?
    public let ramPercent: Int?
    public let uptimeSeconds: Int64?
}

/// GET /v1/activity.
public struct Activity: Codable, Sendable, Equatable {
    public let session: SessionState
    public let activeApp: String?
    public let idleSeconds: Int64?
}

/// One PANIC step result; `steps` carries per-application detail for the
/// close-apps step (spec §19). Mirrors the agent's `control.StepResult`.
public struct PanicStep: Codable, Sendable, Equatable {
    public let name: String
    public let ok: Bool
    public let error: String?
    public let steps: [PanicStep]?
}

/// POST /v1/control/panic structured result.
public struct PanicResult: Codable, Sendable, Equatable {
    public let ok: Bool
    public let actions: [PanicStep]
    public let elapsedMs: Int64
}

/// A human-facing interpretation of a PANIC result. `.secured` only when every
/// step succeeded; otherwise the failure is surfaced, never hidden behind a
/// false SECURED (spec §17, THIRD ARTILLERY ORDER).
public enum PanicOutcome: Equatable, Sendable {
    case secured(elapsedMs: Int64)
    case partial(failed: [String], elapsedMs: Int64)
    case failed(String)

    public init(result: PanicResult) {
        if result.ok {
            self = .secured(elapsedMs: result.elapsedMs)
            return
        }
        var failed: [String] = []
        for action in result.actions where !action.ok {
            if let subs = action.steps {
                for s in subs where !s.ok { failed.append(s.name) }
            }
            if action.steps == nil || action.steps?.isEmpty == true {
                failed.append(action.name)
            }
        }
        self = .partial(failed: failed, elapsedMs: result.elapsedMs)
    }
}

/// One audit event, GET /v1/logs (spec §12). `time` is an RFC3339 string kept
/// verbatim so the Logs view can show it without reinterpreting the clock.
public struct LogEvent: Codable, Sendable, Equatable {
    public let time: String
    /// The audit class (INFO, SCREEN, ACTION, …). Named `category` in Swift to
    /// avoid the `class` keyword; it maps to the JSON "class" field.
    public let category: String
    public let message: String

    enum CodingKeys: String, CodingKey {
        case time
        case category = "class"
        case message
    }
}

/// Metadata describing a captured screen frame, read from the Grab Screen
/// response headers (spec §5, §15).
public struct ScreenCaptureMetadata: Sendable, Equatable {
    public let display: String
    public let width: Int
    public let height: Int
    public let format: String
    public let capturedAt: Date
    public let captureMs: Int
    public let encodeMs: Int
}

/// A grabbed frame: the encoded image bytes plus its metadata. The caller
/// renders `image` and discards it; nothing is written to disk unless the owner
/// explicitly saves it (spec §11).
public struct ScreenCapture: Sendable {
    public let image: Data
    public let metadata: ScreenCaptureMetadata
}

/// POST /v1/pair request body.
public struct PairRequestBody: Codable, Sendable {
    public let displayName: String
    public let deviceNonce: String
}

/// POST /v1/pair success body. Carries no secret: the device key is derived
/// independently on both sides (see PairingService).
public struct PairResultBody: Codable, Sendable {
    public let deviceId: String
    public let agentNonce: String
    public let agentProof: String
    public let protocolVersion: Int
}

/// Errors surfaced by the client, each mapping to an explicit UI state rather
/// than a silent failure (spec §14: explicit failure states).
public enum SentinelError: Error, Equatable, Sendable {
    case notConfigured
    case offline
    case unauthorized
    case captureUnavailable
    case badRequest(String)
    case server(status: Int, message: String)
    case malformedResponse(String)
}
