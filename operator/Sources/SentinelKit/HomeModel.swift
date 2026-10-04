import Foundation

/// HomeModel drives the Home screen: it fetches real status and maps success or
/// failure to an explicit connection state. On any failure it clears the cached
/// status so the UI cannot render stale telemetry as if it were live; it keeps
/// only a last-seen timestamp for the OFFLINE display.
@MainActor
public final class HomeModel: ObservableObject {
    @Published public private(set) var status: Status?
    @Published public private(set) var connection: ConnectionState = .connecting
    @Published public private(set) var lastSeen: Date?
    @Published public private(set) var lastError: SentinelError?

    private let api: SentinelAPI?
    private let now: () -> Date

    public init(api: SentinelAPI?, now: @escaping () -> Date = { Date() }) {
        self.api = api
        self.now = now
        if api == nil {
            connection = .offline(lastSeen: nil)
        }
    }

    public var hostName: String? { status?.deviceName }

    /// Fetches status once, updating published state. Safe to call repeatedly
    /// (pull-to-refresh, timer, retry button).
    public func refresh() async {
        guard let api else {
            connection = .offline(lastSeen: lastSeen)
            status = nil
            return
        }
        connection = .connecting
        let started = now()
        do {
            let s = try await api.status()
            let latency = Int(now().timeIntervalSince(started) * 1000)
            status = s
            lastSeen = now()
            lastError = nil
            connection = .online(latencyMs: max(0, latency))
        } catch let err as SentinelError {
            fail(err)
        } catch {
            fail(.offline)
        }
    }

    private func fail(_ err: SentinelError) {
        lastError = err
        status = nil // never present stale telemetry as live
        connection = .offline(lastSeen: lastSeen)
    }
}
