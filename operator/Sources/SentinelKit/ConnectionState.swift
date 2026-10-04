import Foundation

/// ConnectionState is what the Home screen shows about reachability. It never
/// implies live data when offline: the offline case carries only a last-seen
/// time, and the Home model drops cached telemetry when it goes offline so
/// stale values are never presented as current (spec §14, THIRD ARTILLERY
/// ORDER).
public enum ConnectionState: Equatable, Sendable {
    case connecting
    case online(latencyMs: Int?)
    case offline(lastSeen: Date?)

    public var isOnline: Bool {
        if case .online = self { return true }
        return false
    }
}
