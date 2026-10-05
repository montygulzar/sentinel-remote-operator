import SwiftUI
import SentinelKit

/// A metric value rendered honestly: a real value, or UNAVAILABLE when the host
/// did not supply it (spec §2, §14). Never a fabricated zero.
struct MetricView: View {
    let key: String
    let value: String?

    var body: some View {
        HStack(spacing: 8) {
            MetaLabel(text: key, color: Theme.textDim)
            Spacer(minLength: 8)
            Text(value ?? "UNAVAILABLE")
                .font(.system(.subheadline, design: .monospaced))
                .foregroundColor(value == nil ? Theme.textDim : Theme.textPrimary)
        }
    }
}

/// The status card at the top of Home: session + activity words and the four
/// core metrics, laid out as two columns (spec §4).
struct StatusCard: View {
    let status: Status?
    let online: Bool

    private func pct(_ v: Int?) -> String? { v.map { "\($0)%" } }

    var body: some View {
        let dimmed = !online || status == nil
        VStack(spacing: 14) {
            HStack {
                MetaLabel(text: sessionWord, color: sessionColor)
                Spacer()
                MetaLabel(text: activityWord, color: Theme.textSecondary)
            }
            HStack(alignment: .top, spacing: 22) {
                VStack(spacing: 10) {
                    MetricView(key: "CPU", value: online ? pct(status?.cpuPercent) : nil)
                    MetricView(key: "RAM", value: online ? pct(status?.ramPercent) : nil)
                }
                VStack(spacing: 10) {
                    // GPU is not yet implemented on the agent; shown honestly.
                    MetricView(key: "GPU", value: nil)
                    MetricView(key: "BAT", value: online ? pct(status?.batteryPercent) : nil)
                }
            }
        }
        .opacity(dimmed ? 0.55 : 1)
        .sentinelCard()
    }

    private var sessionWord: String {
        guard online, let s = status else { return "—" }
        switch s.session {
        case .unlocked: return "UNLOCKED"
        case .locked: return "LOCKED"
        case .unknown: return "SESSION UNKNOWN"
        }
    }

    private var sessionColor: Color {
        guard online, let s = status else { return Theme.textDim }
        return s.session == .locked ? Theme.danger.opacity(0.9) : Theme.online
    }

    private var activityWord: String {
        guard online, let s = status, let idle = s.idleSeconds else { return "" }
        return idle < 60 ? "ACTIVE" : "IDLE \(idle / 60)m"
    }
}

/// A Home category card: icon glyph, title, subtitle. Tapping navigates to its
/// destination; an unavailable category is visibly muted and not tappable as if
/// functional.
struct CategoryCard: View {
    let title: String
    let subtitle: String
    let glyph: String
    var enabled: Bool = true

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Image(systemName: glyph)
                .font(.system(size: 22, weight: .regular))
                .foregroundColor(enabled ? Theme.textPrimary : Theme.textDim)
            Spacer(minLength: 8)
            Text(title)
                .font(.system(.headline, design: .rounded))
                .foregroundColor(enabled ? Theme.textPrimary : Theme.textSecondary)
            Text(subtitle)
                .font(.footnote)
                .foregroundColor(Theme.textDim)
        }
        .frame(maxWidth: .infinity, minHeight: 112, alignment: .leading)
        .sentinelCard()
        .opacity(enabled ? 1 : 0.6)
    }
}
