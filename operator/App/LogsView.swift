import SwiftUI
import SentinelKit

/// LogsView shows the agent's real audit stream (spec §12), which already
/// exists in the Milestone 1 API. It is read-only: the richer filtered Logs
/// experience is a later order, but surfacing the genuine event stream here is
/// not "building ahead" — the data is real and the view invents nothing.
struct LogsView: View {
    let api: SentinelAPI?

    @State private var events: [LogEvent] = []
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        List {
            if let error {
                MetaLabel(text: error, color: Theme.textDim)
                    .listRowBackground(Theme.background)
            }
            ForEach(Array(events.enumerated()), id: \.offset) { _, e in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        MetaLabel(text: e.category, color: color(for: e.category))
                        Spacer()
                        Text(e.time)
                            .font(.caption2.monospaced())
                            .foregroundColor(Theme.textDim)
                    }
                    Text(e.message)
                        .font(.footnote)
                        .foregroundColor(Theme.textPrimary)
                }
                .listRowBackground(Theme.surface)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Theme.background)
        .navigationTitle("LOGS")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await load() }
        .task { await load() }
    }

    private func load() async {
        guard let api, !loading else {
            if api == nil { error = "No paired device" }
            return
        }
        loading = true
        defer { loading = false }
        do {
            events = try await api.logs(limit: 100, class: nil).reversed()
            error = nil
        } catch {
            self.error = "Could not load logs"
        }
    }

    private func color(for category: String) -> Color {
        switch category {
        case "ERROR", "ALERT": return Theme.danger.opacity(0.9)
        case "SUCCESS": return Theme.online
        case "SECURITY": return Theme.textPrimary
        default: return Theme.textSecondary
        }
    }
}
