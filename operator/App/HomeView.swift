import SwiftUI
import SentinelKit

/// Home is the opening screen (spec §4): real status, the four category cards,
/// an always-reachable PANIC, and a HOME/LOGS footer. It consumes live Sentinel
/// data and degrades to an explicit OFFLINE state — it never shows stale
/// telemetry as if current.
struct HomeView: View {
    @EnvironmentObject private var app: AppModel
    @StateObject private var home: HomeModel
    @StateObject private var panic: PanicController

    private let api: SentinelAPI?

    init(api: SentinelAPI?) {
        self.api = api
        _home = StateObject(wrappedValue: HomeModel(api: api))
        let perform: () async throws -> PanicResult = {
            guard let api else { throw SentinelError.notConfigured }
            return try await api.panic()
        }
        _panic = StateObject(wrappedValue: PanicController(perform: perform))
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    header
                    StatusCard(status: home.status, online: home.connection.isOnline)
                    grid
                    PanicButton(controller: panic)
                        .padding(.top, 4)
                }
                .padding(16)
            }
            .background(Theme.background)
            .safeAreaInset(edge: .bottom) { footer }
            .refreshable { await home.refresh() }
            .task { await home.refresh() }
        }
    }

    private var header: some View {
        VStack(spacing: 6) {
            HStack(spacing: 8) {
                MetaLabel(text: "SENTINEL", color: Theme.textSecondary)
                Circle()
                    .fill(home.connection.isOnline ? Theme.online : Theme.offline)
                    .frame(width: 8, height: 8)
            }
            Text(hostName)
                .font(.system(.largeTitle, design: .rounded).weight(.semibold))
                .foregroundColor(Theme.textPrimary)
            Text(statusLine)
                .font(.footnote)
                .foregroundColor(Theme.textSecondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 8)
    }

    private var grid: some View {
        let cols = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
        return LazyVGrid(columns: cols, spacing: 12) {
            NavigationLink { IntelView(api: api) } label: {
                CategoryCard(title: "INTEL", subtitle: "Observe", glyph: "eye")
            }
            NavigationLink { NotAvailableView(title: "CONTROL", detail: "Operate — arriving in a later order.") } label: {
                CategoryCard(title: "CONTROL", subtitle: "Operate", glyph: "slider.horizontal.3", enabled: false)
            }
            NavigationLink { NotAvailableView(title: "TERMINAL", detail: "Command — arriving after the audit/authorization foundation.") } label: {
                CategoryCard(title: "TERMINAL", subtitle: "Command", glyph: "chevron.left.forwardslash.chevron.right", enabled: false)
            }
            NavigationLink { NotAvailableView(title: "SENTINEL", detail: "Monitor — arriving in a later order.") } label: {
                CategoryCard(title: "SENTINEL", subtitle: "Monitor", glyph: "bolt.shield", enabled: false)
            }
        }
        .buttonStyle(.plain)
    }

    private var footer: some View {
        HStack {
            Label("HOME", systemImage: "house.fill")
                .font(.footnote.weight(.medium))
                .foregroundColor(Theme.textPrimary)
            Spacer()
            NavigationLink { LogsView(api: api) } label: {
                Label("LOGS", systemImage: "list.bullet.rectangle")
                    .font(.footnote.weight(.medium))
                    .foregroundColor(Theme.textSecondary)
            }
        }
        .padding(.horizontal, 28)
        .padding(.vertical, 12)
        .background(.ultraThinMaterial)
    }

    private var hostName: String {
        home.status?.deviceName ?? app.paired?.hostDisplayName ?? "SENTINEL"
    }

    private var statusLine: String {
        switch home.connection {
        case .connecting:
            return "Connecting…"
        case .online(let ms):
            if let ms { return "Online · \(ms) ms" }
            return "Online"
        case .offline(let lastSeen):
            if let lastSeen {
                return "Offline · last seen \(Self.relative.localizedString(for: lastSeen, relativeTo: Date()))"
            }
            return "Offline"
        }
    }

    private static let relative = RelativeDateTimeFormatter()
}
