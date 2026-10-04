import SwiftUI
import SentinelKit

/// INTEL is the observe surface (spec §5). For this order only GRAB SCREEN is
/// functional; the rest are shown as explicitly not-yet-available rather than as
/// fake buttons that appear to work.
struct IntelView: View {
    let api: SentinelAPI?

    private let cols = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]

    var body: some View {
        ScrollView {
            LazyVGrid(columns: cols, spacing: 12) {
                NavigationLink { GrabScreenView(api: api) } label: {
                    IntelTile(title: "GRAB SCREEN", glyph: "camera.viewfinder", enabled: true)
                }
                tile("LIVE SCREEN", "play.rectangle")
                tile("CAMERA", "camera")
                tile("LOCATION", "location")
                tile("ACTIVE APP", "app.badge")
                tile("PROCESSES", "list.bullet.indent")
                tile("SYSTEM", "cpu")
                tile("NETWORK", "network")
            }
            .buttonStyle(.plain)
            .padding(16)
        }
        .background(Theme.background)
        .navigationTitle("INTEL")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func tile(_ title: String, _ glyph: String) -> some View {
        NavigationLink {
            NotAvailableView(title: title, detail: "\(title.capitalized) is not part of this order yet.")
        } label: {
            IntelTile(title: title, glyph: glyph, enabled: false)
        }
    }
}

private struct IntelTile: View {
    let title: String
    let glyph: String
    let enabled: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Image(systemName: glyph)
                .font(.system(size: 20))
                .foregroundColor(enabled ? Theme.textPrimary : Theme.textDim)
            Spacer(minLength: 6)
            Text(title)
                .font(.system(.subheadline, design: .rounded).weight(.medium))
                .foregroundColor(enabled ? Theme.textPrimary : Theme.textSecondary)
            if !enabled {
                MetaLabel(text: "UNAVAILABLE", color: Theme.textDim)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 96, alignment: .leading)
        .sentinelCard()
        .opacity(enabled ? 1 : 0.6)
    }
}
