import SwiftUI

/// Theme is the Operator's restrained visual language (spec §14): near-black
/// surfaces, charcoal cards, calm text, red reserved strictly for the
/// destructive PANIC path. No decorative "hacker" styling — the interface reads
/// as deliberate, not cyberpunk.
enum Theme {
    static let background = Color(white: 0.04)
    static let surface = Color(white: 0.10)
    static let surfaceRaised = Color(white: 0.14)
    static let hairline = Color(white: 0.24)
    static let textPrimary = Color(white: 0.96)
    static let textSecondary = Color(white: 0.62)
    static let textDim = Color(white: 0.42)
    static let accent = Color(white: 0.85)
    static let online = Color(red: 0.30, green: 0.80, blue: 0.52)
    static let offline = Color(white: 0.45)
    static let danger = Color(red: 0.86, green: 0.18, blue: 0.20)

    static let cardCorner: CGFloat = 18
    static let cardPadding: CGFloat = 16
}

extension View {
    /// A charcoal rounded card with a hairline border, the Operator's standard
    /// container.
    func sentinelCard(padding: CGFloat = Theme.cardPadding) -> some View {
        self
            .padding(padding)
            .background(Theme.surface)
            .clipShape(RoundedRectangle(cornerRadius: Theme.cardCorner, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: Theme.cardCorner, style: .continuous)
                    .stroke(Theme.hairline, lineWidth: 1)
            )
    }
}

/// Monospaced small caps-ish label used for metric keys and status words.
struct MetaLabel: View {
    let text: String
    var color: Color = Theme.textSecondary
    var body: some View {
        Text(text)
            .font(.system(.footnote, design: .monospaced))
            .tracking(1.0)
            .foregroundColor(color)
    }
}
