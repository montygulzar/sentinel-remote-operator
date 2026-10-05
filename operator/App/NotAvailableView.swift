import SwiftUI

/// A restrained placeholder for a category whose functionality belongs to a
/// later order. It states plainly that the capability is not yet available —
/// no fake controls that appear to work (spec §2, §18).
struct NotAvailableView: View {
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "lock.circle")
                .font(.system(size: 34, weight: .light))
                .foregroundColor(Theme.textDim)
            MetaLabel(text: "NOT YET AVAILABLE", color: Theme.textSecondary)
            Text(detail)
                .font(.footnote)
                .multilineTextAlignment(.center)
                .foregroundColor(Theme.textDim)
                .padding(.horizontal, 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.background)
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
    }
}
