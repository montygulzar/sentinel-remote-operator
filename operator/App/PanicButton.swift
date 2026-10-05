import SwiftUI
import SentinelKit

/// PanicButton is the hold-to-confirm PANIC control (spec §7, THIRD ARTILLERY
/// ORDER). A tap does nothing. Holding blooms red from inside the rounded button
/// outward; releasing early retracts the fill and sends no request; completing
/// the hold fires a strong haptic, drives the controller (which guarantees
/// exactly one request), and shows SECURED or the real partial/failure result.
/// The animation communicates hold progress — it is not decorative.
struct PanicButton: View {
    @ObservedObject var controller: PanicController
    var holdDuration: Double = 1.2

    @State private var progress: CGFloat = 0
    @State private var holding = false

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: Theme.cardCorner, style: .continuous)
                    .fill(Theme.surfaceRaised)

                // The red bloom grows with the hold.
                RoundedRectangle(cornerRadius: Theme.cardCorner, style: .continuous)
                    .fill(Theme.danger)
                    .frame(width: max(0, geo.size.width * progress))

                RoundedRectangle(cornerRadius: Theme.cardCorner, style: .continuous)
                    .stroke(Theme.danger.opacity(0.8), lineWidth: 1.5)

                Text(label)
                    .font(.system(.title3, design: .rounded).weight(.semibold))
                    .tracking(2)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity, alignment: .center)
            }
        }
        .frame(height: 64)
        .contentShape(RoundedRectangle(cornerRadius: Theme.cardCorner, style: .continuous))
        .onLongPressGesture(minimumDuration: holdDuration, maximumDistance: 40) {
            complete()
        } onPressingChanged: { pressing in
            pressing ? beginHold() : endHoldEarly()
        }
        .disabled(isBusyOrDone)
        .onTapGesture {} // absorb taps so a plain tap never triggers anything
    }

    private var isBusyOrDone: Bool {
        switch controller.state {
        case .idle: return false
        case .securing, .secured, .partial, .failed: return true
        }
    }

    private var label: String {
        switch controller.state {
        case .idle: return holding ? "HOLD…" : "PANIC"
        case .securing: return "SECURING"
        case .secured: return "SECURED ✓"
        case .partial(let failed):
            return failed.isEmpty ? "PARTIAL — NOT SECURED" : "PARTIAL: \(failed.joined(separator: ", "))"
        case .failed(let msg): return "FAILED: \(msg)"
        }
    }

    private func beginHold() {
        guard case .idle = controller.state else { return }
        holding = true
        Haptics.impact(.medium)
        withAnimation(.linear(duration: holdDuration)) { progress = 1 }
    }

    private func endHoldEarly() {
        // Fires on release. If the hold already completed, state is no longer
        // idle and we leave it alone; otherwise this is a cancel.
        holding = false
        if case .idle = controller.state {
            controller.cancelHold()
            withAnimation(.easeOut(duration: 0.2)) { progress = 0 }
        }
    }

    private func complete() {
        holding = false
        Haptics.impact(.heavy)
        Task {
            await controller.completeHold()
            switch controller.state {
            case .secured: Haptics.notify(.success)
            case .partial, .failed: Haptics.notify(.error)
            default: break
            }
        }
    }
}
