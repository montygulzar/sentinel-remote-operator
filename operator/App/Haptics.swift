import SwiftUI

#if canImport(UIKit)
import UIKit

/// Haptics are purposeful (spec §14): light for selection, medium for an
/// accepted action, strong for a completed destructive action, and a notification
/// buzz for success/failure. Wrapped here so views call one small API and so the
/// whole thing compiles away on non-UIKit platforms.
enum Haptics {
    static func selection() {
        UISelectionFeedbackGenerator().selectionChanged()
    }

    static func impact(_ style: UIImpactFeedbackGenerator.FeedbackStyle) {
        UIImpactFeedbackGenerator(style: style).impactOccurred()
    }

    static func notify(_ type: UINotificationFeedbackGenerator.FeedbackType) {
        UINotificationFeedbackGenerator().notificationOccurred(type)
    }
}
#else
enum Haptics {
    enum ImpactStyle { case light, medium, heavy, rigid, soft }
    enum NotifyType { case success, warning, error }
    static func selection() {}
    static func impact(_ style: ImpactStyle) {}
    static func notify(_ type: NotifyType) {}
}
#endif
