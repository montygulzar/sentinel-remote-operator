import SwiftUI

/// The Operator application entry point. It shows the pairing flow until a
/// device is paired, then the main Home experience. This file is the Xcode app
/// target's @main; all reusable logic lives in the SentinelKit package.
@main
struct SentinelOperatorApp: App {
    @StateObject private var model = AppModel.live()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .preferredColorScheme(.dark)
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            Theme.background.ignoresSafeArea()
            if model.isPaired {
                HomeView(api: model.makeClient())
            } else {
                PairingView()
            }
        }
        .tint(Theme.accent)
    }
}
