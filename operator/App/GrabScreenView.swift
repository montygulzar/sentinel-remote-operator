import SwiftUI
import SentinelKit
#if canImport(UIKit)
import UIKit
#endif

/// GrabScreenView requests a single current frame of the Windows desktop and
/// displays it (spec §5, §11; THIRD ARTILLERY ORDER). REFRESH requests a new
/// frame; SAVE is an explicit share/save of the received image on the phone and
/// never causes the agent to keep a copy. A subtle haptic marks a new frame.
struct GrabScreenView: View {
    let api: SentinelAPI?

    enum Phase {
        case idle
        case requesting
        case loaded(ScreenCapture)
        case failed(String)
    }

    @State private var phase: Phase = .idle

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                frame
                caption
                controls
            }
            .padding(16)
        }
        .background(Theme.background)
        .navigationTitle("GRAB SCREEN")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await grab() }
        .task { if case .idle = phase { await grab() } }
    }

    @ViewBuilder private var frame: some View {
        switch phase {
        case .idle, .requesting:
            placeholder(text: "REQUESTING FRAME…", showSpinner: true)
        case .failed(let msg):
            placeholder(text: msg, showSpinner: false)
        case .loaded(let capture):
            imageView(for: capture)
        }
    }

    @ViewBuilder private func imageView(for capture: ScreenCapture) -> some View {
        #if canImport(UIKit)
        if let ui = UIImage(data: capture.image) {
            Image(uiImage: ui)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: .infinity)
                .clipShape(RoundedRectangle(cornerRadius: Theme.cardCorner, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.cardCorner, style: .continuous)
                        .stroke(Theme.hairline, lineWidth: 1)
                )
        } else {
            placeholder(text: "UNREADABLE FRAME", showSpinner: false)
        }
        #else
        placeholder(text: "\(capture.image.count) bytes", showSpinner: false)
        #endif
    }

    private func placeholder(text: String, showSpinner: Bool) -> some View {
        VStack(spacing: 12) {
            if showSpinner { ProgressView().tint(Theme.textSecondary) }
            MetaLabel(text: text, color: Theme.textSecondary)
        }
        .frame(maxWidth: .infinity, minHeight: 220)
        .sentinelCard()
    }

    @ViewBuilder private var caption: some View {
        if case .loaded(let capture) = phase {
            HStack {
                MetaLabel(text: "CAPTURED \(Self.time.string(from: capture.metadata.capturedAt))", color: Theme.textDim)
                Spacer()
                MetaLabel(text: "\(capture.metadata.width)×\(capture.metadata.height)", color: Theme.textDim)
            }
        }
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Button {
                Task { await grab() }
            } label: {
                Label("REFRESH", systemImage: "arrow.clockwise")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .sentinelCard(padding: 0)
            .buttonStyle(.plain)
            .foregroundColor(Theme.textPrimary)

            saveButton
        }
    }

    @ViewBuilder private var saveButton: some View {
        if case .loaded(let capture) = phase, let shareImage = shareableImage(capture) {
            ShareLink(item: shareImage, preview: SharePreview("Sentinel screen", image: shareImage)) {
                Label("SAVE", systemImage: "square.and.arrow.down")
                    .font(.subheadline.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .sentinelCard(padding: 0)
            .buttonStyle(.plain)
            .foregroundColor(Theme.textPrimary)
        } else {
            Label("SAVE", systemImage: "square.and.arrow.down")
                .font(.subheadline.weight(.semibold))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .sentinelCard(padding: 0)
                .foregroundColor(Theme.textDim)
        }
    }

    #if canImport(UIKit)
    private func shareableImage(_ capture: ScreenCapture) -> Image? {
        UIImage(data: capture.image).map { Image(uiImage: $0) }
    }
    #else
    private func shareableImage(_ capture: ScreenCapture) -> Image? { nil }
    #endif

    private func grab() async {
        guard let api else {
            phase = .failed("No paired device")
            return
        }
        phase = .requesting
        do {
            let capture = try await api.grabScreen(display: nil, format: nil, quality: nil)
            phase = .loaded(capture)
            Haptics.impact(.light)
        } catch let err as SentinelError {
            phase = .failed(Self.describe(err))
        } catch {
            phase = .failed("Capture failed")
        }
    }

    private static func describe(_ err: SentinelError) -> String {
        switch err {
        case .offline: return "OFFLINE"
        case .unauthorized: return "NOT AUTHORIZED"
        case .captureUnavailable: return "CAPTURE UNAVAILABLE"
        case .notConfigured: return "NO PAIRED DEVICE"
        case .badRequest(let m), .server(_, let m), .malformedResponse(let m): return m.uppercased()
        }
    }

    private static let time: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
}
