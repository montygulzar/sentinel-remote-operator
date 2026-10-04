import SwiftUI
import SentinelKit
#if canImport(UIKit)
import UIKit
#endif

/// PairingView is the minimum useful first-time pairing experience (spec §13,
/// THIRD ARTILLERY ORDER): the owner enters the agent address and the one-time
/// code shown by `sentinel-agent pair`, and the Operator completes the signed
/// pairing handshake. On success the permanent key is derived locally and
/// stored in the Keychain; it is never typed, shown, or transmitted.
struct PairingView: View {
    @EnvironmentObject private var app: AppModel

    @State private var address = ""
    @State private var code = ""
    @State private var name = UIDeviceName.current
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(spacing: 22) {
                VStack(spacing: 6) {
                    MetaLabel(text: "PAIR SENTINEL", color: Theme.textSecondary)
                    Text("Connect this Operator to your workstation")
                        .font(.footnote)
                        .foregroundColor(Theme.textDim)
                        .multilineTextAlignment(.center)
                }
                .padding(.top, 40)

                VStack(spacing: 14) {
                    field(label: "DEVICE / ADDRESS", text: $address, placeholder: "100.x.y.z:8787", mono: true)
                    field(label: "PAIRING CODE", text: $code, placeholder: "one-time code", mono: true)
                    field(label: "OPERATOR NAME", text: $name, placeholder: "My iPhone", mono: false)
                }

                if let error {
                    Text(error)
                        .font(.footnote)
                        .foregroundColor(Theme.danger)
                        .multilineTextAlignment(.center)
                }

                Button {
                    Task { await pair() }
                } label: {
                    HStack {
                        if busy { ProgressView().tint(.black) }
                        Text(busy ? "PAIRING…" : "PAIR")
                            .font(.headline)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(canPair ? Theme.accent : Theme.surfaceRaised)
                    .foregroundColor(canPair ? .black : Theme.textDim)
                    .clipShape(RoundedRectangle(cornerRadius: Theme.cardCorner, style: .continuous))
                }
                .disabled(!canPair || busy)

                Text("The code comes from `sentinel-agent pair` on the workstation and expires quickly.")
                    .font(.caption2)
                    .foregroundColor(Theme.textDim)
                    .multilineTextAlignment(.center)
            }
            .padding(20)
        }
        .background(Theme.background)
    }

    private var canPair: Bool {
        !address.trimmingCharacters(in: .whitespaces).isEmpty &&
        !code.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private func field(label: String, text: Binding<String>, placeholder: String, mono: Bool) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            MetaLabel(text: label, color: Theme.textDim)
            TextField(placeholder, text: text)
                .font(mono ? .system(.body, design: .monospaced) : .body)
                .foregroundColor(Theme.textPrimary)
                .textInputAutocapitalization(mono ? .never : .words)
                .autocorrectionDisabled(mono)
                .padding(12)
                .background(Theme.surface)
                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(Theme.hairline, lineWidth: 1))
        }
    }

    private func pair() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            let device = try await app.makePairingService().pair(
                address: address, code: code, displayName: name.trimmingCharacters(in: .whitespaces)
            )
            Haptics.notify(.success)
            app.didPair(device)
        } catch let err as SentinelError {
            Haptics.notify(.error)
            error = describe(err)
        } catch {
            Haptics.notify(.error)
            self.error = "Pairing failed"
        }
    }

    private func describe(_ err: SentinelError) -> String {
        switch err {
        case .offline: return "Could not reach the workstation at that address."
        case .unauthorized: return "That pairing code was wrong or has expired."
        case .badRequest(let m): return m
        case .server(_, let m): return m
        case .malformedResponse: return "The workstation sent an unexpected response."
        case .captureUnavailable, .notConfigured: return "Pairing failed."
        }
    }
}

/// A best-effort default Operator name, so the field is pre-filled.
enum UIDeviceName {
    static var current: String {
        #if canImport(UIKit)
        return UIDevice.current.name
        #else
        return "Operator"
        #endif
    }
}
