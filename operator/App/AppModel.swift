import Foundation
import SentinelKit

/// AppModel is the Operator's root state: it owns the credential store, exposes
/// the currently paired device, and builds the signed API client from it.
/// Pairing and unpairing flow through here so every screen sees one source of
/// truth for "which machine am I operating, if any".
@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var paired: PairedDevice?

    let store: CredentialStore

    init(store: CredentialStore) {
        self.store = store
        self.paired = (try? store.load()) ?? nil
    }

    /// The default production configuration: credentials live in the Keychain.
    static func live() -> AppModel {
        #if canImport(Security)
        return AppModel(store: KeychainCredentialStore())
        #else
        return AppModel(store: InMemoryCredentialStore())
        #endif
    }

    var isPaired: Bool { paired != nil }

    /// A signed client for the paired device, or nil when not paired.
    func makeClient() -> SentinelAPI? {
        guard let paired else { return nil }
        return SentinelClient(device: paired)
    }

    func makePairingService() -> PairingService {
        PairingService(store: store)
    }

    func didPair(_ device: PairedDevice) {
        paired = device
    }

    func unpair() {
        try? store.clear()
        paired = nil
    }
}
