import Foundation

/// A paired device: the permanent per-device HMAC key plus the agent address it
/// belongs to. The `key` is the secret established at pairing and never leaves
/// the Keychain in production; it is never logged and never sent on the wire —
/// only used locally to sign requests.
public struct PairedDevice: Codable, Sendable, Equatable {
    public let deviceID: String
    public let key: Data
    public let serverAddress: String
    public let hostDisplayName: String

    public init(deviceID: String, key: Data, serverAddress: String, hostDisplayName: String) {
        self.deviceID = deviceID
        self.key = key
        self.serverAddress = serverAddress
        self.hostDisplayName = hostDisplayName
    }
}

/// CredentialStore persists the single paired device. The whole record —
/// crucially the secret key — is stored as one protected item, so no permanent
/// secret ever lands in UserDefaults, a plist, source, or a log (spec §13,
/// THIRD ARTILLERY ORDER).
public protocol CredentialStore: Sendable {
    func save(_ device: PairedDevice) throws
    func load() throws -> PairedDevice?
    func clear() throws
}

/// InMemoryCredentialStore is a non-persistent store for tests and previews. It
/// deliberately keeps nothing on disk.
public final class InMemoryCredentialStore: CredentialStore, @unchecked Sendable {
    private let lock = NSLock()
    private var device: PairedDevice?

    public init(_ device: PairedDevice? = nil) { self.device = device }

    public func save(_ device: PairedDevice) throws {
        lock.lock(); defer { lock.unlock() }
        self.device = device
    }

    public func load() throws -> PairedDevice? {
        lock.lock(); defer { lock.unlock() }
        return device
    }

    public func clear() throws {
        lock.lock(); defer { lock.unlock() }
        device = nil
    }
}
