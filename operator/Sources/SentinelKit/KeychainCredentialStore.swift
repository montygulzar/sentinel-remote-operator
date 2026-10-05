import Foundation

#if canImport(Security)
import Security

/// KeychainCredentialStore stores the paired device in the iOS/macOS Keychain
/// as a single generic-password item, with the record (including the secret
/// key) as the item's secret data. Accessibility is
/// `kSecAttrAccessibleAfterFirstThisDeviceOnly`: the credential is usable while
/// the device is unlocked-since-boot, is never migrated to another device, and
/// never leaves the Keychain (spec §13).
public final class KeychainCredentialStore: CredentialStore, @unchecked Sendable {
    private let service: String
    private let account: String

    public init(service: String = "sentinel.operator.device", account: String = "default") {
        self.service = service
        self.account = account
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    public func save(_ device: PairedDevice) throws {
        let data = try JSONEncoder().encode(device)

        // Replace any existing item atomically: delete then add.
        SecItemDelete(baseQuery() as CFDictionary)

        var add = baseQuery()
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    public func load() throws -> PairedDevice? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw KeychainError.unexpectedStatus(status)
        }
        return try JSONDecoder().decode(PairedDevice.self, from: data)
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}

public enum KeychainError: Error, Equatable {
    case unexpectedStatus(OSStatus)
}
#endif
