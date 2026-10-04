import CryptoKit
import Foundation

/// PairingKeyDerivation reproduces the agent's pairing math (agent
/// `auth/pairing.go`). The permanent device key and the agent's proof are both
/// HMAC-SHA256 over the one-time code and the two exchanged nonces, so each side
/// derives the key independently and it is never transmitted. The labels and
/// field order must match the agent exactly.
public enum PairingKeyDerivation {
    static let deviceKeyLabel = "sentinel/device-key/v1"
    static let pairConfirmLabel = "sentinel/pair-confirm/v1"

    /// mac = HMAC-SHA256(code, label || extra || agentNonce || deviceNonce).
    static func mac(code: Data, label: String, extra: Data, agentNonce: Data, deviceNonce: Data) -> Data {
        var message = Data()
        message.append(Data(label.utf8))
        message.append(extra)
        message.append(agentNonce)
        message.append(deviceNonce)
        let tag = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: code))
        return Data(tag)
    }

    public static func deviceKey(code: String, agentNonce: Data, deviceNonce: Data) -> Data {
        mac(code: Data(code.utf8), label: deviceKeyLabel, extra: Data(), agentNonce: agentNonce, deviceNonce: deviceNonce)
    }

    public static func pairConfirm(code: String, deviceID: String, agentNonce: Data, deviceNonce: Data) -> Data {
        mac(code: Data(code.utf8), label: pairConfirmLabel, extra: Data(deviceID.utf8), agentNonce: agentNonce, deviceNonce: deviceNonce)
    }
}

/// PairingService runs the owner-initiated pairing handshake against an agent:
/// it signs POST /v1/pair with the one-time code, verifies the agent's proof
/// (so a network attacker who never knew the code cannot complete pairing),
/// derives the permanent key, and persists the resulting device.
public final class PairingService: @unchecked Sendable {
    private let store: CredentialStore
    private let session: URLSession
    private let now: @Sendable () -> Date
    private let nonceFactory: @Sendable () -> String
    private let randomNonce: @Sendable () -> Data

    /// The device-id value used in the pairing request. The agent takes it from
    /// the request header and signs with the same value, so any stable constant
    /// works; "pairing" makes the intent clear in logs.
    public static let pairingDeviceID = "pairing"

    public init(
        store: CredentialStore,
        session: URLSession = .shared,
        now: @escaping @Sendable () -> Date = { Date() },
        nonce: @escaping @Sendable () -> String = { UUID().uuidString },
        randomNonce: @escaping @Sendable () -> Data = { PairingService.secureRandom(16) }
    ) {
        self.store = store
        self.session = session
        self.now = now
        self.nonceFactory = nonce
        self.randomNonce = randomNonce
    }

    /// Completes pairing and returns (and persists) the paired device.
    public func pair(address: String, code: String, displayName: String) async throws -> PairedDevice {
        guard let endpoint = ServerEndpoint(address: address) else {
            throw SentinelError.badRequest("invalid device address")
        }
        let trimmedCode = code.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !trimmedCode.isEmpty else {
            throw SentinelError.badRequest("pairing code is required")
        }

        let deviceNonce = randomNonce()
        let bodyObj = PairRequestBody(displayName: displayName, deviceNonce: deviceNonce.base64EncodedString())
        let body = try JSONEncoder().encode(bodyObj)

        guard let req = RequestBuilder.make(
            endpoint: endpoint, key: Data(trimmedCode.utf8), deviceID: PairingService.pairingDeviceID,
            method: "POST", path: "/v1/pair", query: [], body: body,
            timestamp: String(Int(now().timeIntervalSince1970)), nonce: nonceFactory()
        ) else {
            throw SentinelError.badRequest("could not build pairing request")
        }

        let data: Data
        let http: HTTPURLResponse
        do {
            let (d, response) = try await session.data(for: req)
            guard let h = response as? HTTPURLResponse else {
                throw SentinelError.malformedResponse("non-HTTP response")
            }
            data = d
            http = h
        } catch let err as SentinelError {
            throw err
        } catch {
            throw SentinelError.offline
        }

        switch http.statusCode {
        case 200...299:
            break
        case 401:
            // The agent returns an opaque 401 for a wrong/expired code.
            throw SentinelError.unauthorized
        default:
            throw SentinelError.server(status: http.statusCode, message: "pairing failed")
        }

        let result: PairResultBody
        do {
            result = try JSONDecoder().decode(PairResultBody.self, from: data)
        } catch {
            throw SentinelError.malformedResponse("could not decode pairing result")
        }

        guard let agentNonce = Data(base64Encoded: result.agentNonce),
              let agentProof = Data(base64Encoded: result.agentProof) else {
            throw SentinelError.malformedResponse("invalid pairing nonce/proof encoding")
        }

        // Verify the agent proved knowledge of the code before trusting it.
        let expectedProof = PairingKeyDerivation.pairConfirm(
            code: trimmedCode, deviceID: result.deviceId, agentNonce: agentNonce, deviceNonce: deviceNonce
        )
        guard constantTimeEquals(expectedProof, agentProof) else {
            throw SentinelError.unauthorized
        }

        let deviceKey = PairingKeyDerivation.deviceKey(
            code: trimmedCode, agentNonce: agentNonce, deviceNonce: deviceNonce
        )
        let hostName = displayName.isEmpty ? endpoint.authority : displayName
        let device = PairedDevice(
            deviceID: result.deviceId, key: deviceKey,
            serverAddress: address.trimmingCharacters(in: .whitespacesAndNewlines),
            hostDisplayName: hostName
        )
        try store.save(device)
        return device
    }

    static func secureRandom(_ n: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: n)
        for i in 0..<n { bytes[i] = UInt8.random(in: 0...255) }
        return Data(bytes)
    }
}

/// Constant-time comparison so proof verification does not leak via timing.
func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count { diff |= a[i] ^ b[i] }
    return diff == 0
}
