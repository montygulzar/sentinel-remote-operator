import CryptoKit
import Foundation

/// The request attributes covered by a Sentinel signature. This mirrors the Go
/// agent's `auth.SignedRequest` exactly: the same fields, the same canonical
/// ordering, the same body-hash scheme. Any divergence here breaks
/// authentication, so the shared, locked test vectors
/// (`Resources/signing_vectors.json`) pin both sides to one algorithm.
public struct SignedRequest: Sendable {
    public let deviceID: String
    public let method: String
    /// Full request target: path plus any query string, e.g.
    /// `/v1/logs?limit=50`. Signing the whole target authenticates the query.
    public let path: String
    public let timestamp: String
    public let nonce: String
    public let body: Data

    public init(deviceID: String, method: String, path: String, timestamp: String, nonce: String, body: Data) {
        self.deviceID = deviceID
        self.method = method
        self.path = path
        self.timestamp = timestamp
        self.nonce = nonce
        self.body = body
    }
}

/// Header names carrying authentication material on every request. These match
/// the agent's `auth` package.
public enum SentinelHeader {
    public static let device = "X-Sentinel-Device"
    public static let timestamp = "X-Sentinel-Timestamp"
    public static let nonce = "X-Sentinel-Nonce"
    public static let signature = "X-Sentinel-Signature"
}

/// RequestSigner reproduces the agent's HMAC-SHA256 request signature.
///
/// canonical = join("\n", [deviceID, UPPERCASE(method), path, timestamp, nonce,
/// hex(sha256(body))]); signature = hex(HMAC-SHA256(key, utf8(canonical))).
public enum RequestSigner {
    /// The exact byte string that is HMAC'd. The body is reduced to its
    /// lowercase-hex SHA-256 digest, so an empty body hashes deterministically.
    public static func canonical(_ r: SignedRequest) -> String {
        let bodyHex = hex(SHA256.hash(data: r.body))
        return [
            r.deviceID,
            r.method.uppercased(),
            r.path,
            r.timestamp,
            r.nonce,
            bodyHex,
        ].joined(separator: "\n")
    }

    /// Lowercase-hex HMAC-SHA256 of the request under `key`.
    public static func signature(key: Data, _ r: SignedRequest) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(canonical(r).utf8),
            using: SymmetricKey(data: key)
        )
        return hex(mac)
    }

    static func hex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        // Manual nibble mapping avoids any String(format:) vararg width
        // ambiguity and is what the signatures must match byte-for-byte.
        let digits: [Character] = Array("0123456789abcdef")
        var s = ""
        s.reserveCapacity(64)
        for b in bytes {
            s.append(digits[Int(b >> 4)])
            s.append(digits[Int(b & 0x0f)])
        }
        return s
    }
}
