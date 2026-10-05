import Foundation

/// Builds a fully-signed URLRequest for an endpoint. Shared by the device
/// client (signing with the per-device key) and the pairing flow (signing with
/// the one-time code), so the exact header set and the signed target string are
/// produced in exactly one place.
enum RequestBuilder {
    static func make(
        endpoint: ServerEndpoint,
        key: Data,
        deviceID: String,
        method: String,
        path: String,
        query: [URLQueryItem],
        body: Data,
        timestamp: String,
        nonce: String
    ) -> URLRequest? {
        guard let (url, target) = endpoint.target(path: path, query: query) else { return nil }
        let signed = SignedRequest(
            deviceID: deviceID, method: method, path: target,
            timestamp: timestamp, nonce: nonce, body: body
        )
        let signature = RequestSigner.signature(key: key, signed)

        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue(deviceID, forHTTPHeaderField: SentinelHeader.device)
        req.setValue(timestamp, forHTTPHeaderField: SentinelHeader.timestamp)
        req.setValue(nonce, forHTTPHeaderField: SentinelHeader.nonce)
        req.setValue(signature, forHTTPHeaderField: SentinelHeader.signature)
        if !body.isEmpty {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return req
    }
}
