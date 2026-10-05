import Foundation

/// SentinelClient is the real SentinelAPI: it signs every request with the
/// paired device key (identical algorithm to the agent) and maps HTTP outcomes
/// to explicit `SentinelError` cases so the UI never has to guess. It holds no
/// mutable state and is safe to share.
public final class SentinelClient: SentinelAPI, @unchecked Sendable {
    private let device: PairedDevice
    private let endpoint: ServerEndpoint
    private let session: URLSession
    private let now: @Sendable () -> Date
    private let nonceFactory: @Sendable () -> String

    public init?(
        device: PairedDevice,
        session: URLSession = .shared,
        now: @escaping @Sendable () -> Date = { Date() },
        nonce: @escaping @Sendable () -> String = { UUID().uuidString }
    ) {
        guard let endpoint = ServerEndpoint(address: device.serverAddress) else { return nil }
        self.device = device
        self.endpoint = endpoint
        self.session = session
        self.now = now
        self.nonceFactory = nonce
    }

    // MARK: - Typed calls

    public func status() async throws -> Status {
        try await getJSON(path: "/v1/status")
    }

    public func activity() async throws -> Activity {
        try await getJSON(path: "/v1/activity")
    }

    public func panic() async throws -> PanicResult {
        let (data, http) = try await send(method: "POST", path: "/v1/control/panic", query: [], body: Data())
        try throwForStatus(http, data)
        return try decode(PanicResult.self, data)
    }

    public func logs(limit: Int?, class klass: String?) async throws -> [LogEvent] {
        var query: [URLQueryItem] = []
        if let limit { query.append(URLQueryItem(name: "limit", value: String(limit))) }
        if let klass { query.append(URLQueryItem(name: "class", value: klass)) }
        let (data, http) = try await send(method: "GET", path: "/v1/logs", query: query, body: Data())
        try throwForStatus(http, data)
        struct Wrapper: Decodable { let events: [LogEvent] }
        return try decode(Wrapper.self, data).events
    }

    public func grabScreen(display: String?, format: String?, quality: Int?) async throws -> ScreenCapture {
        var query: [URLQueryItem] = []
        if let display, !display.isEmpty { query.append(URLQueryItem(name: "display", value: display)) }
        if let format, !format.isEmpty { query.append(URLQueryItem(name: "format", value: format)) }
        if let quality { query.append(URLQueryItem(name: "quality", value: String(quality))) }

        let (data, http) = try await send(method: "GET", path: "/v1/screen/grab", query: query, body: Data())
        if http.statusCode == 503 { throw SentinelError.captureUnavailable }
        try throwForStatus(http, data)

        let meta = try ScreenMetadataParser.parse { http.value(forHTTPHeaderField: $0) }
        if data.isEmpty { throw SentinelError.malformedResponse("empty image body") }
        return ScreenCapture(image: data, metadata: meta)
    }

    // MARK: - Transport

    private func getJSON<T: Decodable>(path: String) async throws -> T {
        let (data, http) = try await send(method: "GET", path: path, query: [], body: Data())
        try throwForStatus(http, data)
        return try decode(T.self, data)
    }

    private func send(method: String, path: String, query: [URLQueryItem], body: Data) async throws -> (Data, HTTPURLResponse) {
        guard let req = RequestBuilder.make(
            endpoint: endpoint, key: device.key, deviceID: device.deviceID,
            method: method, path: path, query: query, body: body,
            timestamp: String(Int(now().timeIntervalSince1970)), nonce: nonceFactory()
        ) else {
            throw SentinelError.badRequest("could not build request URL")
        }

        do {
            let (data, response) = try await session.data(for: req)
            guard let http = response as? HTTPURLResponse else {
                throw SentinelError.malformedResponse("non-HTTP response")
            }
            return (data, http)
        } catch let err as SentinelError {
            throw err
        } catch {
            // A transport failure (host unreachable, timeout) is an offline
            // condition, not a crash: the UI shows OFFLINE and a retry.
            throw SentinelError.offline
        }
    }

    private func throwForStatus(_ http: HTTPURLResponse, _ data: Data) throws {
        switch http.statusCode {
        case 200...299:
            return
        case 401:
            throw SentinelError.unauthorized
        case 400:
            throw SentinelError.badRequest(errorMessage(data) ?? "bad request")
        default:
            throw SentinelError.server(status: http.statusCode, message: errorMessage(data) ?? "server error")
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw SentinelError.malformedResponse("could not decode \(type)")
        }
    }

    private func errorMessage(_ data: Data) -> String? {
        struct E: Decodable { let error: String? }
        return (try? JSONDecoder().decode(E.self, from: data))?.error
    }
}
