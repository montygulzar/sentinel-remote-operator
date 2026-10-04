import Foundation

/// ServerEndpoint parses an owner-entered agent address into a base URL and
/// builds request targets. It accepts `host:port`, `http://host:port`, or a
/// bare host (defaulting to the agent's port 8787). Transport is plain HTTP:
/// confidentiality comes from the private overlay network (e.g. Tailscale) and
/// integrity from Sentinel's own request signatures (spec §3), so the agent
/// serves HTTP and the Operator must not assume TLS it cannot verify.
public struct ServerEndpoint: Sendable, Equatable {
    public let scheme: String
    public let host: String
    public let port: Int

    public static let defaultPort = 8787

    public init?(address: String) {
        var s = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return nil }

        var scheme = "http"
        if let range = s.range(of: "://") {
            scheme = String(s[s.startIndex..<range.lowerBound]).lowercased()
            s = String(s[range.upperBound...])
        }
        guard scheme == "http" || scheme == "https" else { return nil }

        // Strip any trailing path the user may have pasted.
        if let slash = s.firstIndex(of: "/") {
            s = String(s[s.startIndex..<slash])
        }
        if s.isEmpty { return nil }

        var host = s
        var port = ServerEndpoint.defaultPort
        // Split host:port, but leave bracketed IPv6 literals intact.
        if !s.hasPrefix("[") , let colon = s.lastIndex(of: ":") {
            host = String(s[s.startIndex..<colon])
            let portStr = String(s[s.index(after: colon)...])
            guard let p = Int(portStr), p > 0, p <= 65535 else { return nil }
            port = p
        }
        if host.isEmpty { return nil }

        self.scheme = scheme
        self.host = host
        self.port = port
    }

    /// The `host:port` authority used in URLs.
    public var authority: String { "\(host):\(port)" }

    /// Builds the request target (path plus percent-encoded query) and the full
    /// URL from one source, so the string that is signed is exactly the string
    /// that is sent.
    public func target(path: String, query: [URLQueryItem]) -> (url: URL, target: String)? {
        var comps = URLComponents()
        comps.path = path
        if !query.isEmpty { comps.queryItems = query }
        let encodedPath = comps.percentEncodedPath
        let target: String
        if let q = comps.percentEncodedQuery, !q.isEmpty {
            target = encodedPath + "?" + q
        } else {
            target = encodedPath
        }
        guard let url = URL(string: "\(scheme)://\(authority)\(target)") else { return nil }
        return (url, target)
    }
}
