import Foundation
import SdJwt
import WalletAPI

/// What the wallet shows on the consent screen about the verifier and its trust status.
public struct VerifierInfo {
    public let clientId: String
    public let clientIdScheme: String
    /// X.509 chain from the request signature, leaf-first DER (nil for unsigned requests).
    public let certificateChainDer: [[UInt8]]?
    public let commonName: String?
    /// True only when the trust verifier confirmed signature + scheme + chain to a trust anchor.
    public let trusted: Bool

    public init(clientId: String, clientIdScheme: String, certificateChainDer: [[UInt8]]?, commonName: String?, trusted: Bool) {
        self.clientId = clientId
        self.clientIdScheme = clientIdScheme
        self.certificateChainDer = certificateChainDer
        self.commonName = commonName
        self.trusted = trusted
    }
}

/// Verifies an OpenID4VP signed request object: JWS signature, client_id scheme
/// (x509_san_dns / x509_hash), and the certificate chain to a trust anchor. Implemented by
/// the `Trust` module (swift-certificates); the resolver stays platform-neutral.
public protocol RequestTrustVerifier: Sendable {
    func verifyRequestObject(_ jws: Jws, clientId: String, scheme: String) async throws -> VerifierInfo
}

public struct ResolvedRequest {
    public let clientId: String
    public let nonce: String
    public let state: String?
    public let responseMode: String
    public let responseUri: String?
    public let redirectUri: String?
    public let dcqlQuery: DcqlQuery
    public let clientMetadata: JsonValue?
    public let transactionData: [String]?
    public let verifier: VerifierInfo
}

/// Resolves an OpenID4VP authorization request (OpenID4VP §5): parses the request URI and
/// follows JAR (`request_uri`/`request`).
///
/// NOTE: `x509_san_dns` signature/SAN verification needs X.509 parsing (swift-certificates),
/// which lands with the trust module (M3, mirrors the issuer-x5c gap). This resolver handles
/// unsigned requests and parses signed request objects; on Apple/Linux without the trust
/// module it reports `signatureValid = false` for x509 schemes rather than asserting trust.
public struct AuthorizationRequestResolver {
    private let http: any HttpTransport
    private let trust: (any RequestTrustVerifier)?

    public init(http: any HttpTransport, trust: (any RequestTrustVerifier)? = nil) {
        self.http = http
        self.trust = trust
    }

    public func resolve(_ requestUri: String) async throws -> ResolvedRequest {
        let params = try parseQuery(requestUri)
        guard let clientId = params["client_id"] else { throw VpError.invalidRequest("missing client_id") }
        let scheme = clientIdScheme(clientId, params["client_id_scheme"])

        let claims: JsonValue
        let verifier: VerifierInfo
        if let requestUriParam = params["request_uri"] {
            let jwt = try await fetchRequestObject(requestUriParam)
            (claims, verifier) = try await parseSignedRequest(jwt, clientId, scheme)
        } else if let requestParam = params["request"] {
            (claims, verifier) = try await parseSignedRequest(requestParam, clientId, scheme)
        } else {
            claims = try unsignedRequest(params)
            verifier = VerifierInfo(clientId: clientId, clientIdScheme: scheme, certificateChainDer: nil, commonName: nil, trusted: false)
        }

        return try build(claims, clientId, scheme, verifier)
    }

    private func build(_ claims: JsonValue, _ clientId: String, _ scheme: String, _ verifier: VerifierInfo) throws -> ResolvedRequest {
        guard case let .str(nonce)? = claims["nonce"] else { throw VpError.invalidRequest("missing nonce") }
        guard let dcqlObj = claims["dcql_query"], case .obj = dcqlObj else {
            throw VpError.invalidRequest("missing dcql_query (only DCQL is supported)")
        }
        var responseMode = "direct_post"
        if case let .str(m)? = claims["response_mode"] { responseMode = m }
        guard responseMode == "direct_post" || responseMode == "direct_post.jwt" else {
            throw VpError.unsupported("response_mode '\(responseMode)'")
        }
        var txData: [String]?
        if case let .arr(items)? = claims["transaction_data"] {
            txData = items.compactMap { if case let .str(s) = $0 { return s } else { return nil } }
        }
        func str(_ n: String) -> String? { if case let .str(s)? = claims[n] { return s }; return nil }
        return ResolvedRequest(
            clientId: clientId, nonce: nonce, state: str("state"),
            responseMode: responseMode, responseUri: str("response_uri"), redirectUri: str("redirect_uri"),
            dcqlQuery: try DcqlQuery.parse(dcqlObj), clientMetadata: claims["client_metadata"],
            transactionData: txData, verifier: verifier
        )
    }

    private func unsignedRequest(_ params: [String: String]) throws -> JsonValue {
        var entries: [(String, JsonValue)] = []
        for (k, v) in params {
            if k == "dcql_query" || k == "client_metadata" || k == "transaction_data" {
                entries.append((k, try JsonValue.parse(v)))
            } else {
                entries.append((k, .str(v)))
            }
        }
        return .obj(entries)
    }

    private func parseSignedRequest(_ jwt: String, _ clientId: String, _ scheme: String) async throws -> (JsonValue, VerifierInfo) {
        let jws = try Jws.parse(jwt)
        guard let text = String(bytes: jws.payloadBytes, encoding: .utf8),
              let claims = try? JsonValue.parse(text), case .obj = claims
        else { throw VpError.invalidRequest("request object payload must be JSON") }
        let verifier: VerifierInfo
        if let trust {
            verifier = try await trust.verifyRequestObject(jws, clientId: clientId, scheme: scheme)
        } else {
            verifier = VerifierInfo(clientId: clientId, clientIdScheme: scheme, certificateChainDer: jws.x5c, commonName: nil, trusted: false)
        }
        return (claims, verifier)
    }

    private func fetchRequestObject(_ url: String) async throws -> String {
        let resp = try await http.execute(HttpRequest(method: .get, url: url, headers: [("Accept", "application/oauth-authz-req+jwt")]))
        guard (200...299).contains(resp.status) else { throw VpError.invalidRequest("request_uri fetch failed: HTTP \(resp.status)") }
        return (String(bytes: resp.body, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func clientIdScheme(_ clientId: String, _ explicit: String?) -> String {
        if let explicit { return explicit }
        if clientId.contains(":") { return String(clientId.split(separator: ":")[0]) }
        return "redirect_uri"
    }

    private func parseQuery(_ uri: String) throws -> [String: String] {
        guard let q = uri.split(separator: "?", maxSplits: 1).dropFirst().first else {
            throw VpError.invalidRequest("no query parameters in request")
        }
        var out: [String: String] = [:]
        for pair in q.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            let k = String(kv[0]).removingPercentEncoding ?? String(kv[0])
            let v = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? String(kv[1])) : ""
            out[k] = v
        }
        return out
    }
}
