import Foundation
import SdJwt

public struct DcqlError: Error, CustomStringConvertible {
    public let description: String
    init(_ description: String) { self.description = description }
}

/// A single element of a DCQL claims path (OpenID4VP §6.4): key, array index, or wildcard (JSON null).
public enum PathElement: Equatable {
    case key(String)
    case index(Int)
    case wildcard
}

public struct ClaimQuery {
    public let id: String?
    public let path: [PathElement]
    public let values: [JsonValue]?
}

public struct CredentialMeta {
    public let vctValues: [String]?
    public let doctypeValue: String?
}

public struct CredentialQuery {
    public let id: String
    public let format: String
    public let meta: CredentialMeta?
    public let claims: [ClaimQuery]
    public let claimSets: [[String]]?
}

public struct CredentialSetQuery {
    public let options: [[String]]
    public let required: Bool
}

public struct DcqlQuery {
    public let credentials: [CredentialQuery]
    public let credentialSets: [CredentialSetQuery]?

    public static func parse(_ obj: JsonValue) throws -> DcqlQuery {
        guard case let .arr(credArr)? = obj["credentials"] else { throw DcqlError("dcql: missing 'credentials'") }
        let creds = try credArr.map { try parseCredentialQuery($0) }
        guard !creds.isEmpty else { throw DcqlError("dcql: 'credentials' is empty") }
        var sets: [CredentialSetQuery]?
        if case let .arr(setArr)? = obj["credential_sets"] {
            sets = try setArr.map { try parseCredentialSet($0) }
        }
        return DcqlQuery(credentials: creds, credentialSets: sets)
    }

    private static func parseCredentialQuery(_ o: JsonValue) throws -> CredentialQuery {
        guard case let .str(id)? = o["id"] else { throw DcqlError("credential query: missing 'id'") }
        guard case let .str(format)? = o["format"] else { throw DcqlError("credential query '\(id)': missing 'format'") }
        var meta: CredentialMeta?
        if let m = o["meta"] {
            var vct: [String]?
            if case let .arr(items)? = m["vct_values"] {
                vct = items.compactMap { if case let .str(s) = $0 { return s } else { return nil } }
            }
            var doctype: String?
            if case let .str(d)? = m["doctype_value"] { doctype = d }
            meta = CredentialMeta(vctValues: vct, doctypeValue: doctype)
        }
        var claims: [ClaimQuery] = []
        if case let .arr(cArr)? = o["claims"] { claims = try cArr.map { try parseClaimQuery($0) } }
        var claimSets: [[String]]?
        if case let .arr(csArr)? = o["claim_sets"] {
            claimSets = try csArr.map { set in
                guard case let .arr(ids) = set else { throw DcqlError("claim_sets must be arrays") }
                return try ids.map { if case let .str(s) = $0 { return s } else { throw DcqlError("claim_sets entries must be strings") } }
            }
        }
        // mdoc (ISO 18013-5): a claim path addresses [namespace, data element], both strings.
        // Require the first two segments to be string keys (>=2, not strictly ==2 — a deeper
        // path may index into a structured element value).
        if format == "mso_mdoc" {
            for c in claims {
                let firstTwoAreKeys = c.path.count >= 2 && {
                    if case .key = c.path[0], case .key = c.path[1] { return true } else { return false }
                }()
                if !firstTwoAreKeys {
                    throw DcqlError("credential query '\(id)': mso_mdoc claim path must start with [namespace, element] (two strings)")
                }
            }
        }
        return CredentialQuery(id: id, format: format, meta: meta, claims: claims, claimSets: claimSets)
    }

    private static func parseClaimQuery(_ o: JsonValue) throws -> ClaimQuery {
        guard case let .arr(pathArr)? = o["path"] else { throw DcqlError("claim: missing 'path'") }
        let path = try pathArr.map { el -> PathElement in
            switch el {
            case let .str(s): return .key(s)
            case let .numInt(i): return .index(Int(i))
            case .null: return .wildcard
            default: throw DcqlError("path element must be string, int, or null")
            }
        }
        var values: [JsonValue]?
        if case let .arr(v)? = o["values"] { values = v }
        var id: String?
        if case let .str(s)? = o["id"] { id = s }
        return ClaimQuery(id: id, path: path, values: values)
    }

    private static func parseCredentialSet(_ o: JsonValue) throws -> CredentialSetQuery {
        guard case let .arr(optArr)? = o["options"] else { throw DcqlError("credential_set: missing 'options'") }
        let options = try optArr.map { opt -> [String] in
            guard case let .arr(ids) = opt else { throw DcqlError("options must be arrays") }
            return try ids.map { if case let .str(s) = $0 { return s } else { throw DcqlError("option ids must be strings") } }
        }
        var required = true
        if case let .bool(b)? = o["required"] { required = b }
        return CredentialSetQuery(options: options, required: required)
    }
}
