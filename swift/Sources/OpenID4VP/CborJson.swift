import CborCose
import SdJwt

/// Projects a CBOR value into the JSON claim tree DCQL matches against. Byte strings become
/// base64url text and tags are unwrapped (mdoc element values are plain CBOR — text, ints,
/// bools, arrays, maps, and tdate/bstr for dates and portraits).
public enum CborJson {
    public static func toJson(_ c: Cbor) -> JsonValue {
        switch c {
        case let .text(s): return .str(s)
        case let .bytes(b): return .str(Base64Url.encode(b))
        case let .bool(v): return .bool(v)
        case let .uint(v): return .numInt(Int64(clamping: v))
        case let .nint(v): return .numInt(v <= UInt64(Int64.max) ? -1 - Int64(v) : Int64.min)
        case let .float(bits): return .numDouble(Double(bitPattern: bits))
        case let .array(items): return .arr(items.map { toJson($0) })
        case let .map(entries): return .obj(entries.map { (keyString($0.0), toJson($0.1)) })
        case let .tagged(_, inner): return toJson(inner) // e.g. tdate (#6.0) -> its inner text
        case .null, .undefined, .simple: return .null
        }
    }

    private static func keyString(_ k: Cbor) -> String {
        switch k {
        case let .text(s): return s
        case let .uint(v): return String(v)
        case let .nint(v): return String(v <= UInt64(Int64.max) ? -1 - Int64(v) : Int64.min)
        default: return "\(k)"
        }
    }
}
