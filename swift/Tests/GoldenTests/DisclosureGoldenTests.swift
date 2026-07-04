import Crypto
import Foundation
import SdJwt
import XCTest

/// Cross-language golden vectors for SD-JWT (RFC 9901) disclosure encoding + digests — shared with Kotlin.
final class DisclosureGoldenTests: XCTestCase {

    private func buildValue(_ spec: JsonValue) -> JsonValue {
        guard case let .obj(o) = spec else { fatalError() }
        func f(_ k: String) -> JsonValue? { o.first { $0.0 == k }?.1 }
        guard case let .str(t)? = f("t") else { fatalError() }
        switch t {
        case "str": if case let .str(v)? = f("v") { return .str(v) }
        case "num": if case let .numInt(v)? = f("v") { return .numInt(v) }
        case "bool": if case let .bool(v)? = f("v") { return .bool(v) }
        default: break
        }
        fatalError("bad value spec")
    }

    private func str(_ o: [(String, JsonValue)], _ k: String) -> String {
        if case let .str(v)? = o.first(where: { $0.0 == k })?.1 { return v }
        fatalError("missing \(k)")
    }
    private func arr(_ root: JsonValue, _ k: String) -> [JsonValue] {
        guard case let .obj(o) = root, case let .arr(a)? = o.first(where: { $0.0 == k })?.1 else { return [] }
        return a
    }

    func testDisclosureDigestsMatchGolden() throws {
        let root = try GoldenVectors.load("sdjwt/disclosures.json")

        // 1) digest = base64url(SHA-256(disclosure bytes)) — SD-JWT spec authoritative
        for v in arr(root, "digest_of_string") {
            guard case let .obj(o) = v else { continue }
            let digest = Base64Url.encode([UInt8](SHA256.hash(data: Data(str(o, "disclosure").utf8))))
            XCTAssertEqual(str(o, "digest"), digest, "digest_of_string '\(str(o, "name"))'")
        }

        // 2) our object-property disclosure serialization + digest
        for v in arr(root, "object_property") {
            guard case let .obj(o) = v, let value = o.first(where: { $0.0 == "value" })?.1 else { continue }
            let d = try Disclosure.objectProperty(salt: str(o, "salt"), name: str(o, "key"), value: buildValue(value))
            XCTAssertEqual(str(o, "disclosure"), d.encoded, "object_property encoded '\(str(o, "name"))'")
            XCTAssertEqual(str(o, "digest"), d.digest, "object_property digest '\(str(o, "name"))'")
        }

        // 3) our array-element disclosure serialization + digest
        for v in arr(root, "array_element") {
            guard case let .obj(o) = v, let value = o.first(where: { $0.0 == "value" })?.1 else { continue }
            let d = Disclosure.arrayElement(salt: str(o, "salt"), value: buildValue(value))
            XCTAssertEqual(str(o, "disclosure"), d.encoded, "array_element encoded '\(str(o, "name"))'")
            XCTAssertEqual(str(o, "digest"), d.digest, "array_element digest '\(str(o, "name"))'")
        }
    }
}
