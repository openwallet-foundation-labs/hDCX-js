import Foundation
import SdJwt
import XCTest
@testable import OpenID4VP

/// Cross-language golden vectors for DCQL matching (OpenID4VP §6, incl. null/values edges) — shared with Kotlin.
final class DcqlGoldenTests: XCTestCase {

    private struct VectorCred: QueryableCredential {
        let credentialId: String
        let format: String
        let vct: String?
        let docType: String?
        let claims: JsonValue
    }

    private func loadVectors() throws -> JsonValue {
        var d = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        for _ in 0..<8 {
            let f = d.appendingPathComponent("vectors/dcql/matching.json")
            if FileManager.default.fileExists(atPath: f.path) {
                return try JsonValue.parse(try String(contentsOf: f, encoding: .utf8))
            }
            d = d.deletingLastPathComponent()
        }
        fatalError("vectors/dcql/matching.json not found")
    }

    private func field(_ v: JsonValue, _ k: String) -> JsonValue? {
        guard case let .obj(o) = v else { return nil }
        return o.first { $0.0 == k }?.1
    }
    private func str(_ v: JsonValue, _ k: String) -> String? {
        if case let .str(s)? = field(v, k) { return s }
        return nil
    }

    func testDcqlMatchingMatchesGolden() throws {
        let root = try loadVectors()
        let c = field(root, "credential")!
        let cred = VectorCred(credentialId: str(c, "credentialId")!, format: str(c, "format")!,
                              vct: str(c, "vct"), docType: str(c, "docType"), claims: field(c, "claims")!)

        guard case let .arr(cases)? = field(root, "cases") else { return XCTFail("no cases") }
        for caseV in cases {
            let name = str(caseV, "name")!
            let query = try DcqlQuery.parse(field(caseV, "query")!)
            let result = DcqlEngine.match(query, held: [cred])
            let expected = field(caseV, "expected")!

            guard case let .bool(wantSatisfiable)? = field(expected, "satisfiable") else { return XCTFail() }
            XCTAssertEqual(wantSatisfiable, result.isSatisfiable(), "satisfiable '\(name)'")

            var expectedPaths = Set<[String]>()
            if case let .arr(paths)? = field(expected, "disclosedPaths") {
                for p in paths {
                    if case let .arr(segs) = p {
                        expectedPaths.insert(segs.compactMap { if case let .str(s) = $0 { return s }; return nil })
                    }
                }
            }
            let actualPaths = Set(result.candidatesByQuery["q"]?.first?.disclosedPaths ?? [])
            XCTAssertEqual(expectedPaths, actualPaths, "disclosedPaths '\(name)'")
        }
    }
}
