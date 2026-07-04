import CborCose
import Foundation
import MDoc
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VP

final class MdocDcqlTests: XCTestCase {

    private let docType = "org.iso.18013.5.1.mDL"
    private let namespace = "org.iso.18013.5.1"

    private func heldMdoc() async throws -> HeldMdoc {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
        let bytes = try await MdocTestIssuer.issue(
            area: area, issuerKey: issuerKey, deviceKey: deviceKey,
            docType: docType, namespace: namespace,
            elements: [("family_name", .text("Han")), ("given_name", .text("Jongho")), ("age_over_18", .bool(true))],
            x5chain: [[0x30, 0x01]],
            signed: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validFrom: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validUntil: MdocTestIssuer.isoFormatter.date(from: "2027-01-01T00:00:00Z")!
        )
        return try HeldMdoc(credentialId: "mdl-1", issuerSigned: try IssuerSigned.decode(bytes))
    }

    private func query(_ json: String) throws -> DcqlQuery { try DcqlQuery.parse(JsonValue.parse(json)) }

    func testMatchesMdocByDoctypeAndNamespacePath() async throws {
        let held = try await heldMdoc()
        let q = try query(
            #"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"\#(docType)"},"claims":[{"path":["\#(namespace)","family_name"]},{"path":["\#(namespace)","given_name"]}]}]}"#
        )
        let result = DcqlEngine.match(q, held: [held])
        XCTAssertTrue(result.isSatisfiable())
        let candidate = result.candidatesByQuery["mdl"]!
        XCTAssertEqual(1, candidate.count)
        XCTAssertEqual([[namespace, "family_name"], [namespace, "given_name"]], candidate[0].disclosedPaths)
    }

    func testWrongDoctypeExcludes() async throws {
        let held = try await heldMdoc()
        let q = try query(
            #"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"other"},"claims":[{"path":["\#(namespace)","family_name"]}]}]}"#
        )
        XCTAssertTrue(DcqlEngine.match(q, held: [held]).candidatesByQuery["mdl"]!.isEmpty)
    }

    func testValueConstraintMatchesElement() async throws {
        let held = try await heldMdoc()
        let q = try query(
            #"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"\#(docType)"},"claims":[{"path":["\#(namespace)","age_over_18"],"values":[true]}]}]}"#
        )
        XCTAssertTrue(DcqlEngine.match(q, held: [held]).isSatisfiable())
    }

    func testOneElementPathRejectedAtParse() throws {
        XCTAssertThrowsError(try query(
            #"{"credentials":[{"id":"mdl","format":"mso_mdoc","claims":[{"path":["\#(namespace)"]}]}]}"#
        ))
    }

    func testNonStringSecondElementRejectedAtParse() throws {
        XCTAssertThrowsError(try query(
            #"{"credentials":[{"id":"mdl","format":"mso_mdoc","claims":[{"path":["\#(namespace)",0]}]}]}"#
        ))
    }
}
