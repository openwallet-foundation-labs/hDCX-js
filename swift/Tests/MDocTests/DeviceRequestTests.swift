import CborCose
import Foundation
import WalletAPI
import WalletTestKit
import XCTest
@testable import MDoc

final class DeviceRequestTests: XCTestCase {

    private let docType = "org.iso.18013.5.1.mDL"
    private let namespace = "org.iso.18013.5.1"
    private let origin = "https://verifier.example"

    private struct TestReaderTrust: MdocReaderTrust {
        let key: EcPublicKey
        func readerKey(x5chain: [[UInt8]]) async throws -> EcPublicKey { key }
    }

    private func field(_ c: Cbor, _ k: String) -> Cbor { guard case let .map(e) = c else { fatalError() }; return e.first { if case let .text(t) = $0.0 { return t == k }; return false }!.1 }

    private func mdoc(area: SoftwareSecureArea, issuerKey: KeyInfo, deviceKey: EcPublicKey) async throws -> [UInt8] {
        try await MdocTestIssuer.issue(
            area: area, issuerKey: issuerKey, deviceKey: deviceKey, docType: docType, namespace: namespace,
            elements: [("family_name", .text("Han")), ("given_name", .text("Jongho")), ("age_over_18", .bool(true))],
            x5chain: [[0x30, 0x01]],
            signed: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validFrom: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validUntil: MdocTestIssuer.isoFormatter.date(from: "2027-01-01T00:00:00Z")!)
    }

    func testParsesDeviceRequest() async throws {
        let area = SoftwareSecureArea()
        let readerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: origin)
        let bytes = try await MdocTestReader.deviceRequest(area: area, readerKey: readerKey, docType: docType, requested: [(namespace, ["family_name", "given_name"])], sessionTranscript: st, x5chain: [[0x30, 0x01]])

        let request = try DeviceRequest.decode(bytes)
        XCTAssertEqual("1.0", request.version)
        let docReq = request.docRequest(for: docType)!
        XCTAssertEqual(Set(["family_name", "given_name"]), Set(docReq.requested.first!.1.map { $0.identifier }))
        XCTAssertNotNil(docReq.readerAuth)
    }

    func testVerifiesReaderAuth() async throws {
        let area = SoftwareSecureArea()
        let readerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: origin)
        let bytes = try await MdocTestReader.deviceRequest(area: area, readerKey: readerKey, docType: docType, requested: [(namespace, ["family_name"])], sessionTranscript: st, x5chain: [[0x30, 0x01]])
        let docReq = try DeviceRequest.decode(bytes).docRequest(for: docType)!
        let info = try await ReaderAuth.verify(docReq, sessionTranscript: st, trust: TestReaderTrust(key: readerKey.publicKey))
        XCTAssertTrue(info.trusted)
    }

    func testWrongReaderKeyRejected() async throws {
        let area = SoftwareSecureArea()
        let readerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let wrong = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: origin)
        let bytes = try await MdocTestReader.deviceRequest(area: area, readerKey: readerKey, docType: docType, requested: [(namespace, ["family_name"])], sessionTranscript: st, x5chain: [[0x30, 0x01]])
        let docReq = try DeviceRequest.decode(bytes).docRequest(for: docType)!
        do { _ = try await ReaderAuth.verify(docReq, sessionTranscript: st, trust: TestReaderTrust(key: wrong.publicKey)); XCTFail("should reject") } catch is MdocError {}
    }

    func testReaderAuthBoundToSessionTranscript() async throws {
        let area = SoftwareSecureArea()
        let readerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: origin)
        let bytes = try await MdocTestReader.deviceRequest(area: area, readerKey: readerKey, docType: docType, requested: [(namespace, ["family_name"])], sessionTranscript: st, x5chain: [[0x30, 0x01]])
        let docReq = try DeviceRequest.decode(bytes).docRequest(for: docType)!
        let otherSt = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: "https://evil.example")
        do { _ = try await ReaderAuth.verify(docReq, sessionTranscript: otherSt, trust: TestReaderTrust(key: readerKey.publicKey)); XCTFail("should reject") } catch is MdocError {}
    }

    func testOrgIsoMdocDcApiRoundTrip() async throws {
        let area = SoftwareSecureArea()
        let readerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let issuerSigned = try IssuerSigned.decode(try await mdoc(area: area, issuerKey: issuerKey, deviceKey: deviceKey.publicKey))

        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: origin)
        let requestBytes = try await MdocTestReader.deviceRequest(area: area, readerKey: readerKey, docType: docType, requested: [(namespace, ["family_name", "given_name"])], sessionTranscript: st, x5chain: [[0x30, 0x01]])

        let docReq = try DeviceRequest.decode(requestBytes).docRequest(for: docType)!
        let info = try await ReaderAuth.verify(docReq, sessionTranscript: st, trust: TestReaderTrust(key: readerKey.publicKey))
        XCTAssertTrue(info.trusted)
        let disclose = docReq.disclosable(issuerSigned)
        XCTAssertEqual(Set(["family_name", "given_name"]), Set(disclose[namespace] ?? []))

        let deviceResponse = try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docType, disclosed: disclose,
            sessionTranscript: st, deviceSigner: SecureAreaCoseSigner(area: area, key: deviceKey.handle, algorithm: .es256))

        guard case let .array(documents) = field(try CborDecoder.decode(deviceResponse), "documents") else { return XCTFail() }
        let document = documents[0]
        let disclosed = Set(try IssuerSigned.fromCbor(field(document, "issuerSigned")).nameSpaces.first!.1.map { $0.item.elementIdentifier })
        XCTAssertEqual(["family_name", "given_name"], disclosed)

        let deviceSignature = try CoseSign1.fromCbor(field(field(field(document, "deviceSigned"), "deviceAuth"), "deviceSignature"))
        let deviceNsBytes = Cbor.tagged(24, .bytes(try CborEncoder.encode(.map([]))))
        let deviceAuth = Cbor.array([.text("DeviceAuthentication"), st, .text(docType), deviceNsBytes])
        let deviceAuthBytes = try CborEncoder.encode(.tagged(24, .bytes(try CborEncoder.encode(deviceAuth))))
        XCTAssertTrue(deviceSignature.verify(publicKey: deviceKey.publicKey, detachedPayload: deviceAuthBytes))
    }
}
