import CborCose
import Foundation
import WalletAPI
import WalletTestKit
import XCTest
@testable import MDoc

/// The dual-role loop: reader builds a DeviceRequest, wallet responds, reader verifies the response.
final class MdocReaderTests: XCTestCase {

    private let docType = "org.iso.18013.5.1.mDL"
    private let namespace = "org.iso.18013.5.1"
    private let readerX5c: [[UInt8]] = [[0x30, 0x01]]
    private let verifyTime = MdocTestIssuer.isoFormatter.date(from: "2026-06-01T00:00:00Z")!

    private struct TestIssuerTrust: MdocIssuerTrust {
        let key: EcPublicKey
        func issuerKey(x5chain: [[UInt8]]) async throws -> EcPublicKey { key }
    }

    private struct Party {
        let area = SoftwareSecureArea()
        let reader: KeyInfo, issuer: KeyInfo, device: KeyInfo
        init() async throws {
            reader = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
            issuer = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
            device = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        }
    }

    private func mdoc(_ p: Party) async throws -> [UInt8] {
        try await MdocTestIssuer.issue(
            area: p.area, issuerKey: p.issuer, deviceKey: p.device.publicKey, docType: docType, namespace: namespace,
            elements: [("family_name", .text("Han")), ("given_name", .text("Jongho")), ("age_over_18", .bool(true))],
            x5chain: [[0x30, 0x02]],
            signed: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validFrom: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validUntil: MdocTestIssuer.isoFormatter.date(from: "2027-01-01T00:00:00Z")!)
    }

    private func readerFacade(_ p: Party) -> MdocReader {
        MdocReader(readerAuth: ReaderAuthSigner(signer: SecureAreaCoseSigner(area: p.area, key: p.reader.handle, algorithm: .es256), x5chain: readerX5c),
                   issuerTrust: TestIssuerTrust(key: p.issuer.publicKey), now: { [verifyTime] in verifyTime })
    }

    /// ISO 18013-5 §9.1.3.5: a key-agreement DeviceKey authenticates with `deviceMac` instead of a signature.
    /// The EMacKey is HKDF'd from a DeviceKey/EReaderKey ECDH secret both sides can compute; here it stands in
    /// as an opaque key so this test stays independent of the Proximity module's derivation.
    func testDeviceMacRoundTrip() async throws {
        let p = try await Party()
        let issuerSigned = try IssuerSigned.decode(try await mdoc(p))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: "https://reader.example")
        let emacKey = (0..<32).map { UInt8(($0 * 7 + 1) & 0xff) }

        let deviceResponse = try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docType, disclosed: [namespace: ["family_name"]],
            sessionTranscript: st, deviceAuth: .mac(emacKey: emacKey))

        // The wire carries deviceMac, not deviceSignature.
        let doc = try DeviceResponse.decode(deviceResponse).documents.first!
        XCTAssertNotNil(doc.deviceMac)
        XCTAssertNil(doc.deviceSignature)

        let verified = try await readerFacade(p).verifyDeviceResponse(deviceResponse, sessionTranscript: st) { _ in emacKey }.first!
        XCTAssertTrue(verified.deviceAuthenticated)
        XCTAssertEqual(.text("Han"), verified.elements[namespace]?["family_name"])
    }

    /// A reader that cannot derive the EMacKey cannot verify a MAC-authenticated response.
    func testDeviceMacWithoutEmacKeyRejected() async throws {
        let p = try await Party()
        let issuerSigned = try IssuerSigned.decode(try await mdoc(p))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: "https://reader.example")
        let deviceResponse = try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docType, disclosed: [namespace: ["family_name"]],
            sessionTranscript: st, deviceAuth: .mac(emacKey: [UInt8](repeating: 3, count: 32)))

        do {
            _ = try await readerFacade(p).verifyDeviceResponse(deviceResponse, sessionTranscript: st)
            XCTFail("deviceMac without an EMacKey must not verify")
        } catch is MdocError {}
    }

    /// A MAC keyed with the wrong EMacKey must not verify — the holder binding fails.
    func testDeviceMacWithWrongKeyRejected() async throws {
        let p = try await Party()
        let issuerSigned = try IssuerSigned.decode(try await mdoc(p))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: "https://reader.example")
        let deviceResponse = try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docType, disclosed: [namespace: ["family_name"]],
            sessionTranscript: st, deviceAuth: .mac(emacKey: [UInt8](repeating: 3, count: 32)))

        do {
            _ = try await readerFacade(p).verifyDeviceResponse(deviceResponse, sessionTranscript: st) { _ in [UInt8](repeating: 9, count: 32) }
            XCTFail("a wrong EMacKey must not verify")
        } catch is MdocError {}
    }

    func testReaderWalletRoundTrip() async throws {
        let p = try await Party()
        let issuerSigned = try IssuerSigned.decode(try await mdoc(p))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: "https://reader.example")
        let reader = readerFacade(p)

        // 1. reader builds the DeviceRequest
        let deviceRequest = try await reader.buildDeviceRequest([RequestedDocument(docType: docType, elements: [(namespace, ["family_name", "given_name"])])], sessionTranscript: st)

        // 2. wallet parses, authenticates the reader, discloses, builds the DeviceResponse
        let docReq = try DeviceRequest.decode(deviceRequest).docRequest(for: docType)!
        struct RT: MdocReaderTrust { let k: EcPublicKey; func readerKey(x5chain: [[UInt8]]) async throws -> EcPublicKey { k } }
        let readerInfo = try await ReaderAuth.verify(docReq, sessionTranscript: st, trust: RT(k: p.reader.publicKey))
        XCTAssertTrue(readerInfo.trusted)
        let deviceResponse = try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docType, disclosed: docReq.disclosable(issuerSigned),
            sessionTranscript: st, deviceSigner: SecureAreaCoseSigner(area: p.area, key: p.device.handle, algorithm: .es256))

        // 3. reader verifies the DeviceResponse (issuer trust + holder binding)
        let verified = try await reader.verifyDeviceResponse(deviceResponse, sessionTranscript: st).first!
        XCTAssertEqual(docType, verified.docType)
        XCTAssertTrue(verified.deviceAuthenticated)
        XCTAssertEqual(.text("Han"), verified.elements[namespace]?["family_name"])
        XCTAssertEqual(.text("Jongho"), verified.elements[namespace]?["given_name"])
        XCTAssertNil(verified.elements[namespace]?["age_over_18"]) // not disclosed
    }

    /// §8.3.2.1.2.3 Table 8: a non-zero DeviceResponse status (mdoc returned no documents) is surfaced.
    func testNonZeroDeviceResponseStatusRejected() async throws {
        let response = try CborEncoder.encode(.map([(.text("version"), .text("1.0")), (.text("status"), .uint(10))]))
        // No issuer trust needed — the status gate fires before the trust check.
        do {
            _ = try await MdocReader().verifyDeviceResponse(response, sessionTranscript: .null)
            XCTFail("should reject a non-zero status")
        } catch let e as MdocError {
            XCTAssertTrue(e.description.contains("status 10"), "message names the status: \(e.description)")
        }
    }

    func testDeviceResponseFromWrongSessionRejected() async throws {
        let p = try await Party()
        let issuerSigned = try IssuerSigned.decode(try await mdoc(p))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: "https://reader.example")
        let deviceResponse = try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docType, disclosed: [namespace: ["family_name"]],
            sessionTranscript: st, deviceSigner: SecureAreaCoseSigner(area: p.area, key: p.device.handle, algorithm: .es256))
        let otherSt = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: "https://evil.example")
        do { _ = try await readerFacade(p).verifyDeviceResponse(deviceResponse, sessionTranscript: otherSt); XCTFail("should reject") } catch is MdocError {}
    }

    func testUntrustedIssuerRejected() async throws {
        let p = try await Party()
        let rogue = try await p.area.createKey(spec: KeySpec(secureArea: p.area.id, algorithm: .es256))
        let issuerSigned = try IssuerSigned.decode(try await mdoc(p))
        let st = try MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: "https://reader.example")
        let deviceResponse = try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docType, disclosed: [namespace: ["family_name"]],
            sessionTranscript: st, deviceSigner: SecureAreaCoseSigner(area: p.area, key: p.device.handle, algorithm: .es256))
        let reader = MdocReader(issuerTrust: TestIssuerTrust(key: rogue.publicKey), now: { [verifyTime] in verifyTime })
        do { _ = try await reader.verifyDeviceResponse(deviceResponse, sessionTranscript: st); XCTFail("should reject") } catch is MdocError {}
    }
}
