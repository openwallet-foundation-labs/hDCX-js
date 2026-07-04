import CborCose
import Foundation
import MDoc
import SdJwt
import WalletAPI
import WalletTestKit
import XCTest
@testable import OpenID4VP

final class MdocDcApiTests: XCTestCase {

    private let docType = "org.iso.18013.5.1.mDL"
    private let namespace = "org.iso.18013.5.1"
    private let origin = "https://verifier.example"

    private struct NoHttp: HttpTransport {
        func execute(_ request: HttpRequest) async throws -> HttpResponse { throw VpError.responseFailed("DC API must not do HTTP") }
    }

    private func field(_ c: Cbor, _ key: String) -> Cbor? {
        guard case let .map(entries) = c else { return nil }
        return entries.first { if case let .text(t) = $0.0 { return t == key }; return false }?.1
    }

    private func heldMdoc() async throws -> (HeldMdoc, EcPublicKey) {
        let area = SoftwareSecureArea()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let bytes = try await MdocTestIssuer.issue(
            area: area, issuerKey: issuerKey, deviceKey: deviceKey.publicKey, docType: docType, namespace: namespace,
            elements: [("family_name", .text("Han")), ("given_name", .text("Jongho")), ("age_over_18", .bool(true))],
            x5chain: [[0x30, 0x01]],
            signed: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validFrom: MdocTestIssuer.isoFormatter.date(from: "2026-01-01T00:00:00Z")!,
            validUntil: MdocTestIssuer.isoFormatter.date(from: "2027-01-01T00:00:00Z")!)
        let held = try HeldMdoc(credentialId: "mdl-1", issuerSigned: try IssuerSigned.decode(bytes),
                                deviceSigner: SecureAreaCoseSigner(area: area, key: deviceKey.handle, algorithm: .es256))
        return (held, deviceKey.publicKey)
    }

    private func dcApiRequest(_ responseMode: String = "dc_api", clientMetadata: String? = nil) -> String {
        let cm = clientMetadata.map { ",\"client_metadata\":\($0)" } ?? ""
        return "{\"response_type\":\"vp_token\",\"response_mode\":\"\(responseMode)\",\"nonce\":\"dcapi-nonce\",\"dcql_query\":{\"credentials\":[{\"id\":\"query_0\",\"format\":\"mso_mdoc\",\"meta\":{\"doctype_value\":\"\(docType)\"},\"claims\":[{\"path\":[\"\(namespace)\",\"family_name\"]},{\"path\":[\"\(namespace)\",\"given_name\"]}]}]}\(cm)}"
    }

    func testDcApiHandoverHasOriginBoundStructure() throws {
        guard case let .array(st) = try Oid4vpSessionTranscript.dcApi(origin: origin, nonce: "nonce-x", verifierJwkThumbprint: nil) else { return XCTFail() }
        XCTAssertEqual(.null, st[0]); XCTAssertEqual(.null, st[1])
        guard case let .array(handover) = st[2] else { return XCTFail() }
        XCTAssertEqual(.text("OpenID4VPDCAPIHandover"), handover[0])
        guard case let .bytes(hash) = handover[1] else { return XCTFail() }
        XCTAssertEqual(32, hash.count)

        guard case let .array(iso) = try MDoc.MdocSessionTranscript.dcApiIsoMdoc(encryptionInfoBase64: "ZW5j", origin: origin),
              case let .array(isoHandover) = iso[2] else { return XCTFail() }
        XCTAssertEqual(.text("dcapi"), isoHandover[0])
    }

    func testResolvesAndPresentsMdocOverDcApi() async throws {
        let (held, deviceKey) = try await heldMdoc()
        let client = Openid4VpClient(http: NoHttp(), clock: { 1_700_000_000 })

        let request = try await client.resolveDcApiRequest(dcApiRequest(), origin: origin)
        XCTAssertEqual(origin, request.origin)
        XCTAssertEqual("dc_api", request.responseMode)

        let matches = client.match(request, held: [held])
        XCTAssertTrue(matches.isSatisfiable())
        let response = try await client.respondDcApi(request: request, matches: matches, selection: PresentationSelection.auto(matches), held: [held])

        guard let vpToken = response["vp_token"], case let .arr(arr)? = vpToken["query_0"], case let .str(presentation) = arr[0] else { return XCTFail("no vp_token") }
        let deviceResponse = try CborDecoder.decode(Base64Url.decode(presentation))
        guard case let .array(documents)? = field(deviceResponse, "documents") else { return XCTFail() }
        let document = documents[0]

        let disclosed = Set(try IssuerSigned.fromCbor(field(document, "issuerSigned")!).nameSpaces.first!.1.map { $0.item.elementIdentifier })
        XCTAssertEqual(["family_name", "given_name"], disclosed)

        // deviceSignature verifies over the DC API handover SessionTranscript (origin-bound)
        let deviceSigned = field(document, "deviceSigned")!
        let deviceSignature = try CoseSign1.fromCbor(field(field(deviceSigned, "deviceAuth")!, "deviceSignature")!)
        let st = try Oid4vpSessionTranscript.dcApi(origin: origin, nonce: "dcapi-nonce", verifierJwkThumbprint: nil)
        let deviceNsBytes = Cbor.tagged(24, .bytes(try CborEncoder.encode(.map([]))))
        let deviceAuth = Cbor.array([.text("DeviceAuthentication"), st, .text(docType), deviceNsBytes])
        let deviceAuthBytes = try CborEncoder.encode(.tagged(24, .bytes(try CborEncoder.encode(deviceAuth))))
        XCTAssertTrue(deviceSignature.verify(publicKey: deviceKey, detachedPayload: deviceAuthBytes))
    }

    func testDcApiJwtReturnsEncryptedResponse() async throws {
        let (held, _) = try await heldMdoc()
        let client = Openid4VpClient(http: NoHttp(), clock: { 1_700_000_000 })
        let area = SoftwareSecureArea()
        let encKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256)).publicKey
        let jwks = "{\"jwks\":{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"enc\",\"x\":\"\(Base64Url.encode(encKey.x))\",\"y\":\"\(Base64Url.encode(encKey.y))\"}]},\"encrypted_response_enc_values_supported\":[\"A128GCM\"]}"
        let request = try await client.resolveDcApiRequest(dcApiRequest("dc_api.jwt", clientMetadata: jwks), origin: origin)

        let matches = client.match(request, held: [held])
        let response = try await client.respondDcApi(request: request, matches: matches, selection: PresentationSelection.auto(matches), held: [held])
        guard case let .str(jwe)? = response["response"] else { return XCTFail("no encrypted response") }
        XCTAssertEqual(5, jwe.split(separator: ".", omittingEmptySubsequences: false).count) // compact JWE (empty CEK for ECDH-ES)
        XCTAssertNil(response["vp_token"])
    }
}
