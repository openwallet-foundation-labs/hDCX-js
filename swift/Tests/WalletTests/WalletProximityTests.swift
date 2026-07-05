import CborCose
import CredentialStore
import Foundation
import MDoc
import Proximity
import Wallet
import WalletAPI
import WalletTestKit
import XCTest

/// Phase D: ISO 18013-5 proximity presentation over an in-memory transport (BLE/NFC stand-in).
final class WalletProximityTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private actor RecordingLog: TransactionLog {
        private(set) var entries: [TransactionLogEntry] = []
        func record(_ entry: TransactionLogEntry) async throws { entries.append(entry) }
        func list() async throws -> [TransactionLogEntry] { entries }
    }

    /// A one-directional async mailbox (send/receive), used to build a duplex in-memory transport.
    private actor Mailbox {
        private var messages: [[UInt8]] = []
        private var waiters: [CheckedContinuation<[UInt8], Never>] = []
        func send(_ message: [UInt8]) {
            if waiters.isEmpty { messages.append(message) } else { waiters.removeFirst().resume(returning: message) }
        }
        func receive() async -> [UInt8] {
            if !messages.isEmpty { return messages.removeFirst() }
            return await withCheckedContinuation { waiters.append($0) }
        }
    }

    private struct DeviceTransport: ProximityTransport {
        let inbound: Mailbox   // reader → device
        let outbound: Mailbox  // device → reader
        func send(_ message: [UInt8]) async throws { await outbound.send(message) }
        func receive() async throws -> [UInt8] { await inbound.receive() }
        func close() async {}
    }

    private func field(_ c: Cbor, _ key: String) -> Cbor? {
        guard case let .map(entries) = c else { return nil }
        return entries.first(where: { if case let .text(k) = $0.0 { return k == key }; return false })?.1
    }

    func testProximityDeviceRetrievalRoundTrip() async throws {
        let docType = "org.iso.18013.5.1.mDL"
        let namespace = "org.iso.18013.5.1"
        let area = SoftwareSecureArea()
        let storage = InMemoryStorageDriver()
        let issuerKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let deviceKey = try await area.createKey(spec: KeySpec(secureArea: area.id, algorithm: .es256))
        let mdocBytes = try await MdocTestIssuer.issue(
            area: area, issuerKey: issuerKey, deviceKey: deviceKey.publicKey, docType: docType, namespace: namespace,
            elements: [("family_name", .text("Han")), ("given_name", .text("Jongho")), ("age_over_18", .bool(true))],
            x5chain: [[0x30, 0x01]],
            signed: now, validFrom: now, validUntil: now.addingTimeInterval(31_536_000))
        try await DefaultCredentialStore(driver: storage).save(CredentialEnvelope(
            id: CredentialId("mdl-1"), format: .msoMdoc(docType: docType), createdAt: now,
            lifecycle: .issued(policy: CredentialPolicy(), instances: [CredentialInstance(key: deviceKey.handle, payload: mdocBytes)])))

        let log = RecordingLog()
        let wallet = Wallet.create(config: WalletConfig(), ports: WalletPorts(secureAreas: [area], storage: storage, http: NoHttp(), transactionLog: log))

        let toDevice = Mailbox(), toReader = Mailbox()
        let session = wallet.proximity.present(DeviceTransport(inbound: toDevice, outbound: toReader))

        var readerSession: SessionEncryption?
        var transcript: Cbor?
        var terminal: ProximityState?
        for await state in session.states {
            switch state {
            case let .engagementReady(engagement):
                // reader: establish the encrypted session and send a DeviceRequest for family_name + given_name
                let eReader = EphemeralKeyPair()
                let eDeviceKey = try DeviceEngagement.parseEDeviceKey(engagement)
                let t = try ProximitySessionTranscript.build(deviceEngagement: engagement, eReaderKey: eReader.publicKey)
                transcript = t
                let rs = try SessionEncryption.forReader(ephemeral: eReader, devicePublicKey: eDeviceKey,
                                                         sessionTranscriptBytes: try ProximitySessionTranscript.encode(t))
                readerSession = rs
                let deviceRequest = try await MdocReader().buildDeviceRequest(
                    [RequestedDocument(docType: docType, elements: [(namespace, ["family_name", "given_name"])])], sessionTranscript: t)
                await toDevice.send(try SessionMessages.encodeEstablishment(eReaderKey: eReader.publicKey, encryptedDeviceRequest: try rs.encrypt(deviceRequest)))
            case let .requestReceived(request):
                XCTAssertTrue(request.satisfiable, "mDL request satisfiable")
                XCTAssertEqual(CredentialId("mdl-1"), request.documents.first?.candidate)
                session.respond(ProximitySelection.auto(request))
            default:
                break
            }
            if state.isTerminal { terminal = state; break }
        }
        guard case .completed = terminal else { return XCTFail("terminal: \(String(describing: terminal))") }

        // reader: decrypt the DeviceResponse and verify selective disclosure + device signature over the transcript
        let deviceResponse = try readerSession!.decrypt(SessionMessages.decodeData(await toReader.receive()))
        guard case let .array(docs)? = field(try CborDecoder.decode(deviceResponse), "documents") else { return XCTFail("no documents") }
        let document = docs[0]
        let issuerSigned = try IssuerSigned.fromCbor(field(document, "issuerSigned")!)
        let disclosed = Set(issuerSigned.nameSpaces.first(where: { $0.0 == namespace })?.1.map { $0.item.elementIdentifier } ?? [])
        XCTAssertEqual(Set(["family_name", "given_name"]), disclosed, "age_over_18 must be withheld")

        let deviceSigned = field(document, "deviceSigned")!
        let deviceSignature = try CoseSign1.fromCbor(field(field(deviceSigned, "deviceAuth")!, "deviceSignature")!)
        let deviceNsBytes = Cbor.tagged(24, .bytes(try CborEncoder.encode(.map([]))))
        let deviceAuth = Cbor.array([.text("DeviceAuthentication"), transcript!, .text(docType), deviceNsBytes])
        let deviceAuthBytes = try CborEncoder.encode(.tagged(24, .bytes(try CborEncoder.encode(deviceAuth))))
        XCTAssertTrue(deviceSignature.verify(publicKey: deviceKey.publicKey, detachedPayload: deviceAuthBytes), "device signature over proximity transcript")

        let entries = await log.entries
        XCTAssertEqual(.success, entries.first?.status)
    }

    private struct NoHttp: HttpTransport {
        func execute(_ request: HttpRequest) async throws -> HttpResponse { HttpResponse(status: 404, headers: [], body: []) }
    }
}
