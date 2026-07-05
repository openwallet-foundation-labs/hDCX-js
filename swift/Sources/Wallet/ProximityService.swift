import CborCose
import CredentialStore
import Foundation
import MDoc
import Proximity
import SdJwt
import TransactionLog
import Trust
import WalletAPI

/// ISO 18013-5 proximity presentation. Generates device engagement, establishes the
/// encrypted session over the app-provided `ProximityTransport`, and replies with a device-signed DeviceResponse.
public struct ProximityService {
    let store: DefaultCredentialStore
    let txlog: TransactionLog
    let secureAreas: [any SecureArea]
    /// Verifies reader authentication against configured reader anchors; nil = no anchors, readers stay untrusted.
    let readerTrust: (any MdocReaderTrust)?

    /// Starts a proximity session over `transport`: engage → session → reader request → consent → reply.
    public func present(_ transport: any ProximityTransport) -> ProximitySession {
        let session = ProximitySession { s in
            s.emit(.generatingEngagement)
            let eDevice = EphemeralKeyPair()
            let engagement = try DeviceEngagement.qr(eDeviceKey: eDevice.publicKey)
            // engagementReady stays the current state while blocked on receive() — the reader-waiting state.
            s.emit(.engagementReady(deviceEngagement: engagement))

            let establishment = try await catchingProximity { try SessionMessages.decodeEstablishment(try await transport.receive()) }
            let transcript = try ProximitySessionTranscript.build(deviceEngagement: engagement, eReaderKey: establishment.eReaderKey)
            let enc = try SessionEncryption.forMdoc(
                ephemeral: eDevice, readerPublicKey: establishment.eReaderKey,
                sessionTranscriptBytes: try ProximitySessionTranscript.encode(transcript))
            let deviceRequest = try await catchingProximity { try DeviceRequest.decode(try enc.decrypt(establishment.encryptedDeviceRequest)) }

            let request = try await buildRequest(deviceRequest, transcript, enc)
            switch await s.awaitDecision(request) {
            case .none:
                try await recordDeclined(request)
                await transport.close()
                s.emit(.declined)
            case let .some(selection):
                s.emit(.submitting)
                let deviceResponse = try await buildDeviceResponse(deviceRequest, transcript, selection)
                try await transport.send(try SessionMessages.encodeData(try enc.encrypt(deviceResponse)))
                try await recordSuccess(request, selection)
                await transport.close()
                s.emit(.completed)
            }
        }
        session.launch()
        return session
    }

    private func buildRequest(_ deviceRequest: DeviceRequest, _ transcript: Cbor, _ session: SessionEncryption) async throws -> ProximityRequest {
        var documents: [RequestedDocumentView] = []
        for dr in deviceRequest.docRequests {
            var requestedElements: [String: [String]] = [:]
            for (ns, elems) in dr.requested { requestedElements[ns] = elems.map { $0.identifier } }
            documents.append(RequestedDocumentView(docType: dr.docType, requestedElements: requestedElements, candidate: try await findMdoc(dr.docType)))
        }
        let reader = await verifyReader(deviceRequest, transcript)
        return ProximityRequest(documents: documents, satisfiable: documents.allSatisfy { $0.candidate != nil },
                                reader: reader, deviceRequest: deviceRequest, transcript: transcript, session: session)
    }

    /// Verifies reader authentication (ISO 18013-5 §9.1.4) against the configured reader anchors.
    private func verifyReader(_ deviceRequest: DeviceRequest, _ transcript: Cbor) async -> ProximityReaderInfo {
        let untrusted = ProximityReaderInfo(trusted: false, commonName: nil, certificateChainDer: [])
        guard let trust = readerTrust,
              let docRequest = deviceRequest.docRequests.first(where: { $0.readerAuth != nil }) else { return untrusted }
        do {
            let info = try await ReaderAuth.verify(docRequest, sessionTranscript: transcript, trust: trust)
            let cn = info.certificateChain?.first.flatMap { X509Support.commonName(fromDer: $0) }
            return ProximityReaderInfo(trusted: info.trusted, commonName: cn, certificateChainDer: info.certificateChain ?? [])
        } catch {
            return untrusted
        }
    }

    private func findMdoc(_ docType: String) async throws -> CredentialId? {
        try await store.list().first(where: { envelope in
            if case .issued = envelope.lifecycle, case let .msoMdoc(dt) = envelope.format, dt == docType { return true }
            return false
        })?.id
    }

    /// Builds the DeviceResponse for the first requested document (single-document retrieval; multi-doc is a follow-up).
    private func buildDeviceResponse(_ deviceRequest: DeviceRequest, _ transcript: Cbor, _ selection: ProximitySelection) async throws -> [UInt8] {
        guard let docRequest = deviceRequest.docRequests.first(where: { selection.chosen[$0.docType] != nil }) else {
            throw ProximityError.noMatchingCredential("no chosen document")
        }
        let credentialId = selection.chosen[docRequest.docType]!
        guard let consumed = try await store.consumeInstance(credentialId) else {
            throw ProximityError.noMatchingCredential(docRequest.docType)
        }
        let area = secureAreas.first(where: { $0.id == consumed.instance.key.secureArea }) ?? secureAreas[0]
        let issuerSigned = try IssuerSigned.decode(consumed.instance.payload)
        return try await MdocPresenter.deviceResponse(
            issuerSigned: issuerSigned, docType: docRequest.docType, disclosed: docRequest.disclosable(issuerSigned),
            sessionTranscript: transcript, deviceSigner: SecureAreaCoseSigner(area: area, key: consumed.instance.key, algorithm: .es256))
    }

    private func recordSuccess(_ request: ProximityRequest, _ selection: ProximitySelection) async throws {
        let documents = request.documents.filter { selection.chosen[$0.docType] != nil }.map { doc in
            LoggedDocument(format: "mso_mdoc", type: doc.docType, queryId: nil,
                           claims: doc.requestedElements.flatMap { ns, els in els.map { LoggedClaim(path: [ns, $0]) } })
        }
        await txlog.recordPresentation(relyingParty: proximityReader(request), documents: documents, status: .success)
    }

    private func recordDeclined(_ request: ProximityRequest) async throws {
        await txlog.recordPresentation(relyingParty: proximityReader(request), documents: [], status: .incomplete)
    }

    /// The in-person reader, from verified reader authentication (unauthenticated readers stay untrusted).
    private func proximityReader(_ request: ProximityRequest) -> RelyingParty {
        RelyingParty(id: request.reader.commonName ?? "proximity-reader", name: request.reader.commonName,
                     trusted: request.reader.trusted, certificateChainDer: request.reader.certificateChainDer)
    }

    private func catchingProximity<T>(_ block: () async throws -> T) async throws -> T {
        do {
            return try await block()
        } catch let e as Proximity.ProximityError {
            throw ProximityError.sessionFailed(e.description)
        }
    }
}
