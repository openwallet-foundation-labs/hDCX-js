import CborCose
import MDoc
import Proximity
import WalletAPI

/// The reader/verifier side of ISO 18013-5 proximity: drives a `ProximityTransport` to request documents
/// from a wallet and verify the returned `DeviceResponse`. Symmetric to `ProximityService.present`; the
/// host supplies the transport (BLE central) and the scanned QR `DeviceEngagement`.
public struct ProximityReaderService: Sendable {
    private let issuerTrust: (any MdocIssuerTrust)?
    private let readerAuth: ReaderAuthSigner?

    init(issuerTrust: (any MdocIssuerTrust)?, readerAuth: ReaderAuthSigner? = nil) {
        self.issuerTrust = issuerTrust
        self.readerAuth = readerAuth
    }

    /// Requests `documents` from a wallet over `transport` (the reader is the BLE central) and verifies the
    /// response against `engagement` (the scanned QR). Fully verified when issuer trust + holder binding
    /// check out (`deviceAuthenticated == true`); otherwise the disclosed elements are still returned, unverified.
    /// - Parameter handoverNdef: the NFC Handover Select message when the engagement was delivered by NFC
    ///   handover (else nil = QR); it's bound into the SessionTranscript so both sides agree.
    /// - Parameter handoverRequestNdef: the NFC Handover Request the reader sent for **negotiated** handover
    ///   (§8.2.2.1); binds the SessionTranscript as `[Hs, Hr]` (§9.1.5.1). Nil = static handover (`[Hs, null]`).
    ///   The host performs the NFC exchange and supplies both messages; the SDK only binds them.
    public func read(
        transport: any ProximityTransport,
        engagement: [UInt8],
        documents: [RequestedDocument],
        handoverNdef: [UInt8]? = nil,
        handoverRequestNdef: [UInt8]? = nil
    ) async throws -> [VerifiedDocument] {
        try await exchange(transport, engagement, documents, handoverNdef, handoverRequestNdef)
    }

    private func exchange(
        _ transport: any ProximityTransport,
        _ engagement: [UInt8],
        _ documents: [RequestedDocument],
        _ handoverNdef: [UInt8]?,
        _ handoverRequestNdef: [UInt8]?
    ) async throws -> [VerifiedDocument] {
        // Session setup runs before the session begins: if it throws there is nothing to terminate.
        let eDeviceKey = try DeviceEngagement.parseEDeviceKey(engagement)
        // §9.1.5.2: the reader's ephemeral key must be on the same curve as the mdoc's EDeviceKey.
        let eReader = EphemeralKeyPair(curve: eDeviceKey.curve)
        let handover: Cbor = handoverNdef != nil ? ProximitySessionTranscript.nfcHandover(handoverNdef!, handoverRequestMessage: handoverRequestNdef) : .null
        let transcript = try ProximitySessionTranscript.build(deviceEngagement: engagement, eReaderKey: eReader.publicKey, handover: handover)
        let transcriptBytes = try ProximitySessionTranscript.encode(transcript)
        let enc = try SessionEncryption.forReader(ephemeral: eReader, devicePublicKey: eDeviceKey, sessionTranscriptBytes: transcriptBytes)
        let reader = MdocReader(readerAuth: readerAuth, issuerTrust: issuerTrust)

        let deviceRequest = try await reader.buildDeviceRequest(documents, sessionTranscript: transcript)
        try await transport.send(try SessionMessages.encodeEstablishment(
            eReaderKey: eReader.publicKey, encryptedDeviceRequest: try enc.encrypt(deviceRequest)))

        return try await withTermination(transport, enc) {
            // ISO 18013-5 Table 20: the mdoc may answer with an error/termination status instead of data.
            let frame = try SessionMessages.decodeSessionData(try await transport.receive())
            guard let encryptedResponse = frame.data else {
                throw ProximityError.sessionFailed("mdoc returned status \(String(describing: frame.status)) without a DeviceResponse")
            }
            let deviceResponse = try enc.decrypt(encryptedResponse)

            // §8.3.2.1.2.3: a non-zero DeviceResponse status means no documents were returned, with a reason.
            // Surface it here — otherwise the verify/unverified fallback reports an empty list silently.
            let responseStatus = try DeviceResponse.decode(deviceResponse).status
            guard responseStatus == 0 else { throw ProximityError.sessionFailed("mdoc returned DeviceResponse status \(responseStatus)") }
            return try await verify(reader, deviceResponse, transcript, eReader, transcriptBytes)
        }
    }

    /// §9.1.1.4: run `body`, then always signal termination, destroy the session keys, and close.
    private func withTermination(
        _ transport: any ProximityTransport, _ enc: SessionEncryption,
        _ body: () async throws -> [VerifiedDocument]
    ) async throws -> [VerifiedDocument] {
        do {
            let result = try await body()
            await terminate(transport, enc)
            return result
        } catch {
            await terminate(transport, enc)
            throw error
        }
    }

    private func terminate(_ transport: any ProximityTransport, _ enc: SessionEncryption) async {
        if let frame = try? SessionMessages.encodeStatus(SessionMessages.Status.sessionTermination) {
            try? await transport.send(frame)
        }
        enc.destroy()
        await transport.close()
    }

    private func verify(
        _ reader: MdocReader, _ deviceResponse: [UInt8], _ transcript: Cbor,
        _ eReader: EphemeralKeyPair, _ transcriptBytes: [UInt8]
    ) async throws -> [VerifiedDocument] {
        do {
            if issuerTrust != nil {
                // Verify deviceSignature or deviceMac (EMacKey via the reader's EReaderKey ↔ mdoc DeviceKey ECDH).
                return try await reader.verifyDeviceResponse(deviceResponse, sessionTranscript: transcript) { deviceKey in
                    try SessionEncryption.deriveEMacKey(ephemeral: eReader, deviceKey: deviceKey, sessionTranscriptBytes: transcriptBytes)
                }
            }
            return try parseUnverified(deviceResponse)
        } catch {
            // Untrusted issuer or holder-binding failure — still surface what the wallet disclosed, unverified.
            return try parseUnverified(deviceResponse)
        }
    }

    private func parseUnverified(_ deviceResponse: [UInt8]) throws -> [VerifiedDocument] {
        try DeviceResponse.decode(deviceResponse).documents.map { doc in
            var elements: [String: [String: Cbor]] = [:]
            for (ns, items) in doc.issuerSigned.nameSpaces {
                var m: [String: Cbor] = [:]
                for e in items { m[e.item.elementIdentifier] = e.item.elementValue }
                elements[ns] = m
            }
            return VerifiedDocument(docType: doc.docType, elements: elements, deviceAuthenticated: false)
        }
    }
}
