import CborCose
import Foundation
import WalletAPI

/// Builds a signed mdoc `DeviceRequest` (with `readerAuth`) for tests — the reader side.
public enum MdocTestReader {

    private static let tag24: UInt64 = 24

    public static func deviceRequest(
        area: any SecureArea,
        readerKey: KeyInfo,
        docType: String,
        requested: [(String, [String])],
        sessionTranscript: Cbor,
        x5chain: [[UInt8]],
        intentToRetain: Bool = false
    ) async throws -> [UInt8] {
        let nameSpaces = Cbor.map(requested.map { ns, elems in
            (.text(ns), .map(elems.map { (.text($0), .bool(intentToRetain)) }))
        })
        let itemsRequest = Cbor.map([(.text("docType"), .text(docType)), (.text("nameSpaces"), nameSpaces)])
        let itemsRequestBytes = Cbor.tagged(tag24, .bytes(try CborEncoder.encode(itemsRequest)))

        let readerAuthentication = Cbor.array([.text("ReaderAuthentication"), sessionTranscript, itemsRequestBytes])
        let readerAuthBytes = try CborEncoder.encode(.tagged(tag24, .bytes(try CborEncoder.encode(readerAuthentication))))
        let readerAuth = try await CoseSign1.sign(
            protected: CoseHeaders.of(algorithm: SigningAlgorithm.es256.coseAlgorithm),
            unprotected: CoseHeaders([(.int(33), .array(x5chain.map { .bytes($0) }))]),
            payload: nil,
            detachedPayload: readerAuthBytes,
            signer: SecureAreaCoseSigner(area: area, key: readerKey.handle, algorithm: .es256)
        )

        let docRequest = Cbor.map([(.text("itemsRequest"), itemsRequestBytes), (.text("readerAuth"), readerAuth.toCbor(tagged: false))])
        let deviceRequest = Cbor.map([(.text("version"), .text("1.0")), (.text("docRequests"), .array([docRequest]))])
        return try CborEncoder.encode(deviceRequest)
    }
}
