import Foundation

/// Duplex message channel to an in-person reader for ISO 18013-5 proximity presentation. The host
/// implements it over BLE / NFC / Wi-Fi Aware; the SDK drives the device-retrieval message exchange.
public protocol ProximityTransport: Sendable {
    /// Sends one framed message (e.g. SessionData) to the reader.
    func send(_ message: [UInt8]) async throws

    /// Suspends until the reader delivers the next framed message (e.g. SessionEstablishment).
    func receive() async throws -> [UInt8]

    /// Tears down the transport; idempotent.
    func close() async
}
