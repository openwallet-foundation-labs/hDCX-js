import CoreBluetooth
import Foundation

/// ISO/IEC 18013-5 §8.3.3.1.1 BLE constants and framing shared by the peripheral (holder) and central
/// (reader) transports — the iOS counterpart of android `Ble.kt`. Only the fixed mdoc **characteristic**
/// UUIDs live here; the GATT **service** UUID is generated per session by the holder and carried in the
/// QR DeviceEngagement.
enum Ble {
    /// mdoc characteristic UUID template: `0000000{n}-a123-48ce-896b-4c76973373e6` (single-digit n, 1…8).
    static func mdocUuid(_ n: Int) -> CBUUID { CBUUID(string: "0000000\(n)-a123-48ce-896b-4c76973373e6") }

    /// One BLE mode's three data characteristics.
    struct ModeUuids {
        let state: CBUUID
        let client2Server: CBUUID
        let server2Client: CBUUID
    }

    /// mdoc **peripheral server mode** (holder = peripheral): state=1, client2Server=2, server2Client=3.
    static let peripheralServer = ModeUuids(state: mdocUuid(1), client2Server: mdocUuid(2), server2Client: mdocUuid(3))
    /// mdoc **central client mode** (holder = central): state=5, client2Server=6, server2Client=7.
    static let centralClient = ModeUuids(state: mdocUuid(5), client2Server: mdocUuid(6), server2Client: mdocUuid(7))
    /// Ident characteristic (§8.3.3.1.1.4) — read-only, present only in the reader's central-client-mode service.
    static let ident = mdocUuid(8)

    // State characteristic bytes.
    static let stateStart: UInt8 = 0x01 // client → server: begin session (also stops the server advertising)
    static let stateEnd: UInt8 = 0x02   // server → client: end session

    // Data-chunk prefix bytes (client2Server / server2Client).
    static let chunkMore: UInt8 = 0x01 // more chunks follow
    static let chunkLast: UInt8 = 0x00 // final chunk of the message

    /// Inter-chunk gap for paced Write-Without-Response, so each chunk lands in its own connection event and
    /// the receiver peripheral doesn't drop a burst (matches the Android client's pacing).
    static let chunkPacing: TimeInterval = 0.04

    /// Splits a whole framed message into chunks, each prefixed with `chunkMore`/`chunkLast`. `payloadSize`
    /// is the usable bytes per chunk (the negotiated MTU budget minus the 1-byte prefix). An empty message
    /// still yields one final (empty) chunk.
    static func chunk(_ message: [UInt8], payloadSize: Int) -> [[UInt8]] {
        let size = max(payloadSize, 1)
        var chunks: [[UInt8]] = []
        var i = 0
        repeat {
            let end = Swift.min(i + size, message.count)
            let more = end < message.count
            chunks.append([more ? chunkMore : chunkLast] + Array(message[i..<end]))
            i = end
        } while i < message.count
        return chunks
    }

    /// 16-byte big-endian encoding of a UUID, as carried in the DeviceEngagement retrieval method.
    static func uuidBytes(_ uuid: UUID) -> [UInt8] {
        withUnsafeBytes(of: uuid.uuid) { Array($0) }
    }
}
