package com.hopae.eudi.wallet.android.proximity

import java.nio.ByteBuffer
import java.util.UUID

/** The ISO/IEC 18013-5 §8.3.3.1.1 mdoc BLE characteristic UUIDs for one mode. */
class BleModeUuids(val state: UUID, val client2Server: UUID, val server2Client: UUID)

/**
 * Shared BLE constants. The GATT server/client transports below are role-agnostic — the mode picks the
 * characteristic set and which side advertises vs scans:
 *  - **peripheral server mode**: mdoc(holder)=GATT server (chars 1/2/3), reader=GATT client.
 *  - **central client mode**: mdoc(holder)=GATT client (chars 5/6/7), reader=GATT server.
 */
object Ble {
    /** Client Characteristic Configuration Descriptor (enables notifications). */
    val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    /** mdoc peripheral server mode: State / Client2Server / Server2Client = 00000001/2/3. */
    val PERIPHERAL_SERVER = BleModeUuids(mdocUuid(1), mdocUuid(2), mdocUuid(3))

    /** mdoc central client mode: State / Client2Server / Server2Client = 00000005/6/7. */
    val CENTRAL_CLIENT = BleModeUuids(mdocUuid(5), mdocUuid(6), mdocUuid(7))

    /** ISO 18013-5 §8.3.3.1.1.4 Ident characteristic (00000008, Read) — only in the reader's service (central client mode). */
    val IDENT: UUID = mdocUuid(8)

    private fun mdocUuid(n: Int): UUID = UUID.fromString("0000000$n-a123-48ce-896b-4c76973373e6")

    /** 16-byte big-endian encoding of [uuid] (as the DeviceEngagement carries it). */
    fun uuidToBytes(uuid: UUID): ByteArray =
        ByteBuffer.allocate(16).putLong(uuid.mostSignificantBits).putLong(uuid.leastSignificantBits).array()

    fun bytesToUuid(bytes: ByteArray): UUID = ByteBuffer.wrap(bytes).let { UUID(it.long, it.long) }
}
