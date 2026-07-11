package com.hopae.eudi.wallet.android.proximity

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import com.hopae.eudi.wallet.proximity.DeviceEngagement
import com.hopae.eudi.wallet.spi.ProximityTransport
import com.hopae.eudi.wallet.spi.WalletLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.util.UUID
import kotlin.math.min

/**
 * The GATT **client** side of an ISO/IEC 18013-5 BLE mdoc session: scans for [serviceUuid], connects,
 * subscribes, sends framed messages by writing Client2Server, and receives via Server2Client notifications.
 * Used by the reader in peripheral server mode ([Ble.PERIPHERAL_SERVER]) and the holder in central client mode
 * ([Ble.CENTRAL_CLIENT]). [connect] must be called before driving the session.
 */
@SuppressLint("MissingPermission")
class BleGattClientTransport(
    private val context: Context,
    private val serviceUuid: UUID,
    private val uuids: BleModeUuids = Ble.PERIPHERAL_SERVER,
    private val advertisedMethods: List<ByteArray> = emptyList(), // set when a holder uses this in central client mode
    identKey: ByteArray? = null,
    /** Upper bound on a single [receive]; guards against a stalled peer (no infinite wait). */
    private val receiveTimeoutMs: Long = 60_000,
    /** Initial-connection attempts (Android BLE connect is flaky — GATT_ERROR 133 etc.); each re-scans + reconnects. */
    private val connectAttempts: Int = 3,
    /** Backoff between connect attempts. */
    private val retryDelayMs: Long = 400,
    /** Optional trace sink (BLE is stateful + flaky; on-device breadcrumbs help). Null = no logging. */
    private val logger: WalletLogger? = null,
) : ProximityTransport {
    override fun retrievalMethods(): List<ByteArray> = advertisedMethods

    /**
     * ISO 18013-5 §8.3.3.1.1.4: the raw `EDeviceKeyBytes` used to verify the reader's Ident characteristic.
     * Settable after construction because the holder only learns its ephemeral key once the SDK emits the
     * engagement — later than the transport is created. Null ⇒ Ident is not verified (spec-optional).
     */
    @Volatile
    private var identKey: ByteArray? = identKey

    /** Arms Ident verification with the engagement's `EDeviceKeyBytes` (call before the connection completes). */
    fun armIdent(eDeviceKeyBytes: ByteArray) { identKey = eDeviceKeyBytes }

    private val manager = context.getSystemService(BluetoothManager::class.java)
    private var gatt: BluetoothGatt? = null
    private var stateChar: BluetoothGattCharacteristic? = null
    private var c2sChar: BluetoothGattCharacteristic? = null
    private var s2cChar: BluetoothGattCharacteristic? = null
    private var mtu = 23

    private val incoming = Channel<ByteArray>(Channel.UNLIMITED)
    private val assembling = ByteArrayOutputStream()
    @Volatile private var connectedSignal = CompletableDeferred<Boolean>() // fresh per connect attempt
    private var pending: CompletableDeferred<Boolean>? = null
    private var pendingRead: CompletableDeferred<ByteArray>? = null

    /**
     * Connects and subscribes, retrying the flaky initial connection up to [connectAttempts] times (Android BLE
     * often fails the first `connectGatt` with GATT_ERROR 133). Each attempt re-scans and reconnects with fresh
     * per-attempt state; the half-open GATT is torn down between attempts, but the message channel survives.
     * There is no *session* resumption (mdoc keys/counters are bound to the connection) — this only hardens the
     * initial link setup. Coroutine cancellation aborts immediately without retrying.
     */
    suspend fun connect() {
        var lastError: Throwable? = null
        for (attempt in 1..connectAttempts) {
            try {
                connectOnce()
                return
            } catch (e: TimeoutCancellationException) {
                lastError = e // a connect/op timeout is retryable (must precede CancellationException — it is a subtype)
            } catch (e: CancellationException) {
                cleanupGatt() // genuine cancellation (caller closed the scope) — abort, don't retry
                throw e
            } catch (e: Throwable) {
                lastError = e
            }
            logger?.log(WalletLogger.Level.Debug,"BLE client connect attempt $attempt/$connectAttempts failed: ${lastError?.message}")
            cleanupGatt() // drop the half-open GATT + scanner; keep the message channel for the next attempt
            if (attempt < connectAttempts) delay(retryDelayMs)
        }
        stop()
        throw lastError ?: IllegalStateException("BLE connect failed after $connectAttempts attempts")
    }

    private suspend fun connectOnce() {
        connectedSignal = CompletableDeferred() // fresh signal so a stale callback can't complete this attempt
        assembling.reset()
        val device = scan()
        gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
        withTimeout(15_000) { connectedSignal.await() }
        awaitOp { gatt!!.requestMtu(517) }
        awaitOp { gatt!!.discoverServices() }
        val service = gatt!!.getService(serviceUuid) ?: error("peer service $serviceUuid not found")
        stateChar = service.getCharacteristic(uuids.state)
        c2sChar = service.getCharacteristic(uuids.client2Server)
        s2cChar = service.getCharacteristic(uuids.server2Client)
        enableNotify(stateChar!!)
        enableNotify(s2cChar!!)
        verifyIdent(service) // §8.3.3.1.1.4 — no-op unless identKey was supplied
        writeChar(stateChar!!, byteArrayOf(0x01), BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE) // STATE_START
        logger?.log(WalletLogger.Level.Debug,"BLE client connected + subscribed (mtu=$mtu)")
    }

    /** Tears down the half-open GATT + scanner without closing the message channel (so a retry can reuse it). */
    private fun cleanupGatt() {
        if (pendingRead?.isCompleted == false) pendingRead?.completeExceptionally(IllegalStateException("connect attempt aborted"))
        runCatching { gatt?.disconnect() }
        runCatching { gatt?.close() }
        gatt = null
    }

    /**
     * ISO 18013-5 §8.3.3.1.1.4: verify the reader's Ident characteristic (00000008) equals
     * `HKDF(EDeviceKeyBytes, "BLEIdent")`, confirming we connected to the reader that scanned this engagement.
     * Terminates on mismatch. No-op when [identKey] is null or the reader exposes no Ident characteristic.
     */
    private suspend fun verifyIdent(service: android.bluetooth.BluetoothGattService) {
        val key = identKey ?: return
        val identChar = service.getCharacteristic(Ble.IDENT) ?: return
        val read = CompletableDeferred<ByteArray>()
        pendingRead = read
        check(gatt!!.readCharacteristic(identChar)) { "Ident read failed to start" }
        val value = withTimeout(10_000) { read.await() }
        val expected = DeviceEngagement.bleIdent(key)
        if (!value.contentEquals(expected)) throw IllegalStateException("BLE Ident mismatch — wrong mdoc reader")
        logger?.log(WalletLogger.Level.Debug,"BLE Ident verified")
    }

    private suspend fun scan(): BluetoothDevice {
        val found = CompletableDeferred<BluetoothDevice>()
        val scanner = manager.adapter.bluetoothLeScanner ?: error("BLE scanner unavailable (Bluetooth off?)")
        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                if (!found.isCompleted) found.complete(result.device)
            }
            override fun onScanFailed(errorCode: Int) { if (!found.isCompleted) found.completeExceptionally(IllegalStateException("scan failed $errorCode")) }
        }
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(serviceUuid)).build()
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        scanner.startScan(listOf(filter), settings, cb)
        logger?.log(WalletLogger.Level.Debug,"BLE client scanning for $serviceUuid")
        return try {
            withTimeout(20_000) { found.await() }
        } finally {
            runCatching { scanner.stopScan(cb) }
        }
    }

    override suspend fun send(message: ByteArray) {
        val maxChunk = min(512, mtu - 3) - 1
        var offset = 0
        while (offset < message.size) {
            val size = min(maxChunk, message.size - offset)
            val last = offset + size >= message.size
            val chunk = ByteArray(size + 1)
            chunk[0] = if (last) 0x00 else 0x01
            message.copyInto(chunk, 1, offset, offset + size)
            writeChar(c2sChar!!, chunk, BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE)
            offset += size
        }
        logger?.log(WalletLogger.Level.Debug,"BLE client sent ${message.size}B")
    }

    override suspend fun receive(): ByteArray = withTimeout(receiveTimeoutMs) { incoming.receive() }

    override suspend fun close() = stop()

    /** Synchronous teardown, safe to call from a Compose `onDispose`. */
    fun stop() {
        cleanupGatt()
        runCatching { incoming.close() }
    }

    // ---- serial GATT operation plumbing (one op in flight at a time) ----

    private suspend fun awaitOp(start: () -> Boolean) {
        val d = CompletableDeferred<Boolean>()
        pending = d
        check(start()) { "BLE operation failed to start" }
        withTimeout(10_000) { d.await() }
    }

    private suspend fun enableNotify(c: BluetoothGattCharacteristic) {
        gatt!!.setCharacteristicNotification(c, true)
        val cccd = c.getDescriptor(Ble.CCCD)
        val enable = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        awaitOp {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                gatt!!.writeDescriptor(cccd, enable) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION") run { cccd.value = enable; gatt!!.writeDescriptor(cccd) }
            }
        }
    }

    private suspend fun writeChar(c: BluetoothGattCharacteristic, value: ByteArray, writeType: Int) {
        awaitOp {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                gatt!!.writeCharacteristic(c, value, writeType) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION") run { c.writeType = writeType; c.value = value; gatt!!.writeCharacteristic(c) }
            }
        }
    }

    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (g !== gatt) return // a late callback from a prior (retried) connection — ignore
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (!connectedSignal.isCompleted) connectedSignal.complete(true)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                if (!connectedSignal.isCompleted) connectedSignal.completeExceptionally(IllegalStateException("disconnected (status $status)"))
            }
        }

        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
            if (g !== gatt) return
            this@BleGattClientTransport.mtu = mtu
            pending?.complete(status == BluetoothGatt.GATT_SUCCESS)
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) { if (g === gatt) pending?.complete(status == BluetoothGatt.GATT_SUCCESS) }
        override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) { if (g === gatt) pending?.complete(status == BluetoothGatt.GATT_SUCCESS) }
        override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) { if (g === gatt) pending?.complete(status == BluetoothGatt.GATT_SUCCESS) }

        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
            if (g !== gatt) return
            if (status == BluetoothGatt.GATT_SUCCESS) pendingRead?.complete(value)
            else pendingRead?.completeExceptionally(IllegalStateException("Ident read failed (status $status)"))
        }

        // Pre-Tiramisu delivers the read value via the characteristic itself.
        @Deprecated("Deprecated in Java")
        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
            @Suppress("DEPRECATION") onCharacteristicRead(g, c, c.value ?: ByteArray(0), status)
        }

        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray) {
            when (c.uuid) {
                uuids.server2Client -> {
                    if (value.isEmpty()) return
                    assembling.write(value, 1, value.size - 1)
                    if (value[0].toInt() == 0x00) { // last chunk
                        incoming.trySend(assembling.toByteArray())
                        assembling.reset()
                    }
                }
                uuids.state -> if (value.size == 1 && value[0].toInt() == 0x02) { // STATE_END
                    logger?.log(WalletLogger.Level.Debug,"BLE client: peer ended session")
                }
            }
        }

        // Pre-Tiramisu delivers the value via the characteristic itself.
        @Deprecated("Deprecated in Java")
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
            @Suppress("DEPRECATION") onCharacteristicChanged(g, c, c.value ?: ByteArray(0))
        }
    }
}
