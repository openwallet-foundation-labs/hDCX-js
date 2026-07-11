package com.hopae.eudi.demo.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import com.hopae.eudi.demo.LogStore
import com.hopae.eudi.wallet.proximity.DeviceEngagement
import com.hopae.eudi.wallet.spi.NfcCarrier
import com.hopae.eudi.wallet.spi.ProximityTransport
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.util.UUID
import kotlin.math.min

/**
 * The GATT **server** side of an ISO/IEC 18013-5 BLE mdoc session: advertises [serviceUuid], receives framed
 * messages on Client2Server, and sends framed messages via Server2Client notifications. Used by the holder in
 * peripheral server mode ([Ble.PERIPHERAL_SERVER]) and by the reader in central client mode ([Ble.CENTRAL_CLIENT]).
 */
@SuppressLint("MissingPermission")
class BleGattServerTransport(
    private val context: Context,
    private val serviceUuid: UUID,
    private val uuids: BleModeUuids = Ble.PERIPHERAL_SERVER,
    private val advertisedMethods: List<ByteArray> = emptyList(),
    /** ISO 18013-5 §8.3.3.1.1.4: when set (raw `EDeviceKeyBytes`), expose the Ident characteristic — reader in central client mode. */
    private val identKey: ByteArray? = null,
    /** Upper bound on a single [receive] and on waiting for the peer in [send]; guards against a stalled peer. */
    private val receiveTimeoutMs: Long = 60_000,
) : ProximityTransport {
    private val manager = context.getSystemService(BluetoothManager::class.java)

    private var gattServer: BluetoothGattServer? = null
    private var stateChar: BluetoothGattCharacteristic? = null
    private var s2cChar: BluetoothGattCharacteristic? = null
    private var device: BluetoothDevice? = null
    private var mtu = 23

    private val incoming = Channel<ByteArray>(Channel.UNLIMITED)
    private val assembling = ByteArrayOutputStream()
    private var notifySent: CompletableDeferred<Boolean>? = null
    private val connected = CompletableDeferred<Unit>() // a peer subscribed + wrote STATE_START

    /** Starts the GATT server + advertising. Call before driving the session. */
    fun start() {
        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        stateChar = char(uuids.state, BluetoothGattCharacteristic.PROPERTY_NOTIFY or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE)
        val c2s = char(uuids.client2Server, BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE)
        s2cChar = char(uuids.server2Client, BluetoothGattCharacteristic.PROPERTY_NOTIFY)
        service.addCharacteristic(stateChar)
        service.addCharacteristic(c2s)
        service.addCharacteristic(s2cChar)
        // §8.3.3.1.1.4: the reader (central client mode) exposes Ident so the mdoc can confirm the connection.
        if (identKey != null) service.addCharacteristic(char(Ble.IDENT, BluetoothGattCharacteristic.PROPERTY_READ))

        gattServer = manager.openGattServer(context, callback)
        gattServer!!.addService(service)

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true).setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM).build()
        val data = AdvertiseData.Builder().setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(serviceUuid)).build()
        manager.adapter.bluetoothLeAdvertiser?.startAdvertising(settings, data, advertiseCallback)
        LogStore.log("BLE server advertising · service=$serviceUuid")
    }

    override fun retrievalMethods(): List<ByteArray> = advertisedMethods

    override fun nfcCarrier(): NfcCarrier = NfcCarrier(Ble.uuidToBytes(serviceUuid), peripheralServerMode = uuids.state == Ble.PERIPHERAL_SERVER.state)

    override suspend fun receive(): ByteArray = withTimeout(receiveTimeoutMs) { incoming.receive() }

    override suspend fun send(message: ByteArray) {
        // in central client mode the reader sends first, before the holder has connected — bounded so we don't wait forever
        withTimeout(receiveTimeoutMs) { connected.await() }
        val maxChunk = min(512, mtu - 3) - 1 // room for the 0x00/0x01 prefix
        var offset = 0
        while (offset < message.size) {
            val size = min(maxChunk, message.size - offset)
            val last = offset + size >= message.size
            val chunk = ByteArray(size + 1)
            chunk[0] = if (last) 0x00 else 0x01
            message.copyInto(chunk, 1, offset, offset + size)
            notify(s2cChar!!, chunk)
            offset += size
        }
        LogStore.log("BLE server sent ${message.size}B")
    }

    override suspend fun close() = stop()

    /** Synchronous teardown, safe to call from a Compose `onDispose`. */
    fun stop() {
        if (!connected.isCompleted) connected.completeExceptionally(IllegalStateException("transport closed"))
        runCatching { if (device != null) stateChar?.let { notifyNoWait(it, byteArrayOf(0x02)) } } // STATE_END
        runCatching { manager.adapter.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
        runCatching { gattServer?.close() }
        gattServer = null
        runCatching { incoming.close() }
    }

    private suspend fun notify(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        val signal = CompletableDeferred<Boolean>()
        notifySent = signal
        notifyNoWait(characteristic, value)
        withTimeout(10_000) { signal.await() } // bounded: don't hang if onNotificationSent never fires
    }

    private fun notifyNoWait(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        val dev = device ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gattServer?.notifyCharacteristicChanged(dev, characteristic, false, value)
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = value
            @Suppress("DEPRECATION")
            gattServer?.notifyCharacteristicChanged(dev, characteristic, false)
        }
    }

    private fun char(uuid: UUID, properties: Int): BluetoothGattCharacteristic {
        val c = BluetoothGattCharacteristic(uuid, properties, BluetoothGattCharacteristic.PERMISSION_WRITE or BluetoothGattCharacteristic.PERMISSION_READ)
        if (properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0) {
            c.addDescriptor(BluetoothGattDescriptor(Ble.CCCD, BluetoothGattDescriptor.PERMISSION_WRITE))
        }
        return c
    }

    private val callback = object : BluetoothGattServerCallback() {
        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            this@BleGattServerTransport.mtu = mtu
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray,
        ) {
            if (responseNeeded) gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            when (characteristic.uuid) {
                uuids.state -> if (value.size == 1 && value[0].toInt() == 0x01) { // STATE_START
                    this@BleGattServerTransport.device = device
                    if (!connected.isCompleted) connected.complete(Unit)
                    runCatching { manager.adapter.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
                    LogStore.log("BLE server: peer connected")
                }
                uuids.client2Server -> {
                    if (value.isEmpty()) return
                    assembling.write(value, 1, value.size - 1)
                    if (value[0].toInt() == 0x00) { // last chunk
                        val message = assembling.toByteArray()
                        assembling.reset()
                        incoming.trySend(message)
                    }
                }
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic,
        ) {
            // §8.3.3.1.1.4: answer an Ident read with HKDF(EDeviceKeyBytes, "BLEIdent"); reject other reads.
            if (characteristic.uuid == Ble.IDENT && identKey != null) {
                val ident = DeviceEngagement.bleIdent(identKey)
                val slice = if (offset < ident.size) ident.copyOfRange(offset, ident.size) else ByteArray(0)
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
                LogStore.log("BLE Ident served (§8.3.3.1.1.4)")
            } else {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, 0, null)
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray,
        ) {
            if (responseNeeded) gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            notifySent?.complete(status == BluetoothStatusCodes.SUCCESS || status == BluetoothGatt.GATT_SUCCESS)
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) { LogStore.log("❌ BLE advertise failed: $errorCode") }
    }
}
