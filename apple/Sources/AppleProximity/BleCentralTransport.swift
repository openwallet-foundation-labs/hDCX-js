import CoreBluetooth
import Foundation
import Proximity
import WalletAPI

/// ISO/IEC 18013-5 BLE **GATT central** transport over CoreBluetooth. Used in two roles (identical
/// plumbing; only the UUIDs / advertised engagement / Ident differ):
/// - **reader, peripheral-server mode** — scans for and connects to the holder's advertised service.
/// - **holder, central-client mode** — advertises its central-client UUID in the QR, then scans for and
///   connects to the reader's service, verifying the reader's **Ident** (§8.3.3.1.1.4) matches its EDeviceKey.
///
/// Connection is lazy: the first `send`/`receive` scans + connects. All mutable state is confined to the
/// manager's serial `queue`.
public final class BleCentralTransport: NSObject, ProximityTransport, @unchecked Sendable {
    private let serviceUuid: CBUUID
    private let uuids: Ble.ModeUuids
    private let advertisedRetrievalUuid: [UInt8]? // central-client holder only: goes into the QR retrieval method
    private let log: (@Sendable (String) -> Void)?

    private let queue = DispatchQueue(label: "com.hopae.axle.wallet.ble.central")
    private var manager: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var stateChar: CBCharacteristic?
    private var c2sChar: CBCharacteristic?
    private var s2cChar: CBCharacteristic?
    private var identChar: CBCharacteristic?

    // Queue-confined state.
    private var connected = false
    private var closed = false
    private var stateNotifying = false
    private var s2cNotifying = false
    private var expectedIdent: [UInt8]?
    private var reassembly: [UInt8] = []
    private var incoming: [[UInt8]] = []
    private var sendState: (chunks: [[UInt8]], index: Int, cont: CheckedContinuation<Void, Error>)?

    private var poweredOnWaiter: CheckedContinuation<Void, Error>?
    private var connectWaiter: CheckedContinuation<Void, Error>?
    private var receiveWaiter: CheckedContinuation<[UInt8], Error>?

    private let connectLock = NSLock()
    private var connectTask: Task<Void, Error>?

    init(serviceUuid: CBUUID, uuids: Ble.ModeUuids, advertisedRetrievalUuid: [UInt8]?, logger: (@Sendable (String) -> Void)?) {
        self.serviceUuid = serviceUuid
        self.uuids = uuids
        self.advertisedRetrievalUuid = advertisedRetrievalUuid
        self.log = logger
        super.init()
    }

    /// Reader in **peripheral-server mode**: connects to the holder's advertised service (from the scanned engagement).
    public static func reader(engagement: [UInt8], logger: (@Sendable (String) -> Void)? = nil) throws -> BleCentralTransport {
        guard let ble = DeviceEngagement.parseBle(engagement), let uuidBytes = ble.peripheralServerUuid else {
            throw ProximityTransportError.engagementMissingBle
        }
        return BleCentralTransport(serviceUuid: CBUUID(data: Data(uuidBytes)), uuids: Ble.peripheralServer,
                                   advertisedRetrievalUuid: nil, logger: logger)
    }

    /// Holder in **central-client mode**: advertises `serviceUuid` in the QR, connects to the reader, and
    /// verifies the reader's Ident (armed via `armIdent` once the engagement's EDeviceKey is known).
    public static func holder(serviceUuid: UUID = UUID(), logger: (@Sendable (String) -> Void)? = nil) -> BleCentralTransport {
        BleCentralTransport(serviceUuid: CBUUID(nsuuid: serviceUuid), uuids: Ble.centralClient,
                            advertisedRetrievalUuid: Ble.uuidBytes(serviceUuid), logger: logger)
    }

    /// Arm the Ident check from the QR engagement (holder role; call on `engagementReady`). Keeps the
    /// `Proximity` types out of the app.
    public func armIdent(engagement: [UInt8]) {
        guard let bytes = try? DeviceEngagement.eDeviceKeyBytes(engagement) else { return }
        let expected = DeviceEngagement.bleIdent(bytes)
        queue.async { [self] in expectedIdent = expected }
    }

    // MARK: ProximityTransport

    public func send(_ message: [UInt8]) async throws {
        try await ensureConnected()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async { [self] in beginSend(message, cont) }
        }
    }

    public func receive() async throws -> [UInt8] {
        try await ensureConnected()
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[UInt8], Error>) in
            queue.async { [self] in
                if closed { cont.resume(throwing: ProximityTransportError.closed); return }
                if !incoming.isEmpty { cont.resume(returning: incoming.removeFirst()) }
                else { receiveWaiter = cont }
            }
        }
    }

    public func close() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            queue.async { [self] in
                if !closed {
                    closed = true
                    manager?.stopScan()
                    if let peripheral {
                        peripheral.delegate = nil
                        manager?.cancelPeripheralConnection(peripheral)
                    }
                    manager?.delegate = nil
                    receiveWaiter?.resume(throwing: ProximityTransportError.closed); receiveWaiter = nil
                    connectWaiter?.resume(throwing: ProximityTransportError.closed); connectWaiter = nil
                    sendState?.cont.resume(throwing: ProximityTransportError.closed); sendState = nil
                    log?("central: closed")
                }
                cont.resume()
            }
        }
    }

    /// The BLE central-client-mode DeviceRetrievalMethod embedded in the QR (holder role only).
    public func retrievalMethods() -> [[UInt8]] {
        guard let advertisedRetrievalUuid,
              let method = try? DeviceEngagement.bleRetrievalMethod(centralClientUuid: advertisedRetrievalUuid) else { return [] }
        return [method]
    }

    public func nfcCarrier() -> NfcCarrier? { nil }

    // MARK: connect

    private func ensureConnected() async throws {
        connectLock.lock()
        if connectTask == nil { connectTask = Task { try await performConnect() } }
        let task = connectTask!
        connectLock.unlock()
        try await task.value
    }

    private func performConnect() async throws {
        log?("central: starting Bluetooth…")
        manager = CBCentralManager(delegate: self, queue: queue)
        try await awaitPoweredOn()
        log?("central: scanning for \(serviceUuid.uuidString)")
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async { [self] in
                if closed { cont.resume(throwing: ProximityTransportError.closed); return }
                connectWaiter = cont
                manager.scanForPeripherals(withServices: [serviceUuid], options: nil)
            }
        }
    }

    private func awaitPoweredOn() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async { [self] in
                switch manager.state {
                case .poweredOn: cont.resume()
                case .unknown, .resetting: poweredOnWaiter = cont
                default: cont.resume(throwing: ProximityTransportError.bluetoothUnavailable(manager.state))
                }
            }
        }
    }

    // MARK: queue-confined helpers

    private func deliver(_ message: [UInt8]) {
        if let waiter = receiveWaiter { receiveWaiter = nil; waiter.resume(returning: message) }
        else { incoming.append(message) }
    }

    private func subscribe() {
        guard let peripheral, let stateChar, let s2cChar else { return }
        log?("central: subscribing")
        peripheral.setNotifyValue(true, for: stateChar)
        peripheral.setNotifyValue(true, for: s2cChar)
    }

    /// Once both notifications are on, begin the session (write STATE_START) and unblock `performConnect`.
    private func startSessionIfReady() {
        guard stateNotifying, s2cNotifying, !connected, let peripheral, let stateChar else { return }
        connected = true
        peripheral.writeValue(Data([Ble.stateStart]), for: stateChar, type: .withoutResponse)
        log?("central: subscribed + wrote START — session open")
        if let waiter = connectWaiter { connectWaiter = nil; waiter.resume() }
    }

    private func failConnect(_ error: Error) {
        if let waiter = connectWaiter { connectWaiter = nil; waiter.resume(throwing: error) }
    }

    private func beginSend(_ message: [UInt8], _ cont: CheckedContinuation<Void, Error>) {
        guard let peripheral, c2sChar != nil, connected, !closed else {
            cont.resume(throwing: ProximityTransportError.notConnected); return
        }
        log?("central: sending \(message.count)B")
        let payload = max(peripheral.maximumWriteValueLength(for: .withoutResponse) - 1, 1)
        sendState = (Ble.chunk(message, payloadSize: payload), 0, cont)
        pumpSend()
    }

    /// Sends one chunk per call, then schedules the next after a gap. Write-Without-Response has no ATT ack;
    /// `canSendWriteWithoutResponse` only guards *our* transmit buffer, not the receiver's per-connection-event
    /// capacity — a bursted multi-chunk write is silently dropped by the peer peripheral. Pacing each chunk
    /// into its own connection event is the fix (same reason the Android client paces its writes).
    private func pumpSend() {
        guard let st = sendState, let peripheral, let c2sChar else { return }
        guard st.index < st.chunks.count else {
            sendState = nil
            log?("central: sent (\(st.chunks.count) chunks)")
            st.cont.resume()
            return
        }
        guard peripheral.canSendWriteWithoutResponse else {
            queue.asyncAfter(deadline: .now() + Ble.chunkPacing) { [self] in pumpSend() } // buffer busy — retry
            return
        }
        peripheral.writeValue(Data(st.chunks[st.index]), for: c2sChar, type: .withoutResponse)
        log?("central: c2s chunk \(st.index + 1)/\(st.chunks.count)")
        var next = st
        next.index += 1
        sendState = next
        queue.asyncAfter(deadline: .now() + Ble.chunkPacing) { [self] in pumpSend() }
    }
}

extension BleCentralTransport: CBCentralManagerDelegate {
    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard let waiter = poweredOnWaiter else { return }
        poweredOnWaiter = nil
        switch central.state {
        case .poweredOn: waiter.resume()
        case .unknown, .resetting: poweredOnWaiter = waiter
        default: waiter.resume(throwing: ProximityTransportError.bluetoothUnavailable(central.state))
        }
    }

    public func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                               advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard self.peripheral == nil else { return }
        self.peripheral = peripheral
        peripheral.delegate = self
        central.stopScan()
        log?("central: found peer, connecting")
        central.connect(peripheral, options: nil)
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        log?("central: connected, discovering services")
        peripheral.discoverServices([serviceUuid])
    }

    public func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        failConnect(error ?? ProximityTransportError.notConnected)
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if !connected { failConnect(error ?? ProximityTransportError.notConnected) }
    }
}

extension BleCentralTransport: CBPeripheralDelegate {
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let service = peripheral.services?.first(where: { $0.uuid == serviceUuid }) else {
            failConnect(error ?? ProximityTransportError.notConnected); return
        }
        peripheral.discoverCharacteristics([uuids.state, uuids.client2Server, uuids.server2Client, Ble.ident], for: service)
    }

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        for characteristic in service.characteristics ?? [] {
            switch characteristic.uuid {
            case uuids.state: stateChar = characteristic
            case uuids.client2Server: c2sChar = characteristic
            case uuids.server2Client: s2cChar = characteristic
            case Ble.ident: identChar = characteristic
            default: break
            }
        }
        guard stateChar != nil, s2cChar != nil, c2sChar != nil else {
            log?("central: ❌ missing characteristics on peer service")
            failConnect(ProximityTransportError.notConnected); return
        }
        // Central-client mode: verify the reader's Ident before opening the session; else subscribe directly.
        if expectedIdent != nil, let identChar {
            log?("central: reading Ident")
            peripheral.readValue(for: identChar)
        } else {
            log?("central: characteristics found")
            subscribe()
        }
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == uuids.state { stateNotifying = true }
        if characteristic.uuid == uuids.server2Client { s2cNotifying = true }
        startSessionIfReady()
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let value = characteristic.value else { return }
        if characteristic.uuid == Ble.ident {
            if let expectedIdent, [UInt8](value) != expectedIdent {
                log?("central: ❌ Ident mismatch")
                failConnect(ProximityTransportError.identMismatch)
            } else {
                log?("central: Ident verified")
                subscribe()
            }
            return
        }
        if characteristic.uuid == uuids.server2Client {
            guard let prefix = value.first else { return }
            reassembly.append(contentsOf: value.dropFirst())
            log?("central: s2c chunk \(value.count)B \(prefix == Ble.chunkLast ? "last" : "more") total=\(reassembly.count)")
            if prefix == Ble.chunkLast {
                let message = reassembly
                reassembly = []
                log?("central: received \(message.count)B message")
                deliver(message)
            }
        }
        // A state value of 0x02 means the peer ended the session; the exchange has already completed by then.
    }

    public func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        // No-op: sending is driven by the paced timer in pumpSend (which re-checks canSendWriteWithoutResponse),
        // so we don't also advance here — that would collapse the pacing back into a burst.
    }
}
