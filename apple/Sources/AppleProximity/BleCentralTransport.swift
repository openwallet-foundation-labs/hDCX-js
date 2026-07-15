import CoreBluetooth
import Foundation
import Proximity
import WalletAPI

/// ISO/IEC 18013-5 BLE **mdoc central client** transport (reader side) over CoreBluetooth — the iOS
/// counterpart of android `BleGattClientTransport`. The reader scans for the holder's per-session service
/// UUID (from the scanned QR DeviceEngagement), connects, subscribes to the state + server→client
/// characteristics, and writes `0x01` to state to begin. `ProximityReaderService.read` then drives the
/// exchange over `send`/`receive`.
///
/// This implements the default **peripheral-server holder** pairing: the holder is the GATT peripheral,
/// this reader is the central. All mutable state is confined to the manager's serial `queue`.
public final class BleCentralTransport: NSObject, ProximityTransport, @unchecked Sendable {
    private let serviceUuid: CBUUID
    private let uuids = Ble.peripheralServer // reader connects to the holder's peripheral-server service
    private let log: (@Sendable (String) -> Void)?

    private let queue = DispatchQueue(label: "com.hopae.axle.wallet.ble.central")
    private var manager: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var stateChar: CBCharacteristic?
    private var c2sChar: CBCharacteristic?
    private var s2cChar: CBCharacteristic?

    // Queue-confined state.
    private var connected = false
    private var closed = false
    private var stateNotifying = false
    private var s2cNotifying = false
    private var reassembly: [UInt8] = []
    private var incoming: [[UInt8]] = []
    private var sendState: (chunks: [[UInt8]], index: Int, cont: CheckedContinuation<Void, Error>)?

    private var poweredOnWaiter: CheckedContinuation<Void, Error>?
    private var connectWaiter: CheckedContinuation<Void, Error>?
    private var receiveWaiter: CheckedContinuation<[UInt8], Error>?

    public init(serviceUuid: CBUUID, logger: (@Sendable (String) -> Void)? = nil) {
        self.serviceUuid = serviceUuid
        self.log = logger
        super.init()
    }

    /// Reader convenience: derive the holder's peripheral-server service UUID from the scanned engagement.
    public convenience init(engagement: [UInt8], logger: (@Sendable (String) -> Void)? = nil) throws {
        guard let ble = DeviceEngagement.parseBle(engagement), let uuidBytes = ble.peripheralServerUuid else {
            throw ProximityTransportError.engagementMissingBle
        }
        self.init(serviceUuid: CBUUID(data: Data(uuidBytes)), logger: logger)
    }

    /// Powers up CoreBluetooth, scans for and connects to the holder, and completes the BLE handshake.
    public func connect() async throws {
        log?("reader: starting Bluetooth…")
        manager = CBCentralManager(delegate: self, queue: queue)
        try await awaitPoweredOn()
        log?("reader: scanning for \(serviceUuid.uuidString)")
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async { [self] in
                if closed { cont.resume(throwing: ProximityTransportError.closed); return }
                connectWaiter = cont
                manager.scanForPeripherals(withServices: [serviceUuid], options: nil)
            }
        }
    }

    // MARK: ProximityTransport

    public func send(_ message: [UInt8]) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async { [self] in beginSend(message, cont) }
        }
    }

    public func receive() async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[UInt8], Error>) in
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
                    log?("reader: closed")
                }
                cont.resume()
            }
        }
    }

    // MARK: queue-confined helpers

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

    private func deliver(_ message: [UInt8]) {
        if let waiter = receiveWaiter { receiveWaiter = nil; waiter.resume(returning: message) }
        else { incoming.append(message) }
    }

    /// Once both notifications are on, begin the session (write STATE_START) and unblock `connect()`. (on queue)
    private func startSessionIfReady() {
        guard stateNotifying, s2cNotifying, !connected, let peripheral, let stateChar else { return }
        connected = true
        peripheral.writeValue(Data([Ble.stateStart]), for: stateChar, type: .withoutResponse)
        log?("reader: subscribed + wrote START — session open")
        if let waiter = connectWaiter { connectWaiter = nil; waiter.resume() }
    }

    private func failConnect(_ error: Error) {
        if let waiter = connectWaiter { connectWaiter = nil; waiter.resume(throwing: error) }
    }

    private func beginSend(_ message: [UInt8], _ cont: CheckedContinuation<Void, Error>) {
        guard let peripheral, c2sChar != nil, connected, !closed else {
            cont.resume(throwing: ProximityTransportError.notConnected); return
        }
        log?("reader: sending \(message.count)B request")
        let payload = max(peripheral.maximumWriteValueLength(for: .withoutResponse) - 1, 1)
        sendState = (Ble.chunk(message, payloadSize: payload), 0, cont)
        pumpSend()
    }

    private func pumpSend() {
        guard var st = sendState, let peripheral, let c2sChar else { return }
        while st.index < st.chunks.count {
            if !peripheral.canSendWriteWithoutResponse {
                sendState = st
                log?("reader: c2s buffer full at chunk \(st.index)/\(st.chunks.count), waiting")
                return // wait for peripheralIsReady
            }
            peripheral.writeValue(Data(st.chunks[st.index]), for: c2sChar, type: .withoutResponse)
            st.index += 1
            sendState = st
        }
        sendState = nil
        log?("reader: request sent")
        st.cont.resume()
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
        log?("reader: found holder, connecting")
        central.connect(peripheral, options: nil)
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        log?("reader: connected, discovering services")
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
        peripheral.discoverCharacteristics([uuids.state, uuids.client2Server, uuids.server2Client], for: service)
    }

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        for characteristic in service.characteristics ?? [] {
            switch characteristic.uuid {
            case uuids.state: stateChar = characteristic
            case uuids.client2Server: c2sChar = characteristic
            case uuids.server2Client: s2cChar = characteristic
            default: break
            }
        }
        guard let stateChar, let s2cChar, c2sChar != nil else {
            log?("reader: ❌ missing characteristics on holder service")
            failConnect(ProximityTransportError.notConnected); return
        }
        log?("reader: characteristics found, subscribing")
        peripheral.setNotifyValue(true, for: stateChar)
        peripheral.setNotifyValue(true, for: s2cChar)
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == uuids.state { stateNotifying = true }
        if characteristic.uuid == uuids.server2Client { s2cNotifying = true }
        startSessionIfReady()
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let value = characteristic.value else { return }
        if characteristic.uuid == uuids.server2Client {
            guard let prefix = value.first else { return }
            reassembly.append(contentsOf: value.dropFirst())
            if prefix == Ble.chunkLast {
                let message = reassembly
                reassembly = []
                deliver(message)
            }
        }
        // A state value of 0x02 means the holder ended the session; the read has already completed by then.
    }

    public func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        log?("reader: c2s buffer ready")
        pumpSend()
    }
}
