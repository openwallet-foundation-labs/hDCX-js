import CoreBluetooth
import Foundation
import Proximity
import WalletAPI

/// Errors surfaced by the BLE transports.
public enum ProximityTransportError: Error, CustomStringConvertible {
    case bluetoothUnavailable(CBManagerState)
    case notConnected
    case closed
    case engagementMissingBle

    public var description: String {
        switch self {
        case let .bluetoothUnavailable(state): return "Bluetooth unavailable (state \(state.rawValue))"
        case .notConnected: return "BLE peer not connected"
        case .closed: return "BLE transport closed"
        case .engagementMissingBle: return "DeviceEngagement carries no BLE retrieval method"
        }
    }
}

/// ISO/IEC 18013-5 BLE **mdoc peripheral server** transport (holder side) over CoreBluetooth — the iOS
/// counterpart of android `BleGattServerTransport`. The holder advertises a per-session service UUID (carried
/// in the QR DeviceEngagement); the reader connects as central, subscribes to the state + server→client
/// characteristics, and writes `0x01` to state to begin. `ProximityService.present` then drives the
/// device-retrieval exchange over `send`/`receive`.
///
/// All mutable state is confined to the CoreBluetooth manager's serial `queue`; the async port methods hop
/// onto it to register/resume continuations, so no additional locking is needed.
public final class BlePeripheralTransport: NSObject, ProximityTransport, @unchecked Sendable {
    private let serviceUuid: CBUUID
    private let serviceUuidBytes: [UInt8]
    private let uuids = Ble.peripheralServer
    private let log: (@Sendable (String) -> Void)?

    private let queue = DispatchQueue(label: "com.hopae.axle.wallet.ble.peripheral")
    private var manager: CBPeripheralManager!

    private var stateChar: CBMutableCharacteristic!
    private var c2sChar: CBMutableCharacteristic!
    private var s2cChar: CBMutableCharacteristic!

    // Queue-confined state.
    private var central: CBCentral?
    private var connected = false
    private var closed = false
    private var reassembly: [UInt8] = []
    private var incoming: [[UInt8]] = []
    private var sendState: (chunks: [[UInt8]], index: Int, cont: CheckedContinuation<Void, Error>)?

    private var poweredOnWaiter: CheckedContinuation<Void, Error>?
    private var addServiceWaiter: CheckedContinuation<Void, Never>?
    private var connectedWaiter: CheckedContinuation<Void, Error>?
    private var receiveWaiter: CheckedContinuation<[UInt8], Error>?

    /// - Parameter serviceUuid: the per-session GATT service UUID (default: a fresh random one). Its
    ///   big-endian bytes go into the engagement so the reader knows where to connect.
    /// - Parameter logger: optional sink for BLE lifecycle events (wired to the app's Debug console).
    public init(serviceUuid: UUID = UUID(), logger: (@Sendable (String) -> Void)? = nil) {
        self.serviceUuid = CBUUID(nsuuid: serviceUuid)
        self.serviceUuidBytes = Ble.uuidBytes(serviceUuid)
        self.log = logger
        super.init()
    }

    /// Powers up CoreBluetooth, publishes the GATT service, and starts advertising. Call before `present`.
    public func start() async throws {
        log?("holder: starting Bluetooth…")
        manager = CBPeripheralManager(delegate: self, queue: queue)
        try await awaitPoweredOn()
        log?("holder: Bluetooth powered on")
        await publish()
    }

    // MARK: ProximityTransport

    public func send(_ message: [UInt8]) async throws {
        try await awaitConnected()
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
                    if let central { _ = manager?.updateValue(Data([Ble.stateEnd]), for: stateChar, onSubscribedCentrals: [central]) }
                    manager?.stopAdvertising()
                    manager?.removeAllServices()
                    manager?.delegate = nil // stop the dying manager from delivering stale callbacks to a new session
                    central = nil
                    receiveWaiter?.resume(throwing: ProximityTransportError.closed); receiveWaiter = nil
                    connectedWaiter?.resume(throwing: ProximityTransportError.closed); connectedWaiter = nil
                    sendState?.cont.resume(throwing: ProximityTransportError.closed); sendState = nil
                    log?("holder: closed")
                }
                cont.resume()
            }
        }
    }

    /// The BLE peripheral-server-mode DeviceRetrievalMethod embedded in the QR so the reader connects.
    public func retrievalMethods() -> [[UInt8]] {
        guard let method = try? DeviceEngagement.bleRetrievalMethod(peripheralServerUuid: serviceUuidBytes) else { return [] }
        return [method]
    }

    public func nfcCarrier() -> NfcCarrier? { nil } // BLE-only; NFC handover is out of scope on iOS.

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

    private func publish() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            queue.async { [self] in
                stateChar = CBMutableCharacteristic(type: uuids.state, properties: [.notify, .writeWithoutResponse], value: nil, permissions: [.writeable, .readable])
                c2sChar = CBMutableCharacteristic(type: uuids.client2Server, properties: [.writeWithoutResponse], value: nil, permissions: [.writeable])
                s2cChar = CBMutableCharacteristic(type: uuids.server2Client, properties: [.notify], value: nil, permissions: [.readable])
                let service = CBMutableService(type: serviceUuid, primary: true)
                service.characteristics = [stateChar, c2sChar, s2cChar]
                addServiceWaiter = cont
                manager.add(service)
            }
        }
    }

    private func awaitConnected() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            queue.async { [self] in
                if connected { cont.resume() }
                else if closed { cont.resume(throwing: ProximityTransportError.closed) }
                else { connectedWaiter = cont }
            }
        }
    }

    /// Deliver a fully-reassembled message to a waiting `receive()` or buffer it. (on queue)
    private func deliver(_ message: [UInt8]) {
        if let waiter = receiveWaiter { receiveWaiter = nil; waiter.resume(returning: message) }
        else { incoming.append(message) }
    }

    private func markConnected() {
        guard !connected else { return }
        connected = true
        if let waiter = connectedWaiter { connectedWaiter = nil; waiter.resume() }
    }

    private func beginSend(_ message: [UInt8], _ cont: CheckedContinuation<Void, Error>) {
        guard let central, !closed else { cont.resume(throwing: ProximityTransportError.notConnected); return }
        log?("holder: sending \(message.count)B response")
        let payload = max(central.maximumUpdateValueLength - 1, 1)
        sendState = (Ble.chunk(message, payloadSize: payload), 0, cont)
        pumpSend()
    }

    /// Sends queued chunks until the notify buffer is full, then yields to `peripheralManagerIsReady`. (on queue)
    private func pumpSend() {
        guard var st = sendState, let central else { return }
        while st.index < st.chunks.count {
            let ok = manager.updateValue(Data(st.chunks[st.index]), for: s2cChar, onSubscribedCentrals: [central])
            if ok { st.index += 1; sendState = st }
            else { sendState = st; return } // wait for peripheralManagerIsReady(toUpdateSubscribers:)
        }
        sendState = nil
        st.cont.resume()
    }
}

extension BlePeripheralTransport: CBPeripheralManagerDelegate {
    public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard let waiter = poweredOnWaiter else { return }
        poweredOnWaiter = nil
        switch peripheral.state {
        case .poweredOn: waiter.resume()
        case .unknown, .resetting: poweredOnWaiter = waiter // keep waiting for a settled state
        default: waiter.resume(throwing: ProximityTransportError.bluetoothUnavailable(peripheral.state))
        }
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if let error { log?("holder: ❌ add service: \(error.localizedDescription)") }
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [serviceUuid]])
        log?("holder: advertising \(serviceUuid.uuidString)")
        if let waiter = addServiceWaiter { addServiceWaiter = nil; waiter.resume() }
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        self.central = central
        log?("holder: reader subscribed to \(characteristic.uuid == uuids.state ? "state" : "server2client") (mtu \(central.maximumUpdateValueLength))")
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            let uuid = request.characteristic.uuid
            let n = request.value?.count ?? 0
            if uuid == uuids.state {
                if let value = request.value, value.count == 1, value.first == Ble.stateStart {
                    if central == nil { central = request.central }
                    peripheral.stopAdvertising()
                    log?("holder: session START from reader")
                    markConnected()
                } else {
                    log?("holder: state write \(n)B (ignored)")
                }
            } else if uuid == uuids.client2Server {
                if let value = request.value, let prefix = value.first {
                    reassembly.append(contentsOf: value.dropFirst())
                    log?("holder: c2s chunk \(n)B \(prefix == Ble.chunkLast ? "last" : "more") total=\(reassembly.count)")
                    if prefix == Ble.chunkLast {
                        let message = reassembly
                        reassembly = []
                        log?("holder: received \(message.count)B message")
                        deliver(message)
                    }
                } else {
                    log?("holder: c2s empty write")
                }
            } else {
                log?("holder: write to \(uuid.uuidString) \(n)B")
            }
        }
        // ISO 18013-5 c2s/state are Write-Without-Response: the central expects NO ATT response. Sending one
        // (via respond) violates the protocol and stalls iOS's delivery of the central's subsequent chunks —
        // the cause of the multi-chunk SessionEstablishment truncation. Only acknowledge with-response writes.
        if let ack = requests.first(where: { $0.characteristic.properties.contains(.write) }) {
            peripheral.respond(to: ack, withResult: .success)
        }
    }

    public func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        pumpSend()
    }
}
