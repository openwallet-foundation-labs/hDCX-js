import CborCose
import Crypto
import Foundation
import SdJwt
import WalletAPI
import XCTest
@testable import StatusList

final class StatusListTests: XCTestCase {

    private let uri = "https://issuer.example/statuslists/1"

    private let key = P256.Signing.PrivateKey()
    private var publicKey: EcPublicKey {
        let raw = key.publicKey.rawRepresentation
        return EcPublicKey(curve: .p256, x: [UInt8](raw.prefix(32)), y: [UInt8](raw.suffix(32)))
    }
    private struct KeySigner: JwsSigner {
        let algorithm: SigningAlgorithm = .es256
        let key: P256.Signing.PrivateKey
        func sign(_ signingInput: [UInt8]) async throws -> [UInt8] {
            [UInt8](try key.signature(for: Data(signingInput)).rawRepresentation)
        }
    }
    private struct TestResolver: IssuerKeyResolver {
        let publicKey: EcPublicKey
        func resolve(iss: String, header: JsonValue) async throws -> IssuerSigningKey {
            IssuerSigningKey(publicKey: publicKey, algorithm: .es256)
        }
    }
    private final class CountingTransport: HttpTransport, @unchecked Sendable {
        let body: String; let status: Int; var calls = 0
        init(_ body: String, status: Int = 200) { self.body = body; self.status = status }
        func execute(_ request: HttpRequest) async throws -> HttpResponse {
            calls += 1
            return HttpResponse(status: status, headers: [], body: [UInt8](body.utf8))
        }
    }

    private func packLst(bits: Int, statuses: [Int]) throws -> String {
        let perByte = 8 / bits
        var unpacked = [UInt8](repeating: 0, count: (statuses.count + perByte - 1) / perByte)
        for (i, s) in statuses.enumerated() { unpacked[i / perByte] |= UInt8(s << ((i % perByte) * bits)) }
        return Base64Url.encode(try Zlib.deflate(unpacked))
    }

    private func token(bits: Int, statuses: [Int], sub: String? = nil, exp: Int64? = nil, ttl: Int64? = nil) async throws -> String {
        var payload: [(String, JsonValue)] = [("sub", .str(sub ?? uri)), ("iat", .numInt(1_700_000_000))]
        if let exp { payload.append(("exp", .numInt(exp))) }
        if let ttl { payload.append(("ttl", .numInt(ttl))) }
        payload.append(("status_list", .obj([("bits", .numInt(Int64(bits))), ("lst", .str(try packLst(bits: bits, statuses: statuses)))])))
        let header = JsonValue.obj([("typ", .str("statuslist+jwt")), ("alg", .str("ES256"))])
        return try await Jws.sign(header: header, payload: [UInt8](JsonValue.obj(payload).serialize().utf8), signer: KeySigner(key: key)).compact()
    }

    private func client(_ t: any HttpTransport, now: Int64 = 1_700_000_100) -> StatusListClient {
        StatusListClient(http: t, keyResolver: TestResolver(publicKey: publicKey), clock: { now })
    }

    func testReadsStatusesAcrossBits() async throws {
        let c = client(CountingTransport(try await token(bits: 2, statuses: [0, 1, 2, 0])))
        let s0 = try await c.check(StatusReference(index: 0, uri: uri))
        let s1 = try await c.check(StatusReference(index: 1, uri: uri))
        let s2 = try await c.check(StatusReference(index: 2, uri: uri))
        let s3 = try await c.check(StatusReference(index: 3, uri: uri))
        XCTAssertEqual([.valid, .invalid, .suspended, .valid], [s0, s1, s2, s3])
    }

    func testOneBitRevocation() async throws {
        let statuses = (0..<20).map { ($0 == 7 || $0 == 13) ? 1 : 0 }
        let c = client(CountingTransport(try await token(bits: 1, statuses: statuses)))
        let s6 = try await c.check(StatusReference(index: 6, uri: uri))
        let s7 = try await c.check(StatusReference(index: 7, uri: uri))
        let s13 = try await c.check(StatusReference(index: 13, uri: uri))
        XCTAssertEqual([.valid, .invalid, .invalid], [s6, s7, s13])
    }

    func testCachesAcrossChecks() async throws {
        let t = CountingTransport(try await token(bits: 1, statuses: [Int](repeating: 0, count: 16), ttl: 3600))
        let c = client(t)
        for i in 0..<5 { _ = try await c.check(StatusReference(index: Int64(i), uri: uri)) }
        XCTAssertEqual(1, t.calls, "a cached (ttl) list must be fetched only once")
    }

    func testFromClaimsExtractsReference() throws {
        let claims = try JsonValue.parse(#"{"vct":"x","status":{"status_list":{"idx":42,"uri":"\#(uri)"}}}"#)
        let ref = StatusReference.fromClaims(claims)!
        XCTAssertEqual(42, ref.index)
        XCTAssertEqual(uri, ref.uri)
    }

    func testUnlistedCredentialIsValid() async throws {
        let claims = try JsonValue.parse(#"{"vct":"x"}"#)
        let status = try await client(CountingTransport("")).check(claims: claims)
        XCTAssertEqual(.valid, status)
    }

    func testSubMismatchRejected() async throws {
        let c = client(CountingTransport(try await token(bits: 1, statuses: [Int](repeating: 0, count: 16), sub: "https://evil.example/list")))
        do { _ = try await c.check(StatusReference(index: 0, uri: uri)); XCTFail("should reject") } catch is StatusListError {}
    }

    func testExpiredTokenRejected() async throws {
        let c = client(CountingTransport(try await token(bits: 1, statuses: [Int](repeating: 0, count: 16), exp: 1_700_000_050)), now: 1_700_000_100)
        do { _ = try await c.check(StatusReference(index: 0, uri: uri)); XCTFail("should reject") } catch is StatusListError {}
    }

    func testIndexOutOfRangeRejected() async throws {
        let c = client(CountingTransport(try await token(bits: 1, statuses: [Int](repeating: 0, count: 8))))
        do { _ = try await c.check(StatusReference(index: 9999, uri: uri)); XCTFail("should reject") } catch is StatusListError {}
    }

    func testTamperedTokenRejected() async throws {
        let good = try await token(bits: 1, statuses: [Int](repeating: 0, count: 16))
        let parts = good.split(separator: ".").map(String.init)
        let forged = parts[0] + "." + Base64Url.encode(#"{"sub":"\#(uri)","status_list":{"bits":1,"lst":"eJw"}}"#) + "." + parts[2]
        let c = client(CountingTransport(forged))
        do { _ = try await c.check(StatusReference(index: 0, uri: uri)); XCTFail("should reject") } catch {}
    }
}
