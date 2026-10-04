import XCTest
@testable import SentinelKit

final class CredentialAndPairingTests: XCTestCase {
    func testInMemoryStoreRoundTrip() throws {
        let store = InMemoryCredentialStore()
        XCTAssertNil(try store.load())

        let dev = PairedDevice(
            deviceID: "dev-1", key: Data([1, 2, 3, 4]),
            serverAddress: "100.64.0.1:8787", hostDisplayName: "BEEFCAKES"
        )
        try store.save(dev)
        XCTAssertEqual(try store.load(), dev)

        try store.clear()
        XCTAssertNil(try store.load())
    }

    func testPairedDeviceCodableRoundTrip() throws {
        let dev = PairedDevice(
            deviceID: "dev-xyz", key: Data([9, 8, 7, 6, 5]),
            serverAddress: "host:8787", hostDisplayName: "PC"
        )
        let data = try JSONEncoder().encode(dev)
        let back = try JSONDecoder().decode(PairedDevice.self, from: data)
        XCTAssertEqual(dev, back)
    }

    func testEndpointParsing() {
        XCTAssertEqual(ServerEndpoint(address: "host"), ServerEndpoint(address: "http://host:8787"))
        XCTAssertEqual(ServerEndpoint(address: "1.2.3.4:9000")?.port, 9000)
        XCTAssertEqual(ServerEndpoint(address: "http://1.2.3.4:9000/ignored/path")?.host, "1.2.3.4")
        XCTAssertNil(ServerEndpoint(address: ""))
        XCTAssertNil(ServerEndpoint(address: "host:notaport"))
        XCTAssertNil(ServerEndpoint(address: "ftp://host:21"))
    }

    // Pairing key derivation is the Swift mirror of the agent's. We cannot run
    // the Go side here, so this checks internal consistency: the proof the
    // Operator would verify is reproducible from the same inputs, and the device
    // key derivation is deterministic. Cross-language equality is proven
    // on-device (NEEDS XCODE/iOS) and by the shared signing vectors.
    func testPairingDerivationIsDeterministicAndProofVerifies() {
        let code = "ABCDEFGHIJKLMNOP"
        let agentNonce = Data([0x01, 0x02, 0x03, 0x04])
        let deviceNonce = Data([0x10, 0x20, 0x30, 0x40])
        let deviceID = "dev-9"

        let k1 = PairingKeyDerivation.deviceKey(code: code, agentNonce: agentNonce, deviceNonce: deviceNonce)
        let k2 = PairingKeyDerivation.deviceKey(code: code, agentNonce: agentNonce, deviceNonce: deviceNonce)
        XCTAssertEqual(k1, k2)
        XCTAssertEqual(k1.count, 32, "HMAC-SHA256 key must be 32 bytes")

        let proof = PairingKeyDerivation.pairConfirm(code: code, deviceID: deviceID, agentNonce: agentNonce, deviceNonce: deviceNonce)
        let expected = PairingKeyDerivation.pairConfirm(code: code, deviceID: deviceID, agentNonce: agentNonce, deviceNonce: deviceNonce)
        XCTAssertTrue(constantTimeEquals(proof, expected))

        // A different code must not verify.
        let wrong = PairingKeyDerivation.pairConfirm(code: "ZZZZZZZZZZZZZZZZ", deviceID: deviceID, agentNonce: agentNonce, deviceNonce: deviceNonce)
        XCTAssertFalse(constantTimeEquals(proof, wrong))

        // Device key and proof are distinct derivations (different labels).
        XCTAssertNotEqual(k1, proof)
    }

    func testConstantTimeEqualsRejectsLengthMismatch() {
        XCTAssertFalse(constantTimeEquals(Data([1, 2, 3]), Data([1, 2])))
        XCTAssertTrue(constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 3])))
    }
}
