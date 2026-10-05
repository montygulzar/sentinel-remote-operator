import XCTest
@testable import SentinelKit

/// Holds the Swift side to the locked cross-language signing vectors. These are
/// the same bytes the Go agent's TestSigningVectorsAreReproducedExactly checks,
/// so a pass here means Operator and agent compute byte-identical signatures.
/// (Execution of this test NEEDS XCODE/iOS: no Swift toolchain in the agent's
/// Linux build environment.)
final class SigningVectorsTests: XCTestCase {
    struct VectorFile: Decodable {
        struct Vector: Decodable {
            let name: String
            let deviceId: String
            let keyBase64: String
            let method: String
            let path: String
            let timestamp: String
            let nonce: String
            let body: String
            let expectedSignature: String
        }
        let vectors: [Vector]
    }

    func loadVectors() throws -> VectorFile {
        guard let url = Bundle.module.url(forResource: "signing_vectors", withExtension: "json") else {
            XCTFail("signing_vectors.json resource missing from test bundle")
            throw NSError(domain: "test", code: 1)
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(VectorFile.self, from: data)
    }

    func testSignaturesMatchLockedVectors() throws {
        let file = try loadVectors()
        XCTAssertFalse(file.vectors.isEmpty, "no vectors loaded")
        for v in file.vectors {
            guard let key = Data(base64Encoded: v.keyBase64) else {
                XCTFail("\(v.name): bad key base64")
                continue
            }
            let signed = SignedRequest(
                deviceID: v.deviceId, method: v.method, path: v.path,
                timestamp: v.timestamp, nonce: v.nonce, body: Data(v.body.utf8)
            )
            let got = RequestSigner.signature(key: key, signed)
            XCTAssertEqual(got, v.expectedSignature, "signature mismatch for vector \(v.name)")
        }
    }
}
