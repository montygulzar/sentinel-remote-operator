// swift-tools-version: 5.9
import PackageDescription

// SentinelKit holds every part of the Operator that is not SwiftUI: request
// signing (byte-for-byte identical to the Go agent), the typed API client,
// Keychain-backed credential storage, pairing key derivation, and the view
// models. Keeping it a plain library means `swift test` on a Mac exercises all
// of it without an iOS simulator. The SwiftUI app target lives in ../App and is
// assembled in Xcode (see README); it depends on this library.
let package = Package(
    name: "SentinelOperator",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "SentinelKit", targets: ["SentinelKit"]),
    ],
    targets: [
        .target(name: "SentinelKit"),
        .testTarget(
            name: "SentinelKitTests",
            dependencies: ["SentinelKit"],
            resources: [.process("Resources/signing_vectors.json")]
        ),
    ]
)
