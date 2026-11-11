// swift-tools-version: 6.0
// The Swift SDK, sdk/swift. Its manifest is here because SwiftPM fetches packages only from a
// repository's root; nothing else in this repository is Swift.
import PackageDescription

let package = Package(
    name: "ShadybinVerify",
    // CryptoKit's Ed25519, so Apple platforms only, and no dependencies.
    platforms: [.macOS(.v13), .iOS(.v16), .tvOS(.v16), .watchOS(.v9), .visionOS(.v1)],
    products: [.library(name: "ShadybinVerify", targets: ["ShadybinVerify"])],
    targets: [
        .target(name: "ShadybinVerify", path: "sdk/swift/Sources/ShadybinVerify"),
        .testTarget(
            name: "ShadybinVerifyTests", dependencies: ["ShadybinVerify"],
            path: "sdk/swift/Tests/ShadybinVerifyTests", resources: [.copy("vectors.json")]),
    ]
)
