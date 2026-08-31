// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "macop",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "MacopCore", targets: ["MacopCore"]),
        .executable(name: "macop", targets: ["MacopCLI"]),
        .executable(name: "macop-agent", targets: ["MacopAgent"]),
        .executable(name: "MacopAuth", targets: ["MacopAuth"]),
        .executable(name: "macop-selftest", targets: ["MacopSelftest"])
    ],
    targets: [
        .target(name: "MacopPTY", publicHeadersPath: "include"),
        .target(name: "MacopCore", dependencies: ["MacopPTY"]),
        .executableTarget(name: "MacopCLI", dependencies: ["MacopCore"]),
        .executableTarget(name: "MacopAgent", dependencies: ["MacopCore", "MacopPTY"]),
        .executableTarget(name: "MacopAuth", dependencies: ["MacopCore"]),
        .executableTarget(name: "MacopSelftest", dependencies: ["MacopCore"]),
        .testTarget(name: "MacopCoreTests", dependencies: ["MacopCore"])
    ]
)
