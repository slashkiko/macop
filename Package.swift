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
        .executable(name: "macop-agent", targets: ["MacopAgent"])
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-testing.git", from: "0.7.0")
    ],
    targets: [
        .target(name: "MacopCore"),
        .executableTarget(name: "MacopCLI", dependencies: ["MacopCore"]),
        .executableTarget(name: "MacopAgent", dependencies: ["MacopCore"]),
        .testTarget(
            name: "MacopCoreTests",
            dependencies: [
                "MacopCore",
                .product(name: "Testing", package: "swift-testing")
            ]
        )
    ]
)
