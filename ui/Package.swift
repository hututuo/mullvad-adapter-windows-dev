// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "MullvadAdapterUI",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "MullvadAdapterUI", targets: ["MullvadAdapterUI"])
    ],
    targets: [
        .executableTarget(
            name: "MullvadAdapterUI",
            path: "Sources/MullvadAdapterUI"
        ),
        .testTarget(name: "MullvadAdapterUITests", dependencies: ["MullvadAdapterUI"])
    ]
)
