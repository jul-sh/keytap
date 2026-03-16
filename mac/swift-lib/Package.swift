// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "PasskeyBridge",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "PasskeyBridge", type: .static, targets: ["PasskeyBridge"]),
    ],
    targets: [
        .target(
            name: "PasskeyBridge",
            path: "Sources/PasskeyBridge",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
