// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "HDWatcher",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "HDWatcher", targets: ["HDWatcher"]),
        .executable(name: "hdwatcherd", targets: ["HDWatcherAgent"]),
        .library(name: "HDWatcherCore", targets: ["HDWatcherCore"]),
    ],
    targets: [
        .target(
            name: "HDWatcherCore",
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [
                .linkedFramework("CoreServices"),
                .linkedFramework("DiskArbitration"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("AppKit"),
                // Reading the format most of the interesting data on a Mac
                // actually lives in.
                .linkedLibrary("sqlite3"),
            ]
        ),
        .executableTarget(
            name: "HDWatcherAgent",
            dependencies: ["HDWatcherCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "HDWatcher",
            dependencies: ["HDWatcherCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "HDWatcherCoreTests",
            dependencies: ["HDWatcherCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
