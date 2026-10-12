// swift-tools-version:5.10
import PackageDescription
import Foundation

/// The Command Line Tools toolchain ships `libTestingMacros.dylib` but does not
/// put it on the compiler's plugin search path, so `@Test`/`@Suite` fail with
/// "plugin for module 'TestingMacros' not found". Point the compiler at it
/// directly when it is actually present, so `swift test` works without extra
/// flags. A full Xcode install resolves the plugin on its own.
let testMacroPluginFlags: [String] = {
    let candidates = [
        "/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing",
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/host/plugins/testing",
    ]
    for dir in candidates {
        let plugin = (dir as NSString).appendingPathComponent("libTestingMacros.dylib")
        if FileManager.default.isReadableFile(atPath: plugin) {
            return ["-load-plugin-library", plugin]
        }
    }
    return []
}()

let package = Package(
    name: "MacGuard",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "macguard", targets: ["macguard"]),
        .library(name: "MacGuardKit", targets: ["MacGuardKit"]),
    ],
    targets: [
        .target(name: "MacGuardKit"),
        .executableTarget(name: "macguard", dependencies: ["MacGuardKit"]),
        .testTarget(
            name: "MacGuardKitTests",
            dependencies: ["MacGuardKit"],
            swiftSettings: [.unsafeFlags(testMacroPluginFlags)]
        ),
    ]
)
