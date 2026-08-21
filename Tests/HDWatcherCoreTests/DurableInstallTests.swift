import XCTest
@testable import HDWatcherCore

/// The daemon kept needing manual repair after every restart and every rebuild.
/// SMAppService ties its registration to the app's code signature and to an
/// approval in Login Items: rebuilding changes the signature, a system update
/// can withdraw the approval, and either way the daemon silently stops starting
/// at boot. These cover the durable route that does not depend on either.
final class DurableInstallTests: XCTestCase {

    func testItLivesSomewhereRebuildingTheAppCannotDisturb() {
        // The binary is copied out of the bundle deliberately: replacing or
        // deleting the app must not stop the daemon starting at boot.
        XCTAssertEqual(BackgroundService.Durable.binaryPath, "/usr/local/libexec/hdwatcherd")
        XCTAssertFalse(BackgroundService.Durable.binaryPath.hasPrefix("/Applications"))
        XCTAssertEqual(BackgroundService.Durable.plistPath,
                       "/Library/LaunchDaemons/co.pixelworship.hdwatcher.daemon.plist")
    }

    func testTheCommandIsOneTheUserCanActuallyRun() {
        let command = BackgroundService.Durable.command
        XCTAssertTrue(command.hasPrefix("sudo "))
        XCTAssertTrue(command.contains("install-daemon.sh"))
    }

    func testTheInstallerScriptSaysWhatItDoes() throws {
        // The script ships in the repository and is copied into the bundle at
        // build time; it is the thing an administrator is being asked to run,
        // so it has to be readable and do exactly what the button claims.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let script = try String(contentsOf: root.appendingPathComponent("Scripts/install-daemon.sh"),
                                encoding: .utf8)
        XCTAssertTrue(script.contains("/Library/LaunchDaemons/"))
        XCTAssertTrue(script.contains("launchctl bootstrap system"))
        XCTAssertTrue(script.contains("<key>RunAtLoad</key>"), "it must start at boot")
        XCTAssertTrue(script.contains("<key>KeepAlive</key>"), "and be restarted if it stops")
        XCTAssertTrue(script.contains("launchctl enable"),
                      "a service left on the disabled list will not load")
        XCTAssertTrue(script.contains("--uninstall"), "it has to be removable too")
    }

    func testAnAbsentInstallationIsReportedAsAbsent() {
        // On a machine without it, nothing here should claim otherwise — and
        // nothing should claim an out-of-date install either.
        if !FileManager.default.fileExists(atPath: BackgroundService.Durable.plistPath) {
            XCTAssertFalse(BackgroundService.Durable.isInstalled)
            XCTAssertFalse(BackgroundService.Durable.isOutOfDate)
        }
    }
}
