import XCTest
@testable import HDWatcherCore

/// Publishing configuration to the daemon is not a formality: the app runs
/// unprivileged and cannot write into /Library, and for days the daemon ran on
/// defaults while the app believed every setting had reached it.
final class AgentConfigurationPublishTests: XCTestCase {

    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-config-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testAFailedWriteIsReportedAsFailure() {
        let configuration = AgentConfiguration()
        // A directory nobody can write to is exactly the /Library case.
        let unwritable = URL(fileURLWithPath: "/System/hdwatcher-should-not-exist/agent-config.enc")
        XCTAssertFalse(configuration.write(to: unwritable))
    }

    func testTheNewerCopyWins() throws {
        // Two copies exist: one in /Library that only root can write, one in
        // the user's home that the app writes. A stale privileged file must not
        // outrank everything the user has changed since.
        let system = directory.appendingPathComponent("system.enc")
        let user = directory.appendingPathComponent("user.enc")

        try Data("older".utf8).write(to: system)
        try Data("newer".utf8).write(to: user)
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -600)],
                                              ofItemAtPath: system.path)

        // Neither decrypts here — no daemon key in a test process — so the
        // ordering is what is under test, and it must not crash or pick blind.
        XCTAssertNil(AgentConfiguration.readNewest(system: system, user: user))
    }

    func testMissingFilesAreSkippedRatherThanTreatedAsEmpty() {
        let missing = directory.appendingPathComponent("nothing-here.enc")
        XCTAssertNil(AgentConfiguration.readNewest(system: missing, user: nil))
        XCTAssertNil(AgentConfiguration.readNewest(system: missing, user: missing))
    }

    func testConfigurationCarriesTheSettingsTheDaemonActsOn() {
        var settings = AppSettings()
        settings.maxCaptureFileBytes = 32 * 1024 * 1024
        settings.captureExcludePatterns = [GlobPattern("*.mov")]
        settings.backgroundRecordingEnabled = true

        let configuration = AgentConfiguration(from: settings, rules: [], enabled: true)
        let round = configuration.appSettings
        XCTAssertEqual(round.maxCaptureFileBytes, 32 * 1024 * 1024)
        XCTAssertEqual(round.captureExcludePatterns.map(\.pattern), ["*.mov"])
        XCTAssertTrue(configuration.enabled)
    }
}
