import XCTest
@testable import HDWatcherCore

/// Coverage has to be reported by whoever is holding the FSEvents stream. Ask
/// the wrong one and the screen says "Not watching anything" about a Mac that a
/// root daemon has been watching since boot.
final class CoverageReportTests: XCTestCase {

    private func agent(monitoring: Bool, paths: [String], alive: Bool = true) -> AgentStatus {
        AgentStatus(pid: alive ? ProcessInfo.processInfo.processIdentifier : 999_999,
                    startedAt: Date(timeIntervalSinceNow: -3_600),
                    heartbeat: alive ? Date() : Date(timeIntervalSinceNow: -600),
                    watchedPaths: paths,
                    isMonitoring: monitoring)
    }

    private func engine(monitoring: Bool, paths: [String]) -> WatcherEngine.Status {
        var status = WatcherEngine.Status()
        status.isMonitoring = monitoring
        status.watchedPaths = paths
        status.startedAt = monitoring ? Date(timeIntervalSinceNow: -60) : nil
        return status
    }

    func testTheDaemonIsAuthoritativeWhenItIsRecording() {
        // The app's own engine stands down in this state rather than watching
        // the same tree twice — so its empty roots mean nothing.
        let report = CoverageReport.resolve(agent: agent(monitoring: true, paths: ["/"]),
                                            engine: engine(monitoring: false, paths: []))
        XCTAssertEqual(report.recorder, .daemon)
        XCTAssertEqual(report.watchedPaths, ["/"])
        XCTAssertTrue(report.isRecording)
        XCTAssertTrue(report.survivesQuitting)
        XCTAssertNotNil(report.startedAt)
    }

    func testTheAppReportsItsOwnWhenThereIsNoDaemon() {
        let report = CoverageReport.resolve(agent: nil, engine: engine(monitoring: true, paths: ["/Users"]))
        XCTAssertEqual(report.recorder, .app)
        XCTAssertEqual(report.watchedPaths, ["/Users"])
        XCTAssertFalse(report.survivesQuitting, "closing the app ends this recording")
    }

    func testADeadDaemonIsIgnored() {
        // Stale status files outlive the process that wrote them.
        let report = CoverageReport.resolve(agent: agent(monitoring: true, paths: ["/"], alive: false),
                                            engine: engine(monitoring: true, paths: ["/Users"]))
        XCTAssertEqual(report.recorder, .app)
        XCTAssertEqual(report.watchedPaths, ["/Users"])
    }

    func testNothingRecordingIsReportedAsSuch() {
        let report = CoverageReport.resolve(agent: nil, engine: engine(monitoring: false, paths: []))
        XCTAssertEqual(report.recorder, .none)
        XCTAssertFalse(report.isRecording)
        XCTAssertTrue(report.watchedPaths.isEmpty)
        XCTAssertNil(report.startedAt)
    }

    func testAPausedDaemonStillSaysWhatItWouldWatch() {
        let report = CoverageReport.resolve(agent: agent(monitoring: false, paths: ["/"]),
                                            engine: engine(monitoring: false, paths: []))
        XCTAssertFalse(report.isRecording)
        XCTAssertEqual(report.watchedPaths, ["/"], "the roots are still the answer to \"what would be watched\"")
        XCTAssertNil(report.startedAt, "but nothing is being recorded right now")
    }

    func testRootCoversEveryVolumeBeneathIt() {
        let report = CoverageReport.resolve(agent: agent(monitoring: true, paths: ["/"]),
                                            engine: engine(monitoring: false, paths: []))
        XCTAssertTrue(report.covers(mountPath: "/"))
        XCTAssertTrue(report.covers(mountPath: "/Volumes/BACKUP"))
    }

    func testASpecificRootCoversOnlyItself() {
        let report = CoverageReport.resolve(agent: nil, engine: engine(monitoring: true, paths: ["/Users"]))
        XCTAssertTrue(report.covers(mountPath: "/Users"))
        XCTAssertTrue(report.covers(mountPath: "/Users/matt/Data"))
        XCTAssertFalse(report.covers(mountPath: "/Volumes/BACKUP"))
        // A prefix match on the string alone would wrongly cover this.
        XCTAssertFalse(report.covers(mountPath: "/UsersBackup"))
    }
}
