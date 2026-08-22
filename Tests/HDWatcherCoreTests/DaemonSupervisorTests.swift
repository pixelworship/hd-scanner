import XCTest
@testable import HDWatcherCore

/// A macOS update leaves SMAppService reporting a daemon as installed while
/// launchd has no such service — `launchctl kickstart` answers "Could not find
/// service … in domain for system". The app believed the bookkeeping and said
/// "Installed, starting up" forever, recording nothing.
final class DaemonSupervisorTests: XCTestCase {

    private func input(state: BackgroundService.State = .enabled,
                       wanted: Bool = true,
                       heartbeatAge: TimeInterval? = nil,
                       processAlive: Bool = false,
                       registeredAgo: TimeInterval? = nil,
                       attempts: Int = 0) -> DaemonSupervisor.Input {
        DaemonSupervisor.Input(
            state: state, wanted: wanted,
            heartbeat: heartbeatAge.map { Date(timeIntervalSinceNow: -$0) },
            processAlive: processAlive,
            registeredAt: registeredAgo.map { Date(timeIntervalSinceNow: -$0) },
            repairAttempts: attempts)
    }

    func testARecentHeartbeatIsProofOfRecording() {
        let verdict = DaemonSupervisor.assess(input(heartbeatAge: 4))
        XCTAssertEqual(verdict.health, .recording)
        XCTAssertEqual(verdict.repair, .none)
    }

    func testRegisteredWithNoHeartbeatIsAFailureNotAStartup() {
        // The bug: registered, nothing running, and the app waited forever.
        let verdict = DaemonSupervisor.assess(input(heartbeatAge: 600, registeredAgo: 3_600))
        XCTAssertEqual(verdict.health, .droppedByLaunchd)
        XCTAssertEqual(verdict.repair, .reregister)
        XCTAssertTrue(DaemonSupervisor.shouldRepairAutomatically(verdict))
    }

    func testNeverHeardFromAndLongPastRegistrationIsAlsoAFailure() {
        let verdict = DaemonSupervisor.assess(input(heartbeatAge: nil, registeredAgo: 3_600))
        XCTAssertEqual(verdict.health, .droppedByLaunchd)
    }

    func testAFreshRegistrationIsGivenTimeToStart() {
        let verdict = DaemonSupervisor.assess(input(registeredAgo: 5))
        XCTAssertEqual(verdict.health, .startingUp)
        XCTAssertEqual(verdict.repair, .wait)
        XCTAssertFalse(DaemonSupervisor.shouldRepairAutomatically(verdict))
    }

    func testALiveProcessThatHasNotWrittenYetIsStartingUp() {
        // Running but silent is a different thing from absent, and must not
        // trigger a re-registration that would kill it.
        let verdict = DaemonSupervisor.assess(input(heartbeatAge: 300, processAlive: true))
        XCTAssertEqual(verdict.health, .startingUp)
        XCTAssertEqual(verdict.repair, .wait)
    }

    func testRepairIsNotAttemptedForever() {
        let verdict = DaemonSupervisor.assess(input(heartbeatAge: 600, registeredAgo: 3_600,
                                                    attempts: DaemonSupervisor.maximumRepairAttempts))
        XCTAssertEqual(verdict.repair, .askForHelp)
        XCTAssertFalse(DaemonSupervisor.shouldRepairAutomatically(verdict))
        XCTAssertTrue(verdict.detail.contains("Login Items"))
    }

    func testApprovalWithdrawnByAnUpdateAsksForApproval() {
        let verdict = DaemonSupervisor.assess(input(state: .requiresApproval))
        XCTAssertEqual(verdict.health, .needsApproval)
        XCTAssertEqual(verdict.repair, .openLoginItems)
    }

    func testUnregisteredButWantedIsRepaired() {
        let verdict = DaemonSupervisor.assess(input(state: .notRegistered))
        XCTAssertEqual(verdict.health, .notInstalled)
        XCTAssertEqual(verdict.repair, .reregister)
    }

    func testUnregisteredAndUnwantedIsNotAProblem() {
        let verdict = DaemonSupervisor.assess(input(state: .notRegistered, wanted: false))
        XCTAssertEqual(verdict.health, .disabledByUser)
        XCTAssertEqual(verdict.repair, .none)
    }

    func testAStaleHeartbeatIsNotAccepted() {
        // Exactly at the deadline counts as stale: the daemon writes far more
        // often than this when it is alive.
        let verdict = DaemonSupervisor.assess(
            input(heartbeatAge: DaemonSupervisor.heartbeatDeadline + 1, registeredAgo: 3_600))
        XCTAssertNotEqual(verdict.health, .recording)
    }

    func testOldMacOSIsReportedPlainlyRatherThanAsBroken() {
        let verdict = DaemonSupervisor.assess(input(state: .unsupported))
        XCTAssertEqual(verdict.health, .unsupported)
        XCTAssertEqual(verdict.repair, .none)
    }
}

/// A permanently installed daemon is launchd's to start. Telling the user it is
/// "registered but not running" and offering to re-register sends them back
/// round a loop that does not apply to it.
final class DurableDaemonVerdictTests: XCTestCase {

    private func input(heartbeatAge: TimeInterval?, processAlive: Bool = false,
                       registeredAgo: TimeInterval? = nil) -> DaemonSupervisor.Input {
        DaemonSupervisor.Input(
            state: .enabled, wanted: true,
            heartbeat: heartbeatAge.map { Date(timeIntervalSinceNow: -$0) },
            processAlive: processAlive,
            registeredAt: registeredAgo.map { Date(timeIntervalSinceNow: -$0) },
            isDurable: true)
    }

    func testARecentHeartbeatIsStillAllTheProofNeeded() {
        XCTAssertEqual(DaemonSupervisor.assess(input(heartbeatAge: 3)).health, .recording)
    }

    func testItIsNeverAskedToReregister() {
        let verdict = DaemonSupervisor.assess(input(heartbeatAge: 3_600, registeredAgo: 7_200))
        XCTAssertEqual(verdict.repair, .askForHelp)
        XCTAssertFalse(DaemonSupervisor.shouldRepairAutomatically(verdict))
        XCTAssertTrue(verdict.detail.contains("launchctl print"),
                      "the user needs the command that says what launchd thinks")
    }

    func testItIsGivenLongerToStart() {
        // It boots before login and may be waiting on the disk; a freshly
        // installed one is not a broken one.
        XCTAssertEqual(DaemonSupervisor.assess(input(heartbeatAge: nil, registeredAgo: 60)).health,
                       .startingUp)
    }
}
