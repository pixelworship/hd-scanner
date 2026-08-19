import XCTest
@testable import HDWatcherCore

/// The Recovery list polls once a second. These cover what that poll is allowed
/// to do — which is nothing at all, unless something actually changed.
final class RecoveryRefreshGateTests: XCTestCase {

    func testAPollWithNothingNewDoesNoWork() {
        var gate = RecoveryRefreshGate()
        XCTAssertTrue(gate.needsPass(revision: 4, deletedOnly: false, search: "biome"))
        gate.finished(revision: 4, deletedOnly: false, search: "biome")

        // The bug this exists for: every tick re-filtered thousands of groups
        // and flashed the spinner, for a list that had not changed.
        for _ in 0..<10 {
            XCTAssertFalse(gate.needsPass(revision: 4, deletedOnly: false, search: "biome"))
        }
    }

    func testNewCapturesTriggerAPass() {
        var gate = RecoveryRefreshGate()
        gate.finished(revision: 4, deletedOnly: false, search: "biome")
        XCTAssertTrue(gate.needsPass(revision: 5, deletedOnly: false, search: "biome"))
    }

    func testChangingTheFilterTriggersAPass() {
        var gate = RecoveryRefreshGate()
        gate.finished(revision: 4, deletedOnly: false, search: "biome")
        XCTAssertTrue(gate.needsPass(revision: 4, deletedOnly: true, search: "biome"))
        XCTAssertTrue(gate.needsPass(revision: 4, deletedOnly: false, search: "biom"))
        XCTAssertTrue(gate.needsPass(revision: 4, deletedOnly: false, search: nil))
    }

    func testForceAlwaysRuns() {
        var gate = RecoveryRefreshGate()
        gate.finished(revision: 4, deletedOnly: false, search: nil)
        XCTAssertTrue(gate.needsPass(revision: 4, deletedOnly: false, search: nil, force: true))
    }

    func testACancelledPassIsRepeated() {
        var gate = RecoveryRefreshGate()
        // Typing cancels a pass part-way; nothing is recorded, so the work is
        // still outstanding.
        XCTAssertTrue(gate.needsPass(revision: 1, deletedOnly: false, search: "bio"))
        XCTAssertTrue(gate.needsPass(revision: 1, deletedOnly: false, search: "bio"))
    }

    func testProgressIsShownOnlyForWhatTheReaderTyped() {
        var gate = RecoveryRefreshGate()
        // A new query: the reader is waiting.
        XCTAssertTrue(gate.showsProgress(for: "biome"))
        gate.finished(revision: 1, deletedOnly: false, search: "biome")

        // Same query, new data arriving: re-filter silently.
        XCTAssertFalse(gate.showsProgress(for: "biome"))

        // Typing again: waiting once more.
        XCTAssertTrue(gate.showsProgress(for: "biomes"))
    }

    func testNoProgressWithoutAQuery() {
        let gate = RecoveryRefreshGate()
        XCTAssertFalse(gate.showsProgress(for: nil))
        XCTAssertFalse(gate.showsProgress(for: ""))
    }

    func testResetForgetsEverything() {
        var gate = RecoveryRefreshGate()
        gate.finished(revision: 9, deletedOnly: false, search: "x")
        gate.reset()
        XCTAssertTrue(gate.needsPass(revision: 9, deletedOnly: false, search: "x"))
        XCTAssertTrue(gate.showsProgress(for: "x"))
    }
}
