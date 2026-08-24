import XCTest
@testable import HDWatcherCore

/// The Reads spinner spun forever, twice, for the same reason: the poll
/// cancelled the query still running, and the guard against that compared with
/// state only written when a pass completes — which, thanks to the guard,
/// never happened. These tests are the cold-start sequence that both shipped
/// versions failed.
final class ReadsRefreshGateTests: XCTestCase {

    func testColdStartPollsWaitInsteadOfCancelling() {
        var gate = ReadsRefreshGate()
        XCTAssertEqual(gate.decide(signature: ""), .start)

        // The bug, exactly: polls arriving while the first pass is still
        // running must wait, not restart. Restarting is why the list never
        // appeared — the pass takes minutes and the poll fires every two
        // seconds.
        for _ in 0..<5 {
            XCTAssertEqual(gate.decide(signature: ""), .waitForRunning)
        }
    }

    func testAFinishedPassIsNeverRescannedByThePoll() {
        var gate = ReadsRefreshGate()
        _ = gate.decide(signature: "")
        gate.finished(signature: "")
        // Deliberately no notion of "new data arrived": a full pass costs
        // minutes, so new reads reach the list from the live stream instead.
        for _ in 0..<5 {
            XCTAssertEqual(gate.decide(signature: ""), .skip)
        }
    }

    func testTypingRestartsBecauseTheQueryChanged() {
        var gate = ReadsRefreshGate()
        _ = gate.decide(signature: "")
        XCTAssertEqual(gate.decide(signature: "invoice"), .start,
                       "a different query is the one legitimate reason to cancel")
    }

    func testForceRestartsEvenTheSameQuery() {
        var gate = ReadsRefreshGate()
        _ = gate.decide(signature: "")
        XCTAssertEqual(gate.decide(signature: "", force: true), .start)
    }

    func testACancelledPassIsStillOutstanding() {
        var gate = ReadsRefreshGate()
        _ = gate.decide(signature: "")
        gate.cancelled(signature: "")
        XCTAssertEqual(gate.decide(signature: ""), .start,
                       "abandoned work must be repeated, not assumed done")
    }

    func testClearingTheSearchIsItsOwnQuery() {
        var gate = ReadsRefreshGate()
        _ = gate.decide(signature: "invoice")
        gate.finished(signature: "invoice")
        XCTAssertEqual(gate.decide(signature: ""), .start)
    }
}
