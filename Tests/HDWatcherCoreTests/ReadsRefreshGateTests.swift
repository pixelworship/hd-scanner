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

/// The Reads list is fed from two directions at once — a scan of the log and a
/// live stream of new reads — and getting that wrong broke the window itself:
/// rows reordering every second under a List, and the list flipping to empty
/// mid-scan, which tore down the split view and took the sidebar with it.
/// The merge rules live here so they can be checked without a running app.
final class ReadMergeOrderingTests: XCTestCase {

    /// Mirrors AppModel.ReadGroup's ordering contract: newest read first.
    private struct Group {
        let path: String
        var timestamps: [Date]
        var lastRead: Date { timestamps.max() ?? .distantPast }
    }

    private func merge(existing: [Group], incoming: [(String, Date)]) -> [Group] {
        var indexByPath: [String: Int] = [:]
        for (index, group) in existing.enumerated() { indexByPath[group.path] = index }
        var updated = existing
        var fresh: [Group] = []
        for (path, at) in incoming {
            if let index = indexByPath[path] {
                updated[index].timestamps.insert(at, at: 0)
            } else if let position = fresh.firstIndex(where: { $0.path == path }) {
                fresh[position].timestamps.insert(at, at: 0)
            } else {
                fresh.append(Group(path: path, timestamps: [at]))
            }
        }
        fresh.sort { $0.lastRead > $1.lastRead }
        return fresh + updated
    }

    func testAnExistingRowIsUpdatedWhereItSitsRatherThanMoved() {
        let now = Date()
        let existing = [
            Group(path: "/a.txt", timestamps: [now.addingTimeInterval(-300)]),
            Group(path: "/b.txt", timestamps: [now.addingTimeInterval(-200)]),
            Group(path: "/c.txt", timestamps: [now.addingTimeInterval(-100)]),
        ]
        // /a.txt is read again — the newest read in the list — but it must not
        // jump to the top. Rows moving under the pointer once a second is both
        // unreadable and enough churn to break the layout.
        let merged = merge(existing: existing, incoming: [("/a.txt", now)])
        XCTAssertEqual(merged.map(\.path), ["/a.txt", "/b.txt", "/c.txt"])
        XCTAssertEqual(merged[0].timestamps.count, 2, "the new read is still recorded")
    }

    func testAFileNotSeenBeforeGoesToTheTop() {
        let now = Date()
        let existing = [Group(path: "/a.txt", timestamps: [now.addingTimeInterval(-300)])]
        let merged = merge(existing: existing, incoming: [("/new.txt", now)])
        XCTAssertEqual(merged.map(\.path), ["/new.txt", "/a.txt"])
    }

    func testSeveralNewFilesArriveNewestFirst() {
        let now = Date()
        let merged = merge(existing: [], incoming: [
            ("/old.txt", now.addingTimeInterval(-10)),
            ("/newest.txt", now),
            ("/middle.txt", now.addingTimeInterval(-5)),
        ])
        XCTAssertEqual(merged.map(\.path), ["/newest.txt", "/middle.txt", "/old.txt"])
    }

    func testRepeatedReadsOfOneNewFileAreOneRow() {
        let now = Date()
        let merged = merge(existing: [], incoming: [
            ("/loop.bin", now.addingTimeInterval(-2)),
            ("/loop.bin", now.addingTimeInterval(-1)),
            ("/loop.bin", now),
        ])
        XCTAssertEqual(merged.count, 1, "one file is one row, however often it is read")
        XCTAssertEqual(merged[0].timestamps.count, 3)
    }
}
