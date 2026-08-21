import XCTest
@testable import HDWatcherCore

/// `MDQueryExecute` with `kMDQuerySynchronous` waits without a deadline, and
/// Spotlight is not always answering — it reindexes after a system update, it
/// can be switched off, it can simply be busy. The lookup that resolves where a
/// copied file came from ran inside the path that reports the copy, so a stuck
/// index did not merely lose the attribution: the transfer was never reported
/// at all. A copy to a USB stick silently produced no alert.
final class SpotlightTimeoutTests: XCTestCase {

    func testALookupComesBackWithinItsDeadline() {
        let locator = SpotlightLocator()
        locator.timeout = 0.5

        // Whatever Spotlight is doing, the caller is released on time.
        let started = Date()
        _ = locator.findByName("a-name-that-should-not-exist-\(UUID().uuidString).bin")
        XCTAssertLessThan(Date().timeIntervalSince(started), 3.0)
    }

    func testAnImpossibleDeadlineGivesUpRatherThanBlocking() {
        let locator = SpotlightLocator()
        locator.timeout = 0

        let started = Date()
        let found = locator.findByName("anything-\(UUID().uuidString)")
        XCTAssertTrue(found.isEmpty)
        XCTAssertLessThan(Date().timeIntervalSince(started), 1.0)
        XCTAssertGreaterThan(locator.timeouts, 0, "giving up has to be visible, not silent")
    }

    func testEmptyNamesAreNotSentToSpotlightAtAll() {
        let locator = SpotlightLocator()
        XCTAssertTrue(locator.findByName("").isEmpty)
        XCTAssertEqual(locator.timeouts, 0)
    }

    func testAStuckIndexIsAskedOnceNotOncePerFile() {
        // A hundred files copied at once must not wait out the deadline a
        // hundred times; a stuck index answers no faster for the last of them.
        let locator = SpotlightLocator()
        locator.timeout = 0
        locator.backoff = 30
        _ = locator.findByName("first-\(UUID().uuidString)")
        XCTAssertTrue(locator.isBackedOff)

        let started = Date()
        for index in 0..<50 { _ = locator.findByName("burst-\(index)-\(UUID().uuidString)") }
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.5)
        XCTAssertEqual(locator.timeouts, 1, "one refusal, not fifty-one")
    }

    func testRepeatedMissesAreNotRequeried() {
        let locator = SpotlightLocator()
        locator.timeout = 5
        let name = "definitely-not-on-this-disk-\(UUID().uuidString).xyz"
        _ = locator.findByName(name)

        // Answered from the cache — or from the backoff, when the index did not
        // answer at all. Either way the second call is immediate.
        let started = Date()
        XCTAssertTrue(locator.findByName(name).isEmpty)
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.2)
    }

    func testAnArrivalIsReportedEvenWhenNothingIsFound() {
        // The point of the deadline: something is always reported for a file
        // that appears on off-machine media.
        let detector = TransferDetector(registry: nil)
        var reported: FileEvent?
        detector.onTransfer = { reported = $0 }

        let arrival = FileEvent(kind: .created, path: "/Volumes/Elsewhere/report.pdf", size: 4_096)
        let finding = detector.testUnattributedArrival(arrival, destClass: .removable)
        XCTAssertEqual(finding.kind, .copiedOut,
                       "a file landing on removable media is data leaving this Mac")
        XCTAssertEqual(finding.confidence, .low)
        XCTAssertNil(finding.sourcePath)
        XCTAssertNil(reported, "this entry point returns the finding rather than publishing it")
    }
}
