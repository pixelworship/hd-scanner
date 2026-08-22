import XCTest
@testable import HDWatcherCore

/// Two recorders writing one log is not untidiness — each keeps its own hash
/// chain and its own manifest, so they interleave into a log that cannot be
/// verified afterwards. This vault was found in exactly that state, reported
/// as tampering. The recorders settle it between themselves rather than relying
/// on every install path getting the sequence right.
final class RecorderLockTests: XCTestCase {

    private var directory: URL!
    private var lockFile: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-lock-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        lockFile = directory.appendingPathComponent("recorder.lock")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testTheFirstRecorderGetsIt() {
        let lock = RecorderLock(url: lockFile)
        XCTAssertTrue(lock.acquire())
        XCTAssertTrue(lock.isHeld)
        lock.release()
        XCTAssertFalse(lock.isHeld)
    }

    func testTakingItTwiceFromOneProcessIsHarmless() {
        let lock = RecorderLock(url: lockFile)
        XCTAssertTrue(lock.acquire())
        XCTAssertTrue(lock.acquire(), "re-entrancy must not deadlock the recorder against itself")
        lock.release()
    }

    func testItRecordsWhoHoldsIt() throws {
        let lock = RecorderLock(url: lockFile)
        XCTAssertTrue(lock.acquire())
        XCTAssertEqual(lock.holder, ProcessInfo.processInfo.processIdentifier,
                       "a human looking at the file should be able to tell who has it")
        lock.release()
    }

    func testAnotherProcessIsRefusedWhileItIsHeld() throws {
        let lock = RecorderLock(url: lockFile)
        XCTAssertTrue(lock.acquire())
        defer { lock.release() }

        // A real second process, because flock is per-descriptor and a second
        // object in this process would not prove anything.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/flock")
        process.arguments = ["-n", lockFile.path, "-c", "true"]
        if FileManager.default.isExecutableFile(atPath: "/usr/bin/flock") {
            try process.run()
            process.waitUntilExit()
            XCTAssertNotEqual(process.terminationStatus, 0, "the lock must exclude other processes")
        }
    }

    func testItIsReleasedForATakeover() {
        // The waiting recorder takes over when the holder stops, rather than
        // exiting and leaving nothing recording.
        let first = RecorderLock(url: lockFile)
        XCTAssertTrue(first.acquire())
        first.release()

        let second = RecorderLock(url: lockFile)
        XCTAssertTrue(second.acquire())
        second.release()
    }

    func testAnUnwritableLocationIsRefusedNotAssumed() {
        let lock = RecorderLock(url: URL(fileURLWithPath: "/System/nowhere/recorder.lock"))
        XCTAssertFalse(lock.acquire())
        XCTAssertFalse(lock.isHeld)
    }
}
