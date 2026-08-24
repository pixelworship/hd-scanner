import XCTest
@testable import HDWatcherCore

/// TEMPORARY probe (review verification only) — delete after running.
final class ZZFlapProbeTests: XCTestCase {

    func testAContinuouslyOpenFileIsReReportedWhenAPassSkipsItsProcess() throws {
        let raw = FileManager.default.temporaryDirectory
            .appendingPathComponent("flap-probe-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
        let dir = URL(fileURLWithPath: AppPaths.canonicalPath(raw.path))
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("contract.txt")
        try "held open the whole time".write(to: file, atomically: true, encoding: .utf8)

        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = [dir.path]
        configuration.excludePatterns = []
        configuration.maximumDescriptorsPerProcess = 512
        let watcher = FileAccessMonitor(configuration: configuration)

        let scriptURL = dir.appendingPathComponent("holder.py")
        try """
        import os, sys, time
        f = open(sys.argv[1])
        time.sleep(4)                                     # phase A: few fds
        fds = [os.open('/dev/null', os.O_RDONLY) for _ in range(700)]
        time.sleep(4)                                     # phase B: over the limit
        for fd in fds: os.close(fd)
        time.sleep(10)                                    # phase C: few fds again
        f.close()
        """.write(to: scriptURL, atomically: true, encoding: .utf8)

        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        child.arguments = [scriptURL.path, file.path]
        try child.run()
        defer { child.terminate() }
        Thread.sleep(forTimeInterval: 2.0)
        let pid = child.processIdentifier
        print("PROBE child pid \(pid) fds=\(ProcessAuditor.openPaths(pid: pid)?.count ?? -1)")

        var finished: [FileAccessMonitor.Access] = []
        watcher.onAccessFinished = { finished.append($0) }

        watcher.sample()                                   // prime (phase A)
        let firstSighting = watcher.sample()               // phase A: real open reported
        XCTAssertTrue(firstSighting.contains { $0.path == file.path },
                      "phase A must see the held file: \(firstSighting.map(\.path))")
        let openedAtFirst = firstSighting.first { $0.path == file.path }!.openedAt

        Thread.sleep(forTimeInterval: 3.0)                 // into phase B
        print("PROBE phase B fds=\(ProcessAuditor.openPaths(pid: pid, limit: 512)?.count ?? -1)")
        let duringSkip = watcher.sample()                  // holder skipped
        XCTAssertFalse(duringSkip.contains { $0.path == file.path })
        XCTAssertTrue(finished.contains { $0.path == file.path },
                      "the file was reported CLOSED while still open")

        Thread.sleep(forTimeInterval: 4.0)                 // into phase C
        let reappearance = watcher.sample()
        let refabricated = reappearance.first { $0.path == file.path }
        XCTAssertNotNil(refabricated, "phase C sees it again")
        print("PROBE first openedAt=\(openedAtFirst) second openedAt=\(refabricated!.openedAt) delta=\(refabricated!.openedAt.timeIntervalSince(openedAtFirst)) samples=\(refabricated!.samples)")
        XCTAssertGreaterThan(refabricated!.openedAt.timeIntervalSince(openedAtFirst), 3,
                             "a brand-new read event with a fabricated timestamp")
    }
}
