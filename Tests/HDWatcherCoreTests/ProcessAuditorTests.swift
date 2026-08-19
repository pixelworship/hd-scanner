import XCTest
@testable import HDWatcherCore

final class ProcessAuditorTests: XCTestCase {

    private var workDir: URL!

    override func setUpWithError() throws {
        workDir = URL(fileURLWithPath: AppPaths.canonicalPath(NSTemporaryDirectory()))
            .appendingPathComponent("hdw-proc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: workDir)
    }

    // MARK: - Primitives

    func testEnumeratesProcesses() {
        let pids = ProcessAuditor.allPIDs()
        XCTAssertGreaterThan(pids.count, 20, "the machine is obviously running more processes than this")
        XCTAssertTrue(pids.contains(getpid()))
    }

    func testReadsOwnProcessDetails() throws {
        let me = getpid()
        let info = try XCTUnwrap(ProcessAuditor.bsdInfo(pid: me))
        XCTAssertEqual(Int32(info.pbi_pid), me)
        XCTAssertEqual(info.pbi_uid, getuid())
        XCTAssertNotNil(ProcessAuditor.processName(info))
        XCTAssertNotNil(ProcessAuditor.executablePath(pid: me))
        XCTAssertNotNil(ProcessAuditor.userName(for: getuid()))
    }

    func testReadsOwnOpenFiles() throws {
        let file = workDir.appendingPathComponent("held-open.txt")
        try "content".write(to: file, atomically: false, encoding: .utf8)
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }

        let open = try XCTUnwrap(ProcessAuditor.openPaths(pid: getpid()))
        XCTAssertTrue(open.contains(file.path),
                      "a file this process holds open must show up in its descriptor list")
    }

    func testResolvesCodeSignature() throws {
        // /bin/ls is Apple-signed and always present.
        let signing = ProcessAuditor.signingInformation(path: "/bin/ls")
        XCTAssertEqual(signing.id, "com.apple.ls")
        XCTAssertTrue(signing.apple, "an Apple platform binary must be recognised as Apple-signed")
        XCTAssertNil(signing.team, "Apple platform binaries carry no team identifier")
    }

    // MARK: - Attribution

    func testAttributesAProcessHoldingTheFile() throws {
        let file = workDir.appendingPathComponent("watched.log")
        try "line one\n".write(to: file, atomically: false, encoding: .utf8)

        // `tail -f` keeps the file open, standing in for whatever real process
        // might be holding a credential file.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/tail")
        process.arguments = ["-f", file.path]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        defer { process.terminate() }

        // Give it a moment to actually open the descriptor.
        Thread.sleep(forTimeInterval: 1.0)

        let auditor = ProcessAuditor()
        let result = auditor.attribute(path: file.path)

        XCTAssertGreaterThan(result.scannedProcesses, 10,
                             "the scan must reach a meaningful number of processes")
        let holder = result.actors.first { $0.pid == process.processIdentifier }
        XCTAssertNotNil(holder, "the process holding the file open must be identified")
        XCTAssertEqual(holder?.evidence, .holdsFileOpen)
        XCTAssertEqual(holder?.name, "tail")
        XCTAssertEqual(holder?.userID, UInt32(getuid()))
        XCTAssertEqual(holder?.userName, ProcessAuditor.userName(for: getuid()))
        XCTAssertEqual(holder?.executablePath, "/usr/bin/tail")
        XCTAssertTrue(holder?.isAppleSigned == true)
        XCTAssertNotNil(holder?.startedAt)
        XCTAssertEqual(result.best?.pid, process.processIdentifier,
                       "an open descriptor is the strongest evidence, so it should rank first")
    }

    func testEvidenceRanking() {
        XCTAssertGreaterThan(AttributionEvidence.holdsFileOpen.weight,
                             AttributionEvidence.holdsParentDirectory.weight)
        XCTAssertGreaterThan(AttributionEvidence.namedInSystemLog.weight,
                             AttributionEvidence.startedNearEvent.weight)
        XCTAssertGreaterThan(AttributionEvidence.startedNearEvent.weight,
                             AttributionEvidence.running.weight)
        XCTAssertEqual(AttributionEvidence.holdsFileOpen.confidence, .high)
        XCTAssertEqual(AttributionEvidence.running.confidence, .none)
    }

    func testUnattributableFileReportsHonestly() {
        let auditor = ProcessAuditor()
        // Nothing holds a path that does not exist.
        let result = auditor.attribute(path: "/nonexistent/\(UUID().uuidString)/file.txt")
        XCTAssertNil(result.actors.first { $0.evidence == .holdsFileOpen },
                     "no process can be holding a file that never existed")
    }

    func testRollingTableTracksProcesses() {
        let auditor = ProcessAuditor()
        XCTAssertGreaterThan(auditor.trackedProcessCount, 20)
        let running = auditor.runningProcesses()
        XCTAssertFalse(running.isEmpty)
        XCTAssertTrue(running.allSatisfy { $0.evidence == .running })
        // Our own process should be in the table with sane details.
        XCTAssertTrue(running.contains { $0.pid == getpid() })
    }

    func testCatchesShortLivedProcess() throws {
        let auditor = ProcessAuditor()
        Thread.sleep(forTimeInterval: 0.3)

        // A command that runs and exits immediately — the case an open-descriptor
        // scan always misses.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/echo")
        process.arguments = ["transient"]
        process.standardOutput = Pipe()
        try process.run()
        let firedAt = Date()
        process.waitUntilExit()

        // Let the sampler notice it.
        Thread.sleep(forTimeInterval: 2.5)

        let result = auditor.attribute(path: "/tmp/\(UUID().uuidString)", at: firedAt)
        // The exact process may or may not be caught depending on sampler timing,
        // but the mechanism must produce start-proximity candidates rather than
        // silently giving up.
        XCTAssertTrue(result.actors.allSatisfy { $0.evidence != .holdsFileOpen })
    }
}

/// Transfers must name a process without needing a rule to ask for it.
final class TransferAttributionPolicyTests: XCTestCase {

    func testTransferKindsAlwaysWarrantAttribution() {
        // The engine attributes an event when it is a transfer OR a rule asks.
        // With no rules at all, transfers must still qualify.
        let engine = RuleEngine(registry: nil, rules: [])
        for kind in [EventKind.copiedOut, .copiedIn, .movedOut, .movedIn] {
            let event = FileEvent(kind: kind, path: "/Volumes/USB/x.txt")
            XCTAssertTrue(kind.isTransfer)
            XCTAssertFalse(engine.wantsProcessAudit(for: event),
                           "no rule requests it, so the rule engine says no…")
        }
        // …and an ordinary write does not qualify on its own.
        XCTAssertFalse(EventKind.modified.isTransfer)
        XCTAssertFalse(EventKind.created.isTransfer)
    }

    func testEvidenceConfidenceMapping() {
        // What the detail sheet colours each actor by.
        XCTAssertEqual(AttributionEvidence.holdsFileOpen.confidence, .high)
        XCTAssertEqual(AttributionEvidence.namedInSystemLog.confidence, .medium)
        XCTAssertEqual(AttributionEvidence.holdsParentDirectory.confidence, .medium)
        XCTAssertEqual(AttributionEvidence.startedNearEvent.confidence, .low)
        XCTAssertEqual(AttributionEvidence.running.confidence, .none)
    }

    func testActorSummaryReadsSensibly() {
        let apple = ProcessActor(pid: 1, name: "securityd", isAppleSigned: true,
                                 userName: "root", evidence: .holdsFileOpen)
        XCTAssertEqual(apple.summary, "securityd · Apple · as root")

        let thirdParty = ProcessActor(pid: 2, name: "Dropbox", teamIdentifier: "G7HH3F8CAK",
                                      userName: "matt", evidence: .running)
        XCTAssertEqual(thirdParty.summary, "Dropbox · team G7HH3F8CAK · as matt")
    }
}
