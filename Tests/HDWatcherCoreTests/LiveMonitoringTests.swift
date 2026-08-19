import XCTest
import CryptoKit
@testable import HDWatcherCore

/// End-to-end tests against the real filesystem and a real mounted volume.
/// These exercise FSEvents, volume attribution, transfer inference and the
/// encrypted log together — the parts that unit tests cannot prove work.
final class LiveMonitoringTests: XCTestCase {

    private var workDir: URL!
    private var vault: VaultKeyManager!
    private var store: EventStore!
    private var engine: WatcherEngine!
    private static var dmgPath: URL?
    private static var dmgMount: String?

    // MARK: - Disk image helpers

    @discardableResult
    private static func shell(_ launchPath: String, _ args: [String]) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try? process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    override class func setUp() {
        super.setUp()
        // A writable disk image stands in for an external drive: macOS reports
        // it as a separate, non-internal volume, which is exactly the boundary
        // the transfer detector cares about.
        let path = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-itest-\(UUID().uuidString.prefix(8)).dmg")
        let create = shell("/usr/bin/hdiutil", [
            "create", "-size", "40m", "-fs", "APFS",
            "-volname", "HDWTestDrive", "-quiet", path.path
        ])
        guard create.status == 0 else {
            print("hdiutil create failed: \(create.output)")
            return
        }
        dmgPath = path

        let attach = shell("/usr/bin/hdiutil", ["attach", path.path, "-nobrowse"])
        guard attach.status == 0 else {
            print("hdiutil attach failed: \(attach.output)")
            return
        }
        // Output looks like: /dev/disk5s1  Apple_APFS  /Volumes/HDWTestDrive
        for line in attach.output.split(separator: "\n") {
            if let range = line.range(of: "/Volumes/") {
                let mount = String(line[range.lowerBound...]).trimmingCharacters(in: .whitespaces)
                dmgMount = AppPaths.canonicalPath(mount)
            }
        }
        print("mounted test volume at: \(dmgMount ?? "nil")")
    }

    override class func tearDown() {
        if let mount = dmgMount {
            shell("/usr/bin/hdiutil", ["detach", mount, "-force", "-quiet"])
        }
        if let path = dmgPath {
            try? FileManager.default.removeItem(at: path)
        }
        super.tearDown()
    }

    // MARK: - Fixture

    override func setUpWithError() throws {
        let raw = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-live-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
        // FSEvents reports canonical paths (/var is a symlink to /private/var),
        // so the fixture must use canonical paths or every comparison is a
        // false negative.
        workDir = URL(fileURLWithPath: AppPaths.canonicalPath(raw.path))
        // Redirect storage away from the machine's real directories. Without
        // this the store also reads the live daemon's log in /Library, and its
        // segments show up here as unexplained history.
        setenv(AppPaths.overrideEnvironmentKey,
               workDir.appendingPathComponent("support").path, 1)

        vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "integration-test-password", enableQuickUnlock: false)
        store = try EventStore(keys: vault.currentKeys!, directory: workDir.appendingPathComponent("log"))
    }

    override func tearDownWithError() throws {
        engine?.stop()
        store?.close()
        engine = nil
        store = nil
        unsetenv(AppPaths.overrideEnvironmentKey)
        try? FileManager.default.removeItem(at: workDir)
    }

    /// Starts an engine watching the given paths with filtering disabled, so
    /// activity in a temp directory is not treated as noise.
    private func startEngine(watching paths: [String], rules: [AlertRule] = []) throws {
        var settings = AppSettings.default
        settings.watchScope = .customPaths
        settings.customWatchPaths = paths
        settings.filter = .raw
        settings.transferSettleSeconds = 1.0
        settings.notificationsEnabled = false

        engine = WatcherEngine(store: store, settings: settings, rules: rules)
        XCTAssertTrue(engine.start(), "engine must start with paths \(paths)")
        // FSEvents needs a moment before it begins delivering.
        Thread.sleep(forTimeInterval: 1.0)
    }

    /// Polls until `condition` holds or the timeout expires.
    @discardableResult
    private func wait(seconds: TimeInterval = 12, for condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if condition() { return true }
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
        }
        return condition()
    }

    private func loggedEvents() -> [FileEvent] {
        store.flush()
        return store.query(EventQuery())
    }

    // MARK: - Tests

    func testCapturesRealFileLifecycle() throws {
        try startEngine(watching: [workDir.path])

        let file = workDir.appendingPathComponent("subject.txt")
        try "first write".write(to: file, atomically: false, encoding: .utf8)

        XCTAssertTrue(wait { loggedEvents().contains { $0.path == file.path && $0.kind == .created } },
                      "creating a file must produce a Created event")

        try "second write, longer content".write(to: file, atomically: false, encoding: .utf8)
        XCTAssertTrue(wait { loggedEvents().contains { $0.path == file.path && $0.kind == .modified } },
                      "writing to an existing file must produce a Modified event")

        try FileManager.default.removeItem(at: file)
        XCTAssertTrue(wait { loggedEvents().contains { $0.path == file.path && $0.kind == .removed } },
                      "deleting a file must produce a Deleted event")
    }

    func testRecordsFileSizeAndVolume() throws {
        try startEngine(watching: [workDir.path])

        let file = workDir.appendingPathComponent("sized.bin")
        let payload = Data(repeating: 0x41, count: 65_536)
        try payload.write(to: file)

        XCTAssertTrue(wait {
            loggedEvents().contains { $0.path == file.path && ($0.size ?? 0) == 65_536 }
        }, "the recorded event must carry the real file size")

        let event = loggedEvents().first { $0.path == file.path && ($0.size ?? 0) == 65_536 }
        XCTAssertNotNil(event?.volumeID, "events must be attributed to a volume")
        XCTAssertNotNil(event?.inode, "extended FSEvents data must supply the inode")
    }

    func testDetectsRenameWithCertainty() throws {
        try startEngine(watching: [workDir.path])

        let original = workDir.appendingPathComponent("before.txt")
        try "rename me".write(to: original, atomically: false, encoding: .utf8)
        XCTAssertTrue(wait { loggedEvents().contains { $0.path == original.path } })

        let renamed = workDir.appendingPathComponent("after.txt")
        try FileManager.default.moveItem(at: original, to: renamed)

        XCTAssertTrue(wait {
            loggedEvents().contains { event in
                event.kind == .renamed && event.sourcePath == original.path && event.path == renamed.path
            }
        }, "a same-volume rename must be paired by inode into one event with both paths")

        let pair = loggedEvents().first { $0.kind == .renamed && $0.sourcePath == original.path }
        XCTAssertEqual(pair?.confidence, .certain,
                       "inode pairing is direct observation, so confidence is Certain")
    }

    // MARK: - Cross-volume

    func testDetectsCopyToExternalVolume() throws {
        let mount = try XCTUnwrap(Self.dmgMount, "test disk image is not mounted")
        try startEngine(watching: [workDir.path, mount])

        // Confirm the disk image really is classified as off-machine, or the
        // rest of this test proves nothing.
        let destVolume = engine.registry.volume(for: mount)
        XCTAssertNotNil(destVolume)
        XCTAssertTrue(destVolume!.volumeClass.isOffMachine,
                      "a mounted disk image must classify as off-machine, got \(destVolume!.volumeClass)")

        let source = workDir.appendingPathComponent("confidential.txt")
        let payload = String(repeating: "sensitive-payload-", count: 500)
        try payload.write(to: source, atomically: false, encoding: .utf8)
        XCTAssertTrue(wait { loggedEvents().contains { $0.path == source.path } },
                      "the source file must be observed before it can be correlated")

        let destination = URL(fileURLWithPath: mount).appendingPathComponent("confidential.txt")
        try FileManager.default.copyItem(at: source, to: destination)

        let found = wait(seconds: 20) {
            loggedEvents().contains { $0.kind == .copiedOut && $0.path == destination.path }
        }
        let transfer = loggedEvents().first { $0.kind == .copiedOut && $0.path == destination.path }

        XCTAssertTrue(found, "copying a file to an external volume must be detected as Copied Out")
        XCTAssertEqual(transfer?.sourcePath, source.path,
                       "the detector must identify where the copy came from")
        XCTAssertGreaterThanOrEqual(transfer?.confidence ?? .none, .high,
                                    "a live source with matching content should give High confidence")
        XCTAssertEqual(transfer?.severity, .warning, "data leaving the machine defaults to Warning")
    }

    func testDetectsMoveToExternalVolume() throws {
        let mount = try XCTUnwrap(Self.dmgMount, "test disk image is not mounted")
        try startEngine(watching: [workDir.path, mount])

        let source = workDir.appendingPathComponent("relocated.dat")
        try Data(repeating: 0x7A, count: 40_000).write(to: source)
        XCTAssertTrue(wait { loggedEvents().contains { $0.path == source.path } })

        let destination = URL(fileURLWithPath: mount).appendingPathComponent("relocated.dat")
        try FileManager.default.moveItem(at: source, to: destination)

        let found = wait(seconds: 20) {
            loggedEvents().contains {
                ($0.kind == .movedOut || $0.kind == .copiedOut) && $0.path == destination.path
            }
        }
        XCTAssertTrue(found, "moving a file across volumes must be detected as a transfer")

        let transfer = loggedEvents().first {
            ($0.kind == .movedOut || $0.kind == .copiedOut) && $0.path == destination.path
        }
        XCTAssertEqual(transfer?.sourcePath, source.path)
        XCTAssertGreaterThanOrEqual(transfer?.confidence ?? .none, .high)
    }

    func testExfiltrationRuleFiresOnRealCopy() throws {
        let mount = try XCTUnwrap(Self.dmgMount, "test disk image is not mounted")

        // The shipping built-in rule, unmodified.
        let rule = try XCTUnwrap(
            AlertRule.builtInRules().first { $0.name == "Data copied to external drive" }
        )
        try startEngine(watching: [workDir.path, mount], rules: [rule])

        let collector = AlertCollector()
        engine.onAlert = { alert in collector.add(alert) }

        let source = workDir.appendingPathComponent("payroll.txt")
        try String(repeating: "salary-data-", count: 400)
            .write(to: source, atomically: false, encoding: .utf8)
        XCTAssertTrue(wait { loggedEvents().contains { $0.path == source.path } })

        try FileManager.default.copyItem(
            at: source,
            to: URL(fileURLWithPath: mount).appendingPathComponent("payroll.txt")
        )

        let fired = wait(seconds: 20) { !collector.all.isEmpty }
        XCTAssertTrue(fired, "the built-in exfiltration rule must fire on a real copy to external media")

        let alert = collector.all.first
        XCTAssertEqual(alert?.ruleName, "Data copied to external drive")
        XCTAssertEqual(alert?.severity, .warning)
        XCTAssertEqual(alert?.event?.path.hasSuffix("payroll.txt"), true)
    }

    // MARK: - Whole-pipeline properties

    func testEventsAreEncryptedOnDisk() throws {
        try startEngine(watching: [workDir.path])

        let marker = "UNIQUE-PLAINTEXT-MARKER-9F2C7A"
        let file = workDir.appendingPathComponent("\(marker).txt")
        try "content".write(to: file, atomically: false, encoding: .utf8)
        XCTAssertTrue(wait { loggedEvents().contains { $0.path.contains(marker) } })

        store.flush()
        // The path must not be recoverable by reading the segment files.
        let logDir = workDir.appendingPathComponent("log")
        let segments = try FileManager.default.contentsOfDirectory(atPath: logDir.path)
            .filter { $0.hasSuffix(".hdwseg") }
        XCTAssertFalse(segments.isEmpty, "events must have been written to a segment")

        for name in segments {
            let bytes = try Data(contentsOf: logDir.appendingPathComponent(name))
            XCTAssertNil(bytes.range(of: Data(marker.utf8)),
                         "a filename must never appear in cleartext inside \(name)")
        }
    }

    func testHotspotsReflectRealActivity() throws {
        try startEngine(watching: [workDir.path])

        let busy = workDir.appendingPathComponent("busy")
        let quiet = workDir.appendingPathComponent("quiet")
        try FileManager.default.createDirectory(at: busy, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: quiet, withIntermediateDirectories: true)

        for i in 0..<40 {
            try "x".write(to: busy.appendingPathComponent("f\(i).txt"), atomically: false, encoding: .utf8)
        }
        try "x".write(to: quiet.appendingPathComponent("only.txt"), atomically: false, encoding: .utf8)

        XCTAssertTrue(wait(seconds: 15) {
            (engine.hotspots.heat(for: busy.path)?.directEvents ?? 0) >= 30
        }, "the busy directory must accumulate heat from real writes")

        let ranked = engine.hotspots.topDirectories(10, by: .totalEvents)
        let busyRank = ranked.firstIndex { $0.path == busy.path }
        let quietRank = ranked.firstIndex { $0.path == quiet.path }
        XCTAssertNotNil(busyRank)
        if let busyRank, let quietRank {
            XCTAssertLessThan(busyRank, quietRank, "the busier directory must rank higher")
        }
    }

    func testIntegrityHoldsOverLiveCapture() throws {
        // Watch a directory that does not contain the log itself. Pointing the
        // watcher at its own storage feeds every segment write back in as an
        // event; the app excludes its own directories precisely to avoid that.
        let subject = workDir.appendingPathComponent("subject")
        try FileManager.default.createDirectory(at: subject, withIntermediateDirectories: true)
        try startEngine(watching: [subject.path])

        for i in 0..<200 {
            try "data".write(to: subject.appendingPathComponent("bulk\(i).txt"),
                             atomically: false, encoding: .utf8)
        }
        XCTAssertTrue(wait(seconds: 15) { loggedEvents().count >= 150 })

        let report = store.verifyIntegrity()
        XCTAssertTrue(report.isIntact,
                      "a log captured live must still verify: \(report.results.compactMap(\.problem))")
    }

    /// Verification runs against a log that is still being written to. The
    /// active segment must not be reported as altered just because a block was
    /// caught half-written.
    func testVerifyingWhileStillRecordingIsNotReportedAsTampering() throws {
        let subject = workDir.appendingPathComponent("busy")
        try FileManager.default.createDirectory(at: subject, withIntermediateDirectories: true)
        try startEngine(watching: [subject.path])

        // Keep writing throughout, and verify repeatedly while it happens.
        for round in 0..<5 {
            for i in 0..<60 {
                try "round \(round)".write(to: subject.appendingPathComponent("f\(round)-\(i).txt"),
                                           atomically: false, encoding: .utf8)
            }
            let report = store.verifyIntegrity()
            let falsePositives = report.results.compactMap(\.problem)
                .filter { $0.contains("altered") || $0.contains("failed to decrypt") }
            XCTAssertTrue(falsePositives.isEmpty,
                          "verifying mid-write must not accuse the log of tampering: \(falsePositives)")
        }
    }
}


/// Thread-safe sink for alerts delivered from the engine's queue.
final class AlertCollector: @unchecked Sendable {
    private let mutex = NSLock()
    private var storage: [SecurityAlert] = []

    func add(_ alert: SecurityAlert) {
        mutex.lock(); defer { mutex.unlock() }
        storage.append(alert)
    }

    var all: [SecurityAlert] {
        mutex.lock(); defer { mutex.unlock() }
        return storage
    }
}

/// End-to-end: a real process writes a file inside an audited path, and the
/// engine must name it on the resulting event.
final class LiveAttributionTests: XCTestCase {

    private var workDir: URL!
    private var vault: VaultKeyManager!
    private var store: EventStore!
    private var engine: WatcherEngine!

    override func setUpWithError() throws {
        workDir = URL(fileURLWithPath: AppPaths.canonicalPath(NSTemporaryDirectory()))
            .appendingPathComponent("hdw-attr-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "attribution-test-password", enableQuickUnlock: false)
        store = try EventStore(keys: vault.currentKeys!,
                               directory: workDir.appendingPathComponent("log"))
    }

    override func tearDownWithError() throws {
        engine?.stop()
        store?.close()
        engine = nil
        store = nil
        unsetenv(AppPaths.overrideEnvironmentKey)
        try? FileManager.default.removeItem(at: workDir)
    }

    func testNamesTheProcessThatWroteASensitiveFile() throws {
        // A rule that audits anything written in the work directory.
        let rule = AlertRule(
            name: "Audited area",
            severity: .critical,
            conditions: RuleConditions(pathIncludes: [GlobPattern(workDir.path + "/**")]),
            actions: RuleActions(notify: false, auditProcesses: true),
            cooldownSeconds: 0
        )

        var settings = AppSettings.default
        settings.watchScope = .customPaths
        settings.customWatchPaths = [workDir.path]
        settings.filter = .raw
        settings.notificationsEnabled = false
        settings.captureFileContents = false

        engine = WatcherEngine(store: store, settings: settings, rules: [rule])
        XCTAssertTrue(engine.start())
        Thread.sleep(forTimeInterval: 1.2)

        let target = workDir.appendingPathComponent("credentials.txt")

        // Write the file and keep the descriptor open, the way a real process
        // holding a credential file would.
        let writer = Process()
        writer.executableURL = URL(fileURLWithPath: "/bin/sh")
        writer.arguments = ["-c", "exec 3> '\(target.path)'; echo 'secret-material' >&3; sleep 8"]
        writer.standardOutput = Pipe()
        writer.standardError = Pipe()
        try writer.run()
        defer { if writer.isRunning { writer.terminate() } }

        // Wait for the event to make it through the pipeline with attribution.
        var attributed: FileEvent?
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline {
            store.flush()
            let events = store.query(EventQuery())
            if let match = events.first(where: {
                $0.path == target.path && ($0.attribution?.isEmpty == false)
            }) {
                attributed = match
                break
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.25))
        }

        let event = try XCTUnwrap(attributed,
            "the engine must attach process attribution to an audited file event")
        let actors = try XCTUnwrap(event.attribution?.actors)
        XCTAssertFalse(actors.isEmpty)

        // The shell holding the descriptor should be the strongest candidate.
        let holder = actors.first { $0.evidence == .holdsFileOpen }
        XCTAssertNotNil(holder, "the process holding the file open must be identified")
        XCTAssertEqual(holder?.userID, UInt32(getuid()))
        XCTAssertNotNil(holder?.userName)
        XCTAssertNotNil(holder?.executablePath)
        XCTAssertEqual(event.attribution?.best?.evidence, .holdsFileOpen)
    }

    func testAuditIsSkippedForRulesThatDidNotAskForIt() throws {
        let rule = AlertRule(
            name: "No audit",
            conditions: RuleConditions(pathIncludes: [GlobPattern(workDir.path + "/**")]),
            actions: RuleActions(notify: false, auditProcesses: false),
            cooldownSeconds: 0
        )
        var settings = AppSettings.default
        settings.watchScope = .customPaths
        settings.customWatchPaths = [workDir.path]
        settings.filter = .raw
        settings.notificationsEnabled = false
        settings.captureFileContents = false

        engine = WatcherEngine(store: store, settings: settings, rules: [rule])
        XCTAssertTrue(engine.start())
        Thread.sleep(forTimeInterval: 1.0)

        try "ordinary".write(to: workDir.appendingPathComponent("plain.txt"),
                             atomically: false, encoding: .utf8)

        var seen: FileEvent?
        let deadline = Date().addingTimeInterval(12)
        while Date() < deadline, seen == nil {
            store.flush()
            seen = store.query(EventQuery()).first { $0.path.hasSuffix("plain.txt") }
            RunLoop.current.run(until: Date().addingTimeInterval(0.25))
        }
        XCTAssertNotNil(seen, "the event itself must still be recorded")
        XCTAssertNil(seen?.attribution,
                     "attribution is expensive and must not run for rules that did not request it")
    }
}

/// Reproduces the real-world case: a file that has been sitting on disk for a
/// while — never written while the watcher was running, so absent from the
/// in-memory index — copied onto removable media. This is the path that has to
/// fall back to Spotlight to find the source.
final class PreexistingSourceTransferTests: XCTestCase {

    private var sourceDir: URL!
    private var vault: VaultKeyManager!
    private var store: EventStore!
    private var engine: WatcherEngine!
    private var work: URL!
    private static var dmgPath: URL?
    private static var dmgMount: String?

    @discardableResult
    private static func shell(_ path: String, _ args: [String]) -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe; p.standardError = pipe
        try? p.run()
        let d = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(data: d, encoding: .utf8) ?? "")
    }

    override class func setUp() {
        super.setUp()
        let path = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-pre-\(UUID().uuidString.prefix(8)).dmg")
        guard shell("/usr/bin/hdiutil", ["create", "-size", "40m", "-fs", "APFS",
                                         "-volname", "PreExistTest", "-quiet", path.path]).0 == 0
        else { return }
        dmgPath = path
        let attach = shell("/usr/bin/hdiutil", ["attach", path.path, "-nobrowse"])
        for line in attach.1.split(separator: "\n") {
            if let r = line.range(of: "/Volumes/") {
                dmgMount = AppPaths.canonicalPath(
                    String(line[r.lowerBound...]).trimmingCharacters(in: .whitespaces))
            }
        }
    }

    override class func tearDown() {
        if let m = dmgMount { shell("/usr/bin/hdiutil", ["detach", m, "-force", "-quiet"]) }
        if let p = dmgPath { try? FileManager.default.removeItem(at: p) }
        super.tearDown()
    }

    override func setUpWithError() throws {
        // The source must live somewhere Spotlight indexes — a temp directory
        // under /private/var is not indexed, which is exactly why the existing
        // tests never exercised this path.
        sourceDir = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("hdw-xfer-test-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: sourceDir, withIntermediateDirectories: true)

        work = URL(fileURLWithPath: AppPaths.canonicalPath(NSTemporaryDirectory()))
            .appendingPathComponent("hdw-pre-work-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        vault = VaultKeyManager(vaultURL: work.appendingPathComponent("vault.json"))
        try vault.createVault(password: "preexisting-source-test", enableQuickUnlock: false)
        store = try EventStore(keys: vault.currentKeys!, directory: work.appendingPathComponent("log"))
    }

    override func tearDownWithError() throws {
        engine?.stop(); store?.close(); engine = nil; store = nil
        try? FileManager.default.removeItem(at: sourceDir)
        try? FileManager.default.removeItem(at: work)
    }

    func testDetectsCopyOfAFileTheWatcherNeverSawBeingWritten() throws {
        let mount = try XCTUnwrap(Self.dmgMount, "test volume not mounted")

        // 1. The file already exists and is indexed, well before monitoring starts.
        let source = sourceDir.appendingPathComponent("quarterly-figures.txt")
        try String(repeating: "confidential quarterly figures\n", count: 200)
            .write(to: source, atomically: true, encoding: .utf8)

        // Wait until Spotlight can actually see it. Under load indexing lags,
        // and without this the test would be measuring Spotlight's latency
        // rather than the detector.
        let locator = SpotlightLocator()
        var indexed = false
        let indexDeadline = Date().addingTimeInterval(30)
        while Date() < indexDeadline, !indexed {
            locator.clearCache()
            indexed = locator.findByName("quarterly-figures.txt")
                .contains { $0.path == source.path }
            if !indexed { Thread.sleep(forTimeInterval: 1) }
        }

        // 2. Watch ONLY the destination volume, so nothing about the source is
        //    ever in the correlation index — precisely the user's situation.
        var settings = AppSettings.default
        settings.watchScope = .customPaths
        settings.customWatchPaths = [mount]
        settings.filter = .raw
        settings.notificationsEnabled = false
        settings.captureFileContents = false
        settings.transferSettleSeconds = 1.0

        engine = WatcherEngine(store: store, settings: settings, rules: [])
        XCTAssertTrue(engine.start())
        Thread.sleep(forTimeInterval: 1.2)

        // 3. Copy it out.
        let destination = URL(fileURLWithPath: mount).appendingPathComponent("quarterly-figures.txt")
        try FileManager.default.copyItem(at: source, to: destination)

        // 4. It must be reported as leaving the machine, with the source named.
        var found: FileEvent?
        let deadline = Date().addingTimeInterval(25)
        while Date() < deadline, found == nil {
            store.flush()
            found = store.query(EventQuery()).first {
                $0.path == destination.path && $0.kind.isTransfer
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.25))
        }

        let event = try XCTUnwrap(found, "copying a pre-existing file to removable media must appear as a transfer")
        // This part holds regardless: the copy is always reported as leaving.
        XCTAssertEqual(event.kind, .copiedOut, "data going onto removable media is egress")

        if indexed {
            XCTAssertEqual(event.sourcePath, source.path,
                           "with the source indexed, Spotlight should have identified it")
            XCTAssertGreaterThanOrEqual(event.confidence, .high,
                                        "a content-digest match is high confidence")
        } else {
            // Spotlight never caught up. The transfer must still be reported,
            // just without a source — which is exactly what the UI shows as
            // "Unidentified source / Low".
            XCTAssertEqual(event.confidence, .low)
            XCTAssertNil(event.sourcePath)
        }
    }
}

/// An audit trail must not silently lose the period when the watcher was down.
final class CoverageGapTests: XCTestCase {

    private var work: URL!
    private var watched: URL!
    private var vault: VaultKeyManager!
    private var store: EventStore!
    private var engine: WatcherEngine!

    override func setUpWithError() throws {
        let root = URL(fileURLWithPath: AppPaths.canonicalPath(NSTemporaryDirectory()))
            .appendingPathComponent("hdw-gap-\(UUID().uuidString)")
        work = root.appendingPathComponent("support")
        // Outside the support directory: the watcher excludes its own storage,
        // so a watched folder nested inside it would report nothing.
        watched = root.appendingPathComponent("watched")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: watched, withIntermediateDirectories: true)
        // Keep the cursor inside the fixture rather than the real support dir.
        setenv(AppPaths.overrideEnvironmentKey, work.path, 1)

        vault = VaultKeyManager(vaultURL: work.appendingPathComponent("vault.json"))
        try vault.createVault(password: "coverage-gap-test", enableQuickUnlock: false)
        store = try EventStore(keys: vault.currentKeys!, directory: work.appendingPathComponent("log"))
    }

    override func tearDownWithError() throws {
        engine?.stop(); store?.close(); engine = nil; store = nil
        unsetenv(AppPaths.overrideEnvironmentKey)
        try? FileManager.default.removeItem(at: work.deletingLastPathComponent())
    }

    private func makeEngine() -> WatcherEngine {
        var settings = AppSettings.default
        settings.watchScope = .customPaths
        settings.customWatchPaths = [watched.path]
        settings.filter = .raw
        settings.notificationsEnabled = false
        settings.captureFileContents = false
        return WatcherEngine(store: store, settings: settings, rules: [],
                             keys: vault.currentKeys)
    }

    private func waitFor(seconds: TimeInterval = 15, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if condition() { return true }
            RunLoop.current.run(until: Date().addingTimeInterval(0.25))
        }
        return condition()
    }

    private func logged() -> [FileEvent] {
        store.flush()
        return store.query(EventQuery())
    }

    func testRecordsChangesMadeWhileTheWatcherWasDown() throws {
        // First session, so a cursor position exists.
        engine = makeEngine()
        XCTAssertTrue(engine.start())
        Thread.sleep(forTimeInterval: 1.2)
        try "before".write(to: watched.appendingPathComponent("before.txt"),
                           atomically: false, encoding: .utf8)
        XCTAssertTrue(waitFor { logged().contains { $0.path.hasSuffix("before.txt") } })

        engine.stop()
        engine = nil
        XCTAssertNotNil(EventCursor.load(settingsKey: vault.currentKeys?.settings)?.lastEventID,
                        "stopping must save the stream position")

        // Nothing is watching now — this is the gap.
        for i in 0..<5 {
            try "during downtime \(i)".write(
                to: watched.appendingPathComponent("gap\(i).txt"),
                atomically: false, encoding: .utf8)
        }
        Thread.sleep(forTimeInterval: 1.0)

        // Second session: FSEvents should replay what happened in between.
        engine = makeEngine()
        XCTAssertTrue(engine.start())

        let recovered = waitFor(seconds: 20) {
            let paths = Set(logged().map(\.path))
            return (0..<5).allSatisfy { paths.contains(watched.appendingPathComponent("gap\($0).txt").path) }
        }
        XCTAssertTrue(recovered,
                      "changes made while the watcher was down must be replayed from the saved cursor")
    }

    func testMarksWhenMonitoringStartsAndStops() throws {
        engine = makeEngine()
        XCTAssertTrue(engine.start())
        XCTAssertTrue(waitFor { logged().contains { $0.kind == .monitoringStarted } },
                      "the log must record when recording began")

        engine.stop()
        engine = nil
        XCTAssertTrue(waitFor { logged().contains { $0.kind == .monitoringStopped } },
                      "the log must record when recording ended")

        let started = logged().first { $0.kind == .monitoringStarted }
        XCTAssertFalse(started?.ruleHits.isEmpty ?? true,
                       "the marker should explain the coverage situation")
    }

    func testCursorIsNeverPoisonedBySinceNowSentinel() throws {
        // kFSEventStreamEventIdSinceNow is UInt64.max; storing it would make the
        // next session resume from an impossible position and replay nothing.
        let key = try XCTUnwrap(vault.currentKeys?.settings)
        var cursor = EventCursor(lastEventID: UInt64.max)
        XCTAssertEqual(cursor.lastEventID, UInt64.max)
        cursor.lastEventID = 42
        cursor.save(settingsKey: key)
        XCTAssertEqual(EventCursor.load(settingsKey: key)?.lastEventID, 42)
    }

    func testCursorIsSealedOnDisk() throws {
        let key = try XCTUnwrap(vault.currentKeys?.settings)
        EventCursor(lastEventID: 123_456_789, savedAt: Date()).save(settingsKey: key)

        let raw = try Data(contentsOf: EventCursor.fileURL)
        XCTAssertNil(raw.range(of: Data("lastEventID".utf8)),
                     "the cursor must not be readable on disk — it reveals when the machine was active")
        XCTAssertNil(raw.range(of: Data("123456789".utf8)))
        XCTAssertEqual(EventCursor.load(settingsKey: key)?.lastEventID, 123_456_789)

        // The wrong key recovers nothing.
        XCTAssertNil(EventCursor.load(settingsKey: SymmetricKey(size: .bits256)))
    }

    func testGapDurationIsReported() {
        let cursor = EventCursor(lastEventID: 100, savedAt: Date(),
                                 stoppedAt: Date().addingTimeInterval(-3600))
        let gap = try? XCTUnwrap(cursor.gapDuration)
        XCTAssertEqual(gap ?? 0, 3600, accuracy: 5)
        XCTAssertEqual(WatcherEngine.describe(3600), "1h")
        XCTAssertEqual(WatcherEngine.describe(45), "45s")
        XCTAssertEqual(WatcherEngine.describe(600), "10m")
    }
}
