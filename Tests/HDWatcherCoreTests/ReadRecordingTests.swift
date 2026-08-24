import XCTest
@testable import HDWatcherCore

/// End to end: a real process reads a real file, and the engine writes a read
/// event into the encrypted log with the reader named.
final class ReadRecordingTests: XCTestCase {

    private var workDir: URL!
    private var vault: VaultKeyManager!
    private var store: EventStore!
    private var engine: WatcherEngine!

    override func setUpWithError() throws {
        let raw = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-readlog-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
        workDir = URL(fileURLWithPath: AppPaths.canonicalPath(raw.path))
        vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "read-recording-password", enableQuickUnlock: false)
        store = try EventStore(mode: .full(vault.currentKeys!),
                               directory: workDir.appendingPathComponent("log"))
    }

    override func tearDownWithError() throws {
        engine?.stop()
        store?.close()
        try? FileManager.default.removeItem(at: workDir)
    }

    func testReadingAFileIsRecordedWithWhoReadIt() throws {
        let watched = workDir.appendingPathComponent("watched", isDirectory: true)
        try FileManager.default.createDirectory(at: watched, withIntermediateDirectories: true)
        let file = watched.appendingPathComponent("payroll.csv")
        try "name,salary\nsomeone,1\n".write(to: file, atomically: true, encoding: .utf8)

        var settings = AppSettings.default
        settings.watchScope = .customPaths
        settings.customWatchPaths = [watched.path]
        settings.notificationsEnabled = false
        settings.captureFileContents = false
        settings.trackFileReads = true
        settings.readSampleSeconds = 0.5
        settings.readRoots = [watched.path]
        // The test's own directory lives under /private/var/folders, which the
        // default exclusions drop as temporary noise.
        settings.readExcludePatterns = []

        engine = WatcherEngine(store: store, settings: settings, rules: [])
        XCTAssertTrue(engine.start())
        // Let the first sample record what was already open. A file open before
        // anyone was watching is not an observed read, and is not reported as
        // one.
        Thread.sleep(forTimeInterval: 1.5)

        // Another process, holding it open long enough to be sampled.
        let reader = Process()
        reader.executableURL = URL(fileURLWithPath: "/bin/sh")
        reader.arguments = ["-c", "exec 3< '\(file.path)'; sleep 3"]
        try reader.run()

        var recorded: FileEvent?
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline, recorded == nil {
            store.flush()
            var query = EventQuery()
            query.kinds = [.read]
            recorded = store.query(query).first { $0.path == file.path }
            RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        }
        reader.terminate()

        let event = try XCTUnwrap(recorded, "a file held open must be recorded as read")
        XCTAssertEqual(event.kind, .read)
        // Attribution here is evidence, not inference: this is the process that
        // had the descriptor.
        let actor = try XCTUnwrap(event.attribution?.best)
        XCTAssertGreaterThan(actor.pid, 0)
        XCTAssertFalse(actor.name.isEmpty)
        XCTAssertEqual(event.attribution?.best?.evidence, .holdsFileOpen)
    }

    func testTurningItOffRecordsNothing() throws {
        let watched = workDir.appendingPathComponent("quiet", isDirectory: true)
        try FileManager.default.createDirectory(at: watched, withIntermediateDirectories: true)
        let file = watched.appendingPathComponent("secret.txt")
        try "nothing to see".write(to: file, atomically: true, encoding: .utf8)

        var settings = AppSettings.default
        settings.watchScope = .customPaths
        settings.customWatchPaths = [watched.path]
        settings.notificationsEnabled = false
        settings.captureFileContents = false
        settings.trackFileReads = false
        settings.readRoots = [watched.path]

        engine = WatcherEngine(store: store, settings: settings, rules: [])
        XCTAssertTrue(engine.start())

        let reader = Process()
        reader.executableURL = URL(fileURLWithPath: "/bin/sh")
        reader.arguments = ["-c", "exec 3< '\(file.path)'; sleep 2"]
        try reader.run()
        Thread.sleep(forTimeInterval: 3)
        reader.terminate()

        store.flush()
        var query = EventQuery()
        query.kinds = [.read]
        XCTAssertTrue(store.query(query).isEmpty, "the switch has to actually switch it off")
    }
}
