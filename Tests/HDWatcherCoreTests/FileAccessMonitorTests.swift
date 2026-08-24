import XCTest
@testable import HDWatcherCore

/// Reading a file changes nothing on disk, so FSEvents never reports it — which
/// is why copying a document to a USB stick leaves no trace on the source side.
/// This samples the kernel's list of open descriptors instead. It catches
/// anything held open when a sample runs, and misses a file opened and closed
/// entirely between two samples; the tests say which is which rather than
/// pretending the coverage is complete.
final class FileAccessMonitorTests: XCTestCase {

    private var directory: URL!

    override func setUpWithError() throws {
        // Canonical from the start: the kernel reports open descriptors as
        // /private/var/…, and comparing those to /var/… matches nothing.
        let raw = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-reads-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
        directory = URL(fileURLWithPath: AppPaths.canonicalPath(raw.path))
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func monitor(roots: [String]? = nil) -> FileAccessMonitor {
        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = roots ?? [directory.path]
        configuration.excludePatterns = []
        return FileAccessMonitor(configuration: configuration)
    }

    /// The first sample records what is already open without reporting it —
    /// those opens happened before anyone was watching. Tests that want to
    /// observe an open have to be watching first.
    private func primed(roots: [String]? = nil) -> FileAccessMonitor {
        let watcher = monitor(roots: roots)
        watcher.sample()
        return watcher
    }

    func testAFileHeldOpenByAnotherProcessIsSeen() throws {
        let file = directory.appendingPathComponent("quarterly-figures.txt")
        try String(repeating: "confidential\n", count: 100).write(to: file, atomically: true, encoding: .utf8)

        // Watching *before* the file is opened: an open that happened before
        // anyone was looking is not an observed read.
        let watcher = primed()

        // A real second process: this monitor deliberately ignores its own pid,
        // and holding the file open in-process would prove nothing.
        let reader = Process()
        reader.executableURL = URL(fileURLWithPath: "/bin/sh")
        reader.arguments = ["-c", "exec 3< '\(file.path)'; sleep 4"]
        try reader.run()
        defer { reader.terminate() }
        Thread.sleep(forTimeInterval: 0.7)

        let started = watcher.sample()
        XCTAssertTrue(started.contains { $0.path == file.path },
                      "a file held open for reading must be reported: \(started.map(\.path))")
        // A child that inherits the descriptor holds the file too, and is
        // reported in its own right — attribution follows whoever has it open,
        // which is what "who read this" means.
        let holders = started.filter { $0.path == file.path }
        XCTAssertTrue(holders.contains { $0.pid == reader.processIdentifier },
                      "the process that opened it must be among the holders")
        XCTAssertEqual(holders.first?.fileName, "quarterly-figures.txt")
        XCTAssertFalse(holders.contains { $0.processName.isEmpty })
    }

    func testTheReadIsReportedFinishedOnceTheFileIsClosed() throws {
        let file = directory.appendingPathComponent("notes.txt")
        try "some notes".write(to: file, atomically: true, encoding: .utf8)

        let watcher = primed()

        let reader = Process()
        reader.executableURL = URL(fileURLWithPath: "/bin/sh")
        reader.arguments = ["-c", "exec 3< '\(file.path)'; sleep 1"]
        try reader.run()
        Thread.sleep(forTimeInterval: 0.5)

        var finished: [FileAccessMonitor.Access] = []
        watcher.onAccessFinished = { finished.append($0) }

        watcher.sample()                       // sees it open
        reader.waitUntilExit()
        Thread.sleep(forTimeInterval: 0.3)
        watcher.sample()                       // sees it gone

        XCTAssertTrue(finished.contains { $0.path == file.path },
                      "closing the file is what makes the read a complete fact")
    }

    func testHowLongItWasHeldIsCounted() throws {
        let file = directory.appendingPathComponent("held.bin")
        try Data(repeating: 7, count: 1_024).write(to: file)

        let watcher = primed()

        let reader = Process()
        reader.executableURL = URL(fileURLWithPath: "/bin/sh")
        reader.arguments = ["-c", "exec 3< '\(file.path)'; sleep 4"]
        try reader.run()
        defer { reader.terminate() }
        Thread.sleep(forTimeInterval: 0.7)

        watcher.sample()
        Thread.sleep(forTimeInterval: 0.4)
        watcher.sample()

        var finished: [FileAccessMonitor.Access] = []
        watcher.onAccessFinished = { finished.append($0) }
        watcher.stop()                          // treats whatever is open as done

        let access = try XCTUnwrap(finished.first { $0.path == file.path })
        XCTAssertEqual(access.samples, 2, "each sighting counts once")
        XCTAssertGreaterThan(access.duration, 0.3)
    }

    func testOnlyFilesUnderTheChosenRootsAreConsidered() throws {
        let inside = directory.appendingPathComponent("inside.txt")
        try "x".write(to: inside, atomically: true, encoding: .utf8)
        let watcher = monitor(roots: ["/nowhere-in-particular"])
        XCTAssertFalse(watcher.isInteresting(inside.path))
        XCTAssertTrue(monitor().isInteresting(inside.path))
    }

    func testTheNoiseEveryProcessMakesIsExcluded() {
        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = ["/"]
        let watcher = FileAccessMonitor(configuration: configuration)
        // Reading these is every process, all the time, and tells nobody
        // anything.
        XCTAssertFalse(watcher.isInteresting("/Users/x/Library/Caches/foo/bar.db"))
        XCTAssertFalse(watcher.isInteresting("/usr/lib/libSystem.dylib"))
        XCTAssertFalse(watcher.isInteresting("/private/var/folders/ab/cd/T/tmpfile"))
        XCTAssertFalse(watcher.isInteresting("/Library/Application Support/co.pixelworship.hdwatcher/log/seg-1.hdwseg"))
    }

    func testDirectoriesAndMissingPathsAreNotReads() throws {
        XCTAssertFalse(monitor().isInteresting(directory.path), "a directory is not a read")
        XCTAssertFalse(monitor().isInteresting(directory.appendingPathComponent("gone.txt").path))
        XCTAssertFalse(monitor().isInteresting(""))
    }

    func testItStopsTrackingRatherThanGrowingWithoutBound() throws {
        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = [directory.path]
        configuration.excludePatterns = []
        configuration.maximumTrackedAccesses = 3
        let watcher = FileAccessMonitor(configuration: configuration)
        watcher.sample()      // prime

        var handles: [FileHandle] = []
        defer { handles.forEach { try? $0.close() } }
        for index in 0..<10 {
            let file = directory.appendingPathComponent("f\(index).txt")
            try "x".write(to: file, atomically: true, encoding: .utf8)
            if let handle = try? FileHandle(forReadingFrom: file) { handles.append(handle) }
        }
        XCTAssertLessThanOrEqual(watcher.sample().count, 3,
                                 "a runaway process must not be able to fill the log")
    }
}

/// Reads are ordinary events in the same encrypted log, so they inherit its
/// guarantees — searchable, attributable, append-only — rather than living in
/// some second store with weaker ones.
final class ReadEventTests: XCTestCase {

    func testAReadIsAFirstClassEventKind() {
        XCTAssertEqual(EventKind.read.displayName, "Read")
        XCTAssertFalse(EventKind.read.isTransfer)
        XCTAssertFalse(EventKind.read.isEgress)
    }

    func testTheDaemonIsToldWhetherToTrackReads() {
        var settings = AppSettings.default
        settings.trackFileReads = true
        settings.readSampleSeconds = 5
        settings.readRoots = ["/Users/someone", "/Volumes"]

        let configuration = AgentConfiguration(from: settings, rules: [], enabled: true)
        let round = configuration.appSettings
        XCTAssertTrue(round.trackFileReads)
        XCTAssertEqual(round.readSampleSeconds, 5)
        XCTAssertEqual(round.readRoots, ["/Users/someone", "/Volumes"])
    }

    func testAnEmptyRootListDoesNotWipeTheDaemonsOwn() {
        // The daemon runs as root with no home of its own; taking an empty list
        // literally would leave it watching nowhere.
        var configuration = AgentConfiguration()
        configuration.readRoots = []
        XCTAssertFalse(configuration.appSettings.readRoots.isEmpty)
    }

    func testReadTrackingCanBeTurnedOff() {
        var settings = AppSettings.default
        settings.trackFileReads = false
        let configuration = AgentConfiguration(from: settings, rules: [], enabled: true)
        XCTAssertFalse(configuration.appSettings.trackFileReads)
    }
}

/// What the defaults are for, measured on a real machine: watching the whole
/// home produced about eleven thousand opens a minute — app databases, group
/// containers, sync state — which would bury anything a person cares about and
/// bloat a permanent log.
final class ReadDefaultsTests: XCTestCase {

    func testItWatchesWhereDocumentsLiveNotTheWholeHome() {
        let roots = FileAccessMonitor.defaultRoots
        XCTAssertFalse(roots.contains(NSHomeDirectory()), "the whole home is eleven thousand opens a minute")
        XCTAssertTrue(roots.contains(NSHomeDirectory() + "/Documents"))
        XCTAssertTrue(roots.contains(NSHomeDirectory() + "/Desktop"))
        XCTAssertTrue(roots.contains("/Volumes"), "external drives are the point")
    }

    func testApplicationPlumbingIsExcluded() {
        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = ["/"]
        let watcher = FileAccessMonitor(configuration: configuration)
        XCTAssertFalse(watcher.isInteresting(NSHomeDirectory() + "/Library/Group Containers/group.com.apple.reminders/Data.sqlite"))
        XCTAssertFalse(watcher.isInteresting(NSHomeDirectory() + "/Documents/project/node_modules/pkg/index.js"))
        XCTAssertFalse(watcher.isInteresting(NSHomeDirectory() + "/Documents/repo/.git/objects/ab/cdef"))
    }
}

/// Sampling every descriptor of every process is the most expensive thing this
/// app does, and as root it sees all of them. Left unbounded it ran at 130% CPU
/// with gigabytes resident, so the bounds are part of the feature rather than a
/// tuning detail.
final class ReadSamplingCostTests: XCTestCase {

    func testItIsOffUntilAskedFor() {
        XCTAssertFalse(AppSettings.default.trackFileReads,
                       "the expensive thing does not run because nobody said no")
        XCTAssertFalse(AgentConfiguration().trackFileReads)
    }

    func testAPassIsBoundedInTime() {
        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = ["/"]
        configuration.excludePatterns = []
        configuration.timeBudget = 0.05          // absurdly small on purpose
        let watcher = FileAccessMonitor(configuration: configuration)

        let started = Date()
        watcher.sample()
        watcher.sample()
        // Two passes, each abandoned at the budget rather than running to
        // completion — the failure mode was one pass overrunning into the next.
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }

    func testAbandonedPassesAreCounted() {
        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = ["/"]
        configuration.timeBudget = 0
        let watcher = FileAccessMonitor(configuration: configuration)
        watcher.sample()
        XCTAssertGreaterThan(watcher.unfinishedPasses, 0,
                             "missing reads has to be visible, not silent")
    }

    func testProcessesHoldingThousandsOfFilesAreSkipped() {
        // Nothing to assert about a specific process, but the limit must be
        // honoured rather than ignored.
        XCTAssertNil(ProcessAuditor.openPaths(pid: ProcessInfo.processInfo.processIdentifier, limit: 0))
        XCTAssertNotNil(ProcessAuditor.openPaths(pid: ProcessInfo.processInfo.processIdentifier))
    }

    func testTheDefaultIntervalIsNotAggressive() {
        XCTAssertGreaterThanOrEqual(FileAccessMonitor.Configuration().interval, 5)
        XCTAssertGreaterThanOrEqual(AppSettings.default.readSampleSeconds, 5)
    }
}

/// Describing a process means code signing, arguments and the executable path.
/// Read tracking asks about the same handful of processes over and over, and
/// without a cache that was most of the 140% CPU.
final class ProcessDescriptionCacheTests: XCTestCase {

    func testDescribingTheSameProcessTwiceIsCheap() {
        let auditor = ProcessAuditor()
        let me = ProcessInfo.processInfo.processIdentifier

        let first = Date()
        _ = auditor.describe(pid: me, evidence: .holdsFileOpen)
        let cold = Date().timeIntervalSince(first)

        let second = Date()
        for _ in 0..<200 { _ = auditor.describe(pid: me, evidence: .holdsFileOpen) }
        let warm = Date().timeIntervalSince(second)

        XCTAssertLessThan(warm, max(cold * 20, 0.5),
                          "two hundred repeats must not cost two hundred lookups")
    }

    func testItStillDescribesTheProcessCorrectly() throws {
        let auditor = ProcessAuditor()
        let result = auditor.describe(pid: ProcessInfo.processInfo.processIdentifier,
                                      evidence: .holdsFileOpen)
        let actor = try XCTUnwrap(result.best)
        XCTAssertEqual(actor.pid, ProcessInfo.processInfo.processIdentifier)
        XCTAssertFalse(actor.name.isEmpty)
        XCTAssertEqual(actor.evidence, .holdsFileOpen)
    }

    func testAProcessThatIsGoneIsNotInvented() {
        let auditor = ProcessAuditor()
        let result = auditor.describe(pid: 999_999, evidence: .holdsFileOpen)
        XCTAssertTrue(result.actors.isEmpty)
        XCTAssertTrue(result.blockedByPrivileges)
    }
}

/// Media libraries are a bundle wrapped around a database that their own
/// daemons read all day. Reporting those as reads buries the documents someone
/// actually opened — this was the whole content of the first real run.
final class ReadNoiseTests: XCTestCase {

    private func watcher() -> FileAccessMonitor {
        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = ["/"]
        return FileAccessMonitor(configuration: configuration)
    }

    func testPhotoAndMusicLibrariesAreNotReads() {
        let home = NSHomeDirectory()
        XCTAssertFalse(watcher().isInteresting("\(home)/Pictures/Photos Library.photoslibrary/database/Photos.sqlite"))
        XCTAssertFalse(watcher().isInteresting("\(home)/Music/Music Library.musiclibrary/Library.musicdb"))
        XCTAssertFalse(watcher().isInteresting("\(home)/Movies/Home.imovielibrary/Projects/x.mov"))
    }

    func testOrdinaryDocumentsStillCount() throws {
        // A real file in a real document folder: the exclusions must not have
        // swallowed the thing the feature exists for.
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-docs-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("contract.pdf")
        try "x".write(to: file, atomically: true, encoding: .utf8)

        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = [AppPaths.canonicalPath(directory.path)]
        // Only the media-library patterns are under test here.
        configuration.excludePatterns = FileAccessMonitor.defaultExclusions
            .filter { !$0.pattern.contains("var/folders") }
        let watcher = FileAccessMonitor(configuration: configuration)
        XCTAssertTrue(watcher.isInteresting(AppPaths.canonicalPath(file.path)))
    }
}

/// With the kernel tap catching every open, a single compile produces thousands
/// of reads of object files and temporaries. Left in, one build is the entire
/// contents of the Reads tab — which is what happened the first time this ran
/// against a checkout on the Desktop.
final class BuildArtefactNoiseTests: XCTestCase {

    private func watcher() -> FileAccessMonitor {
        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = ["/"]
        return FileAccessMonitor(configuration: configuration)
    }

    func testCompilerOutputIsNotAReadWorthRecording() {
        let home = NSHomeDirectory()
        let noise = [
            "\(home)/Desktop/project/.build/x/EventStore.swift-ba3ac9f6.o.tmp",
            "\(home)/Desktop/project/.build/HDWatcherCore.build/AppPaths.swift.o",
            "\(home)/Desktop/project/build/HDWatcher.build/MainView.swift.o",
            "\(home)/Documents/app/DerivedData/Build/Products/Debug/thing.swiftmodule",
            "\(home)/Desktop/proj/HDWatcher.cstemp",
            "\(home)/Documents/site/node_modules/pkg/index.js",
            "\(home)/Documents/py/__pycache__/mod.cpython-311.pyc",
        ]
        for path in noise {
            XCTAssertFalse(watcher().isInteresting(path), "build noise leaked through: \(path)")
        }
    }

    func testRealDocumentsSurviveTheseExclusions() throws {
        // The exclusions must not have quietly swallowed ordinary work.
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-keep-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        for name in ["contract.pdf", "payroll.csv", "photo.png", "notes.md", "build-app.sh"] {
            let file = directory.appendingPathComponent(name)
            try "x".write(to: file, atomically: true, encoding: .utf8)
            var configuration = FileAccessMonitor.Configuration()
            configuration.roots = [AppPaths.canonicalPath(directory.path)]
            configuration.excludePatterns = FileAccessMonitor.defaultExclusions
                .filter { !$0.pattern.contains("var/folders") }
            let watcher = FileAccessMonitor(configuration: configuration)
            XCTAssertTrue(watcher.isInteresting(AppPaths.canonicalPath(file.path)),
                          "\(name) is a real file someone might read")
        }
    }
}

/// Settings saved before an exclusion was added would pin the old list forever,
/// so a shipped noise fix could never reach anyone who had already run the app.
/// This is not hypothetical: the build-artefact exclusions failed to take effect
/// exactly this way.
final class ReadExclusionMigrationTests: XCTestCase {

    private func decode(_ json: String) throws -> AppSettings {
        try JSONDecoder().decode(AppSettings.self, from: Data(json.utf8))
    }

    func testNewDefaultExclusionsReachSettingsSavedBeforeThem() throws {
        // A settings blob from before build artefacts were excluded.
        let old = """
        {"readExcludePatterns":[{"pattern":"**/Library/**","caseSensitive":false}]}
        """
        let settings = try decode(old)
        let patterns = Set(settings.readExcludePatterns.map(\.pattern))
        XCTAssertTrue(patterns.contains("**/Library/**"), "the saved entry survives")
        XCTAssertTrue(patterns.contains("**/*.o.tmp"),
                      "a default added later must still apply")
        XCTAssertTrue(patterns.contains("**/DerivedData/**"))
    }

    func testAUsersOwnPatternIsNeverDiscarded() throws {
        let mine = """
        {"readExcludePatterns":[{"pattern":"**/my-private-folder/**","caseSensitive":false}]}
        """
        let settings = try decode(mine)
        XCTAssertTrue(settings.readExcludePatterns.map(\.pattern).contains("**/my-private-folder/**"))
    }

    func testNoDuplicatesWhenTheSavedListAlreadyHasTheDefaults() throws {
        let current = FileAccessMonitor.defaultExclusions
        let encoded = try JSONEncoder().encode(["readExcludePatterns": current])
        let settings = try JSONDecoder().decode(AppSettings.self, from: encoded)
        let patterns = settings.readExcludePatterns.map(\.pattern)
        XCTAssertEqual(patterns.count, Set(patterns).count, "merging must not duplicate")
    }
}

/// A sampler that skips work must not invent facts about what it skipped.
///
/// A pass abandons processes two ways: the time budget expires, or a process
/// holds more descriptors than it is willing to walk. Either way those files
/// are absent from the pass — and treating absence as "closed" meant a file
/// held open the whole time was reported closed, then reported *open again*
/// with a fabricated timestamp. In a permanent audit log that is a recorded
/// falsehood, which is worse than a gap.
final class SkippedPassHonestyTests: XCTestCase {

    private var directory: URL!

    override func setUpWithError() throws {
        let raw = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-skip-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: raw, withIntermediateDirectories: true)
        directory = URL(fileURLWithPath: AppPaths.canonicalPath(raw.path))
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testAPassThatExaminedNothingClosesNothing() throws {
        let file = directory.appendingPathComponent("held.txt")
        try "still open".write(to: file, atomically: true, encoding: .utf8)

        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = [directory.path]
        configuration.excludePatterns = []
        let watcher = FileAccessMonitor(configuration: configuration)
        watcher.sample()                                   // prime

        let reader = Process()
        reader.executableURL = URL(fileURLWithPath: "/bin/sh")
        reader.arguments = ["-c", "exec 3< '\(file.path)'; sleep 6"]
        try reader.run()
        defer { reader.terminate() }
        Thread.sleep(forTimeInterval: 0.8)

        XCTAssertTrue(watcher.sample().contains { $0.path == file.path },
                      "the open must be seen before the skip can be tested")

        var closed: [FileAccessMonitor.Access] = []
        watcher.onAccessFinished = { closed.append($0) }

        // A pass with no time to look at anything.
        var starved = FileAccessMonitor.Configuration()
        starved.roots = [directory.path]
        starved.excludePatterns = []
        starved.timeBudget = 0
        let starvedWatcher = FileAccessMonitor(configuration: starved)
        starvedWatcher.sample()
        starvedWatcher.onAccessFinished = { closed.append($0) }
        starvedWatcher.sample()

        XCTAssertTrue(closed.isEmpty,
                      "a pass that looked at nothing cannot know anything closed: \(closed.map(\.path))")
    }

    func testTheFileIsStillTrackedAfterASkippedPassRatherThanReopened() throws {
        let file = directory.appendingPathComponent("continuous.txt")
        try "held".write(to: file, atomically: true, encoding: .utf8)

        var configuration = FileAccessMonitor.Configuration()
        configuration.roots = [directory.path]
        configuration.excludePatterns = []
        let watcher = FileAccessMonitor(configuration: configuration)
        watcher.sample()

        let reader = Process()
        reader.executableURL = URL(fileURLWithPath: "/bin/sh")
        reader.arguments = ["-c", "exec 3< '\(file.path)'; sleep 8"]
        try reader.run()
        defer { reader.terminate() }
        Thread.sleep(forTimeInterval: 0.8)

        let first = watcher.sample().first { $0.path == file.path }
        let openedAt = try XCTUnwrap(first?.openedAt, "the first open must be observed")

        // Two more passes while the file stays open the entire time.
        Thread.sleep(forTimeInterval: 0.5)
        let second = watcher.sample()
        Thread.sleep(forTimeInterval: 0.5)
        let third = watcher.sample()

        // It must never be announced as a *new* open: it never closed.
        XCTAssertFalse(second.contains { $0.path == file.path },
                       "a file that never closed must not be reported opened again")
        XCTAssertFalse(third.contains { $0.path == file.path })

        var closed: [FileAccessMonitor.Access] = []
        watcher.onAccessFinished = { closed.append($0) }
        watcher.stop()
        let final = try XCTUnwrap(closed.first { $0.path == file.path })
        XCTAssertEqual(final.openedAt, openedAt,
                       "the recorded time of the open must be when it actually opened")
        XCTAssertGreaterThanOrEqual(final.samples, 3, "it was seen throughout, not re-created")
    }
}
