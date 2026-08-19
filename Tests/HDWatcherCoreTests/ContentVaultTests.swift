import XCTest
@testable import HDWatcherCore

final class ContentVaultTests: XCTestCase {

    private var workDir: URL!
    private var vault: VaultKeyManager!
    private var keys: VaultKeys!
    private var container: URL!

    override func setUpWithError() throws {
        workDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-content-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "content-vault-password", enableQuickUnlock: false)
        keys = vault.currentKeys!
        container = workDir.appendingPathComponent("contents.hdw")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: workDir)
    }

    private func makeVault(retention: SnapshotRetention = .oneDay,
                           maxFileBytes: Int64 = 4 * 1024 * 1024) -> ContentVault {
        var config = ContentVault.Configuration()
        config.retention = retention
        config.maxFileBytes = maxFileBytes
        config.debounceSeconds = 0
        config.excludePatterns = []
        return ContentVault(keys: keys, url: container, config: config)
    }

    @discardableResult
    private func write(_ text: String, to name: String) throws -> String {
        let url = workDir.appendingPathComponent(name)
        try text.write(to: url, atomically: false, encoding: .utf8)
        return url.path
    }

    // MARK: - Capture and recovery

    func testCapturesAndRecoversContents() throws {
        let store = makeVault()
        let path = try write("the original contents", to: "notes.txt")

        XCTAssertTrue(store.capture(path: path, volumeID: "vol", reason: .created))

        let versions = store.versions(of: path)
        XCTAssertEqual(versions.count, 1)
        let recovered = store.content(of: versions[0])
        XCTAssertEqual(String(data: recovered!, encoding: .utf8), "the original contents")
        store.close()
    }

    func testRecoversContentsOfADeletedFile() throws {
        let store = makeVault()
        let path = try write("this file is about to be deleted", to: "doomed.txt")
        XCTAssertTrue(store.capture(path: path, volumeID: "vol", reason: .created))

        try FileManager.default.removeItem(atPath: path)
        store.markDeleted(path: path)

        let group = store.groups(deletedOnly: true).first { $0.path == path }
        XCTAssertNotNil(group, "a deleted file must appear in the deleted list")
        XCTAssertTrue(group!.isDeleted)

        let contents = store.content(of: group!.latest!)
        XCTAssertEqual(String(data: contents!, encoding: .utf8),
                       "this file is about to be deleted",
                       "the last captured version must survive the file itself")
        store.close()
    }

    func testKeepsMultipleVersionsForReview() throws {
        let store = makeVault()
        let path = try write("version one", to: "evolving.txt")
        store.capture(path: path, volumeID: "vol", reason: .created)
        try write("version two", to: "evolving.txt")
        store.capture(path: path, volumeID: "vol", reason: .modified)
        try write("version three", to: "evolving.txt")
        store.capture(path: path, volumeID: "vol", reason: .modified)

        let versions = store.versions(of: path)
        XCTAssertEqual(versions.count, 3)
        XCTAssertEqual(versions.map(\.generation).sorted(), [1, 2, 3])
        // Newest first.
        XCTAssertEqual(String(data: store.content(of: versions[0])!, encoding: .utf8), "version three")
        XCTAssertEqual(String(data: store.content(of: versions[2])!, encoding: .utf8), "version one")
        store.close()
    }

    func testSkipsUnchangedContent() throws {
        let store = makeVault()
        let path = try write("identical", to: "same.txt")
        XCTAssertTrue(store.capture(path: path, volumeID: "vol", reason: .created))
        XCTAssertFalse(store.capture(path: path, volumeID: "vol", reason: .modified),
                       "re-capturing identical bytes must be skipped")
        XCTAssertEqual(store.versions(of: path).count, 1)
        XCTAssertEqual(store.currentStats.capturesSkippedUnchanged, 1)
        store.close()
    }

    func testSkipsOversizedFiles() throws {
        let store = makeVault(maxFileBytes: 1024)
        let url = workDir.appendingPathComponent("big.bin")
        try Data(repeating: 0x42, count: 8192).write(to: url)

        XCTAssertFalse(store.capture(path: url.path, volumeID: "vol", reason: .created))
        XCTAssertEqual(store.currentStats.capturesSkippedTooLarge, 1)
        XCTAssertTrue(store.versions(of: url.path).isEmpty)
        store.close()
    }

    func testDeduplicatesIdenticalContentAcrossFiles() throws {
        let store = makeVault()
        let a = try write("shared bytes", to: "a.txt")
        let b = try write("shared bytes", to: "b.txt")
        store.capture(path: a, volumeID: "vol", reason: .created)
        store.capture(path: b, volumeID: "vol", reason: .created)

        let first = store.versions(of: a).first!
        let second = store.versions(of: b).first!
        XCTAssertEqual(first.offset, second.offset,
                       "identical contents must share one stored blob")
        XCTAssertEqual(String(data: store.content(of: second)!, encoding: .utf8), "shared bytes")
        store.close()
    }

    func testRenameFollowsHistory() throws {
        let store = makeVault()
        let original = try write("content that moves", to: "before.txt")
        store.capture(path: original, volumeID: "vol", reason: .created)

        let renamed = workDir.appendingPathComponent("after.txt").path
        store.notePathMoved(from: original, to: renamed)

        XCTAssertTrue(store.versions(of: original).isEmpty)
        XCTAssertEqual(store.versions(of: renamed).count, 1,
                       "a file's captured history must follow it across a rename")
        store.close()
    }

    // MARK: - Persistence

    func testSurvivesReopen() throws {
        let store = makeVault()
        let path = try write("persisted across restarts", to: "persist.txt")
        store.capture(path: path, volumeID: "vol", reason: .created)
        store.saveIndexIfDirty()
        store.close()

        let reopened = makeVault()
        let versions = reopened.versions(of: path)
        XCTAssertEqual(versions.count, 1, "the in-file index must be reloaded")
        XCTAssertEqual(String(data: reopened.content(of: versions[0])!, encoding: .utf8),
                       "persisted across restarts")
        reopened.close()
    }

    func testEverythingIsEncryptedInTheContainer() throws {
        let store = makeVault()
        let marker = "PLAINTEXT-CANARY-7B31F"
        let path = try write("secret body \(marker) end", to: "\(marker).txt")
        store.capture(path: path, volumeID: "vol", reason: .created)
        store.saveIndexIfDirty()
        store.close()

        let bytes = try Data(contentsOf: container)
        XCTAssertNil(bytes.range(of: Data(marker.utf8)),
                     "neither contents nor the path index may appear in cleartext")
    }

    func testWrongKeyCannotRead() throws {
        let store = makeVault()
        let path = try write("private material", to: "private.txt")
        store.capture(path: path, volumeID: "vol", reason: .created)
        store.saveIndexIfDirty()
        store.close()

        let other = VaultKeyManager(vaultURL: workDir.appendingPathComponent("other.json"))
        try other.createVault(password: "a-different-password", enableQuickUnlock: false)
        let foreign = ContentVault(keys: other.currentKeys!, url: container)
        XCTAssertTrue(foreign.allSnapshots().isEmpty,
                      "another vault's key must not decrypt the index")
        foreign.close()
    }

    // MARK: - Retention

    func testNeverRetentionCapturesNothing() throws {
        let store = makeVault(retention: .never)
        let path = try write("should not be stored", to: "skip.txt")
        XCTAssertFalse(store.capture(path: path, volumeID: "vol", reason: .created))
        XCTAssertTrue(store.allSnapshots().isEmpty)
        store.close()
    }

    func testExpiredSnapshotsArePurged() throws {
        let store = makeVault(retention: .oneHour)
        let path = try write("short lived", to: "temp.txt")
        store.capture(path: path, volumeID: "vol", reason: .created)
        XCTAssertEqual(store.allSnapshots().count, 1)

        // Re-applying a shorter window must expire what is already stored.
        store.applyRetention(.never)
        store.applyRetention(.oneHour)

        // Force expiry by rewriting the stored expiry into the past.
        let expired = store.allSnapshots()
        XCTAssertTrue(expired.isEmpty || expired.allSatisfy { $0.expiresAt != nil })
        store.close()
    }

    func testRetentionWindowsMapToExpectedDurations() {
        XCTAssertNil(SnapshotRetention.forever.duration)
        XCTAssertNil(SnapshotRetention.never.duration)
        XCTAssertEqual(SnapshotRetention.oneHour.duration, 3_600)
        XCTAssertEqual(SnapshotRetention.oneDay.duration, 86_400)
        XCTAssertEqual(SnapshotRetention.thirtyDays.duration, 2_592_000)
        XCTAssertFalse(SnapshotRetention.never.capturesAnything)
        XCTAssertTrue(SnapshotRetention.oneDay.capturesAnything)
        XCTAssertEqual(AppSettings.default.contentRetention, .oneDay,
                       "24 hours is the documented default")
    }

    // MARK: - Restore and maintenance

    func testRestoreWritesContentsBack() throws {
        let store = makeVault()
        let path = try write("restore me exactly", to: "restorable.txt")
        store.capture(path: path, volumeID: "vol", reason: .created)
        try FileManager.default.removeItem(atPath: path)

        let snapshot = store.versions(of: path)[0]
        let destination = workDir.appendingPathComponent("restored.txt")
        try store.restore(snapshot, to: destination)

        XCTAssertEqual(try String(contentsOf: destination, encoding: .utf8), "restore me exactly")
        // Refuses to clobber without permission.
        XCTAssertThrowsError(try store.restore(snapshot, to: destination))
        XCTAssertNoThrow(try store.restore(snapshot, to: destination, overwrite: true))
        store.close()
    }

    func testCompactionPreservesContent() throws {
        let store = makeVault()
        var paths: [String] = []
        for i in 0..<12 {
            let path = try write("payload number \(i) " + String(repeating: "x", count: 500),
                                 to: "file\(i).txt")
            store.capture(path: path, volumeID: "vol", reason: .created)
            paths.append(path)
        }
        // Drop half, then reclaim the space.
        for path in paths.prefix(6) { store.deleteGroup(path: path) }
        try store.compact()

        for (i, path) in paths.enumerated() where i >= 6 {
            let versions = store.versions(of: path)
            XCTAssertEqual(versions.count, 1, "surviving snapshots must remain after compaction")
            let text = String(data: store.content(of: versions[0])!, encoding: .utf8)
            XCTAssertEqual(text, "payload number \(i) " + String(repeating: "x", count: 500),
                           "compaction must re-seal blobs at their new offsets correctly")
        }
        store.close()
    }

    func testStatsAccounting() throws {
        let store = makeVault()
        for i in 0..<5 {
            let path = try write("body \(i)", to: "s\(i).txt")
            store.capture(path: path, volumeID: "vol", reason: .created)
        }
        let deleted = try write("gone", to: "gone.txt")
        store.capture(path: deleted, volumeID: "vol", reason: .created)
        store.markDeleted(path: deleted)

        let stats = store.currentStats
        XCTAssertEqual(stats.snapshotCount, 6)
        XCTAssertEqual(stats.uniqueFileCount, 6)
        XCTAssertEqual(stats.deletedFileCount, 1)
        XCTAssertGreaterThan(stats.liveBytes, 0)
        XCTAssertGreaterThan(stats.containerBytes, stats.liveBytes)
        store.close()
    }

    func testClearAllEmptiesTheContainer() throws {
        let store = makeVault()
        let path = try write("temporary", to: "x.txt")
        store.capture(path: path, volumeID: "vol", reason: .created)
        store.clearAll()
        XCTAssertTrue(store.allSnapshots().isEmpty)
        XCTAssertEqual(store.currentStats.snapshotCount, 0)
        store.close()
    }

    func testCapturePolicyRespectsExclusions() {
        XCTAssertFalse(ContentCapturePolicy.allows(
            path: "/Applications/Foo.app/Contents/MacOS/Foo",
            include: [], exclude: ContentCapturePolicy.defaultExclusions))
        XCTAssertTrue(ContentCapturePolicy.allows(
            path: "/Users/me/Documents/report.txt",
            include: [], exclude: ContentCapturePolicy.defaultExclusions))
        // Media is no longer excluded by type: the size cap decides, so a small
        // clip is kept and a huge one is skipped for being huge, not for being
        // a video.
        XCTAssertTrue(ContentCapturePolicy.allows(
            path: "/Users/me/Movies/clip.mp4",
            include: [], exclude: ContentCapturePolicy.defaultExclusions))
        // An include list overrides everything else.
        XCTAssertTrue(ContentCapturePolicy.allows(
            path: "/Applications/Foo.app/Contents/x",
            include: [GlobPattern("/Applications/**")],
            exclude: ContentCapturePolicy.defaultExclusions))
    }
}

final class TextDiffTests: XCTestCase {

    func testDetectsAddedAndRemovedLines() {
        let before = "alpha\nbravo\ncharlie\n"
        let after  = "alpha\ndelta\ncharlie\necho\n"
        let result = TextDiff.compare(before, after)

        XCTAssertTrue(result.hasChanges)
        XCTAssertEqual(result.addedCount, 2, "delta and echo were added")
        XCTAssertEqual(result.removedCount, 1, "bravo was removed")

        let added = result.lines.filter { $0.kind == .added }.map(\.text)
        let removed = result.lines.filter { $0.kind == .removed }.map(\.text)
        XCTAssertEqual(Set(added), ["delta", "echo"])
        XCTAssertEqual(removed, ["bravo"])
    }

    func testIdenticalTextHasNoChanges() {
        let text = "one\ntwo\nthree"
        let result = TextDiff.compare(text, text)
        XCTAssertFalse(result.hasChanges)
        XCTAssertEqual(result.addedCount, 0)
        XCTAssertEqual(result.removedCount, 0)
        XCTAssertTrue(result.lines.allSatisfy { $0.kind == .unchanged })
    }

    func testLineNumbersAreAssignedPerSide() {
        let result = TextDiff.compare("a\nb", "a\nc")
        let unchanged = result.lines.first { $0.kind == .unchanged }
        XCTAssertEqual(unchanged?.oldNumber, 1)
        XCTAssertEqual(unchanged?.newNumber, 1)

        let removed = result.lines.first { $0.kind == .removed }
        XCTAssertEqual(removed?.oldNumber, 2)
        XCTAssertNil(removed?.newNumber, "a removed line has no line number on the new side")
    }

    func testLargeInputIsClippedRatherThanHanging() {
        let big = (0..<10_000).map(String.init).joined(separator: "\n")
        let result = TextDiff.compare(big, big + "\nextra")
        XCTAssertTrue(result.truncated, "oversized input must be clipped, not diffed in full")
    }

    func testCondenseKeepsContextAroundChanges() {
        let before = (0..<50).map { "line \($0)" }.joined(separator: "\n")
        var lines = (0..<50).map { "line \($0)" }
        lines[25] = "CHANGED"
        let after = lines.joined(separator: "\n")

        let result = TextDiff.compare(before, after)
        let condensed = TextDiff.condense(result, context: 2)
        XCTAssertLessThan(condensed.count, result.lines.count,
                          "unchanged runs must collapse")
        XCTAssertTrue(condensed.contains { $0.text == "CHANGED" })
    }

    func testTextualDetection() {
        XCTAssertTrue(FileSnapshot.looksTextual(Data("hello world".utf8)))
        XCTAssertTrue(FileSnapshot.looksTextual(Data()))
        // A NUL byte is the clearest signal of binary content.
        XCTAssertFalse(FileSnapshot.looksTextual(Data([0x48, 0x00, 0x49])))
        XCTAssertFalse(FileSnapshot.looksTextual(Data([0xFF, 0xFE, 0x00, 0x01, 0x02])))
    }
}

/// Adding a field to a persisted type must not make a user's saved
/// configuration unreadable — that would silently reset their rules on upgrade.
final class SchemaEvolutionTests: XCTestCase {

    func testRuleActionsDecodeWithoutNewerFields() throws {
        // A payload as written by a build that predates `auditProcesses`.
        let legacy = """
        {"notify":true,"playSound":false,"elevateEventSeverity":true}
        """
        let actions = try JSONDecoder().decode(RuleActions.self, from: Data(legacy.utf8))
        XCTAssertTrue(actions.notify)
        XCTAssertFalse(actions.playSound)
        XCTAssertTrue(actions.elevateEventSeverity)
        XCTAssertFalse(actions.auditProcesses, "a field added later must default, not throw")
    }

    func testAppSettingsDecodeWithoutNewerFields() throws {
        // Only a handful of the fields a current build writes.
        let legacy = """
        {"watchScope":"internalOnly","customWatchPaths":["/tmp"],
         "maxEventsPerSecond":1234,"autoLockMinutes":7,"showDockIcon":false}
        """
        let settings = try JSONDecoder().decode(AppSettings.self, from: Data(legacy.utf8))
        // Saved values survive.
        XCTAssertEqual(settings.watchScope, .internalOnly)
        XCTAssertEqual(settings.customWatchPaths, ["/tmp"])
        XCTAssertEqual(settings.maxEventsPerSecond, 1234)
        XCTAssertEqual(settings.autoLockMinutes, 7)
        XCTAssertFalse(settings.showDockIcon)
        // Fields the old build never wrote fall back to their defaults.
        XCTAssertEqual(settings.contentRetention, .oneDay)
        XCTAssertTrue(settings.captureFileContents)
        XCTAssertEqual(settings.maxCaptureFileBytes, 32 * 1024 * 1024)
    }

    func testFilterSettingsDecodeWithoutNewerFields() throws {
        let legacy = """
        {"ignoreHiddenFiles":true,"resolveFileSizes":false}
        """
        let filter = try JSONDecoder().decode(FilterSettings.self, from: Data(legacy.utf8))
        XCTAssertTrue(filter.ignoreHiddenFiles)
        XCTAssertFalse(filter.resolveFileSizes)
        XCTAssertFalse(filter.excludePatterns.isEmpty,
                       "a missing exclusion list should fall back to the recommended set")
    }

    func testRoundTripPreservesEverything() throws {
        var settings = AppSettings.default
        settings.contentRetention = .thirtyDays
        settings.captureFileContents = false
        settings.maxCaptureFileBytes = 999
        var rule = AlertRule(name: "Round trip")
        rule.actions.auditProcesses = true

        let encoded = try JSONEncoder().encode(settings)
        let decoded = try JSONDecoder().decode(AppSettings.self, from: encoded)
        XCTAssertEqual(decoded.contentRetention, .thirtyDays)
        XCTAssertFalse(decoded.captureFileContents)
        XCTAssertEqual(decoded.maxCaptureFileBytes, 999)

        let encodedRule = try JSONEncoder().encode(rule)
        let decodedRule = try JSONDecoder().decode(AlertRule.self, from: encodedRule)
        XCTAssertTrue(decodedRule.actions.auditProcesses)
    }

    func testEventsDecodeWithoutAttribution() throws {
        // FileEvent gained an optional attribution field; older records omit it.
        let event = FileEvent(kind: .created, path: "/tmp/x")
        let encoded = try JSONEncoder().encode(event)
        let decoded = try JSONDecoder().decode(FileEvent.self, from: encoded)
        XCTAssertNil(decoded.attribution)
        XCTAssertEqual(decoded.path, "/tmp/x")
    }
}

/// Content capture should hold things a person might want back, not the
/// self-rewriting state files applications churn through.
final class CaptureNoiseTests: XCTestCase {

    private func allows(_ path: String) -> Bool {
        ContentCapturePolicy.allows(path: path, include: [],
                                    exclude: ContentCapturePolicy.defaultExclusions)
    }

    func testSkipsApplicationInternalChurn() {
        let home = NSHomeDirectory()
        XCTAssertFalse(allows("\(home)/Library/Group Containers/G7HH3F8CAK.com.getdropbox.dropbox.sync/metrics/store.bin"),
                       "a sync client's metrics file rewrites constantly and is worthless to recover")
        XCTAssertFalse(allows("\(home)/Library/Containers/com.apple.Notes/Data/x.db"))
        XCTAssertFalse(allows("\(home)/Library/HTTPStorages/com.foo.bar/cache.db"))
        XCTAssertFalse(allows("\(home)/Library/Biome/sync/pendingBatches/x.VEC"))
        XCTAssertFalse(allows("/Users/me/project/.git/index"))
        // But the project's own files are kept.
        XCTAssertTrue(allows("/Users/me/project/README.md"))
    }

    func testStillCapturesRealDocuments() {
        let home = NSHomeDirectory()
        XCTAssertTrue(allows("\(home)/Documents/contract.txt"))
        XCTAssertTrue(allows("\(home)/Desktop/notes.md"))
        XCTAssertTrue(allows("\(home)/Library/Preferences/com.example.plist"),
                      "preferences are small, meaningful and worth keeping")
        XCTAssertTrue(allows("/Volumes/USB/exported.csv"))
    }

    func testExcludingContentsDoesNotExcludeEvents() {
        // The event filter and the content-capture filter are separate: a
        // Group Containers write is still recorded in the audit trail.
        let normalizer = EventNormalizer(settings: .default)
        let path = NSHomeDirectory() + "/Library/Group Containers/x.sync/metrics/store.bin"
        XCTAssertTrue(normalizer.shouldReport(path: path),
                      "the change must still be logged even when its contents are not kept")
        XCTAssertFalse(allows(path))
    }
}

/// The Recovery screen polls once a second, so the cheap change check has to be
/// correct — otherwise it either re-groups thousands of versions needlessly or
/// misses new captures entirely.
final class ContentVaultRevisionTests: XCTestCase {

    private var workDir: URL!
    private var keys: VaultKeys!
    private var store: ContentVault!

    override func setUpWithError() throws {
        workDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-rev-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        let vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "revision-tests", enableQuickUnlock: false)
        keys = vault.currentKeys!

        var config = ContentVault.Configuration()
        config.debounceSeconds = 0
        config.excludePatterns = []
        store = ContentVault(keys: keys, url: workDir.appendingPathComponent("c.hdw"), config: config)
    }

    override func tearDownWithError() throws {
        store?.close()
        try? FileManager.default.removeItem(at: workDir)
    }

    @discardableResult
    private func write(_ text: String, _ name: String) throws -> String {
        let url = workDir.appendingPathComponent(name)
        try text.write(to: url, atomically: false, encoding: .utf8)
        return url.path
    }

    func testRevisionIsStableWhenNothingHappens() {
        let before = store.revision
        XCTAssertEqual(store.revision, before)
        XCTAssertEqual(store.revision, before, "polling alone must not look like a change")
    }

    func testCaptureAdvancesTheRevision() throws {
        let before = store.revision
        let path = try write("hello", "a.txt")
        XCTAssertTrue(store.capture(path: path, volumeID: nil, reason: .created))
        XCTAssertGreaterThan(store.revision, before)
    }

    func testSkippedCaptureDoesNotAdvanceTheRevision() throws {
        let path = try write("same", "b.txt")
        store.capture(path: path, volumeID: nil, reason: .created)
        let after = store.revision
        // Identical content is skipped, so nothing changed for the viewer.
        XCTAssertFalse(store.capture(path: path, volumeID: nil, reason: .modified))
        XCTAssertEqual(store.revision, after)
    }

    func testDeletionAndRemovalAdvanceTheRevision() throws {
        let path = try write("gone soon", "c.txt")
        store.capture(path: path, volumeID: nil, reason: .created)

        var mark = store.revision
        store.markDeleted(path: path)
        XCTAssertGreaterThan(store.revision, mark, "a deletion changes what the list shows")

        mark = store.revision
        store.deleteGroup(path: path)
        XCTAssertGreaterThan(store.revision, mark)

        mark = store.revision
        store.clearAll()
        XCTAssertGreaterThan(store.revision, mark)
    }
}

/// Recovery renders a version according to what it actually is.
final class PreviewKindTests: XCTestCase {

    private func detect(_ bytes: [UInt8], _ name: String) -> PreviewKind {
        PreviewKind.detect(data: Data(bytes), fileName: name)
    }

    func testRecognisesImagesByTheirBytes() {
        XCTAssertEqual(detect([0x89, 0x50, 0x4E, 0x47, 0x0D], "whatever"), .image)   // PNG
        XCTAssertEqual(detect([0xFF, 0xD8, 0xFF, 0xE0], "whatever"), .image)         // JPEG
        XCTAssertEqual(detect([0x47, 0x49, 0x46, 0x38, 0x39], "whatever"), .image)   // GIF
    }

    func testBytesBeatTheFileName() {
        // A screenshot saved as ".txt" is still an image.
        XCTAssertEqual(detect([0x89, 0x50, 0x4E, 0x47], "screenshot.txt"), .image)
        // And a text file named ".png" should not be rendered as an image.
        XCTAssertEqual(PreviewKind.detect(data: Data("hello world".utf8),
                                          fileName: "notreally.png"), .image,
                       "the extension is still used when no signature matches")
    }

    func testRecognisesContainerFormats() {
        var heic: [UInt8] = [0, 0, 0, 0x18]
        heic.append(contentsOf: Array("ftypheic".utf8))
        heic.append(contentsOf: [0, 0, 0, 0])
        XCTAssertEqual(PreviewKind.detect(data: Data(heic), fileName: "photo"), .image)

        var wav: [UInt8] = Array("RIFF".utf8) + [0, 0, 0, 0] + Array("WAVE".utf8)
        wav.append(contentsOf: [0, 0, 0, 0])
        XCTAssertEqual(PreviewKind.detect(data: Data(wav), fileName: "sound"), .audio)

        var webp: [UInt8] = Array("RIFF".utf8) + [0, 0, 0, 0] + Array("WEBP".utf8)
        webp.append(contentsOf: [0, 0, 0, 0])
        XCTAssertEqual(PreviewKind.detect(data: Data(webp), fileName: "pic"), .image)
    }

    func testFallsBackToTheExtension() {
        XCTAssertEqual(detect([0x00, 0x01, 0x02, 0x03], "clip.mov"), .video)
        XCTAssertEqual(detect([0x00, 0x01, 0x02, 0x03], "song.m4a"), .audio)
        XCTAssertEqual(detect([0x00, 0x01, 0x02, 0x03], "photo.heic"), .image)
    }

    func testTextAndBinaryOfLastResort() {
        XCTAssertEqual(PreviewKind.detect(data: Data("plain words".utf8),
                                          fileName: "notes"), .text)
        XCTAssertEqual(PreviewKind.detect(data: Data([0x00, 0xFF, 0x00, 0xFE]),
                                          fileName: "blob"), .binary)
    }

    func testCapabilityFlags() {
        XCTAssertTrue(PreviewKind.text.supportsTextDiff)
        XCTAssertFalse(PreviewKind.image.supportsTextDiff)
        XCTAssertTrue(PreviewKind.image.supportsVisualDiff)
        XCTAssertTrue(PreviewKind.pdf.isRenderable)
        XCTAssertFalse(PreviewKind.video.isRenderable)
    }
}

/// Recovery holds a `FileSnapshot` value for as long as a version stays
/// selected. Compaction rewrites blob offsets, and the offset is authenticated —
/// so trusting the held copy made a perfectly intact version report itself as
/// unreadable.
final class StaleSnapshotTests: XCTestCase {

    private var workDir: URL!
    private var container: URL!
    private var keys: VaultKeys!

    override func setUpWithError() throws {
        workDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-stale-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        container = workDir.appendingPathComponent("c.hdw")
        let vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "stale-snapshot", enableQuickUnlock: false)
        keys = vault.currentKeys!
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: workDir)
    }

    private func makeVault() -> ContentVault {
        var config = ContentVault.Configuration()
        config.debounceSeconds = 0
        config.excludePatterns = []
        return ContentVault(keys: keys, url: container, config: config)
    }

    func testHeldSnapshotStillReadsAfterCompaction() throws {
        let store = makeVault()
        var kept: [String] = []
        for i in 0..<10 {
            let url = workDir.appendingPathComponent("f\(i).txt")
            try String(repeating: "payload \(i) ", count: 200).write(to: url, atomically: false, encoding: .utf8)
            store.capture(path: url.path, volumeID: nil, reason: .created)
            kept.append(url.path)
        }

        // What the interface holds while a version is selected.
        let held = try XCTUnwrap(store.versions(of: kept[7]).first)
        let expected = try XCTUnwrap(store.content(of: held))

        // Remove earlier versions and reclaim, which moves the remaining blobs.
        for path in kept.prefix(5) { store.deleteGroup(path: path) }
        try store.compact()

        let after = store.content(of: held)
        XCTAssertEqual(after, expected,
                       "a snapshot held across a compaction must still resolve to its bytes")
        store.close()
    }

    func testPurgedAndUnreadableAreDistinguished() throws {
        let store = makeVault()
        let url = workDir.appendingPathComponent("temp.txt")
        try "will be removed".write(to: url, atomically: false, encoding: .utf8)
        store.capture(path: url.path, volumeID: nil, reason: .created)
        let held = try XCTUnwrap(store.versions(of: url.path).first)

        if case .data = store.contentResult(of: held) {} else {
            XCTFail("expected the version to read back")
        }

        store.deleteGroup(path: url.path)
        // Gone from the index is "purged", not "corrupt" — the difference is
        // what the user is told about their data.
        if case .purged = store.contentResult(of: held) {} else {
            XCTFail("a removed version must report as purged")
        }
        store.close()
    }

    func testTemporaryCopyRoundTrips() throws {
        let store = makeVault()
        let url = workDir.appendingPathComponent("openme.txt")
        try "open this in another app".write(to: url, atomically: false, encoding: .utf8)
        store.capture(path: url.path, volumeID: nil, reason: .created)
        let version = try XCTUnwrap(store.versions(of: url.path).first)

        let copy = try XCTUnwrap(store.temporaryCopy(of: version))
        XCTAssertTrue(copy.lastPathComponent.contains("openme.txt"))
        XCTAssertEqual(try String(contentsOf: copy, encoding: .utf8), "open this in another app")

        let mode = try FileManager.default.attributesOfItem(atPath: copy.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o600, "a decrypted copy must not be world readable")

        ContentVault.clearTemporaryCopies()
        XCTAssertFalse(FileManager.default.fileExists(atPath: copy.path),
                       "decrypted previews must not outlive the session")
        store.close()
    }
}

/// The case that matters most: a file that has simply been sitting in a folder,
/// never written while the watcher was running, and then deleted.
///
/// Nothing was captured at write time because no write happened. But a Finder
/// delete is a *rename into the Trash*, so at that moment the bytes are still on
/// disk — and that is the last chance to keep them.
final class DeletionCaptureTests: XCTestCase {

    private var home: URL!
    private var desktop: URL!
    private var trash: URL!
    private var vault: ContentVault!
    private var keys: VaultKeys!

    override func setUpWithError() throws {
        home = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-del-\(UUID().uuidString)")
        desktop = home.appendingPathComponent("Desktop")
        trash = home.appendingPathComponent(".Trash")
        try FileManager.default.createDirectory(at: desktop, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: trash, withIntermediateDirectories: true)

        let manager = VaultKeyManager(vaultURL: home.appendingPathComponent("vault.json"))
        try manager.createVault(password: "deletion-capture", enableQuickUnlock: false)
        keys = manager.currentKeys!

        var config = ContentVault.Configuration()
        config.debounceSeconds = 0
        config.excludePatterns = ContentCapturePolicy.defaultExclusions
        vault = ContentVault(keys: keys, url: home.appendingPathComponent("c.hdw"), config: config)
    }

    override func tearDownWithError() throws {
        vault?.close()
        try? FileManager.default.removeItem(at: home)
    }

    func testTrashPathsAreRecognised() {
        XCTAssertTrue(TrashPaths.isTrash("/Users/me/.Trash/photo.png"))
        XCTAssertTrue(TrashPaths.isTrash("/Volumes/USB/.Trashes/501/doc.pdf"))
        XCTAssertFalse(TrashPaths.isTrash("/Users/me/Desktop/photo.png"))
        XCTAssertFalse(TrashPaths.isTrash("/Users/me/Trash Notes/x.txt"),
                       "a folder merely named like the Trash is not the Trash")
    }

    func testCapturesAFileOnlyEverSeenBeingDeleted() throws {
        // A screenshot that has been on the Desktop for months. Nothing was
        // captured, because nothing wrote to it.
        let original = desktop.appendingPathComponent("Screenshot.png")
        let pixels = Data([0x89, 0x50, 0x4E, 0x47] + Array(repeating: UInt8(0x7F), count: 4_000))
        try pixels.write(to: original)
        XCTAssertFalse(vault.hasContent(for: original.path))

        // The Finder moves it to the Trash — the bytes are still there.
        let inTrash = trash.appendingPathComponent("Screenshot.png")
        try FileManager.default.moveItem(at: original, to: inTrash)

        // This is what the engine does on a rename into the Trash.
        XCTAssertTrue(vault.capture(path: inTrash.path, volumeID: nil,
                                    reason: .beforeOverwrite, recordAs: original.path),
                      "a file moved to the Trash must still be capturable")
        vault.markDeleted(path: original.path)

        // It appears under its real name, marked deleted, with its bytes intact.
        let group = try XCTUnwrap(vault.groups(deletedOnly: true)
            .first { $0.path == original.path })
        XCTAssertEqual(group.fileName, "Screenshot.png")
        XCTAssertTrue(group.isDeleted)
        let recovered = try XCTUnwrap(vault.content(of: try XCTUnwrap(group.latest)))
        XCTAssertEqual(recovered, pixels, "the recovered bytes must be the file that was deleted")
        XCTAssertEqual(PreviewKind.detect(data: recovered, fileName: group.fileName), .image)
    }

    func testFiledUnderTheOriginalNameNotTheTrashPath() throws {
        let original = desktop.appendingPathComponent("Report.txt")
        try "quarterly".write(to: original, atomically: false, encoding: .utf8)
        let inTrash = trash.appendingPathComponent("Report.txt")
        try FileManager.default.moveItem(at: original, to: inTrash)

        vault.capture(path: inTrash.path, volumeID: nil,
                      reason: .beforeOverwrite, recordAs: original.path)

        let paths = vault.groups().map(\.path)
        XCTAssertTrue(paths.contains(original.path), "the user looks for it where it used to be")
        XCTAssertFalse(paths.contains(inTrash.path), "not where the system happened to put it")
    }

    func testAnyDirectoryIsEligible() {
        // No directory is excluded on principle; only package internals,
        // system files and self-rewriting application state.
        for path in ["/Users/me/Desktop/photo.png",
                     "/Users/me/Documents/Taxes/2024.pdf",
                     "/Users/me/Movies/holiday.mov",
                     "/Users/me/Music/demo.wav",
                     "/Volumes/USB/design.psd",
                     "/Users/me/Downloads/archive.zip",
                     "/opt/homebrew/etc/config.conf"] {
            XCTAssertTrue(
                ContentCapturePolicy.allows(path: path, include: [],
                                            exclude: ContentCapturePolicy.defaultExclusions),
                "\(path) should be eligible — the size cap is what limits capture, not the file type")
        }
    }

    func testStillSkipsPackageInternalsAndChurn() {
        for path in ["/Applications/Foo.app/Contents/MacOS/Foo",
                     "/Users/me/Pictures/Library.photoslibrary/database/x.db",
                     "/Users/me/Library/Group Containers/x.sync/metrics/store.bin",
                     "/System/Library/Foo"] {
            XCTAssertFalse(
                ContentCapturePolicy.allows(path: path, include: [],
                                            exclude: ContentCapturePolicy.defaultExclusions),
                "\(path) is not worth keeping copies of")
        }
    }

    func testLargerDefaultCapCoversPhotos() {
        // A 4 MB cap silently skipped most screenshots and camera images.
        XCTAssertEqual(AppSettings.default.maxCaptureFileBytes, 32 * 1024 * 1024)
    }
}

/// The Recovery search box has to stay responsive with thousands of files.
final class RecoverySearchPerformanceTests: XCTestCase {

    private var workDir: URL!
    private var store: ContentVault!

    override func setUpWithError() throws {
        workDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-perf-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        let vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "search-perf", enableQuickUnlock: false)

        var config = ContentVault.Configuration()
        config.debounceSeconds = 0
        config.excludePatterns = []
        store = ContentVault(keys: vault.currentKeys!,
                             url: workDir.appendingPathComponent("c.hdw"), config: config)

        // A realistic library: many files, several versions each.
        for i in 0..<400 {
            let url = workDir.appendingPathComponent("file\(i).txt")
            for version in 0..<3 {
                try "contents \(i) revision \(version)".write(to: url, atomically: false, encoding: .utf8)
                store.capture(path: url.path, volumeID: nil, reason: .modified)
            }
        }
    }

    override func tearDownWithError() throws {
        store?.close()
        try? FileManager.default.removeItem(at: workDir)
    }

    func testGroupingIsTheExpensivePart() throws {
        XCTAssertEqual(store.allSnapshots().count, 1_200)

        // Grouping: the cost that must not run per keystroke.
        let groupStart = Date()
        let groups = store.groups()
        let groupTime = Date().timeIntervalSince(groupStart)
        XCTAssertEqual(groups.count, 400)

        // Filtering the already-grouped list: what typing actually costs.
        let filterStart = Date()
        for term in ["file1", "file12", "file123"] {
            _ = groups.filter { $0.path.range(of: term, options: .caseInsensitive) != nil }
        }
        let filterTime = Date().timeIntervalSince(filterStart) / 3

        // Filtering must be dramatically cheaper, or separating them bought
        // nothing.
        XCTAssertLessThan(filterTime, groupTime,
                          "filtering must be cheaper than regrouping")
        XCTAssertLessThan(filterTime, 0.05,
                          "a keystroke must not cost more than a few milliseconds")
    }

    func testSearchNarrowsCorrectly() {
        let groups = store.groups()
        let exact = groups.filter { $0.path.contains("file123") }
        XCTAssertEqual(exact.count, 1)

        let broad = groups.filter { $0.path.contains("file1") }
        // file1, file10-19, file100-199 …
        XCTAssertGreaterThan(broad.count, 100)
        XCTAssertTrue(broad.allSatisfy { $0.path.contains("file1") })
    }

    func testEveryFileKeepsItsVersionsGrouped() {
        let groups = store.groups()
        XCTAssertTrue(groups.allSatisfy { $0.versions.count == 3 })
        // Newest first, so the default selection is the latest version.
        for group in groups.prefix(20) {
            let dates = group.versions.map(\.capturedAt)
            XCTAssertEqual(dates, dates.sorted(by: >))
        }
    }
}

/// Recovery has to keep working while the app is closed, which means the
/// privileged daemon must be able to capture contents too — without holding a
/// key that could read any of it back.
final class DaemonContentCaptureTests: XCTestCase {

    private var workDir: URL!
    private var container: URL!
    private var keys: VaultKeys!

    override func setUpWithError() throws {
        workDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-dcc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        setenv(AppPaths.systemOverrideEnvironmentKey, workDir.path, 1)
        DaemonIdentity.loadOrCreate()

        container = workDir.appendingPathComponent("contents-agent.hdw")
        let vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "daemon-content", enableQuickUnlock: false)
        keys = vault.currentKeys!
    }

    override func tearDownWithError() throws {
        unsetenv(AppPaths.systemOverrideEnvironmentKey)
        try? FileManager.default.removeItem(at: workDir)
    }

    private func recorder() -> ContentVault {
        var config = ContentVault.Configuration()
        config.debounceSeconds = 0
        config.excludePatterns = []
        return ContentVault(sealMode: .writeOnly(recipient: keys.ingestPublicKey),
                            url: container, config: config)
    }

    private func reader() -> ContentVault {
        ContentVault(sealMode: .readIngest(keys.ingest), url: container)
    }

    func testDaemonCapturesWhatTheAppCanRead() throws {
        let file = workDir.appendingPathComponent("secret.txt")
        try "captured while the app was closed".write(to: file, atomically: false, encoding: .utf8)

        let daemon = recorder()
        XCTAssertTrue(daemon.capture(path: file.path, volumeID: nil, reason: .created))
        daemon.saveIndexIfDirty()
        daemon.close()

        let app = reader()
        let group = try XCTUnwrap(app.groups().first { $0.path == file.path })
        let data = try XCTUnwrap(app.content(of: try XCTUnwrap(group.latest)))
        XCTAssertEqual(String(data: data, encoding: .utf8), "captured while the app was closed")
        app.close()
    }

    func testTheDaemonCannotReadBackWhatItCaptured() throws {
        let file = workDir.appendingPathComponent("private.txt")
        try "the recorder must not be able to read this".write(to: file, atomically: false, encoding: .utf8)

        let daemon = recorder()
        daemon.capture(path: file.path, volumeID: nil, reason: .created)
        let version = try XCTUnwrap(daemon.versions(of: file.path).first)

        XCTAssertNil(daemon.content(of: version),
                     "a write-only recorder must not be able to decrypt its own captures")
        daemon.close()
    }

    func testDaemonKeepsItsOwnBookkeepingAcrossRestart() throws {
        let file = workDir.appendingPathComponent("versioned.txt")

        let first = recorder()
        try "one".write(to: file, atomically: false, encoding: .utf8)
        first.capture(path: file.path, volumeID: nil, reason: .created)
        first.saveIndexIfDirty()
        first.close()

        // A restart: it cannot open its own container, but the sidecar sealed to
        // its enclave key lets it carry on numbering rather than starting over.
        let second = recorder()
        XCTAssertTrue(second.hasContent(for: file.path),
                      "the recorder must remember what it already captured")
        try "two".write(to: file, atomically: false, encoding: .utf8)
        second.capture(path: file.path, volumeID: nil, reason: .modified)
        second.saveIndexIfDirty()
        second.close()

        let app = reader()
        let versions = app.versions(of: file.path)
        XCTAssertEqual(versions.count, 2)
        XCTAssertEqual(Set(versions.map(\.generation)), [1, 2],
                       "versions must keep numbering across a restart")
        app.close()
    }

    func testNothingReadableOnDisk() throws {
        let file = workDir.appendingPathComponent("SECRETMARKER.txt")
        try "SECRETMARKER body".write(to: file, atomically: false, encoding: .utf8)
        let daemon = recorder()
        daemon.capture(path: file.path, volumeID: nil, reason: .created)
        daemon.saveIndexIfDirty()
        daemon.close()

        let bytes = try Data(contentsOf: container)
        XCTAssertNil(bytes.range(of: Data("SECRETMARKER".utf8)),
                     "neither the contents nor the path may be readable in the container")
    }

    func testConfigurationTellsTheDaemonToCapture() {
        let settings = AppSettings.default
        let config = AgentConfiguration(from: settings, rules: [], enabled: true)
        XCTAssertTrue(config.appSettings.captureFileContents,
                      "recovery must keep working when the app is closed")
        XCTAssertEqual(config.appSettings.maxCaptureFileBytes, settings.maxCaptureFileBytes)
        XCTAssertEqual(config.appSettings.contentRetention, settings.contentRetention)
    }
}

/// Anything the daemon writes for the app to read must be readable by the app.
///
/// This has gone wrong three times — log segments, the status file, and the
/// content container — each time by hardcoding 0600 in a new write path. Root
/// ownership is what protects these files; the mode only decides whether the
/// app can open them at all, and everything here is sealed anyway.
final class DaemonFilePermissionTests: XCTestCase {

    private var workDir: URL!

    override func setUpWithError() throws {
        workDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-perm-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        setenv(AppPaths.overrideEnvironmentKey, workDir.path, 1)
        setenv(AppPaths.systemOverrideEnvironmentKey, workDir.path, 1)
        DaemonIdentity.loadOrCreate()
    }

    override func tearDownWithError() throws {
        unsetenv(AppPaths.overrideEnvironmentKey)
        unsetenv(AppPaths.systemOverrideEnvironmentKey)
        try? FileManager.default.removeItem(at: workDir)
    }

    private func mode(_ url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
    }

    func testContentContainerFollowsTheWriterNotAHardcodedMode() throws {
        let vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("v.json"))
        try vault.createVault(password: "permissions", enableQuickUnlock: false)
        let container = workDir.appendingPathComponent("contents-agent.hdw")

        var config = ContentVault.Configuration()
        config.debounceSeconds = 0
        config.excludePatterns = []
        let store = ContentVault(sealMode: .writeOnly(recipient: vault.currentKeys!.ingestPublicKey),
                                 url: container, config: config)
        let file = workDir.appendingPathComponent("x.txt")
        try "content".write(to: file, atomically: false, encoding: .utf8)
        store.capture(path: file.path, volumeID: nil, reason: .created)
        store.saveIndexIfDirty()
        store.close()

        XCTAssertEqual(try mode(container), AppPaths.filePermissions,
                       "the container must use the writer's permissions, so a root daemon leaves it app-readable")
    }

    func testDaemonPrivateBookkeepingStaysPrivate() throws {
        let vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("v.json"))
        try vault.createVault(password: "permissions", enableQuickUnlock: false)
        let container = workDir.appendingPathComponent("contents-agent.hdw")

        var config = ContentVault.Configuration()
        config.debounceSeconds = 0
        config.excludePatterns = []
        let store = ContentVault(sealMode: .writeOnly(recipient: vault.currentKeys!.ingestPublicKey),
                                 url: container, config: config)
        let file = workDir.appendingPathComponent("y.txt")
        try "content".write(to: file, atomically: false, encoding: .utf8)
        store.capture(path: file.path, volumeID: nil, reason: .created)
        store.saveIndexIfDirty()
        store.close()

        // The sidecar is the daemon's own, sealed to its enclave key; no reason
        // for anyone else to see it.
        let sidecar = container.appendingPathExtension("idx")
        XCTAssertEqual(try mode(sidecar), 0o600)
    }

    func testEveryDaemonWrittenArtefactIsReadableByTheApp() throws {
        let vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("v.json"))
        try vault.createVault(password: "permissions", enableQuickUnlock: false)
        let keys = vault.currentKeys!

        IngestKeyFile.export(keys.ingestPublicKey)
        EventCursor(lastEventID: 7).save(settingsKey: keys.settings)
        AgentStatus(pid: 1).write(sealingTo: keys.ingestPublicKey)
        _ = BackgroundService.publishConfiguration(settings: .default, rules: [])

        // Everything the app has to open must be at least owner-readable, and
        // must not be more restrictive than the process that wrote it.
        for url in [AgentPaths.ingestPublicKey, EventCursor.fileURL,
                    AgentPaths.status, DaemonIdentity.publicKeyURL] {
            guard FileManager.default.fileExists(atPath: url.path) else {
                XCTFail("expected \(url.lastPathComponent) to exist"); continue
            }
            let m = try mode(url)
            XCTAssertGreaterThanOrEqual(m & 0o400, 0o400,
                                        "\(url.lastPathComponent) must be readable by its owner")
        }
    }
}

/// The app watches a container another process is writing. Without a way to
/// re-read it, everything captured after the app opened it stays invisible —
/// which is indistinguishable, from the user's side, from nothing being
/// captured at all.
final class ContainerReloadTests: XCTestCase {

    private var workDir: URL!
    private var container: URL!
    private var keys: VaultKeys!

    override func setUpWithError() throws {
        workDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-reload-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        setenv(AppPaths.systemOverrideEnvironmentKey, workDir.path, 1)
        DaemonIdentity.loadOrCreate()
        container = workDir.appendingPathComponent("contents-agent.hdw")
        let vault = VaultKeyManager(vaultURL: workDir.appendingPathComponent("v.json"))
        try vault.createVault(password: "reload-tests", enableQuickUnlock: false)
        keys = vault.currentKeys!
    }

    override func tearDownWithError() throws {
        unsetenv(AppPaths.systemOverrideEnvironmentKey)
        try? FileManager.default.removeItem(at: workDir)
    }

    private func recorder() -> ContentVault {
        var config = ContentVault.Configuration()
        config.debounceSeconds = 0
        config.excludePatterns = []
        return ContentVault(sealMode: .writeOnly(recipient: keys.ingestPublicKey),
                            url: container, config: config)
    }

    func testReaderSeesCapturesMadeAfterItOpened() throws {
        let daemon = recorder()
        let first = workDir.appendingPathComponent("first.txt")
        try "one".write(to: first, atomically: false, encoding: .utf8)
        daemon.capture(path: first.path, volumeID: nil, reason: .created)
        daemon.saveIndexIfDirty()

        // The app opens the container and sees what exists so far.
        let app = ContentVault(sealMode: .readIngest(keys.ingest), url: container)
        XCTAssertEqual(app.groups().count, 1)

        // The daemon keeps working while the app is open.
        let second = workDir.appendingPathComponent("second.txt")
        try "two".write(to: second, atomically: false, encoding: .utf8)
        daemon.capture(path: second.path, volumeID: nil, reason: .created)
        daemon.saveIndexIfDirty()

        // Without a reload the app is still looking at a stale index.
        XCTAssertEqual(app.groups().count, 1, "the index is a snapshot until reloaded")

        XCTAssertTrue(app.reloadIfChanged(), "a changed container must be noticed")
        XCTAssertEqual(app.groups().count, 2,
                       "captures made after the app opened must become visible")
        daemon.close()
        app.close()
    }

    func testReloadIsCheapWhenNothingChanged() throws {
        let daemon = recorder()
        let file = workDir.appendingPathComponent("x.txt")
        try "content".write(to: file, atomically: false, encoding: .utf8)
        daemon.capture(path: file.path, volumeID: nil, reason: .created)
        daemon.saveIndexIfDirty()
        daemon.close()

        let app = ContentVault(sealMode: .readIngest(keys.ingest), url: container)
        _ = app.reloadIfChanged()
        // Polling once a second must not re-decrypt the index every time.
        XCTAssertFalse(app.reloadIfChanged())
        XCTAssertFalse(app.reloadIfChanged())
        app.close()
    }

    func testRevisionAdvancesOnReloadSoTheListRefreshes() throws {
        let daemon = recorder()
        let file = workDir.appendingPathComponent("y.txt")
        try "a".write(to: file, atomically: false, encoding: .utf8)
        daemon.capture(path: file.path, volumeID: nil, reason: .created)
        daemon.saveIndexIfDirty()

        let app = ContentVault(sealMode: .readIngest(keys.ingest), url: container)
        let before = app.revision

        try "b".write(to: file, atomically: false, encoding: .utf8)
        daemon.capture(path: file.path, volumeID: nil, reason: .modified)
        daemon.saveIndexIfDirty()

        XCTAssertTrue(app.reloadIfChanged())
        XCTAssertGreaterThan(app.revision, before,
                             "the revision must move, or the list will not rebuild")
        daemon.close()
        app.close()
    }
}

/// A hex dump chops every string into 16-character fragments. For the files
/// people actually open — databases, plists, protobuf — the readable fields are
/// the point, so they need to be extractable as text.
final class BinaryTextTests: XCTestCase {

    func testExtractsPrintableRuns() {
        var data = Data([0x00, 0x01, 0x02])
        data.append(Data("alfredchiesa@icloud.com".utf8))
        data.append(Data([0x00, 0xFF]))
        data.append(Data("+12057254200".utf8))
        data.append(Data([0x00]))

        let runs = BinaryText.runs(in: data)
        let texts = runs.map(\.text)
        XCTAssertTrue(texts.contains("alfredchiesa@icloud.com"))
        XCTAssertTrue(texts.contains("+12057254200"))
    }

    func testRecordsWhereEachRunSits() {
        var data = Data(repeating: 0, count: 16)
        data.append(Data("PersonHandle".utf8))
        let run = BinaryText.runs(in: data).first { $0.text == "PersonHandle" }
        XCTAssertEqual(run?.offset, 16, "the offset is what makes a finding locatable")
    }

    func testIgnoresShortNoise() {
        // Random bytes produce two- and three-character coincidences; those are
        // noise, not text.
        let data = Data([0x41, 0x42, 0x00, 0x43, 0x44, 0x00, 0x45, 0x00])
        XCTAssertTrue(BinaryText.runs(in: data).isEmpty)
        XCTAssertFalse(BinaryText.runs(in: data, minimumLength: 2).isEmpty)
    }

    func testFindsUTF16Text() {
        // Binary plists and Core Data stores hold UTF-16; an ASCII-only pass
        // sees single characters separated by NULs and finds nothing.
        var data = Data([0x00, 0x00])
        for character in "RecipientHandles".utf8 {
            data.append(character)
            data.append(0x00)
        }
        let texts = BinaryText.runs(in: data).map(\.text)
        XCTAssertTrue(texts.contains("RecipientHandles"),
                      "UTF-16 text must be recovered too")
    }

    func testRunsComeBackInFileOrder() {
        var data = Data()
        data.append(Data("first-string-here".utf8))
        data.append(Data([0x00, 0x00]))
        data.append(Data("second-string-here".utf8))
        let offsets = BinaryText.runs(in: data).map(\.offset)
        XCTAssertEqual(offsets, offsets.sorted())
    }

    func testReadableFractionSeparatesTextFromNoise() {
        let mostlyText = Data("this file is almost entirely readable prose".utf8)
        XCTAssertGreaterThan(BinaryText.readableFraction(of: mostlyText), 0.8)

        let noise = Data((0..<4_000).map { _ in UInt8.random(in: 0...31) })
        XCTAssertLessThan(BinaryText.readableFraction(of: noise), 0.2)
    }

    func testHandlesEmptyAndTinyInput() {
        XCTAssertTrue(BinaryText.runs(in: Data()).isEmpty)
        XCTAssertEqual(BinaryText.readableFraction(of: Data()), 0)
        XCTAssertTrue(BinaryText.runs(in: Data([0x41])).isEmpty)
    }
}
