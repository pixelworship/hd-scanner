import XCTest
@testable import HDWatcherCore

/// A restart of the write-only recorder used to destroy the record of every
/// segment before it, because the published manifest is sealed to a key the
/// recorder does not hold. The files survived; their block counts and chain
/// MACs did not — and verification then reported perfectly good segments as
/// "contents were altered", which is the worst thing an audit tool can say
/// when it is not true.
///
/// These cover both halves: the unlinkable-but-sound case must not be called
/// tampering, and actual tampering must still be caught.
final class LogChainRecoveryTests: XCTestCase {

    private var tempDir: URL!
    private var vault: VaultKeyManager!
    private var logDir: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-chain-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        vault = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "chain-test-password", enableQuickUnlock: false)
        logDir = tempDir.appendingPathComponent("log")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    /// Long, non-repeating paths so the blocks do not compress away to
    /// nothing: the test needs the writer to actually roll over.
    private func events(_ range: Range<Int>) -> [FileEvent] {
        range.map {
            FileEvent(kind: .modified,
                      path: "/data/\(UUID().uuidString)/file-\($0)-\(UUID().uuidString).bin",
                      size: Int64($0))
        }
    }

    /// Writes two segments the way the daemon does, then throws away the
    /// manifest — exactly what a restart used to do.
    private func writeTwoSegmentsAndLoseTheManifest() throws -> [SegmentRecord] {
        var config = EncryptedLogWriter.Configuration()
        config.maxSegmentBytes = 16 * 1024
        config.eventsPerBlock = 32
        let writer = EncryptedLogWriter(directory: logDir,
                                        sealMode: .writeOnly(recipient: vault.currentKeys!.ingestPublicKey),
                                        manifest: LogManifest(), config: config)
        for chunk in stride(from: 0, to: 1_200, by: 200) {
            writer.append(events(chunk..<(chunk + 200)))
        }
        writer.close()

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let discovered = reader.discoverSegments()
        XCTAssertGreaterThan(discovered.count, 1, "the test needs more than one segment")
        return discovered
    }

    func testSegmentsWithNoSurvivingRecordAreVerifiedNotAccused() throws {
        let discovered = try writeTwoSegmentsAndLoseTheManifest()
        var manifest = LogManifest()
        manifest.segments = discovered           // synthesised from disk: no chain MACs

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let report = reader.verify(manifest: manifest)

        XCTAssertTrue(report.results.allSatisfy(\.ok),
                      "sound contents must not be reported as altered: \(report.results.compactMap(\.problem))")
        XCTAssertFalse(report.results.contains { $0.problem?.contains("altered") == true })
    }

    func testAnAlteredBlockIsStillCaught() throws {
        let discovered = try writeTwoSegmentsAndLoseTheManifest()
        var manifest = LogManifest()
        manifest.segments = discovered

        // Corrupt the FIRST segment, just past its header — deterministically
        // an interior block of a segment that cannot be the one being written.
        // Flipping a byte at the midpoint of the *last* segment was a coin
        // toss: if it landed in that segment's trailing block, the torn-write
        // tolerance correctly ignored it and this test failed at random.
        let target = logDir.appendingPathComponent(discovered[0].fileName)
        var bytes = try Data(contentsOf: target)
        let offset = LogFormat.agentHeaderSize + 16
        XCTAssertLessThan(offset, bytes.count, "the segment must have a payload to corrupt")
        bytes[offset] = bytes[offset] ^ 0xFF
        try bytes.write(to: target)

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let report = reader.verify(manifest: manifest)
        XCTAssertFalse(report.isIntact, "a rewritten block must fail verification")
        XCTAssertTrue(report.results.contains { !$0.ok })
    }

    func testTheLastBlockOfASupersededSegmentIsStillVerified() throws {
        // The torn-write tolerance exists because the segment being written can
        // be observed half-finished. It must not extend to segments that have
        // been superseded: every discovered segment carries sealed: false, so
        // tolerating a bad trailing block on all of them left the final block
        // of every segment in the log rewritable without detection.
        let discovered = try writeTwoSegmentsAndLoseTheManifest()
        var manifest = LogManifest()
        manifest.segments = discovered
        XCTAssertGreaterThan(discovered.count, 1, "needs a segment that is not the newest")

        // Corrupt the very last byte of the payload of the FIRST segment — the
        // position the tolerance used to excuse.
        let target = logDir.appendingPathComponent(discovered[0].fileName)
        var bytes = try Data(contentsOf: target)
        let offset = bytes.count - 1
        bytes[offset] = bytes[offset] ^ 0xFF
        try bytes.write(to: target)

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let report = reader.verify(manifest: manifest)
        XCTAssertFalse(report.isIntact,
                       "a rewritten trailing block in a superseded segment must be caught")
    }

    func testTheSegmentBeingWrittenIsStillForgivenATornTail() throws {
        // The other side of the same rule: the newest segment may genuinely be
        // caught mid-write, and calling that tampering would cry wolf every
        // time the log is verified while recording continues.
        let discovered = try writeTwoSegmentsAndLoseTheManifest()
        var manifest = LogManifest()
        manifest.segments = discovered

        let newest = discovered.max { $0.segmentIndex < $1.segmentIndex }!
        let target = logDir.appendingPathComponent(newest.fileName)
        var bytes = try Data(contentsOf: target)
        bytes.append(contentsOf: [0xDE, 0xAD, 0xBE, 0xEF])   // a half-written block
        try bytes.write(to: target)

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let report = reader.verify(manifest: manifest)
        XCTAssertTrue(report.results.allSatisfy(\.ok),
                      "a torn tail on the active segment is not tampering: \(report.results.compactMap(\.problem))")
    }

    func testATruncatedSegmentIsStillCaught() throws {
        let discovered = try writeTwoSegmentsAndLoseTheManifest()
        var manifest = LogManifest()
        // Keep the real block counts for the first segment, so truncation has
        // something to be measured against.
        manifest.segments = discovered
        manifest.segments[0].sealed = true
        manifest.segments[0].blockCount = 9_999

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let report = reader.verify(manifest: manifest)
        XCTAssertTrue(report.results.contains { $0.problem?.contains("truncated") == true },
                      "missing blocks must be reported: \(report.results.compactMap(\.problem))")
    }

    func testADeletedSegmentIsStillReportedMissing() throws {
        let discovered = try writeTwoSegmentsAndLoseTheManifest()
        var manifest = LogManifest()
        manifest.segments = discovered
        try FileManager.default.removeItem(at: logDir.appendingPathComponent(discovered[0].fileName))

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let report = reader.verify(manifest: manifest)
        XCTAssertEqual(report.missingSegments, [discovered[0].fileName])
        XCTAssertFalse(report.isIntact)
    }

    func testAnIntactChainReportsNoBreaks() throws {
        var config = EncryptedLogWriter.Configuration()
        config.maxSegmentBytes = 16 * 1024
        config.eventsPerBlock = 32
        var manifest = LogManifest()
        let writer = EncryptedLogWriter(directory: logDir,
                                        sealMode: .writeOnly(recipient: vault.currentKeys!.ingestPublicKey),
                                        manifest: manifest, config: config)
        writer.onManifestChange = { manifest = $0 }
        for chunk in stride(from: 0, to: 1_200, by: 200) {
            writer.append(events(chunk..<(chunk + 200)))
        }
        writer.close()

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let report = reader.verify(manifest: manifest)
        XCTAssertTrue(report.isIntact)
        XCTAssertEqual(report.chainBreaks, 0,
                       "with the manifest intact every link is provable")
    }

    func testPlaceholderRecordsNeverSeedTheChain() {
        // The placeholder an earlier build wrote is not a file, and letting it
        // into the chain made the next real segment look altered.
        var manifest = LogManifest()
        manifest.segments = [SegmentRecord(segmentIndex: 0, fileName: "(existing)")]
        manifest.removingPhantomRecords()
        XCTAssertTrue(manifest.segments.isEmpty)
    }
}
