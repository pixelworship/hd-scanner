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

        // Rewrite a byte deep inside the second segment's payload.
        let target = logDir.appendingPathComponent(discovered[1].fileName)
        var bytes = try Data(contentsOf: target)
        let offset = bytes.count / 2
        bytes[offset] = bytes[offset] ^ 0xFF
        try bytes.write(to: target)

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let report = reader.verify(manifest: manifest)
        XCTAssertFalse(report.isIntact, "a rewritten block must fail verification")
        XCTAssertTrue(report.results.contains { !$0.ok })
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
