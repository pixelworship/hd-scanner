import XCTest
import CryptoKit
@testable import HDWatcherCore

/// Regression cover for a false "tampering detected" report.
///
/// Each writer keeps its own hash chain and numbers its own segments from 1.
/// When two of them shared a log directory — the app alongside a background
/// recorder — verification chained across both by segment index, interleaving
/// two unrelated chains. Every first block then failed its MAC, and a perfectly
/// intact log was reported as altered.
final class MultiWriterIntegrityTests: XCTestCase {

    private var root: URL!
    private var logDir: URL!
    private var keys: VaultKeys!

    override func setUpWithError() throws {
        root = URL(fileURLWithPath: AppPaths.canonicalPath(NSTemporaryDirectory()))
            .appendingPathComponent("hdw-multi-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        setenv(AppPaths.overrideEnvironmentKey, root.appendingPathComponent("sup").path, 1)
        logDir = root.appendingPathComponent("log")

        let vault = VaultKeyManager(vaultURL: root.appendingPathComponent("vault.json"))
        try vault.createVault(password: "multi-writer-tests", enableQuickUnlock: false)
        keys = vault.currentKeys!
    }

    override func tearDownWithError() throws {
        unsetenv(AppPaths.overrideEnvironmentKey)
        try? FileManager.default.removeItem(at: root)
    }

    func testInterleavedWritersBothVerify() throws {
        for round in 0..<3 {
            let app = try EventStore(keys: keys, directory: logDir)
            app.record((0..<20).map { FileEvent(kind: .created, path: "/app\(round)/\($0)") })
            app.close()

            let recorder = try EventStore(writeOnlyRecipient: keys.ingestPublicKey,
                                          directory: logDir)
            recorder.record((0..<20).map { FileEvent(kind: .created, path: "/agt\(round)/\($0)") })
            recorder.close()
        }

        let store = try EventStore(keys: keys, directory: logDir)
        defer { store.close() }

        let report = store.verifyIntegrity()
        XCTAssertTrue(report.isIntact,
                      "two writers in one directory must both verify: \(report.results.compactMap(\.problem))")
        XCTAssertTrue(report.missingSegments.isEmpty)

        // And everything both of them recorded is readable.
        let events = store.query(EventQuery())
        XCTAssertEqual(events.filter { $0.path.hasPrefix("/app") }.count, 60)
        XCTAssertEqual(events.filter { $0.path.hasPrefix("/agt") }.count, 60)
    }

    func testNoPhantomRecordsInTheManifest() throws {
        let recorder = try EventStore(writeOnlyRecipient: keys.ingestPublicKey, directory: logDir)
        recorder.record((0..<10).map { FileEvent(kind: .created, path: "/x/\($0)") })
        recorder.close()

        let store = try EventStore(keys: keys, directory: logDir)
        defer { store.close() }
        let names = store.visibleManifest.segments.map(\.fileName)

        XCTAssertFalse(names.contains("(existing)"),
                       "the manifest must only ever name real files")
        XCTAssertTrue(names.allSatisfy { $0.hasSuffix(".hdwseg") })
        XCTAssertEqual(Set(names).count, names.count, "no duplicate segment records")
    }

    func testEachWriterNumbersItsOwnLineage() throws {
        let app = try EventStore(keys: keys, directory: logDir)
        app.record([FileEvent(kind: .created, path: "/a/1")])
        app.close()

        let recorder = try EventStore(writeOnlyRecipient: keys.ingestPublicKey, directory: logDir)
        recorder.record([FileEvent(kind: .created, path: "/b/1")])
        recorder.close()

        let files = try FileManager.default.contentsOfDirectory(atPath: logDir.path)
            .filter { $0.hasSuffix(".hdwseg") }
        // Both lineages start at 1; that is fine because they are separate
        // sequences, and it is what verification must cope with.
        XCTAssertTrue(files.contains { $0.hasPrefix("seg-000001-") })
        XCTAssertTrue(files.contains { $0.hasPrefix("agt-000001-") })
    }

    func testWriteOnlyRecorderResumesItsOwnNumbering() throws {
        for _ in 0..<3 {
            let recorder = try EventStore(writeOnlyRecipient: keys.ingestPublicKey, directory: logDir)
            recorder.record([FileEvent(kind: .created, path: "/x/y")])
            recorder.close()
        }
        let indexes = try FileManager.default.contentsOfDirectory(atPath: logDir.path)
            .filter { $0.hasPrefix("agt-") }
            .compactMap { UInt32($0.split(separator: "-")[1]) }
            .sorted()
        XCTAssertEqual(indexes, [1, 2, 3],
                       "restarting must continue the sequence, not overwrite or skip")
    }

    func testRealTamperingIsStillCaught() throws {
        let app = try EventStore(keys: keys, directory: logDir)
        app.record((0..<300).map { FileEvent(kind: .created, path: "/real/\($0)") })
        app.close()

        let recorder = try EventStore(writeOnlyRecipient: keys.ingestPublicKey, directory: logDir)
        recorder.record((0..<300).map { FileEvent(kind: .created, path: "/agt/\($0)") })
        recorder.close()

        // Flip a byte inside one lineage; per-lineage chaining must not have
        // made verification blind.
        let victim = try XCTUnwrap(
            try FileManager.default.contentsOfDirectory(atPath: logDir.path)
                .first { $0.hasPrefix("agt-") && $0.hasSuffix(".hdwseg") })
        let url = logDir.appendingPathComponent(victim)
        var bytes = try Data(contentsOf: url)
        let target = LogFormat.agentHeaderSize + 30
        bytes[target] ^= 0xFF
        try bytes.write(to: url)

        let store = try EventStore(keys: keys, directory: logDir)
        defer { store.close() }
        let report = store.verifyIntegrity()
        XCTAssertFalse(report.isIntact, "a flipped byte must still be detected")
        XCTAssertTrue(report.results.contains { !$0.ok && ($0.problem?.contains("altered") ?? false) })
    }
}
