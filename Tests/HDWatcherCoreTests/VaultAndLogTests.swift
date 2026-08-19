import XCTest
import CryptoKit
@testable import HDWatcherCore

final class VaultAndLogTests: XCTestCase {

    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdwtest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        // Keep the fixture away from the machine's real storage, or a running
        // daemon's log leaks into these assertions.
        setenv(AppPaths.overrideEnvironmentKey, tempDir.path, 1)
    }

    override func tearDownWithError() throws {
        unsetenv(AppPaths.overrideEnvironmentKey)
        try? FileManager.default.removeItem(at: tempDir)
    }

    // MARK: - Vault

    func testVaultCreateLockUnlock() throws {
        let vaultURL = tempDir.appendingPathComponent("vault.json")
        let vault = VaultKeyManager(vaultURL: vaultURL)
        XCTAssertFalse(vault.vaultExists)

        try vault.createVault(password: "correct horse battery staple",
                              hint: "xkcd", enableQuickUnlock: false)
        XCTAssertTrue(vault.vaultExists)
        XCTAssertTrue(vault.isUnlocked)
        let firstKey = vault.currentKeys!.master.rawData

        vault.lock()
        XCTAssertFalse(vault.isUnlocked)
        XCTAssertNil(vault.currentKeys)

        try vault.unlock(password: "correct horse battery staple")
        XCTAssertTrue(vault.isUnlocked)
        XCTAssertEqual(vault.currentKeys!.master.rawData, firstKey,
                       "unlocking must recover the same master key")

        // A fresh manager reading the same file must also unlock.
        let reopened = VaultKeyManager(vaultURL: vaultURL)
        try reopened.unlock(password: "correct horse battery staple")
        XCTAssertEqual(reopened.currentKeys!.master.rawData, firstKey)
    }

    func testWrongPasswordFailsAndThrottles() throws {
        let vault = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "hunter2hunter2", enableQuickUnlock: false)
        vault.lock()

        XCTAssertThrowsError(try vault.unlock(password: "wrong")) { error in
            guard case CryptoError.badPassword = error else {
                return XCTFail("expected badPassword, got \(error)")
            }
        }
        XCTAssertFalse(vault.isUnlocked)
        XCTAssertEqual(vault.failedAttempts, 1)

        _ = try? vault.unlock(password: "wrong")
        _ = try? vault.unlock(password: "wrong")
        XCTAssertNotNil(vault.lockoutUntil, "repeat failures must trigger a lockout")

        vault.resetLockout()
        try vault.unlock(password: "hunter2hunter2")
        XCTAssertTrue(vault.isUnlocked)
        XCTAssertEqual(vault.failedAttempts, 0, "a good password clears the counter")
    }

    func testChangePassword() throws {
        let vault = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "old-password-value", enableQuickUnlock: false)
        let master = vault.currentKeys!.master.rawData

        try vault.changePassword(current: "old-password-value", new: "new-password-value")
        vault.lock()

        XCTAssertThrowsError(try vault.unlock(password: "old-password-value"))
        vault.resetLockout()
        try vault.unlock(password: "new-password-value")
        XCTAssertEqual(vault.currentKeys!.master.rawData, master,
                       "re-keying must preserve the master key so old logs stay readable")
    }

    func testSecureEnclaveTierWhenAvailable() throws {
        let vault = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "enclave-bound-password", enableQuickUnlock: false)
        if SecureEnclaveKeyStore.isAvailable {
            XCTAssertEqual(vault.protectionTier, .secureEnclave,
                           "an enclave-equipped Mac must produce a hardware-bound vault")
        } else {
            XCTAssertEqual(vault.protectionTier, .passwordOnly)
        }
    }

    // MARK: - Log

    private func makeStore() throws -> (VaultKeyManager, EventStore) {
        let vault = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "log-test-password", enableQuickUnlock: false)
        let store = try EventStore(keys: vault.currentKeys!,
                                   directory: tempDir.appendingPathComponent("log"))
        return (vault, store)
    }

    private func sampleEvents(_ n: Int) -> [FileEvent] {
        var out: [FileEvent] = []
        out.reserveCapacity(n)
        let now = Date()
        for i in 0..<n {
            let kind: EventKind
            switch i % 3 {
            case 0:  kind = .created
            case 1:  kind = .modified
            default: kind = .removed
            }
            let severity: Severity = (i % 11 == 0) ? .warning : .info
            let volume: String = (i % 2 == 0) ? "vol-internal" : "vol-external"
            let path = "/Users/test/Documents/folder\(i % 7)/file-\(i).txt"
            let stamp = now.addingTimeInterval(Double(i) * -1)
            out.append(FileEvent(timestamp: stamp,
                                 kind: kind,
                                 path: path,
                                 volumeID: volume,
                                 size: Int64(i) * 1024,
                                 severity: severity))
        }
        return out
    }

    func testLogRoundTrip() throws {
        let (_, store) = try makeStore()
        let events = sampleEvents(1200)
        store.record(events)
        store.flush()

        let all = store.query(EventQuery())
        XCTAssertEqual(all.count, 1200, "every recorded event must survive a round trip")

        let paths = Set(all.map(\.path))
        XCTAssertEqual(paths, Set(events.map(\.path)))
        store.close()
    }

    func testLogSurvivesReopen() throws {
        let vault = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "reopen-password", enableQuickUnlock: false)
        let logDir = tempDir.appendingPathComponent("log")

        let store1 = try EventStore(keys: vault.currentKeys!, directory: logDir)
        store1.record(sampleEvents(600))
        store1.close()

        vault.lock()
        try vault.unlock(password: "reopen-password")

        let store2 = try EventStore(keys: vault.currentKeys!, directory: logDir)
        XCTAssertEqual(store2.query(EventQuery()).count, 600,
                       "log must be readable after lock, unlock and reopen")
        store2.close()
    }

    func testQueryFiltering() throws {
        let (_, store) = try makeStore()
        store.record(sampleEvents(300))
        store.flush()

        var q = EventQuery()
        q.kinds = [.removed]
        let deletions = store.query(q)
        XCTAssertFalse(deletions.isEmpty)
        XCTAssertTrue(deletions.allSatisfy { $0.kind == .removed })

        var q2 = EventQuery()
        q2.minSeverity = .warning
        XCTAssertTrue(store.query(q2).allSatisfy { $0.severity >= .warning })

        var q3 = EventQuery()
        q3.volumeIDs = ["vol-external"]
        XCTAssertTrue(store.query(q3).allSatisfy { $0.volumeID == "vol-external" })

        var q4 = EventQuery()
        q4.limit = 10
        XCTAssertEqual(store.query(q4).count, 10)

        var q5 = EventQuery()
        q5.pathContains = "folder3"
        XCTAssertTrue(store.query(q5).allSatisfy { $0.path.contains("folder3") })
        store.close()
    }

    func testIntegrityPassesOnUntouchedLog() throws {
        let (_, store) = try makeStore()
        store.record(sampleEvents(900))
        store.flush()

        let report = store.verifyIntegrity()
        XCTAssertTrue(report.isIntact, "an untouched log must verify: \(report.results.compactMap(\.problem))")
        XCTAssertGreaterThan(report.totalBlocks, 0)
        store.close()
    }

    func testIntegrityDetectsTampering() throws {
        let logDir = tempDir.appendingPathComponent("log")
        let vault = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "tamper-password", enableQuickUnlock: false)
        let store = try EventStore(keys: vault.currentKeys!, directory: logDir)
        store.record(sampleEvents(900))
        store.close()

        // Flip one byte deep inside a segment's ciphertext.
        let files = try FileManager.default.contentsOfDirectory(atPath: logDir.path)
            .filter { $0.hasSuffix(".hdwseg") }.sorted()
        let victim = logDir.appendingPathComponent(files[0])
        var bytes = try Data(contentsOf: victim)
        let target = LogFormat.headerSize + 40
        bytes[target] = bytes[target] ^ 0xFF
        try bytes.write(to: victim)

        let store2 = try EventStore(keys: vault.currentKeys!, directory: logDir)
        let report = store2.verifyIntegrity()
        XCTAssertFalse(report.isIntact, "a single flipped byte must fail verification")
        XCTAssertTrue(report.results.contains { $0.ok == false && $0.problem != nil })
        store2.close()
    }

    func testIntegrityDetectsDeletedSegment() throws {
        let logDir = tempDir.appendingPathComponent("log")
        let vault = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "delete-password", enableQuickUnlock: false)
        var config = EncryptedLogWriter.Configuration()
        config.maxSegmentBytes = 16 * 1024      // force several segments
        let store = try EventStore(keys: vault.currentKeys!, directory: logDir)
        _ = config
        store.record(sampleEvents(2000))
        store.close()

        let files = try FileManager.default.contentsOfDirectory(atPath: logDir.path)
            .filter { $0.hasSuffix(".hdwseg") }.sorted()
        XCTAssertFalse(files.isEmpty)
        try FileManager.default.removeItem(at: logDir.appendingPathComponent(files[0]))

        let store2 = try EventStore(keys: vault.currentKeys!, directory: logDir)
        let report = store2.verifyIntegrity()
        XCTAssertFalse(report.isIntact, "removing a segment file must be detectable")
        XCTAssertEqual(report.missingSegments.count, 1)
        store2.close()
    }

    func testWrongKeyCannotReadLog() throws {
        let logDir = tempDir.appendingPathComponent("log")
        let vaultA = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vaultA.json"))
        try vaultA.createVault(password: "password-alpha", enableQuickUnlock: false)
        let store = try EventStore(keys: vaultA.currentKeys!, directory: logDir)
        store.record(sampleEvents(400))
        store.close()

        // A different vault (different master key) must recover nothing.
        let vaultB = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vaultB.json"))
        try vaultB.createVault(password: "password-beta", enableQuickUnlock: false)
        let storeB = try EventStore(keys: vaultB.currentKeys!, directory: logDir)
        XCTAssertEqual(storeB.query(EventQuery()).count, 0,
                       "log contents must be unreadable without the right key")
        storeB.close()
    }

    func testCSVExport() throws {
        let (_, store) = try makeStore()
        store.record(sampleEvents(50))
        store.flush()
        let out = tempDir.appendingPathComponent("export.csv")
        let n = try store.export(EventQuery(), to: out, format: .csv)
        XCTAssertEqual(n, 50)
        let text = try String(contentsOf: out, encoding: .utf8)
        XCTAssertTrue(text.hasPrefix("timestamp,kind,severity"))
        XCTAssertEqual(text.split(separator: "\n").count, 51)
        store.close()
    }

    // MARK: - Glob

    func testGlobMatching() throws {
        XCTAssertTrue(GlobPattern("*.pem").matches("/Users/me/keys/server.pem"))
        XCTAssertFalse(GlobPattern("*.pem").matches("/Users/me/keys/server.txt"))
        XCTAssertTrue(GlobPattern("/Users/*/Documents/**").matches("/Users/me/Documents/a/b/c.txt"))
        XCTAssertTrue(GlobPattern("/Users/me/Secrets/**").matches("/Users/me/Secrets"))
        XCTAssertTrue(GlobPattern("*.PEM").matches("/x/y.pem"), "default matching is case-insensitive")
        XCTAssertFalse(GlobPattern("*.PEM", caseSensitive: true).matches("/x/y.pem"))
    }
}

/// The background agent must be able to record an audit trail it cannot read.
final class WriteOnlyIngestTests: XCTestCase {

    private var tempDir: URL!
    private var vault: VaultKeyManager!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-ingest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        vault = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("vault.json"))
        try vault.createVault(password: "ingest-test-password", enableQuickUnlock: false)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    private func events(_ n: Int) -> [FileEvent] {
        (0..<n).map { FileEvent(kind: .created, path: "/data/agent-\($0).txt", size: Int64($0)) }
    }

    func testIngestKeyIsStableAcrossUnlocks() throws {
        let first = vault.currentKeys!.ingest.rawRepresentation
        vault.lock()
        try vault.unlock(password: "ingest-test-password")
        XCTAssertEqual(vault.currentKeys!.ingest.rawRepresentation, first,
                       "the ingest key must be reproducible or agent segments become unreadable")
    }

    func testAgentCanWriteAndAppCanRead() throws {
        let logDir = tempDir.appendingPathComponent("log")
        let publicKey = vault.currentKeys!.ingestPublicKey

        // The agent side: only the public key.
        let writer = EncryptedLogWriter(directory: logDir,
                                        sealMode: .writeOnly(recipient: publicKey),
                                        manifest: LogManifest())
        writer.append(events(400))
        writer.close()

        // The app side: holds the private key.
        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let discovered = reader.discoverSegments()
        XCTAssertFalse(discovered.isEmpty, "segments written by the agent must be discoverable")

        var recovered: [FileEvent] = []
        for record in discovered {
            recovered.append(contentsOf: try reader.readSegment(record))
        }
        XCTAssertEqual(recovered.count, 400)
        XCTAssertEqual(Set(recovered.map(\.path)).count, 400)
    }

    func testAgentSegmentsAreMarkedAsVersionTwo() throws {
        let logDir = tempDir.appendingPathComponent("log")
        let writer = EncryptedLogWriter(directory: logDir,
                                        sealMode: .writeOnly(recipient: vault.currentKeys!.ingestPublicKey),
                                        manifest: LogManifest())
        writer.append(events(10))
        writer.close()

        let file = try XCTUnwrap(
            try FileManager.default.contentsOfDirectory(atPath: logDir.path)
                .first { $0.hasSuffix(".hdwseg") })
        let data = try Data(contentsOf: logDir.appendingPathComponent(file))
        let header = try XCTUnwrap(LogFormat.SegmentHeader.decode(data))
        XCTAssertEqual(header.version, LogFormat.agentVersion)
        XCTAssertTrue(header.isAgentWritten)
        XCTAssertEqual(header.ephemeralPublicKey?.count, 64,
                       "the segment must carry the ephemeral public key needed to reopen it")
    }

    func testAnotherVaultCannotReadAgentSegments() throws {
        let logDir = tempDir.appendingPathComponent("log")
        let writer = EncryptedLogWriter(directory: logDir,
                                        sealMode: .writeOnly(recipient: vault.currentKeys!.ingestPublicKey),
                                        manifest: LogManifest())
        writer.append(events(50))
        writer.close()

        let other = VaultKeyManager(vaultURL: tempDir.appendingPathComponent("other.json"))
        try other.createVault(password: "a-different-password", enableQuickUnlock: false)
        let foreign = EncryptedLogReader(directory: logDir, keys: other.currentKeys!)

        var recovered: [FileEvent] = []
        for record in foreign.discoverSegments() {
            recovered.append(contentsOf: (try? foreign.readSegment(record)) ?? [])
        }
        XCTAssertTrue(recovered.isEmpty,
                      "a different vault must not decrypt what the agent recorded")
    }

    func testIntegrityVerificationWorksOnAgentSegments() throws {
        let logDir = tempDir.appendingPathComponent("log")
        let writer = EncryptedLogWriter(directory: logDir,
                                        sealMode: .writeOnly(recipient: vault.currentKeys!.ingestPublicKey),
                                        manifest: LogManifest())
        writer.append(events(300))
        writer.close()
        let manifest = writer.currentManifest

        let reader = EncryptedLogReader(directory: logDir, keys: vault.currentKeys!)
        let clean = reader.verify(manifest: manifest)
        XCTAssertTrue(clean.isIntact, "an untouched agent log must verify: \(clean.results.compactMap(\.problem))")

        // Tamper with the ciphertext.
        let file = manifest.segments[0].fileName
        let url = logDir.appendingPathComponent(file)
        var bytes = try Data(contentsOf: url)
        let target = LogFormat.agentHeaderSize + 40
        bytes[target] = bytes[target] ^ 0xFF
        try bytes.write(to: url)

        let tampered = reader.verify(manifest: manifest)
        XCTAssertFalse(tampered.isIntact, "tampering with an agent segment must be detected")
    }

    func testAppAndAgentSegmentsCoexist() throws {
        let logDir = tempDir.appendingPathComponent("log")
        let keys = vault.currentKeys!

        // App-written (v1) segments.
        let appWriter = EncryptedLogWriter(directory: logDir, keys: keys, manifest: LogManifest())
        appWriter.append((0..<100).map { FileEvent(kind: .created, path: "/app/\($0)") })
        appWriter.close()

        // Agent-written (v2) segments alongside them.
        let agentWriter = EncryptedLogWriter(directory: logDir,
                                             sealMode: .writeOnly(recipient: keys.ingestPublicKey),
                                             manifest: appWriter.currentManifest)
        agentWriter.append((0..<100).map { FileEvent(kind: .created, path: "/agent/\($0)") })
        agentWriter.close()

        let reader = EncryptedLogReader(directory: logDir, keys: keys)
        var all: [FileEvent] = []
        for record in reader.discoverSegments() {
            all.append(contentsOf: (try? reader.readSegment(record)) ?? [])
        }
        XCTAssertEqual(all.filter { $0.path.hasPrefix("/app/") }.count, 100)
        XCTAssertEqual(all.filter { $0.path.hasPrefix("/agent/") }.count, 100,
                       "both formats must be readable from one directory")
    }
}

/// The contract between the app and the background agent.
final class AgentContractTests: XCTestCase {

    private var scratch: URL!

    override func setUpWithError() throws {
        scratch = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-agentc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        setenv(AppPaths.overrideEnvironmentKey, scratch.path, 1)
        setenv(AppPaths.systemOverrideEnvironmentKey, scratch.path, 1)
        // Configuration is sealed to the daemon's own key, so one has to exist.
        DaemonIdentity.loadOrCreate()
    }

    override func tearDownWithError() throws {
        unsetenv(AppPaths.overrideEnvironmentKey)
        unsetenv(AppPaths.systemOverrideEnvironmentKey)
        try? FileManager.default.removeItem(at: scratch)
    }

    func testSupportDirectoryOverrideIsRespected() {
        XCTAssertEqual(AppPaths.supportDirectory.path, scratch.path)
        XCTAssertTrue(AgentPaths.status.path.hasPrefix(scratch.path))
    }

    func testIngestKeyRoundTripsThroughTheFile() throws {
        let vault = VaultKeyManager(vaultURL: scratch.appendingPathComponent("vault.json"))
        try vault.createVault(password: "agent-contract-password", enableQuickUnlock: false)
        let keys = vault.currentKeys!

        XCTAssertFalse(IngestKeyFile.exists)
        IngestKeyFile.export(keys.ingestPublicKey)
        XCTAssertTrue(IngestKeyFile.exists)

        let published = try XCTUnwrap(IngestKeyFile.read())
        XCTAssertEqual(published.rawRepresentation, keys.ingestPublicKey.rawRepresentation)
        // Only 64 bytes of public key ever reach disk in the clear.
        let onDisk = try Data(contentsOf: AgentPaths.ingestPublicKey)
        XCTAssertEqual(onDisk.count, 64)
        XCTAssertNil(onDisk.range(of: keys.ingest.rawRepresentation),
                     "the private key must never be written alongside the public one")
    }

    func testAgentRecordsWhatTheAppCanRead() throws {
        let vault = VaultKeyManager(vaultURL: scratch.appendingPathComponent("vault.json"))
        try vault.createVault(password: "agent-contract-password", enableQuickUnlock: false)
        let keys = vault.currentKeys!
        IngestKeyFile.export(keys.ingestPublicKey)

        // Agent side: a store built from the published public key alone.
        let published = try XCTUnwrap(IngestKeyFile.read())
        let agentStore = try EventStore(writeOnlyRecipient: published)
        agentStore.record((0..<250).map {
            FileEvent(kind: .created, path: "/watched/agent-file-\($0).txt", size: Int64($0))
        })
        agentStore.close()

        // A write-only store cannot read its own output.
        XCTAssertTrue(agentStore.query(EventQuery()).isEmpty,
                      "the agent must not be able to read back what it recorded")

        // App side: full keys.
        let appStore = try EventStore(keys: keys)
        let recovered = appStore.query(EventQuery())
        XCTAssertEqual(recovered.count, 250,
                       "the app must be able to read everything the agent recorded")
        appStore.close()
    }

    func testTailingPicksUpOnlyNewEvents() throws {
        let vault = VaultKeyManager(vaultURL: scratch.appendingPathComponent("vault.json"))
        try vault.createVault(password: "agent-contract-password", enableQuickUnlock: false)
        let keys = vault.currentKeys!
        IngestKeyFile.export(keys.ingestPublicKey)
        let published = try XCTUnwrap(IngestKeyFile.read())

        let agentStore = try EventStore(writeOnlyRecipient: published)
        agentStore.record((0..<100).map { FileEvent(kind: .created, path: "/w/first-\($0)") })
        agentStore.flush()

        let appStore = try EventStore(keys: keys)
        appStore.primeTail()
        XCTAssertTrue(appStore.tailNewEvents().isEmpty,
                      "priming must mark existing history as already seen")

        agentStore.record((0..<40).map { FileEvent(kind: .modified, path: "/w/second-\($0)") })
        agentStore.flush()

        let fresh = appStore.tailNewEvents()
        XCTAssertEqual(fresh.count, 40, "only events written since the last poll should come back")
        XCTAssertTrue(fresh.allSatisfy { $0.path.contains("second-") })
        XCTAssertTrue(appStore.tailNewEvents().isEmpty, "a second poll with no writes returns nothing")

        agentStore.close()
        appStore.close()
    }

    func testConfigurationRoundTrip() throws {
        var settings = AppSettings.default
        settings.watchScope = .externalOnly
        settings.maxEventsPerSecond = 777
        let rules = AlertRule.builtInRules()

        settings.backgroundRecordingEnabled = true
        XCTAssertTrue(BackgroundService.publishConfiguration(settings: settings, rules: rules))
        let loaded = try XCTUnwrap(AgentConfiguration.read(from: AgentPaths.systemConfiguration))

        XCTAssertTrue(loaded.enabled)
        XCTAssertEqual(loaded.watchScope, .externalOnly)
        XCTAssertEqual(loaded.maxEventsPerSecond, 777)
        XCTAssertEqual(loaded.rules.count, rules.count)
        // The daemon captures contents too, sealed to the ingest key — otherwise
        // recovery would stop the moment the app was quit.
        XCTAssertTrue(loaded.appSettings.captureFileContents)
    }

    func testStatusIsSealedNotPlaintext() throws {
        let vault = VaultKeyManager(vaultURL: scratch.appendingPathComponent("v.json"))
        try vault.createVault(password: "sealed-status", enableQuickUnlock: false)
        let keys = vault.currentKeys!

        var status = AgentStatus(pid: getpid())
        status.watchedPaths = ["/Users/someone/Secret Project"]
        status.write(sealingTo: keys.ingestPublicKey)

        // On disk it must reveal nothing, not even which paths are watched.
        let raw = try Data(contentsOf: AgentPaths.status)
        XCTAssertNil(raw.range(of: Data("Secret Project".utf8)),
                     "watched paths must not be readable on disk")
        XCTAssertNil(raw.range(of: Data("watchedPaths".utf8)))

        // And the holder of the ingest key can still read it.
        let recovered = AgentStatus.read(using: keys.ingest)
        XCTAssertEqual(recovered?.watchedPaths, ["/Users/someone/Secret Project"])
        XCTAssertNil(AgentStatus.read(using: nil), "no key, no status")
    }

    func testConfigurationIsSealedNotPlaintext() throws {
        var settings = AppSettings.default
        settings.customWatchPaths = ["/Users/someone/Confidential"]
        XCTAssertTrue(BackgroundService.publishConfiguration(settings: settings, rules: []))

        let raw = try Data(contentsOf: AgentPaths.systemConfiguration)
        XCTAssertNil(raw.range(of: Data("Confidential".utf8)),
                     "the watch list must not be readable on disk")
        XCTAssertNil(raw.range(of: Data("customWatchPaths".utf8)))

        let recovered = AgentConfiguration.read(from: AgentPaths.systemConfiguration)
        XCTAssertEqual(recovered?.customWatchPaths, ["/Users/someone/Confidential"])
    }

    func testStatusLivenessRequiresAFreshHeartbeat() {
        var status = AgentStatus(pid: getpid())
        status.heartbeat = Date()
        XCTAssertTrue(status.isAlive)

        status.heartbeat = Date().addingTimeInterval(-120)
        XCTAssertFalse(status.isAlive, "a stale heartbeat must not read as running")

        var dead = AgentStatus(pid: 999_999)
        dead.heartbeat = Date()
        XCTAssertFalse(dead.isAlive, "a heartbeat from a pid that no longer exists must not count")
    }

    /// The daemon runs as root and the app does not. `kill(pid, 0)` then fails
    /// with EPERM even though the process exists, which made a healthy daemon
    /// report as unresponsive.
    func testRootOwnedProcessCountsAsAlive() {
        // launchd is pid 1, owned by root, and always running.
        XCTAssertNotEqual(getuid(), 0, "this test is only meaningful as a non-root user")
        XCTAssertTrue(AgentStatus.processExists(1),
                      "a root-owned process must be recognised as running")

        var status = AgentStatus(pid: 1)
        status.heartbeat = Date()
        XCTAssertTrue(status.isAlive,
                      "a fresh heartbeat from a root daemon must read as alive")
    }

    func testNonexistentProcessIsNotAlive() {
        XCTAssertFalse(AgentStatus.processExists(999_999))
        XCTAssertFalse(AgentStatus.processExists(0))
        XCTAssertFalse(AgentStatus.processExists(-5))
    }
}

/// How the privileged daemon obtains its key, and why substitution is refused.
final class DaemonKeyPinningTests: XCTestCase {

    private var scratch: URL!
    private var systemDir: URL!
    private var fakeHome: URL!

    override func setUpWithError() throws {
        scratch = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-pin-\(UUID().uuidString)")
        systemDir = scratch.appendingPathComponent("system")
        fakeHome = scratch.appendingPathComponent("home")
        let support = AppPaths.userSupportDirectory(home: fakeHome.path)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: systemDir, withIntermediateDirectories: true)
        setenv(AppPaths.systemOverrideEnvironmentKey, systemDir.path, 1)
    }

    override func tearDownWithError() throws {
        unsetenv(AppPaths.systemOverrideEnvironmentKey)
        try? FileManager.default.removeItem(at: scratch)
    }

    private func publish(_ key: P256.KeyAgreement.PublicKey) throws {
        let url = AppPaths.userSupportDirectory(home: fakeHome.path)
            .appendingPathComponent("ingest.pub")
        try key.rawRepresentation.write(to: url)
    }

    private func pinnedKeyData() -> Data? {
        try? Data(contentsOf: AgentPaths.pinnedIngestKey)
    }

    func testSystemPathsPointAtLibrary() {
        unsetenv(AppPaths.systemOverrideEnvironmentKey)
        XCTAssertEqual(AppPaths.systemSupportDirectory.path,
                       "/Library/Application Support/co.pixelworship.hdwatcher")
        XCTAssertTrue(AppPaths.systemLogDirectory.path.hasPrefix("/Library/Application Support/"))
        setenv(AppPaths.systemOverrideEnvironmentKey, systemDir.path, 1)
    }

    func testDaemonLogIsSeparateFromTheUserLog() {
        // The two must not collide, or the app would read its own writes as the
        // daemon's and tailing would double-count.
        XCTAssertNotEqual(AppPaths.systemLogDirectory.path, AppPaths.logDirectory.path)
    }

    func testPinsOnFirstUse() throws {
        let real = P256.KeyAgreement.PrivateKey()
        try publish(real.publicKey)

        let resolution = try XCTUnwrap(DaemonKeyLocator.resolve(homes: [fakeHome.path]))
        XCTAssertTrue(resolution.wasPinnedNow)
        XCTAssertFalse(resolution.substitutionDetected)
        XCTAssertEqual(resolution.key.rawRepresentation, real.publicKey.rawRepresentation)
        XCTAssertEqual(pinnedKeyData(), real.publicKey.rawRepresentation,
                       "the key must be copied somewhere only root can change")
    }

    func testSecondResolveUsesThePinnedCopy() throws {
        let real = P256.KeyAgreement.PrivateKey()
        try publish(real.publicKey)
        _ = DaemonKeyLocator.resolve(homes: [fakeHome.path])

        let again = try XCTUnwrap(DaemonKeyLocator.resolve(homes: [fakeHome.path]))
        XCTAssertFalse(again.wasPinnedNow, "pinning happens once")
        XCTAssertEqual(again.key.rawRepresentation, real.publicKey.rawRepresentation)
    }

    func testRefusesASubstitutedKey() throws {
        let real = P256.KeyAgreement.PrivateKey()
        try publish(real.publicKey)
        _ = DaemonKeyLocator.resolve(homes: [fakeHome.path])

        // An attacker with write access to the user's home swaps in their own
        // public key, hoping future events get sealed to them.
        let attacker = P256.KeyAgreement.PrivateKey()
        try publish(attacker.publicKey)

        let resolution = try XCTUnwrap(DaemonKeyLocator.resolve(homes: [fakeHome.path]))
        XCTAssertTrue(resolution.substitutionDetected,
                      "the daemon must notice the published key changed")
        XCTAssertEqual(resolution.key.rawRepresentation, real.publicKey.rawRepresentation,
                       "it must keep sealing to the originally pinned key")
        XCTAssertNotEqual(resolution.key.rawRepresentation, attacker.publicKey.rawRepresentation)
    }

    func testNoKeyAnywhereResolvesToNothing() {
        XCTAssertNil(DaemonKeyLocator.resolve(homes: [fakeHome.path]),
                     "with no published key the daemon must decline to record rather than invent one")
    }

    func testCandidateHomesIncludesRealUsers() {
        let homes = DaemonKeyLocator.candidateHomes()
        XCTAssertFalse(homes.isEmpty)
        XCTAssertTrue(homes.allSatisfy { $0.hasPrefix("/") })
        XCTAssertFalse(homes.contains { $0.hasSuffix("/Shared") })
    }
}

/// Background recording is a standing preference, not something that has to be
/// switched on again after every launch.
final class BackgroundPersistenceTests: XCTestCase {

    private var scratch: URL!

    override func setUpWithError() throws {
        scratch = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-bg-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        setenv(AppPaths.overrideEnvironmentKey, scratch.path, 1)
        setenv(AppPaths.systemOverrideEnvironmentKey, scratch.path, 1)
        DaemonIdentity.loadOrCreate()
    }

    override func tearDownWithError() throws {
        unsetenv(AppPaths.overrideEnvironmentKey)
        unsetenv(AppPaths.systemOverrideEnvironmentKey)
        try? FileManager.default.removeItem(at: scratch)
    }

    func testBackgroundRecordingDefaultsOn() {
        XCTAssertTrue(AppSettings.default.backgroundRecordingEnabled,
                      "an audit recorder should run by default, not wait to be asked")
    }

    func testPreferenceSurvivesEncodingRoundTrip() throws {
        var settings = AppSettings.default
        settings.backgroundRecordingEnabled = false
        let decoded = try JSONDecoder().decode(
            AppSettings.self, from: JSONEncoder().encode(settings))
        XCTAssertFalse(decoded.backgroundRecordingEnabled)
    }

    func testSettingsSavedBeforeThisFeatureDefaultToOn() throws {
        // An older settings file has no such key; it must not read as "off".
        let legacy = #"{"watchScope":"allVolumes","maxEventsPerSecond":4000}"#
        let decoded = try JSONDecoder().decode(AppSettings.self, from: Data(legacy.utf8))
        XCTAssertTrue(decoded.backgroundRecordingEnabled)
    }

    func testPublishedConfigurationFollowsThePreferenceNotRegistration() throws {
        // The old behaviour derived `enabled` from the registration state, so a
        // moment of "awaiting approval" told the daemon to stop.
        var settings = AppSettings.default
        settings.backgroundRecordingEnabled = true
        BackgroundService.publishConfiguration(settings: settings, rules: [])
        XCTAssertEqual(AgentConfiguration.read(from: AgentPaths.systemConfiguration)?.enabled, true)

        settings.backgroundRecordingEnabled = false
        BackgroundService.publishConfiguration(settings: settings, rules: [])
        XCTAssertEqual(AgentConfiguration.read(from: AgentPaths.systemConfiguration)?.enabled, false)
    }

    func testDaemonWrittenFilesAreReadableByTheApp() {
        // Root writes 0644 so the app can read the trail; the app writes 0600.
        // Getting this wrong made the daemon's whole log invisible.
        XCTAssertEqual(AppPaths.filePermissions, AppPaths.isRunningAsRoot ? 0o644 : 0o600)
    }
}

/// Permissions stop everyone below root. This covers what happens when someone
/// above that line interferes anyway.
final class AuditTrailGuardTests: XCTestCase {

    private var root: URL!
    private var logDir: URL!
    private var guardian: AuditTrailGuard!

    override func setUpWithError() throws {
        root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-guard-\(UUID().uuidString)")
        logDir = root.appendingPathComponent("log")
        try FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
        guardian = AuditTrailGuard(logDirectory: logDir, supportDirectory: root)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    private func writeSegment(_ name: String, bytes: Int) throws -> URL {
        let url = logDir.appendingPathComponent(name)
        try Data(repeating: 0x41, count: bytes).write(to: url)
        return url
    }

    func testQuietWhenNothingHasChanged() throws {
        _ = try writeSegment("agt-000001-1.hdwseg", bytes: 500)
        _ = guardian.inspect()                     // baseline
        XCTAssertTrue(guardian.inspect().isEmpty,
                      "an untouched trail must not raise anything")
    }

    func testGrowthIsNormalAndNotReported() throws {
        let url = try writeSegment("agt-000001-1.hdwseg", bytes: 500)
        _ = guardian.inspect()
        try Data(repeating: 0x42, count: 900).write(to: url)
        XCTAssertTrue(guardian.inspect().isEmpty,
                      "append-only storage grows; that is not tampering")
    }

    func testDetectsADeletedSegment() throws {
        let url = try writeSegment("agt-000001-1.hdwseg", bytes: 500)
        _ = guardian.inspect()
        try FileManager.default.removeItem(at: url)

        let findings = guardian.inspect()
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.kind, .tamperDetected)
        XCTAssertEqual(findings.first?.severity, .critical)
        XCTAssertTrue(findings.first?.ruleHits.first?.contains("deleted") ?? false)
    }

    func testReportsADeletionOnlyOnce() throws {
        let url = try writeSegment("agt-000001-1.hdwseg", bytes: 500)
        _ = guardian.inspect()
        try FileManager.default.removeItem(at: url)

        XCTAssertEqual(guardian.inspect().count, 1)
        XCTAssertTrue(guardian.inspect().isEmpty,
                      "the same missing segment must not be re-reported every pass")
    }

    func testDetectsATruncatedSegment() throws {
        let url = try writeSegment("agt-000001-1.hdwseg", bytes: 5_000)
        _ = guardian.inspect()
        // Rewrite it smaller — the shape of someone editing history.
        try Data(repeating: 0x43, count: 100).write(to: url)

        let findings = guardian.inspect()
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.kind, .tamperDetected)
        XCTAssertTrue(findings.first?.ruleHits.first?.contains("truncated") ?? false)
    }

    func testTamperingRaisesACriticalAlert() {
        let engine = RuleEngine(registry: nil, rules: AlertRule.builtInRules())
        let event = FileEvent(kind: .tamperDetected, path: "/Library/…/log/agt-1.hdwseg",
                              severity: .critical)
        let alerts = engine.evaluate(event).alerts
        XCTAssertTrue(alerts.contains { $0.ruleName == "Audit trail tampered with" })
        XCTAssertEqual(alerts.first?.severity, .critical)
    }

    func testPermissionChecksOnlyApplyToThePrivilegedDaemon() {
        // Running as the user, the trail lives in their own home and these
        // guarantees cannot hold — the guard must not claim otherwise.
        XCTAssertFalse(AppPaths.isRunningAsRoot)
        _ = try? writeSegment("agt-000001-1.hdwseg", bytes: 10)
        XCTAssertTrue(guardian.inspect().isEmpty)
    }
}

/// Nothing operational should be readable on disk.
final class OnDiskSecrecyTests: XCTestCase {

    private var scratch: URL!

    override func setUpWithError() throws {
        scratch = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("hdw-secrecy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        setenv(AppPaths.overrideEnvironmentKey, scratch.path, 1)
        setenv(AppPaths.systemOverrideEnvironmentKey, scratch.path, 1)
    }

    override func tearDownWithError() throws {
        unsetenv(AppPaths.overrideEnvironmentKey)
        unsetenv(AppPaths.systemOverrideEnvironmentKey)
        try? FileManager.default.removeItem(at: scratch)
    }

    func testLegacyPlaintextFilesAreRemoved() throws {
        AppPaths.ensureDirectories()
        for name in ["cursor.json", "agent-status.json", "agent-config.json"] {
            try Data("readable".utf8).write(to: scratch.appendingPathComponent(name))
        }
        let removed = LegacyPlaintextCleanup.run()
        XCTAssertEqual(removed.count, 3, "clear-text state from an older build must be deleted")
        for name in ["cursor.json", "agent-status.json", "agent-config.json"] {
            XCTAssertFalse(FileManager.default.fileExists(atPath: scratch.appendingPathComponent(name).path))
        }
    }

    func testCleanupIsSafeToRunRepeatedly() {
        XCTAssertTrue(LegacyPlaintextCleanup.run().isEmpty)
        XCTAssertTrue(LegacyPlaintextCleanup.run().isEmpty)
    }

    func testOnlyPublicKeysAndWrappedMaterialRemainReadable() throws {
        AppPaths.ensureDirectories()
        let vault = VaultKeyManager(vaultURL: scratch.appendingPathComponent("vault.json"))
        try vault.createVault(password: "secrecy-test-password", enableQuickUnlock: false)
        let keys = vault.currentKeys!

        IngestKeyFile.export(keys.ingestPublicKey)
        DaemonIdentity.loadOrCreate()
        EventCursor(lastEventID: 999).save(settingsKey: keys.settings)
        var status = AgentStatus(pid: 1)
        status.watchedPaths = ["/Users/x/PrivateFolder"]
        status.write(sealingTo: keys.ingestPublicKey)
        var settings = AppSettings.default
        settings.customWatchPaths = ["/Users/x/PrivateFolder"]
        _ = BackgroundService.publishConfiguration(settings: settings, rules: AlertRule.builtInRules())

        // No file may contain the monitored path in the clear.
        let files = try FileManager.default.contentsOfDirectory(atPath: scratch.path)
        var checked = 0
        for name in files {
            let url = scratch.appendingPathComponent(name)
            guard let data = try? Data(contentsOf: url) else { continue }
            checked += 1
            XCTAssertNil(data.range(of: Data("PrivateFolder".utf8)),
                         "\(name) leaks a monitored path in the clear")
        }
        XCTAssertGreaterThan(checked, 3)

        // The public keys are exactly 64 bytes and nothing more.
        XCTAssertEqual(try Data(contentsOf: AgentPaths.ingestPublicKey).count, 64)
        XCTAssertEqual(try Data(contentsOf: DaemonIdentity.publicKeyURL).count, 64)
    }
}
