import Foundation
import CryptoKit

/// The event log is an append-only audit trail. There is deliberately no
/// retention policy and no purge: once an event is recorded it stays recorded.
/// Only *captured file contents* expire, on a schedule the user chooses — see
/// `SnapshotRetention`.
/// The app's single entry point to the encrypted log: buffers writes, keeps a
/// hot in-memory window for the live UI, answers queries, enforces retention and
/// runs integrity checks.
public final class EventStore: @unchecked Sendable {

    /// A store either holds the master key (the app) or only the ingest public
    /// key (the background agent), in which case it can record but never read.
    public enum Mode {
        case full(VaultKeys)
        case writeOnly(recipient: P256.KeyAgreement.PublicKey)
    }

    private let lock = NSLock()
    private let mode: Mode
    private let keys: VaultKeys?
    private let directory: URL
    private let manifestURL: URL
    private var manifest: LogManifest
    private var writer: EncryptedLogWriter?
    private let reader: EncryptedLogReader?

    /// Newest-last ring of recent events, so the live feed never has to decrypt.
    private var recent: [FileEvent] = []
    private let recentCapacity = 25_000
    private var totalRecorded: Int = 0
    /// How far into each agent-written segment this process has already read.
    private var tailOffsets: [String: Int] = [:]

    /// Recording-only store for the background agent.
    public convenience init(writeOnlyRecipient: P256.KeyAgreement.PublicKey,
                            directory: URL = AppPaths.logDirectory) throws {
        try self.init(mode: .writeOnly(recipient: writeOnlyRecipient), directory: directory)
    }

    public convenience init(keys: VaultKeys, directory: URL = AppPaths.logDirectory) throws {
        try self.init(mode: .full(keys), directory: directory)
    }

    public init(mode: Mode, directory: URL = AppPaths.logDirectory) throws {
        self.mode = mode
        switch mode {
        case .full(let keys): self.keys = keys
        case .writeOnly:      self.keys = nil
        }
        let keys = self.keys
        self.directory = directory
        self.manifestURL = directory.appendingPathComponent(
            keys == nil ? "manifest-agent.enc" : "manifest.enc")
        AppPaths.ensureDirectories()
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])

        var loaded: LogManifest?
        switch mode {
        case .full(let keys):
            loaded = (try? EncryptedFileBox.read(LogManifest.self, from: manifestURL,
                                                 key: keys.settings, context: "manifest")) ?? nil
        case .writeOnly:
            // The published manifest is sealed to the ingest key, which the
            // agent does not hold — it cannot read back what it wrote. So it
            // keeps a second copy sealed to its *own* enclave key.
            //
            // Without it, every restart began from an empty manifest and then
            // overwrote the published one with a single record, destroying the
            // block counts and chain MACs of every earlier segment. The history
            // survived on disk but became unverifiable, and the app reported
            // the segments that followed as altered.
            loaded = Self.readPrivateManifest(directory: directory)
        }
        self.manifest = loaded ?? LogManifest()
        // Clean up placeholder records left by an earlier build before anything
        // reads them.
        self.manifest.removingPhantomRecords()
        // The app additionally reads the privileged daemon's log; the daemon
        // itself has no reader at all.
        let extraDirectories = (AppPaths.isRunningAsRoot || AppPaths.isUsingOverride)
            ? []
            : [AppPaths.systemLogDirectory].filter { $0.path != directory.path }
        self.reader = keys.map {
            EncryptedLogReader(directory: directory, keys: $0,
                               additionalDirectories: extraDirectories)
        }
        self.totalRecorded = manifest.totalEvents

        var writerConfig = EncryptedLogWriter.Configuration()
        let sealMode: LogSealMode
        switch mode {
        case .full(let keys):
            sealMode = .symmetric(log: keys.log, integrity: keys.integrity)
        case .writeOnly(let recipient):
            sealMode = .writeOnly(recipient: recipient)
            // This store cannot read its own manifest back, so it works out
            // where to resume from the files it previously wrote. Only its own
            // lineage counts: another writer's indexes are a separate sequence.
            let existing = ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [])
                .filter { $0.hasSuffix(".hdwseg") && $0.hasPrefix("agt-") }
                .compactMap { name -> UInt32? in
                    let parts = name.split(separator: "-")
                    return parts.count > 1 ? UInt32(parts[1]) : nil
                }
            writerConfig.startingSegmentIndex = existing.max() ?? 0
        }

        let w = EncryptedLogWriter(directory: directory, sealMode: sealMode,
                                   manifest: self.manifest, config: writerConfig)
        w.onManifestChange = { [weak self] updated in
            guard let self else { return }
            self.lock.lock()
            self.manifest = updated
            self.lock.unlock()
            self.persistManifest(updated)
        }
        self.writer = w

        // Warm the live feed with the tail of the existing log. The agent skips
        // this: it has no way to read anything back.
        if let reader {
            var tailQuery = EventQuery()
            tailQuery.limit = 2_000
            tailQuery.newestFirst = true
            let tail = reader.query(tailQuery, manifest: self.mergedManifest(reader: reader)).reversed()
            self.recent = Array(tail)
        }
    }

    // MARK: - Writing

    public func record(_ events: [FileEvent]) {
        guard !events.isEmpty else { return }
        lock.lock()
        recent.append(contentsOf: events)
        if recent.count > recentCapacity {
            recent.removeFirst(recent.count - recentCapacity)
        }
        totalRecorded += events.count
        lock.unlock()
        writer?.append(events)
    }

    public func record(_ event: FileEvent) { record([event]) }

    public func flush() { writer?.flushNow() }

    public func close() {
        writer?.close()
        writer = nil
        persistManifest(currentManifest)
    }

    // MARK: - Reading

    public var currentManifest: LogManifest {
        lock.lock(); defer { lock.unlock() }
        return manifest
    }

    public var totalEventCount: Int {
        lock.lock(); defer { lock.unlock() }
        return totalRecorded
    }

    /// Most recent events from memory, newest last.
    public func recentEvents(limit: Int = 500, matching filter: ((FileEvent) -> Bool)? = nil) -> [FileEvent] {
        lock.lock(); defer { lock.unlock() }
        let source = filter.map { recent.filter($0) } ?? recent
        return Array(source.suffix(limit))
    }

    public func query(_ q: EventQuery) -> [FileEvent] {
        guard let reader else { return [] }
        return reader.query(q, manifest: mergedManifest(reader: reader))
    }

    /// Follows segments written by another process (the agent), returning only
    /// what has appeared since the last call.
    public func tailNewEvents() -> [FileEvent] {
        guard let reader else { return [] }
        let segments = mergedManifest(reader: reader).segments
        var fresh: [FileEvent] = []

        for record in segments {
            // Skip files this process wrote itself; they are already in memory.
            guard record.fileName.hasPrefix("agt-") else { continue }
            lock.lock()
            let offset = tailOffsets[record.fileName] ?? 0
            lock.unlock()

            let result = reader.readSegment(record, from: offset)
            guard result.nextOffset != offset || !result.events.isEmpty else { continue }

            lock.lock()
            tailOffsets[record.fileName] = result.nextOffset
            lock.unlock()
            fresh.append(contentsOf: result.events)
        }

        if !fresh.isEmpty {
            fresh.sort { $0.timestamp < $1.timestamp }
            lock.lock()
            recent.append(contentsOf: fresh)
            if recent.count > recentCapacity {
                recent.removeFirst(recent.count - recentCapacity)
            }
            totalRecorded += fresh.count
            lock.unlock()
        }
        return fresh
    }

    /// Marks everything currently on disk as already seen, so opening the app
    /// does not replay the whole agent log into the live feed.
    public func primeTail() {
        guard let reader else { return }
        for record in mergedManifest(reader: reader).segments where record.fileName.hasPrefix("agt-") {
            let result = reader.readSegment(record, from: 0)
            lock.lock(); tailOffsets[record.fileName] = result.nextOffset; lock.unlock()
        }
    }

    public func verifyIntegrity() -> IntegrityReport {
        writer?.flushNow()
        guard let reader else { return IntegrityReport() }
        return reader.verify(manifest: mergedManifest(reader: reader))
    }

    /// Everything readable: this store's own manifest, the agent's manifest, and
    /// any segment found on disk that neither manifest mentions.
    private func mergedManifest(reader: EncryptedLogReader) -> LogManifest {
        var combined = currentManifest
        combined.removingPhantomRecords()
        var known = Set(combined.segments.map(\.fileName))

        // The agent's manifest is sealed to the ingest public key, so it opens
        // with the ingest private key rather than the settings key.
        let manifestCandidates = [
            directory.appendingPathComponent("manifest-agent.enc"),
            AppPaths.systemLogDirectory.appendingPathComponent("manifest-agent.enc"),
        ]
        if let keys,
           let sealed = manifestCandidates.lazy.compactMap({ try? Data(contentsOf: $0) }).first,
           let plaintext = try? PublicKeyBox.open(sealed, with: keys.ingest,
                                                  context: "hdwatcher.agent.manifest"),
           let agentManifest = try? JSONDecoder().decode(LogManifest.self, from: plaintext) {
            for record in agentManifest.segments where known.insert(record.fileName).inserted {
                combined.segments.append(record)
            }
        }
        for record in reader.discoverSegments() where known.insert(record.fileName).inserted {
            combined.segments.append(record)
        }
        // After merging, not before: the placeholder that an earlier build
        // wrote lives in the *agent's* manifest, so purging the app's copy
        // first let it straight back in.
        combined.removingPhantomRecords()
        combined.segments.sort { $0.segmentIndex < $1.segmentIndex }
        combined.totalEvents = combined.segments.reduce(0) { $0 + $1.eventCount }
        return combined
    }

    /// Manifest including anything the agent recorded, for display.
    public var visibleManifest: LogManifest {
        guard let reader else { return currentManifest }
        return mergedManifest(reader: reader)
    }

    // MARK: - Archiving

    /// Copies the whole encrypted log elsewhere without removing anything.
    /// Archiving is the only "cleanup" offered, because deleting audit history
    /// is not something this app does.
    @discardableResult
    public func archive(to destination: URL) throws -> Int {
        writer?.flushNow()
        let fm = FileManager.default
        try fm.createDirectory(at: destination, withIntermediateDirectories: true)
        var copied = 0
        for record in currentManifest.segments {
            let source = directory.appendingPathComponent(record.fileName)
            guard fm.fileExists(atPath: source.path) else { continue }
            let target = destination.appendingPathComponent(record.fileName)
            try? fm.removeItem(at: target)
            try fm.copyItem(at: source, to: target)
            copied += 1
        }
        let manifestCopy = destination.appendingPathComponent("manifest.enc")
        try? fm.removeItem(at: manifestCopy)
        try? fm.copyItem(at: manifestURL, to: manifestCopy)
        return copied
    }

    // MARK: - Export

    public enum ExportFormat: String, CaseIterable, Sendable {
        case jsonEncrypted = "Encrypted JSON"
        case jsonPlain = "JSON (unencrypted)"
        case csv = "CSV (unencrypted)"
    }

    /// Writes matching events to `url`. Plain formats are deliberately named as
    /// unencrypted in the UI — exporting is the one way log contents leave the vault.
    @discardableResult
    public func export(_ q: EventQuery, to url: URL, format: ExportFormat) throws -> Int {
        let events = query(q)
        switch format {
        case .jsonEncrypted:
            guard let keys else { throw CryptoError.vaultLocked }
            try EncryptedFileBox.write(events, to: url, key: keys.log, context: "export")
        case .jsonPlain:
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(events).write(to: url, options: [.atomic])
        case .csv:
            var csv = "timestamp,kind,severity,confidence,path,source_path,volume,source_volume,size,is_directory,rules\n"
            for e in events {
                func esc(_ s: String) -> String {
                    let needsQuote = s.contains(",") || s.contains("\"") || s.contains("\n")
                    let body = s.replacingOccurrences(of: "\"", with: "\"\"")
                    return needsQuote ? "\"\(body)\"" : body
                }
                csv += [
                    Format.fullTimestamp(e.timestamp),
                    e.kind.rawValue,
                    e.severity.displayName,
                    e.confidence.displayName,
                    esc(e.path),
                    esc(e.sourcePath ?? ""),
                    esc(e.volumeID ?? ""),
                    esc(e.sourceVolumeID ?? ""),
                    e.size.map(String.init) ?? "",
                    e.isDirectory ? "true" : "false",
                    esc(e.ruleHits.joined(separator: "|"))
                ].joined(separator: ",") + "\n"
            }
            try csv.data(using: .utf8)?.write(to: url, options: [.atomic])
        }
        return events.count
    }

    // MARK: - Private

    /// The agent's own copy, sealed to its enclave key so it can be read back
    /// after a restart. Root-only: it describes the shape of the log.
    static func privateManifestURL(directory: URL) -> URL {
        directory.appendingPathComponent("manifest-agent-private.enc")
    }

    static func readPrivateManifest(directory: URL) -> LogManifest? {
        let url = privateManifestURL(directory: directory)
        guard let sealed = try? Data(contentsOf: url),
              let plaintext = DaemonIdentity.open(sealed, context: "hdwatcher.agent.manifest.private"),
              var manifest = try? JSONDecoder().decode(LogManifest.self, from: plaintext)
        else { return nil }
        manifest.removingPhantomRecords()
        return manifest
    }

    private func persistManifest(_ m: LogManifest) {
        switch mode {
        case .full(let keys):
            try? EncryptedFileBox.write(m, to: manifestURL, key: keys.settings, context: "manifest")
        case .writeOnly(let recipient):
            // Keep the readable-by-us copy first: losing it is what made a
            // restart destroy the record of everything written before.
            if let plaintext = try? JSONEncoder().encode(m),
               let mine = DaemonIdentity.seal(plaintext, context: "hdwatcher.agent.manifest.private") {
                let url = Self.privateManifestURL(directory: directory)
                try? mine.write(to: url, options: [.atomic])
                try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                       ofItemAtPath: url.path)
            }
            // Sealed to the ingest key, so the agent cannot read back even its
            // own bookkeeping; the app merges it in when it opens the log.
            guard let plaintext = try? JSONEncoder().encode(m),
                  let sealed = try? PublicKeyBox.seal(plaintext, to: recipient,
                                                      context: "hdwatcher.agent.manifest")
            else { return }
            try? sealed.write(to: manifestURL, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: AppPaths.filePermissions],
                                                   ofItemAtPath: manifestURL.path)
        }
    }
}
