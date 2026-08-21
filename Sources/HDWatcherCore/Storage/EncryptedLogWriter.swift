import Foundation
import CryptoKit

/// How a writer seals what it records.
public enum LogSealMode: Sendable {
    /// The app, holding the master key: keys are fixed for every segment.
    case symmetric(log: SymmetricKey, integrity: SymmetricKey)
    /// The background agent, holding only the ingest public key: every segment
    /// gets fresh keys from an ephemeral ECDH, and the writer keeps no means of
    /// reading any of it back.
    case writeOnly(recipient: P256.KeyAgreement.PublicKey)

    var version: UInt16 {
        switch self {
        case .symmetric: return LogFormat.version
        case .writeOnly: return LogFormat.agentVersion
        }
    }
}

/// Appends events to encrypted, hash-chained segment files.
///
/// All mutation happens on one serial queue so that event ordering and the MAC
/// chain stay consistent. Events are buffered into blocks (compression works far
/// better on a batch than on single records) and flushed on a timer or when the
/// batch fills.
public final class EncryptedLogWriter: @unchecked Sendable {

    public struct Configuration: Sendable {
        public var eventsPerBlock: Int = 256
        public var flushInterval: TimeInterval = 5
        public var maxSegmentBytes: Int64 = 8 * 1024 * 1024
        /// First index to use when the manifest cannot be read back — the
        /// write-only recorder cannot decrypt its own bookkeeping, so it is told
        /// where its own lineage left off.
        public var startingSegmentIndex: UInt32 = 0
        public init() {}
    }

    private let queue = DispatchQueue(label: "co.pixelworship.hdwatcher.logwriter", qos: .utility)
    private let directory: URL
    private let sealMode: LogSealMode
    /// Keys for the segment currently being written. With `.writeOnly` these
    /// are regenerated per segment and discarded when it rolls over.
    private var logKey: SymmetricKey
    private var integrityKey: SymmetricKey
    private var config: Configuration

    private var buffer: [FileEvent] = []
    private var handle: FileHandle?
    private var header: LogFormat.SegmentHeader?
    private var chainMAC = Data()
    private var blockIndex: UInt32 = 0
    private var segmentBytes: Int64 = 0
    private var currentRecord: SegmentRecord?
    private var manifest: LogManifest
    private var timer: DispatchSourceTimer?
    private var closed = false

    /// Called after each manifest change so the store can persist it.
    public var onManifestChange: (@Sendable (LogManifest) -> Void)?

    public convenience init(directory: URL, keys: VaultKeys, manifest: LogManifest,
                            config: Configuration = Configuration()) {
        self.init(directory: directory,
                  sealMode: .symmetric(log: keys.log, integrity: keys.integrity),
                  manifest: manifest, config: config)
    }

    public init(directory: URL, sealMode: LogSealMode, manifest: LogManifest,
                config: Configuration = Configuration()) {
        self.directory = directory
        self.sealMode = sealMode
        switch sealMode {
        case .symmetric(let log, let integrity):
            self.logKey = log
            self.integrityKey = integrity
        case .writeOnly:
            // Replaced with real per-segment keys as soon as a segment opens.
            self.logKey = SymmetricKey(size: .bits256)
            self.integrityKey = SymmetricKey(size: .bits256)
        }
        self.manifest = manifest
        self.config = config
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        startTimer()
    }

    deinit { timer?.cancel() }

    private func startTimer() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + config.flushInterval, repeating: config.flushInterval)
        t.setEventHandler { [weak self] in self?.flushLocked(force: false) }
        t.resume()
        timer = t
    }

    // MARK: - Public API

    public func append(_ events: [FileEvent]) {
        guard !events.isEmpty else { return }
        queue.async { [weak self] in
            guard let self, !self.closed else { return }
            self.buffer.append(contentsOf: events)
            if self.buffer.count >= self.config.eventsPerBlock {
                self.flushLocked(force: true)
            }
        }
    }

    public func append(_ event: FileEvent) { append([event]) }

    /// Writes any buffered events immediately. Synchronous so callers can use it
    /// before locking the vault or quitting.
    public func flushNow() {
        queue.sync { [weak self] in self?.flushLocked(force: true) }
    }

    public func close() {
        queue.sync { [weak self] in
            guard let self, !self.closed else { return }
            self.flushLocked(force: true)
            self.sealCurrentSegment()
            try? self.handle?.close()
            self.handle = nil
            self.closed = true
        }
        timer?.cancel()
        timer = nil
    }

    public var currentManifest: LogManifest {
        queue.sync { manifest }
    }

    public var pendingCount: Int {
        queue.sync { buffer.count }
    }

    // MARK: - Segment lifecycle

    private func openNewSegment() {
        sealCurrentSegment()
        try? handle?.close()
        handle = nil

        let highestKnown = manifest.segments.map(\.segmentIndex).max() ?? 0
        let index = max(highestKnown, config.startingSegmentIndex) + 1
        let prefix = sealMode.version >= LogFormat.agentVersion ? "agt" : "seg"
        let name = String(format: "%@-%06u-%llu.hdwseg", prefix, index, UInt64(Date().timeIntervalSince1970))
        let url = directory.appendingPathComponent(name)

        let head: LogFormat.SegmentHeader
        switch sealMode {
        case .symmetric:
            head = LogFormat.SegmentHeader(segmentIndex: index)
        case .writeOnly(let recipient):
            // One ephemeral key per segment. Its private half is used once here
            // and then dropped, so this process cannot reopen the segment.
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let segmentID = CryptoPrimitives.randomBytes(16)
            guard let derived = try? PublicKeyBox.segmentKeys(
                ephemeralPrivate: ephemeral, recipient: recipient, segmentID: segmentID
            ) else { return }
            logKey = derived.log
            integrityKey = derived.integrity
            head = LogFormat.SegmentHeader(
                version: LogFormat.agentVersion,
                segmentIndex: index,
                segmentID: segmentID,
                ephemeralPublicKey: ephemeral.publicKey.rawRepresentation
            )
        }
        let headerData = head.encoded()

        // Segments written by the root daemon must be readable by the app.
        // They are sealed to the ingest key, so readability discloses nothing —
        // root ownership is what keeps them from being altered.
        FileManager.default.createFile(atPath: url.path, contents: headerData,
                                       attributes: [.posixPermissions: AppPaths.filePermissions])
        guard let fh = try? FileHandle(forWritingTo: url) else { return }
        try? fh.seekToEnd()

        handle = fh
        header = head
        blockIndex = 0
        segmentBytes = Int64(headerData.count)

        // Seed the chain from this segment's header plus the previous segment's
        // final MAC, so removing an entire segment file breaks verification too.
        //
        // It has to be the previous segment *of this lineage*, which is what
        // verification walks. Taking whatever record happened to be appended
        // last meant that a manifest holding another writer's segment — or a
        // placeholder record — seeded the chain with a value the reader would
        // never arrive at, and the next segment was then reported as altered.
        let lineage = name.split(separator: "-").first.map(String.init) ?? "seg"
        let previousMAC = manifest.segments.last { $0.lineage == lineage }?.finalMAC ?? Data()
        chainMAC = CryptoPrimitives.hmac(headerData + previousMAC, key: integrityKey)

        let record = SegmentRecord(segmentIndex: index, fileName: name,
                                   createdAt: head.createdAt, finalMAC: chainMAC,
                                   byteSize: segmentBytes, sealed: false)
        currentRecord = record
        manifest.segments.append(record)
        publishManifest()
    }

    private func sealCurrentSegment() {
        guard var record = currentRecord else { return }
        record.sealed = true
        replaceRecord(record)
        currentRecord = nil
    }

    private func replaceRecord(_ record: SegmentRecord) {
        if let i = manifest.segments.firstIndex(where: { $0.segmentIndex == record.segmentIndex }) {
            manifest.segments[i] = record
        } else {
            manifest.segments.append(record)
        }
        manifest.updatedAt = Date()
        publishManifest()
    }

    private func publishManifest() {
        manifest.totalEvents = manifest.segments.reduce(0) { $0 + $1.eventCount }
        onManifestChange?(manifest)
    }

    // MARK: - Flush

    private func flushLocked(force: Bool) {
        guard !closed, !buffer.isEmpty else { return }
        if !force && buffer.count < config.eventsPerBlock { return }

        let batch = buffer
        buffer.removeAll(keepingCapacity: true)

        if handle == nil || segmentBytes >= config.maxSegmentBytes {
            openNewSegment()
        }
        guard let fh = handle, let head = header else { return }

        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .secondsSince1970
            let json = try encoder.encode(batch)
            let compressed = LogFormat.compress(json) ?? json

            var plaintext = Data()
            plaintext.appendLE(UInt32(json.count))
            plaintext.append(compressed)

            var aad = head.segmentID
            aad.appendLE(blockIndex)
            let sealed = try CryptoPrimitives.seal(plaintext, key: logKey, aad: aad)

            var block = Data()
            block.appendLE(UInt32(sealed.count))
            block.appendLE(blockIndex)
            block.append(sealed)

            var macInput = chainMAC
            macInput.appendLE(blockIndex)
            macInput.append(CryptoPrimitives.sha256(sealed))
            let mac = CryptoPrimitives.hmac(macInput, key: integrityKey)
            block.append(mac)

            try fh.write(contentsOf: block)
            chainMAC = mac
            blockIndex += 1
            segmentBytes += Int64(block.count)

            if var record = currentRecord {
                record.blockCount = Int(blockIndex)
                record.eventCount += batch.count
                record.byteSize = segmentBytes
                record.finalMAC = mac
                let times = batch.map(\.timestamp)
                record.firstEventAt = record.firstEventAt ?? times.min()
                record.lastEventAt = times.max()
                currentRecord = record
                replaceRecord(record)
            }
        } catch {
            // Put the batch back so a transient failure does not lose events.
            buffer.insert(contentsOf: batch, at: 0)
        }
    }
}
