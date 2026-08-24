import Foundation
import CryptoKit

/// Filters applied when scanning the encrypted log. Everything is optional;
/// an empty query streams the whole log.
public struct EventQuery: Sendable {
    public var start: Date?
    public var end: Date?
    public var kinds: Set<EventKind>?
    public var minSeverity: Severity?
    public var pathContains: String?
    public var pathGlobs: [GlobPattern]?
    public var volumeIDs: Set<String>?
    public var fileExtensions: Set<String>?
    public var minSize: Int64?
    public var maxSize: Int64?
    public var transfersOnly: Bool = false
    public var limit: Int?
    /// Scan newest segment first. Combined with `limit`, this makes
    /// "last N matching events" cheap.
    public var newestFirst: Bool = true

    public init() {}

    public func matches(_ event: FileEvent) -> Bool {
        if let start, event.timestamp < start { return false }
        if let end, event.timestamp > end { return false }
        if let kinds, !kinds.contains(event.kind) { return false }
        if let minSeverity, event.severity < minSeverity { return false }
        if transfersOnly, !event.kind.isTransfer { return false }
        if let pathContains, !pathContains.isEmpty,
           event.path.range(of: pathContains, options: .caseInsensitive) == nil {
            // Also try the source path, so searching for a folder finds copies out of it.
            if event.sourcePath?.range(of: pathContains, options: .caseInsensitive) == nil { return false }
        }
        if let pathGlobs, !pathGlobs.isEmpty, !pathGlobs.matchesAny(event.path) { return false }
        if let volumeIDs, let v = event.volumeID, !volumeIDs.contains(v) { return false }
        if let fileExtensions, !fileExtensions.contains(event.fileExtension) { return false }
        if let minSize, (event.size ?? 0) < minSize { return false }
        if let maxSize, (event.size ?? 0) > maxSize { return false }
        return true
    }
}

public struct IntegrityReport: Sendable {
    public struct SegmentResult: Sendable, Identifiable {
        public var id: UInt32 { segmentIndex }
        public var segmentIndex: UInt32
        public var fileName: String
        public var ok: Bool
        public var blocksVerified: Int
        public var expectedBlocks: Int
        public var problem: String?
        /// The segment's own contents verify, but its chain does not join the
        /// one before it — what a recorder killed mid-write leaves behind.
        public var linkBroken: Bool = false
    }
    public var results: [SegmentResult] = []
    public var missingSegments: [String] = []
    public var unexpectedFiles: [String] = []
    public var checkedAt = Date()

    public var isIntact: Bool {
        results.allSatisfy(\.ok) && missingSegments.isEmpty && unexpectedFiles.isEmpty
    }
    /// Segments whose contents are sound but whose link to the previous segment
    /// cannot be proved.
    public var chainBreaks: Int { results.filter(\.linkBroken).count }
    public var totalBlocks: Int { results.reduce(0) { $0 + $1.blocksVerified } }
}

/// Streams and verifies encrypted segment files.
public struct EncryptedLogReader: Sendable {
    private let directory: URL
    /// Extra directories to read from — the privileged daemon's log lives in
    /// /Library while the app's own lives in the user's home.
    private let additionalDirectories: [URL]
    private let logKey: SymmetricKey
    private let integrityKey: SymmetricKey
    /// Needed to open segments the daemon wrote.
    private let ingest: P256.KeyAgreement.PrivateKey

    public init(directory: URL, keys: VaultKeys, additionalDirectories: [URL] = []) {
        self.directory = directory
        self.additionalDirectories = additionalDirectories.filter { $0.path != directory.path }
        self.logKey = keys.log
        self.integrityKey = keys.integrity
        self.ingest = keys.ingest
    }

    private var searchDirectories: [URL] { [directory] + additionalDirectories }

    /// Resolves a segment name to whichever directory actually holds it.
    private func locate(_ fileName: String) -> URL? {
        for dir in searchDirectories {
            let candidate = dir.appendingPathComponent(fileName)
            if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
        }
        return nil
    }

    /// Keys for one segment: fixed for app-written segments, derived from the
    /// header's ephemeral key for agent-written ones.
    private func keys(for head: LogFormat.SegmentHeader) -> (log: SymmetricKey, integrity: SymmetricKey)? {
        guard head.isAgentWritten else { return (logKey, integrityKey) }
        guard let raw = head.ephemeralPublicKey,
              let ephemeral = try? P256.KeyAgreement.PublicKey(rawRepresentation: raw),
              let derived = try? PublicKeyBox.segmentKeys(privateKey: ingest,
                                                          ephemeralPublic: ephemeral,
                                                          segmentID: head.segmentID)
        else { return nil }
        return derived
    }

    /// Every segment file present on disk, including ones written by the agent
    /// that this process never saw created.
    public func discoverSegments() -> [SegmentRecord] {
        var names: [(name: String, url: URL)] = []
        var seen = Set<String>()
        for dir in searchDirectories {
            let found = ((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? [])
                .filter { $0.hasSuffix(".hdwseg") }
            for name in found where seen.insert(name).inserted {
                names.append((name, dir.appendingPathComponent(name)))
            }
        }
        return names.compactMap { name, url in
            guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
            defer { try? handle.close() }
            guard let prefix = try? handle.read(upToCount: LogFormat.agentHeaderSize),
                  let head = LogFormat.SegmentHeader.decode(prefix) else { return nil }
            let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
            let size = (attributes?[.size] as? Int64) ?? 0
            // sealed: false — the real block count is unknown from the header
            // alone, and asserting zero would read as truncated history.
            //
            // The time span is approximated conservatively: creation time is at
            // or before the first event, the file's mtime at or after the last.
            // Both errors only ever *include* a segment a window query could
            // have skipped — never exclude one it needs. Without any span, a
            // discovered segment is decrypted by every windowed query forever.
            return SegmentRecord(segmentIndex: head.segmentIndex, fileName: name,
                                 createdAt: head.createdAt,
                                 firstEventAt: head.createdAt,
                                 lastEventAt: (attributes?[.modificationDate] as? Date),
                                 byteSize: size, sealed: false)
        }.sorted { $0.segmentIndex < $1.segmentIndex }
    }

    // MARK: - Reading

    /// Decrypts one segment and returns its events in write order.
    public func readSegment(_ record: SegmentRecord) throws -> [FileEvent] {
        guard let url = locate(record.fileName) else { return [] }
        guard let data = try? Data(contentsOf: url),
              let head = LogFormat.SegmentHeader.decode(data),
              let segmentKeys = keys(for: head) else { return [] }
        let logKey = segmentKeys.log

        var events: [FileEvent] = []
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970

        var offset = LogFormat.headerSize(forVersion: head.version)
        while offset + 8 <= data.count {
            guard let payloadLength: UInt32 = data.readLE(at: offset),
                  let storedIndex: UInt32 = data.readLE(at: offset + 4) else { break }
            let payloadStart = offset + 8
            let payloadEnd = payloadStart + Int(payloadLength)
            let blockEnd = payloadEnd + LogFormat.macSize
            // A partially written trailing block (crash during flush) is simply
            // where readable history ends.
            guard blockEnd <= data.count else { break }

            let sealed = data.subdata(in: payloadStart..<payloadEnd)
            var aad = head.segmentID
            aad.appendLE(storedIndex)

            if let plaintext = try? CryptoPrimitives.open(sealed, key: logKey, aad: aad),
               let originalSize: UInt32 = plaintext.readLE(at: 0) {
                let body = plaintext.subdata(in: (plaintext.startIndex + 4)..<plaintext.endIndex)
                if let json = LogFormat.decompress(body, expectedSize: Int(originalSize)),
                   let batch = try? decoder.decode([FileEvent].self, from: json) {
                    events.append(contentsOf: batch)
                }
            }
            offset = blockEnd
        }
        return events
    }

    /// Reads only the blocks added since `offset`.
    ///
    /// The app uses this to follow a log the background agent is still writing:
    /// re-decrypting an 8 MB segment every couple of seconds would be wasteful,
    /// so it remembers how far it got in each file.
    public func readSegment(_ record: SegmentRecord, from offset: Int)
        -> (events: [FileEvent], nextOffset: Int) {
        guard let url = locate(record.fileName) else { return ([], offset) }
        guard let data = try? Data(contentsOf: url),
              let head = LogFormat.SegmentHeader.decode(data),
              let segmentKeys = keys(for: head) else { return ([], offset) }

        let headerSize = LogFormat.headerSize(forVersion: head.version)
        var cursor = max(offset, headerSize)
        guard cursor <= data.count else { return ([], headerSize) }

        var events: [FileEvent] = []
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970

        while cursor + 8 <= data.count {
            guard let payloadLength: UInt32 = data.readLE(at: cursor),
                  let storedIndex: UInt32 = data.readLE(at: cursor + 4) else { break }
            let payloadStart = cursor + 8
            let payloadEnd = payloadStart + Int(payloadLength)
            let blockEnd = payloadEnd + LogFormat.macSize
            // A block still being written is simply not there yet.
            guard blockEnd <= data.count else { break }

            let sealed = data.subdata(in: payloadStart..<payloadEnd)
            var aad = head.segmentID
            aad.appendLE(storedIndex)
            if let plaintext = try? CryptoPrimitives.open(sealed, key: segmentKeys.log, aad: aad),
               let originalSize: UInt32 = plaintext.readLE(at: 0) {
                let body = plaintext.subdata(in: (plaintext.startIndex + 4)..<plaintext.endIndex)
                if let json = LogFormat.decompress(body, expectedSize: Int(originalSize)),
                   let batch = try? decoder.decode([FileEvent].self, from: json) {
                    events.append(contentsOf: batch)
                }
            }
            cursor = blockEnd
        }
        return (events, cursor)
    }

    /// Runs a query across the log, stopping as soon as `limit` is satisfied.
    public func query(_ query: EventQuery, manifest: LogManifest) -> [FileEvent] {
        var segments = manifest.segments
        // Skip segments whose time span cannot contain a match.
        if let start = query.start {
            segments = segments.filter { ($0.lastEventAt ?? .distantFuture) >= start }
        }
        if let end = query.end {
            segments = segments.filter { ($0.firstEventAt ?? .distantPast) <= end }
        }
        segments.sort { query.newestFirst ? $0.segmentIndex > $1.segmentIndex : $0.segmentIndex < $1.segmentIndex }

        var out: [FileEvent] = []
        for segment in segments {
            guard let events = try? readSegment(segment) else { continue }
            let ordered = query.newestFirst ? events.reversed().map { $0 } : events
            for event in ordered where query.matches(event) {
                out.append(event)
                if let limit = query.limit, out.count >= limit { return out }
            }
        }
        return out
    }

    // MARK: - Integrity

    /// Recomputes the MAC chain over every segment. Any edit, reorder,
    /// truncation or deletion shows up here.
    public func verify(manifest: LogManifest) -> IntegrityReport {
        var report = IntegrityReport()
        let fm = FileManager.default
        let known = Set(manifest.segments.map(\.fileName))

        // Only the directory this reader owns is checked for strays. Segments in
        // the daemon's directory are described by its own manifest, and one we
        // merely cannot read (root-owned, wrong permissions) is a permissions
        // problem — reporting it as tampering would be crying wolf.
        let onDisk = (try? fm.contentsOfDirectory(atPath: directory.path)) ?? []
        for file in onDisk where file.hasSuffix(".hdwseg") && !known.contains(file) {
            report.unexpectedFiles.append(file)
        }

        // Verify one lineage at a time. Two writers sharing a directory (the app
        // and a background recorder) each start their own chain at index 1;
        // chaining across both would make every first block look altered.
        var previousMACByLineage: [String: Data] = [:]
        // How an earlier build seeded a new segment: from whichever record was
        // appended last, regardless of lineage. Segments written by that build
        // verify only against that rule, and they are not tampered with.
        var predecessorByFile: [String: Data] = [:]
        for (index, record) in manifest.segments.enumerated() where index > 0 {
            predecessorByFile[record.fileName] = manifest.segments[index - 1].finalMAC
        }
        let ordered = manifest.segments.sorted {
            $0.lineage == $1.lineage ? $0.segmentIndex < $1.segmentIndex : $0.lineage < $1.lineage
        }
        for record in ordered {
            let previousMAC = previousMACByLineage[record.lineage] ?? Data()
            guard let url = locate(record.fileName), let data = try? Data(contentsOf: url) else {
                report.missingSegments.append(record.fileName)
                previousMACByLineage[record.lineage] = record.finalMAC
                continue
            }
            guard let head = LogFormat.SegmentHeader.decode(data),
                  let segmentKeys = keys(for: head) else {
                report.results.append(.init(segmentIndex: record.segmentIndex,
                                            fileName: record.fileName, ok: false,
                                            blocksVerified: 0, expectedBlocks: record.blockCount,
                                            problem: "unreadable or corrupt header"))
                previousMACByLineage[record.lineage] = record.finalMAC
                continue
            }
            let logKey = segmentKeys.log
            let integrityKey = segmentKeys.integrity

            // One pass over the segment from a given point in the chain. Run
            // more than once when that starting point is in doubt.
            func pass(seed: Data, trustFirstBlock: Bool = false) -> (verified: Int, chain: Data, problem: String?) {
                let headerData = data.prefix(LogFormat.headerSize(forVersion: head.version))
                var chain = CryptoPrimitives.hmac(Data(headerData) + seed, key: integrityKey)
                var verified = 0
                var problem: String?
                var offset = LogFormat.headerSize(forVersion: head.version)
                var expectedIndex: UInt32 = 0

                while offset + 8 <= data.count {
                    guard let payloadLength: UInt32 = data.readLE(at: offset),
                          let storedIndex: UInt32 = data.readLE(at: offset + 4) else {
                        problem = "truncated block header at byte \(offset)"; break
                    }
                    let payloadStart = offset + 8
                    let payloadEnd = payloadStart + Int(payloadLength)
                    let blockEnd = payloadEnd + LogFormat.macSize
                    guard blockEnd <= data.count else {
                        problem = "incomplete final block"; break
                    }
                    guard storedIndex == expectedIndex else {
                        problem = "block index out of order (saw \(storedIndex), expected \(expectedIndex))"; break
                    }

                    let sealed = data.subdata(in: payloadStart..<payloadEnd)
                    let storedMAC = data.subdata(in: payloadEnd..<blockEnd)

                    var macInput = chain
                    macInput.appendLE(storedIndex)
                    macInput.append(CryptoPrimitives.sha256(sealed))
                    let computed = CryptoPrimitives.hmac(macInput, key: integrityKey)

                    // With no record of what this segment chained from, block
                    // zero's MAC cannot be checked — but everything after it
                    // can, relative to it. Rewriting any later block still
                    // breaks the chain, and rewriting this one still breaks the
                    // decrypt below.
                    let unverifiableFirstBlock = trustFirstBlock && storedIndex == 0
                    guard computed == storedMAC || unverifiableFirstBlock else {
                        // The active segment may be mid-write: a reader can
                        // observe a block whose bytes are not all on disk yet.
                        // That is not tampering, and calling it tampering would
                        // cry wolf every time the log is verified while
                        // recording continues.
                        let isTrailingBlock = blockEnd == data.count
                        if !record.sealed && isTrailingBlock { break }
                        problem = "MAC mismatch at block \(storedIndex) — contents were altered"
                        break
                    }
                    // Confirm the block still decrypts under its own position.
                    var aad = head.segmentID
                    aad.appendLE(storedIndex)
                    if (try? CryptoPrimitives.open(sealed, key: logKey, aad: aad)) == nil {
                        if !record.sealed && blockEnd == data.count { break }
                        problem = "block \(storedIndex) failed to decrypt"
                        break
                    }

                    chain = unverifiableFirstBlock ? storedMAC : computed
                    verified += 1
                    expectedIndex += 1
                    offset = blockEnd
                }
                return (verified, chain, problem)
            }

            var outcome = pass(seed: previousMAC)
            var note: String?

            // A first-block mismatch usually means the chain was started from a
            // different point, not that the contents were touched: a recorder
            // killed mid-write leaves the manifest behind the file, and an
            // earlier build seeded new segments from a different record
            // entirely. Both are gaps in the join, not rewritten history —
            // producing a segment that verifies from *any* seed still needs the
            // integrity key.
            if outcome.problem?.contains("MAC mismatch at block 0") == true {
                let alternatives: [(seed: Data, note: String)] = [
                    (predecessorByFile[record.fileName] ?? Data(),
                     "verified, but chained the way an earlier build seeded segments"),
                    (Data(),
                     "contents verify, but the chain does not join the previous segment — a recorder was interrupted here"),
                ]
                for candidate in alternatives where candidate.seed != previousMAC {
                    let retry = pass(seed: candidate.seed)
                    if retry.problem == nil {
                        outcome = retry
                        note = candidate.note
                        break
                    }
                }

                // Nothing on record says what this segment chained from — the
                // recorder's manifest was lost when it restarted. Its own
                // contents can still be checked.
                if note == nil {
                    let internalPass = pass(seed: previousMAC, trustFirstBlock: true)
                    if internalPass.problem == nil {
                        outcome = internalPass
                        note = "contents verify against themselves; the record linking this segment to earlier history was lost when the recorder restarted"
                    }
                }
            }
            let linkBroken = note != nil

            var problem = outcome.problem
            if problem == nil, record.sealed, outcome.verified != record.blockCount {
                problem = "expected \(record.blockCount) blocks, found \(outcome.verified) — history was truncated"
            }
            if problem == nil, record.sealed, !linkBroken, outcome.chain != record.finalMAC {
                problem = "final chain MAC does not match the manifest"
            }

            report.results.append(.init(segmentIndex: record.segmentIndex,
                                        fileName: record.fileName, ok: problem == nil,
                                        blocksVerified: outcome.verified,
                                        expectedBlocks: record.blockCount,
                                        problem: problem ?? note,
                                        linkBroken: linkBroken))
            // Carry forward what the file actually ends with, so one interrupted
            // segment does not cascade into every segment written after it.
            previousMACByLineage[record.lineage] = problem == nil ? outcome.chain : record.finalMAC
        }
        return report
    }
}
