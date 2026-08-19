import Foundation

/// Searches what is *inside* captured files, not just their paths.
///
/// A filename search only finds what you already knew to look for. The vault
/// holds the bytes of every version of every file it captured, so the useful
/// question is "which files mention this phone number", or "which Biome stream
/// recorded this bundle identifier" — questions the path can never answer.
///
/// This is deliberately a scan rather than an index. An index of file contents
/// would be a second copy of everything, and it would have to be encrypted,
/// kept in step with the vault, and protected as carefully as the vault itself.
/// Reading the container we already have avoids inventing another place where
/// the contents live.
public final class ContentSearchEngine: @unchecked Sendable {

    public struct Hit: Sendable, Identifiable {
        public var id: UUID { snapshot.id }
        public let snapshot: FileSnapshot
        /// How many times the query appears, counted up to a limit.
        public let matchCount: Int
        /// A little context around the first few matches.
        public let snippets: [String]
        /// Which reading of the file produced the match.
        public let source: Source

        public enum Source: String, Sendable {
            case records = "parsed records"
            case text = "text"
            case bytes = "contents"
        }
    }

    public struct Progress: Sendable {
        public let scanned: Int
        public let total: Int
        public let hits: [Hit]
        public let finished: Bool
    }

    private let vaults: [ContentVault]
    private let cacheByteLimit: Int

    /// Extracted text keyed by content hash. Versions that share bytes — which
    /// the vault deduplicates — are only ever read once, and a second search
    /// for a different phrase reuses the work of the first.
    private var cache: [Data: String] = [:]
    private var cacheOrder: [Data] = []
    private var cachedBytes = 0
    private let mutex = NSLock()

    public init(vaults: [ContentVault], cacheByteLimit: Int = 64 * 1024 * 1024) {
        self.vaults = vaults
        self.cacheByteLimit = cacheByteLimit
    }

    public func clearCache() {
        mutex.lock(); defer { mutex.unlock() }
        cache.removeAll(); cacheOrder.removeAll(); cachedBytes = 0
    }

    /// Scans the given versions, reporting as it goes.
    ///
    /// Results are streamed rather than returned: a full pass over a large
    /// vault takes real time, and a reader wants the first match now, not the
    /// complete answer later. Newest versions are scanned first for the same
    /// reason.
    public func run(query: String,
                    snapshots: [FileSnapshot],
                    maxHits: Int = 500,
                    reportEvery: Int = 25,
                    isCancelled: @Sendable () -> Bool,
                    progress: @Sendable (Progress) -> Void) {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard needle.count >= 2 else {
            progress(Progress(scanned: 0, total: 0, hits: [], finished: true))
            return
        }

        var hits: [Hit] = []
        var scanned = 0
        // Two versions with identical bytes cannot differ in what they contain.
        var seenHashes = Set<Data>()

        for snapshot in snapshots {
            if isCancelled() || hits.count >= maxHits { break }
            scanned += 1

            defer {
                if scanned % reportEvery == 0 {
                    progress(Progress(scanned: scanned, total: snapshots.count,
                                      hits: hits, finished: false))
                }
            }

            if !snapshot.contentHash.isEmpty {
                if seenHashes.contains(snapshot.contentHash) { continue }
                seenHashes.insert(snapshot.contentHash)
            }

            guard let searchable = self.searchable(for: snapshot) else { continue }
            let found: Located
            let source: Hit.Source
            switch searchable {
            case .text(let text, let kind):
                found = Self.locate(needle, in: text)
                source = kind
            case .bytes(let data):
                found = Self.locateBytes(needle, in: data)
                source = .bytes
            }
            guard found.count > 0 else { continue }
            hits.append(Hit(snapshot: snapshot, matchCount: found.count,
                            snippets: found.snippets, source: source))
        }

        progress(Progress(scanned: scanned, total: snapshots.count,
                          hits: hits, finished: !isCancelled()))
    }

    // MARK: - Reading

    enum Searchable {
        /// Content with a meaningful textual form — a parsed record file, or a
        /// text file. Deriving it is expensive, so it is cached.
        case text(String, Hit.Source)
        /// Everything else, searched as bytes. Decoding a 30 MB binary into a
        /// String to look for one phrase costs more than the search itself.
        case bytes(Data)
    }

    private func searchable(for snapshot: FileSnapshot) -> Searchable? {
        if !snapshot.contentHash.isEmpty, let cached = cachedText(for: snapshot.contentHash) {
            return .text(cached, sourceHint(for: cached))
        }
        guard let data = read(snapshot) else { return nil }
        let (text, source) = Self.extract(from: data)
        guard let text else { return .bytes(data) }
        if !snapshot.contentHash.isEmpty { store(text, for: snapshot.contentHash) }
        return .text(text, source)
    }

    private func read(_ snapshot: FileSnapshot) -> Data? {
        for vault in vaults {
            if case .data(let data) = vault.contentResult(of: snapshot) { return data }
        }
        return nil
    }

    /// Turns stored bytes into something worth searching.
    ///
    /// For a record file that means the parsed records: searching the raw bytes
    /// of a Biome stream would miss anything held as a varint or split across a
    /// protobuf field boundary, and would never match a timestamp the reader
    /// can see on screen.
    /// Returns nil when the content has no better textual form than its own
    /// bytes, which is the signal to search it byte-wise instead.
    static func extract(from data: Data) -> (String?, Hit.Source) {
        if let document = SEGB.parse(data) {
            return (SEGB.render(document), .records)
        }
        if FileSnapshot.looksTextual(data), let text = String(data: data, encoding: .utf8) {
            return (text, .text)
        }
        return (nil, .bytes)
    }

    private func sourceHint(for text: String) -> Hit.Source {
        text.hasPrefix("SEGB v") ? .records : .bytes
    }

    // MARK: - Matching

    struct Located {
        let count: Int
        let snippets: [String]
    }

    /// Counts occurrences and lifts a little context around the first few.
    static func locate(_ needle: String, in haystack: String, maxSnippets: Int = 3,
                       maxCount: Int = 500) -> Located {
        var count = 0
        var snippets: [String] = []
        var searchStart = haystack.startIndex

        while searchStart < haystack.endIndex,
              let found = haystack.range(of: needle, options: .caseInsensitive,
                                         range: searchStart..<haystack.endIndex) {
            count += 1
            if snippets.count < maxSnippets {
                snippets.append(snippet(around: found, in: haystack))
            }
            if count >= maxCount { break }
            searchStart = found.upperBound
        }
        return Located(count: count, snippets: snippets)
    }

    /// Searches raw bytes, case-insensitively, for both the plain and the
    /// UTF-16 form of the query.
    ///
    /// macOS stores a great deal of text as UTF-16, which in a byte view is
    /// letters separated by NULs — invisible to a plain search for the word.
    /// Looking for both spellings is what makes a database or a plist findable
    /// without decoding the whole file first.
    static func locateBytes(_ needle: String, in data: Data,
                            maxSnippets: Int = 3, maxCount: Int = 500) -> Located {
        let plain = [UInt8](needle.lowercased().utf8)
        guard !plain.isEmpty else { return Located(count: 0, snippets: []) }
        var wide: [UInt8] = []
        for byte in plain { wide.append(byte); wide.append(0) }

        var offsets: [(offset: Int, length: Int)] = []
        data.withUnsafeBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            for candidate in [plain, wide] {
                var index = 0
                while index + candidate.count <= bytes.count && offsets.count < maxCount {
                    var matched = 0
                    while matched < candidate.count,
                          fold(bytes[index + matched]) == candidate[matched] { matched += 1 }
                    if matched == candidate.count {
                        offsets.append((index, candidate.count))
                        index += candidate.count
                    } else {
                        index += 1
                    }
                }
            }
        }

        let snippets = offsets.prefix(maxSnippets).map { hit in
            byteSnippet(around: hit.offset, length: hit.length, in: data)
        }
        return Located(count: offsets.count, snippets: snippets)
    }

    private static func fold(_ byte: UInt8) -> UInt8 {
        (byte >= 0x41 && byte <= 0x5A) ? byte + 32 : byte
    }

    private static func byteSnippet(around offset: Int, length: Int, in data: Data,
                                    padding: Int = 60) -> String {
        let start = max(0, offset - padding)
        let end = min(data.count, offset + length + padding)
        let slice = data[data.startIndex.advanced(by: start)..<data.startIndex.advanced(by: end)]
        var piece = String(slice.compactMap { byte -> Character? in
            // NULs are dropped rather than shown: in UTF-16 they sit between
            // every letter and would make the match unreadable.
            if byte == 0 { return nil }
            return (byte >= 0x20 && byte < 0x7F) ? Character(UnicodeScalar(byte)) : "·"
        })
        while piece.contains("··") { piece = piece.replacingOccurrences(of: "··", with: "·") }
        if start > 0 { piece = "…" + piece }
        if end < data.count { piece += "…" }
        return piece
    }

    private static func snippet(around range: Range<String.Index>, in text: String,
                                padding: Int = 60) -> String {
        let start = text.index(range.lowerBound, offsetBy: -padding,
                               limitedBy: text.startIndex) ?? text.startIndex
        let end = text.index(range.upperBound, offsetBy: padding,
                             limitedBy: text.endIndex) ?? text.endIndex
        var piece = String(text[start..<end])
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\t", with: " ")
        while piece.contains("  ") { piece = piece.replacingOccurrences(of: "  ", with: " ") }
        piece = piece.trimmingCharacters(in: .whitespaces)
        if start != text.startIndex { piece = "…" + piece }
        if end != text.endIndex { piece += "…" }
        return piece
    }

    // MARK: - Cache

    private func cachedText(for hash: Data) -> String? {
        mutex.lock(); defer { mutex.unlock() }
        return cache[hash]
    }

    private func store(_ text: String, for hash: Data) {
        let size = text.utf8.count
        // One enormous file must not evict everything else.
        guard size < cacheByteLimit / 4 else { return }

        mutex.lock(); defer { mutex.unlock() }
        if cache[hash] != nil { return }
        cache[hash] = text
        cacheOrder.append(hash)
        cachedBytes += size

        while cachedBytes > cacheByteLimit, let oldest = cacheOrder.first {
            cacheOrder.removeFirst()
            if let dropped = cache.removeValue(forKey: oldest) {
                cachedBytes -= dropped.utf8.count
            }
        }
    }
}
