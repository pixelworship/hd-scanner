import Foundation
import CryptoKit

/// A single encrypted container holding captured file contents and the
/// accounting that describes them.
///
/// ## Layout
///
/// ```
/// [ 64-byte header ][ sealed blob ][ sealed blob ] … [ sealed index ]
/// ```
///
/// The header points at the most recent index. Blobs and indexes are only ever
/// appended — nothing is overwritten in place — so a crash mid-write can at
/// worst strand some bytes, never corrupt the index the header still points at.
/// Superseded regions are reclaimed by `compact()`.
///
/// ## What can actually be recovered
///
/// FSEvents reports a deletion *after* the file is gone, so its contents cannot
/// be read at that moment. Contents are therefore captured when a file is
/// written, and what survives a deletion is the most recent captured version.
/// The UI states this plainly rather than implying full undelete.
/// How a content container is protected.
///
/// The daemon has no vault key, so it seals captures to the ingest public key —
/// the same write-only arrangement the event log uses. Its own bookkeeping is
/// sealed separately to its enclave key, because it does need to read that back
/// to deduplicate, number versions and apply retention.
public enum ContentSealMode: Sendable {
    /// The app: full read and write with the vault's content key.
    case symmetric(SymmetricKey)
    /// The daemon: can capture, cannot read a single byte back.
    case writeOnly(recipient: P256.KeyAgreement.PublicKey)
    /// The app reading what the daemon captured.
    case readIngest(P256.KeyAgreement.PrivateKey)

    var canWrite: Bool {
        switch self {
        case .symmetric, .writeOnly: return true
        case .readIngest: return false
        }
    }

    var canReadBlobs: Bool {
        switch self {
        case .symmetric, .readIngest: return true
        case .writeOnly: return false
        }
    }
}

public final class ContentVault: @unchecked Sendable {

    // MARK: - Container format

    private enum Format {
        static let magic: [UInt8] = Array("HDWVLT".utf8) + [0x01, 0x00]
        static let headerSize = 64
        static let version: UInt16 = 1
    }

    public struct Configuration: Sendable {
        public var maxFileBytes: Int64 = 4 * 1024 * 1024
        public var maxContainerBytes: Int64 = 512 * 1024 * 1024
        public var debounceSeconds: TimeInterval = 5
        public var retention: SnapshotRetention = .oneDay
        public var includePatterns: [GlobPattern] = []
        public var excludePatterns: [GlobPattern] = ContentCapturePolicy.defaultExclusions
        public init() {}
    }

    private struct ContainerIndex: Codable {
        var snapshots: [FileSnapshot] = []
        var updatedAt = Date()
    }

    // MARK: - State

    private let url: URL
    private let sealMode: ContentSealMode
    /// Sidecar holding this container's index sealed to the daemon's own key, so
    /// a write-only recorder can still read its own bookkeeping after a restart.
    private let sidecarURL: URL
    private let mutex = NSLock()
    private let queue = DispatchQueue(label: "co.pixelworship.hdwatcher.contentvault", qos: .utility)

    private var index = ContainerIndex()
    private var config: Configuration
    private var lastCapture: [String: Date] = [:]
    /// contentHash -> (offset, length), so identical versions share one blob.
    private var blobByHash: [Data: (offset: UInt64, length: UInt32)] = [:]
    private var stats = ContentVaultStats()
    private var indexDirty = false
    private var revisionCounter: Int = 0
    private var lastSeenSize: Int64 = -1
    private var lastSeenModified: Date = .distantPast
    private var saveTimer: DispatchSourceTimer?

    public convenience init(keys: VaultKeys, url: URL = AppPaths.contentVaultFile,
                            config: Configuration = Configuration()) {
        self.init(sealMode: .symmetric(keys.content), url: url, config: config)
    }

    public init(sealMode: ContentSealMode, url: URL = AppPaths.contentVaultFile,
                config: Configuration = Configuration()) {
        self.url = url
        self.sealMode = sealMode
        self.sidecarURL = url.appendingPathExtension("idx")
        self.config = config
        AppPaths.ensureDirectories()
        openContainer()
        startSaveTimer()
    }

    deinit { saveTimer?.cancel() }

    /// Bumped whenever anything is captured, deleted or expired. Polling this
    /// is cheap; regrouping every version is not.
    public var revision: Int {
        mutex.lock(); defer { mutex.unlock() }
        return revisionCounter
    }

    /// Re-reads the container from disk.
    ///
    /// A read-only view of someone else's container — the app looking at what
    /// the daemon captured — has no other way to notice new work. Without this
    /// the index is frozen at whatever it was when the app started, and
    /// everything captured afterwards is invisible.
    ///
    /// Cheap when nothing changed: the file's size and modification date are
    /// checked first, and the index is only decrypted when they move.
    @discardableResult
    public func reloadIfChanged() -> Bool {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        let size = (attributes?[.size] as? NSNumber)?.int64Value ?? 0
        let modified = (attributes?[.modificationDate] as? Date) ?? .distantPast

        mutex.lock()
        let unchanged = size == lastSeenSize && modified == lastSeenModified
        if !unchanged {
            lastSeenSize = size
            lastSeenModified = modified
        }
        mutex.unlock()
        guard !unchanged else { return false }

        openContainer()
        mutex.lock(); revisionCounter += 1; mutex.unlock()
        return true
    }

    public func updateConfiguration(_ newConfig: Configuration) {
        mutex.lock(); config = newConfig; mutex.unlock()
    }

    // MARK: - Container lifecycle

    private func openContainer() {
        let fm = FileManager.default
        guard fm.fileExists(atPath: url.path) else {
            createEmptyContainer()
            return
        }
        guard let handle = try? FileHandle(forReadingFrom: url),
              let header = try? handle.read(upToCount: Format.headerSize),
              header.count == Format.headerSize,
              Array(header.prefix(8)) == Format.magic else {
            try? handle_close(nil)
            createEmptyContainer()
            return
        }
        defer { try? handle.close() }

        let indexOffset: UInt64 = header.readLE(at: 12) ?? 0
        let indexLength: UInt64 = header.readLE(at: 20) ?? 0

        // A container created by an earlier build kept 0600 and was invisible to
        // the app. Re-assert the correct mode whenever it is opened.
        if sealMode.canWrite {
            try? FileManager.default.setAttributes(
                [.posixPermissions: AppPaths.filePermissions], ofItemAtPath: url.path)
        }

        var loaded = false
        if indexOffset > 0, indexLength > 0,
           (try? handle.seek(toOffset: indexOffset)) != nil,
           let sealed = try? handle.read(upToCount: Int(indexLength)),
           let plaintext = openIndex(sealed),
           let decoded = try? Self.decoder().decode(ContainerIndex.self, from: plaintext) {
            index = decoded
            loaded = true
        }
        if !loaded, case .writeOnly = sealMode,
           let sidecar = try? Data(contentsOf: sidecarURL),
           let plaintext = DaemonIdentity.open(sidecar, context: "hdwatcher.content.index"),
           let decoded = try? Self.decoder().decode(ContainerIndex.self, from: plaintext) {
            // The recorder cannot open its own container, but it can read the
            // sidecar it sealed to its own key — which is what lets it keep
            // deduplicating and numbering versions across a restart.
            index = decoded
        }
        rebuildDerivedState()
    }

    private func handle_close(_ handle: FileHandle?) throws { try handle?.close() }

    private func createEmptyContainer() {
        var header = Data(Format.magic)
        header.appendLE(Format.version)
        header.appendLE(UInt16(0))
        header.appendLE(UInt64(0))     // index offset
        header.appendLE(UInt64(0))     // index length
        header.append(Data(repeating: 0, count: Format.headerSize - header.count))
        try? header.write(to: url, options: [.atomic])
        // 0644 when the daemon writes it: the container is sealed to the ingest
        // key, so the app must be able to open it and exposure costs nothing.
        // Root ownership is what protects it, not the mode.
        try? FileManager.default.setAttributes([.posixPermissions: AppPaths.filePermissions],
                                               ofItemAtPath: url.path)
        index = ContainerIndex()
        rebuildDerivedState()
    }

    private func rebuildDerivedState() {
        blobByHash.removeAll()
        for snapshot in index.snapshots {
            blobByHash[snapshot.contentHash] = (snapshot.offset, snapshot.storedLength)
        }
        recomputeStatsLocked()
    }

    private func startSaveTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 10, repeating: 10)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            _ = self.purgeExpired()
            self.saveIndexIfDirty()
        }
        timer.resume()
        saveTimer = timer
    }

    // MARK: - Capture

    /// Reads and stores the current contents of `path`.
    ///
    /// Returns false when the file is skipped — too large, filtered out,
    /// unchanged since the last capture, or inside the debounce window.
    /// Whether any version of this path is already held.
    public func hasContent(for path: String) -> Bool {
        mutex.lock(); defer { mutex.unlock() }
        return index.snapshots.contains { $0.path == path }
    }

    @discardableResult
    public func capture(path: String, volumeID: String?, reason: SnapshotReason,
                        recordAs recordPath: String? = nil) -> Bool {
        // `recordAs` lets a file be read from where it is now but filed under
        // where it used to be — a file moved to the Trash is still on disk, and
        // the user will look for it by its original name.
        let filedPath = recordPath ?? path
        mutex.lock()
        let config = self.config
        guard config.retention.capturesAnything else { mutex.unlock(); return false }
        if let last = lastCapture[filedPath], Date().timeIntervalSince(last) < config.debounceSeconds {
            mutex.unlock(); return false
        }
        mutex.unlock()

        // The policy applies to the name the user knows it by.
        guard ContentCapturePolicy.allows(path: filedPath,
                                          include: config.includePatterns,
                                          exclude: config.excludePatterns) else { return false }

        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return false }
        let size = Int64(info.st_size)
        guard size > 0 else { return false }

        guard size <= config.maxFileBytes else {
            mutex.lock(); stats.capturesSkippedTooLarge += 1; mutex.unlock()
            return false
        }

        guard let contents = FileManager.default.contents(atPath: path) else {
            mutex.lock(); stats.capturesFailed += 1; mutex.unlock()
            return false
        }
        let hash = CryptoPrimitives.sha256(contents)

        mutex.lock()
        lastCapture[filedPath] = Date()
        // Nothing to do if the newest version of this path already has these bytes.
        if let newest = index.snapshots.last(where: { $0.path == filedPath }), newest.contentHash == hash {
            stats.capturesSkippedUnchanged += 1
            mutex.unlock()
            return false
        }
        let existingBlob = blobByHash[hash]
        let generation = index.snapshots.filter { $0.path == filedPath }.count + 1
        mutex.unlock()

        var offset: UInt64
        var storedLength: UInt32

        if let existingBlob {
            // Identical content already stored — point at it rather than
            // writing the same bytes twice.
            offset = existingBlob.offset
            storedLength = existingBlob.length
        } else {
            guard let written = appendBlob(contents) else {
                mutex.lock(); stats.capturesFailed += 1; mutex.unlock()
                return false
            }
            offset = written.offset
            storedLength = written.length
        }

        let snapshot = FileSnapshot(
            path: filedPath, volumeID: volumeID,
            capturedAt: Date(), expiresAt: config.retention.expiry(),
            byteSize: size, contentHash: hash,
            offset: offset, storedLength: storedLength,
            reason: reason, generation: generation
        )

        mutex.lock()
        index.snapshots.append(snapshot)
        blobByHash[hash] = (offset, storedLength)
        indexDirty = true
        revisionCounter += 1
        recomputeStatsLocked()
        let overCap = stats.liveBytes > config.maxContainerBytes
        mutex.unlock()

        if overCap { evictOldest(toFit: config.maxContainerBytes) }
        return true
    }

    /// Marks every stored version of `path` as belonging to a file that has
    /// since been deleted.
    public func markDeleted(path: String, at date: Date = Date()) {
        mutex.lock(); defer { mutex.unlock() }
        var touched = false
        for i in index.snapshots.indices where index.snapshots[i].path == path {
            if index.snapshots[i].deletedAt == nil {
                index.snapshots[i].deletedAt = date
                touched = true
            }
        }
        if touched {
            indexDirty = true
            recomputeStatsLocked()
        }
        revisionCounter += 1
    }

    /// Follows a rename so a file's captured history stays attached to it.
    public func notePathMoved(from oldPath: String, to newPath: String) {
        mutex.lock(); defer { mutex.unlock() }
        var touched = false
        for i in index.snapshots.indices where index.snapshots[i].path == oldPath {
            index.snapshots[i].path = newPath
            index.snapshots[i].deletedAt = nil   // it moved, it was not destroyed
            touched = true
        }
        if touched { indexDirty = true }
        revisionCounter += 1
    }

    // MARK: - Blob IO

    /// Seals a blob for its position in the container.
    private func sealBlob(_ plaintext: Data, at offset: UInt64) -> Data? {
        switch sealMode {
        case .symmetric(let key):
            var aad = Data("hdwatcher.content.blob".utf8)
            aad.appendLE(offset)
            return try? CryptoPrimitives.seal(plaintext, key: key, aad: aad)
        case .writeOnly(let recipient):
            return try? PublicKeyBox.seal(plaintext, to: recipient,
                                          context: "hdwatcher.content.blob.\(offset)")
        case .readIngest:
            return nil
        }
    }

    private func openBlob(_ sealed: Data, at offset: UInt64) -> Data? {
        switch sealMode {
        case .symmetric(let key):
            var aad = Data("hdwatcher.content.blob".utf8)
            aad.appendLE(offset)
            return try? CryptoPrimitives.open(sealed, key: key, aad: aad)
        case .readIngest(let privateKey):
            return try? PublicKeyBox.open(sealed, with: privateKey,
                                          context: "hdwatcher.content.blob.\(offset)")
        case .writeOnly:
            return nil
        }
    }

    private func sealIndex(_ plaintext: Data) -> Data? {
        switch sealMode {
        case .symmetric(let key):
            return try? CryptoPrimitives.seal(plaintext, key: key,
                                              aad: Data("hdwatcher.content.index".utf8))
        case .writeOnly(let recipient):
            return try? PublicKeyBox.seal(plaintext, to: recipient,
                                          context: "hdwatcher.content.index")
        case .readIngest:
            return nil
        }
    }

    private func openIndex(_ sealed: Data) -> Data? {
        switch sealMode {
        case .symmetric(let key):
            return try? CryptoPrimitives.open(sealed, key: key,
                                              aad: Data("hdwatcher.content.index".utf8))
        case .readIngest(let privateKey):
            return try? PublicKeyBox.open(sealed, with: privateKey,
                                          context: "hdwatcher.content.index")
        case .writeOnly:
            // Read from the daemon-sealed sidecar instead.
            return nil
        }
    }

    private func appendBlob(_ contents: Data) -> (offset: UInt64, length: UInt32)? {
        let compressed = LogFormat.compress(contents)
        let useCompression = (compressed?.count ?? Int.max) < contents.count

        var plaintext = Data()
        plaintext.appendLE(UInt32(contents.count))
        plaintext.appendLE(UInt8(useCompression ? 1 : 0))
        plaintext.append(useCompression ? (compressed ?? contents) : contents)

        guard let handle = try? FileHandle(forWritingTo: url),
              let end = try? handle.seekToEnd() else { return nil }
        defer { try? handle.close() }

        // The offset is authenticated, so a blob cannot be relocated or swapped
        // for another one without detection.
        guard let sealed = sealBlob(plaintext, at: end),
              (try? handle.write(contentsOf: sealed)) != nil else { return nil }

        return (end, UInt32(sealed.count))
    }

    /// Decrypts and returns the stored contents of one snapshot.
    /// Why a version could not be produced, so the interface can say which.
    public enum ContentOutcome: Sendable {
        case data(Data)
        /// No longer in the index — expired, evicted or explicitly removed.
        case purged
        /// Still indexed, but the stored bytes would not decrypt.
        case unreadable
    }

    public func content(of snapshot: FileSnapshot) -> Data? {
        if case .data(let data) = contentResult(of: snapshot) { return data }
        return nil
    }

    /// Decrypts one stored version.
    ///
    /// The record is re-resolved by id rather than trusting the copy handed in.
    /// Compaction rewrites blob offsets, and the offset is part of the
    /// authenticated data — so a `FileSnapshot` value captured before a
    /// compaction points at the wrong place and fails to open. The interface
    /// holds such values for as long as the user leaves a version selected,
    /// which made recovery look broken when it was not.
    public func contentResult(of snapshot: FileSnapshot) -> ContentOutcome {
        mutex.lock()
        let current = index.snapshots.first { $0.id == snapshot.id }
        mutex.unlock()
        guard let current else { return .purged }

        guard let handle = try? FileHandle(forReadingFrom: url) else { return .unreadable }
        defer { try? handle.close() }
        guard (try? handle.seek(toOffset: current.offset)) != nil,
              let sealed = try? handle.read(upToCount: Int(current.storedLength)),
              sealed.count == Int(current.storedLength) else { return .unreadable }

        guard let plaintext = openBlob(sealed, at: current.offset),
              let originalSize: UInt32 = plaintext.readLE(at: 0),
              plaintext.count > 5 else { return .unreadable }

        let compressed = plaintext[plaintext.startIndex + 4] == 1
        let body = plaintext.subdata(in: (plaintext.startIndex + 5)..<plaintext.endIndex)
        guard let result = compressed
            ? LogFormat.decompress(body, expectedSize: Int(originalSize))
            : body
        else { return .unreadable }
        return .data(result)
    }

    /// Writes a version to a temporary file so it can be opened in whatever
    /// application normally handles it.
    ///
    /// This puts decrypted bytes on disk, so the file goes in a private
    /// directory the vault owns, mode 0600, and is removed when the app quits.
    public func temporaryCopy(of snapshot: FileSnapshot) -> URL? {
        guard case .data(let data) = contentResult(of: snapshot) else { return nil }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("HDWatcher-preview", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        // Version-stamped so opening two versions of one file does not collide.
        let name = "v\(snapshot.generation)-\(snapshot.fileName)"
        let url = directory.appendingPathComponent(name)
        guard (try? data.write(to: url, options: [.atomic])) != nil else { return nil }
        try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                               ofItemAtPath: url.path)
        return url
    }

    /// Clears any decrypted previews written to the temporary directory.
    public static func clearTemporaryCopies() {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("HDWatcher-preview", isDirectory: true)
        try? FileManager.default.removeItem(at: directory)
    }

    /// Writes a stored version back to disk. Refuses to clobber an existing file
    /// unless told to.
    public func restore(_ snapshot: FileSnapshot, to destination: URL, overwrite: Bool = false) throws {
        guard let data = content(of: snapshot) else {
            throw CryptoError.vaultCorrupt("stored contents for \(snapshot.fileName) could not be read")
        }
        if FileManager.default.fileExists(atPath: destination.path), !overwrite {
            throw CocoaError(.fileWriteFileExists)
        }
        let parent = destination.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        try data.write(to: destination, options: [.atomic])
    }

    // MARK: - Queries

    public func allSnapshots() -> [FileSnapshot] {
        mutex.lock(); defer { mutex.unlock() }
        return index.snapshots
    }

    /// Captured files grouped by path, newest version first, most recently
    /// touched file first.
    public func groups(deletedOnly: Bool = false, search: String? = nil) -> [SnapshotGroup] {
        mutex.lock()
        let snapshots = index.snapshots
        mutex.unlock()

        var byPath: [String: [FileSnapshot]] = [:]
        for snapshot in snapshots where !snapshot.isExpired {
            byPath[snapshot.path, default: []].append(snapshot)
        }

        var result = byPath.map { path, versions in
            SnapshotGroup(path: path, versions: versions.sorted { $0.capturedAt > $1.capturedAt })
        }
        if deletedOnly { result = result.filter(\.isDeleted) }
        if let search, !search.isEmpty {
            result = result.filter { $0.path.range(of: search, options: .caseInsensitive) != nil }
        }
        return result.sorted { ($0.latest?.capturedAt ?? .distantPast) > ($1.latest?.capturedAt ?? .distantPast) }
    }

    public func versions(of path: String) -> [FileSnapshot] {
        mutex.lock(); defer { mutex.unlock() }
        return index.snapshots.filter { $0.path == path }.sorted { $0.capturedAt > $1.capturedAt }
    }

    public var currentStats: ContentVaultStats {
        mutex.lock(); defer { mutex.unlock() }
        return stats
    }

    private func recomputeStatsLocked() {
        let live = index.snapshots.filter { !$0.isExpired }
        var updated = stats
        updated.snapshotCount = live.count
        updated.uniqueFileCount = Set(live.map(\.path)).count
        updated.deletedFileCount = Set(live.filter(\.isDeleted).map(\.path)).count
        // Shared blobs are counted once.
        var counted = Set<UInt64>()
        var bytes: Int64 = 0
        for snapshot in live where counted.insert(snapshot.offset).inserted {
            bytes += Int64(snapshot.storedLength)
        }
        updated.liveBytes = bytes
        updated.containerBytes = (try? FileManager.default
            .attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
        updated.oldestCapture = live.map(\.capturedAt).min()
        updated.newestCapture = live.map(\.capturedAt).max()
        stats = updated
    }

    // MARK: - Retention

    /// Drops snapshots whose retention window has passed.
    @discardableResult
    public func purgeExpired() -> Int {
        mutex.lock()
        let before = index.snapshots.count
        index.snapshots.removeAll { $0.isExpired }
        let removed = before - index.snapshots.count
        if removed > 0 {
            indexDirty = true
            rebuildDerivedState()
        }
        revisionCounter += 1
        let waste = stats.wastedFraction
        let bytes = stats.containerBytes
        mutex.unlock()

        // Reclaim space once enough of the container is dead weight.
        if waste > 0.5, bytes > 8 * 1024 * 1024 {
            try? compact()
        }
        return removed
    }

    /// Applies a new retention setting to everything already stored, so
    /// shortening the window takes effect immediately.
    public func applyRetention(_ retention: SnapshotRetention) {
        mutex.lock()
        config.retention = retention
        for i in index.snapshots.indices {
            index.snapshots[i].expiresAt = retention.duration.map {
                index.snapshots[i].capturedAt.addingTimeInterval($0)
            }
        }
        indexDirty = true
        mutex.unlock()
        _ = purgeExpired()
        saveIndexIfDirty()
    }

    private func evictOldest(toFit limit: Int64) {
        mutex.lock()
        var ordered = index.snapshots.sorted { $0.capturedAt < $1.capturedAt }
        var live = stats.liveBytes
        var removed: Set<UUID> = []
        while live > limit, ordered.count > 1 {
            let victim = ordered.removeFirst()
            removed.insert(victim.id)
            live -= Int64(victim.storedLength)
        }
        if !removed.isEmpty {
            index.snapshots.removeAll { removed.contains($0.id) }
            indexDirty = true
            rebuildDerivedState()
        }
        mutex.unlock()
    }

    public func delete(snapshotIDs: Set<UUID>) {
        mutex.lock()
        index.snapshots.removeAll { snapshotIDs.contains($0.id) }
        indexDirty = true
        revisionCounter += 1
        rebuildDerivedState()
        mutex.unlock()
        saveIndexIfDirty()
    }

    public func deleteGroup(path: String) {
        mutex.lock()
        index.snapshots.removeAll { $0.path == path }
        indexDirty = true
        revisionCounter += 1
        rebuildDerivedState()
        mutex.unlock()
        saveIndexIfDirty()
    }

    public func clearAll() {
        mutex.lock()
        index = ContainerIndex()
        lastCapture.removeAll()
        blobByHash.removeAll()
        stats = ContentVaultStats()
        revisionCounter += 1
        mutex.unlock()
        createEmptyContainer()
        mutex.lock(); indexDirty = false; mutex.unlock()
    }

    // MARK: - Index persistence

    public func saveIndexIfDirty() {
        mutex.lock()
        guard indexDirty else { mutex.unlock(); return }
        index.updatedAt = Date()
        let snapshot = index
        indexDirty = false
        mutex.unlock()
        writeIndex(snapshot)
    }

    private func writeIndex(_ snapshot: ContainerIndex) {
        guard let plaintext = try? Self.encoder().encode(snapshot),
              let sealed = sealIndex(plaintext),
              let handle = try? FileHandle(forUpdating: url),
              let end = try? handle.seekToEnd() else { return }
        defer { try? handle.close() }

        // Append the new index first, then repoint the header. If the process
        // dies in between, the header still names a complete older index.
        guard (try? handle.write(contentsOf: sealed)) != nil else { return }

        var pointer = Data()
        pointer.appendLE(end)
        pointer.appendLE(UInt64(sealed.count))
        guard (try? handle.seek(toOffset: 12)) != nil else { return }
        try? handle.write(contentsOf: pointer)
        try? handle.synchronize()

        // Keep a copy the recorder itself can reopen.
        if case .writeOnly = sealMode,
           let mine = DaemonIdentity.seal(plaintext, context: "hdwatcher.content.index") {
            try? mine.write(to: sidecarURL, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                   ofItemAtPath: sidecarURL.path)
        }
    }

    /// Rewrites the container keeping only live blobs.
    public func compact() throws {
        mutex.lock()
        let snapshots = index.snapshots.filter { !$0.isExpired }
        mutex.unlock()

        let temporary = url.appendingPathExtension("compact")
        try? FileManager.default.removeItem(at: temporary)

        var header = Data(Format.magic)
        header.appendLE(Format.version)
        header.appendLE(UInt16(0))
        header.appendLE(UInt64(0))
        header.appendLE(UInt64(0))
        header.append(Data(repeating: 0, count: Format.headerSize - header.count))
        try header.write(to: temporary)

        guard let source = try? FileHandle(forReadingFrom: url),
              let destination = try? FileHandle(forWritingTo: temporary) else { return }
        defer { try? source.close(); try? destination.close() }
        try destination.seekToEnd()

        var relocated: [UInt64: (offset: UInt64, length: UInt32)] = [:]
        var rebuilt: [FileSnapshot] = []

        for var snapshot in snapshots.sorted(by: { $0.capturedAt < $1.capturedAt }) {
            if let moved = relocated[snapshot.offset] {
                snapshot.offset = moved.offset
                snapshot.storedLength = moved.length
                rebuilt.append(snapshot)
                continue
            }
            // Decrypt from the old position and re-seal at the new one, because
            // the offset is part of the authenticated data.
            guard let contents = content(of: snapshot) else { continue }
            let compressed = LogFormat.compress(contents)
            let useCompression = (compressed?.count ?? Int.max) < contents.count
            var plaintext = Data()
            plaintext.appendLE(UInt32(contents.count))
            plaintext.appendLE(UInt8(useCompression ? 1 : 0))
            plaintext.append(useCompression ? (compressed ?? contents) : contents)

            guard let newOffset = try? destination.offset() else { continue }
            guard let sealed = sealBlob(plaintext, at: newOffset) else { continue }
            try destination.write(contentsOf: sealed)

            let old = snapshot.offset
            snapshot.offset = newOffset
            snapshot.storedLength = UInt32(sealed.count)
            relocated[old] = (newOffset, UInt32(sealed.count))
            rebuilt.append(snapshot)
        }

        try destination.close()
        try source.close()
        _ = try FileManager.default.replaceItemAt(url, withItemAt: temporary)
        // Replacing the file resets its mode; keep it readable by the app.
        try? FileManager.default.setAttributes([.posixPermissions: AppPaths.filePermissions],
                                               ofItemAtPath: url.path)

        mutex.lock()
        index.snapshots = rebuilt
        indexDirty = true
        rebuildDerivedState()
        let snapshotCopy = index
        indexDirty = false
        mutex.unlock()
        writeIndex(snapshotCopy)
    }

    public func close() {
        saveIndexIfDirty()
        saveTimer?.cancel()
        saveTimer = nil
    }

    // MARK: - Coding

    private static func encoder() -> JSONEncoder {
        let e = JSONEncoder(); e.dateEncodingStrategy = .secondsSince1970; return e
    }
    private static func decoder() -> JSONDecoder {
        let d = JSONDecoder(); d.dateDecodingStrategy = .secondsSince1970; return d
    }
}
