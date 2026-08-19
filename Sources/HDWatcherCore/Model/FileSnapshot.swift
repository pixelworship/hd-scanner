import Foundation

/// How long captured file contents are kept before being purged.
public enum SnapshotRetention: String, Codable, Sendable, CaseIterable, Identifiable {
    case never
    case oneHour
    case sixHours
    case oneDay
    case sevenDays
    case thirtyDays
    case forever

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .never:      return "Don't keep contents"
        case .oneHour:    return "1 hour"
        case .sixHours:   return "6 hours"
        case .oneDay:     return "24 hours"
        case .sevenDays:  return "7 days"
        case .thirtyDays: return "30 days"
        case .forever:    return "Until I delete them"
        }
    }

    /// Nil means keep indefinitely. `.never` also returns nil but is filtered
    /// out earlier — nothing is captured at all in that mode.
    public var duration: TimeInterval? {
        switch self {
        case .never, .forever: return nil
        case .oneHour:    return 3_600
        case .sixHours:   return 21_600
        case .oneDay:     return 86_400
        case .sevenDays:  return 604_800
        case .thirtyDays: return 2_592_000
        }
    }

    public var capturesAnything: Bool { self != .never }

    public func expiry(from date: Date = Date()) -> Date? {
        duration.map { date.addingTimeInterval($0) }
    }
}

public enum SnapshotReason: String, Codable, Sendable {
    case created
    case modified
    case beforeOverwrite

    public var displayName: String {
        switch self {
        case .created:         return "Created"
        case .modified:        return "Modified"
        case .beforeOverwrite: return "Before overwrite"
        }
    }
}

/// One captured version of a file's contents.
///
/// Content is captured when a file is written, because FSEvents reports a
/// deletion only after the file is already gone — by then there is nothing left
/// to read. So the version recoverable after a delete is the last one captured
/// while the file still existed.
public struct FileSnapshot: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    public var path: String
    public var volumeID: String?
    public var capturedAt: Date
    /// Nil means "keep until manually removed".
    public var expiresAt: Date?
    public var byteSize: Int64
    /// SHA-256 of the contents — used to skip unchanged files and to share one
    /// stored blob between identical versions.
    public var contentHash: Data
    /// Where the sealed bytes live inside the container.
    public var offset: UInt64
    public var storedLength: UInt32
    public var reason: SnapshotReason
    /// Set when a delete event later lands on this path.
    public var deletedAt: Date?
    /// 1-based version number for this path.
    public var generation: Int

    public init(id: UUID = UUID(), path: String, volumeID: String? = nil,
                capturedAt: Date = Date(), expiresAt: Date? = nil,
                byteSize: Int64, contentHash: Data, offset: UInt64,
                storedLength: UInt32, reason: SnapshotReason,
                deletedAt: Date? = nil, generation: Int = 1) {
        self.id = id
        self.path = path
        self.volumeID = volumeID
        self.capturedAt = capturedAt
        self.expiresAt = expiresAt
        self.byteSize = byteSize
        self.contentHash = contentHash
        self.offset = offset
        self.storedLength = storedLength
        self.reason = reason
        self.deletedAt = deletedAt
        self.generation = generation
    }

    public var fileName: String { (path as NSString).lastPathComponent }
    public var directory: String { (path as NSString).deletingLastPathComponent }
    public var fileExtension: String { (path as NSString).pathExtension.lowercased() }
    public var isDeleted: Bool { deletedAt != nil }

    public var isExpired: Bool {
        guard let expiresAt else { return false }
        return expiresAt <= Date()
    }

    public var timeRemaining: TimeInterval? {
        guard let expiresAt else { return nil }
        return max(0, expiresAt.timeIntervalSinceNow)
    }

    /// A best-effort guess at whether this content is human-readable text.
    public static func looksTextual(_ data: Data) -> Bool {
        guard !data.isEmpty else { return true }
        let sample = data.prefix(4096)
        if sample.contains(0) { return false }
        // Reject if it does not decode as UTF-8 at all.
        return String(data: sample, encoding: .utf8) != nil
    }
}

/// One file's captured history, as presented in the Recovery screen.
public struct SnapshotGroup: Identifiable, Sendable, Hashable {
    public var id: String { path }
    public var path: String
    public var versions: [FileSnapshot]   // newest first

    public init(path: String, versions: [FileSnapshot]) {
        self.path = path
        self.versions = versions
    }

    public var latest: FileSnapshot? { versions.first }
    public var isDeleted: Bool { versions.contains { $0.isDeleted } }
    public var deletedAt: Date? { versions.compactMap(\.deletedAt).max() }
    public var totalBytes: Int64 { versions.reduce(0) { $0 + Int64($1.storedLength) } }
    public var fileName: String { (path as NSString).lastPathComponent }
    public var directory: String { (path as NSString).deletingLastPathComponent }
}

/// Accounting for the container, shown in Settings and on the Recovery screen.
public struct ContentVaultStats: Codable, Sendable {
    public var snapshotCount: Int = 0
    public var uniqueFileCount: Int = 0
    public var deletedFileCount: Int = 0
    public var liveBytes: Int64 = 0        // sealed bytes still referenced
    public var containerBytes: Int64 = 0   // actual file size on disk
    public var oldestCapture: Date?
    public var newestCapture: Date?
    public var capturesSkippedTooLarge: Int = 0
    public var capturesSkippedUnchanged: Int = 0
    public var capturesFailed: Int = 0

    public init() {}

    /// Fraction of the container that is reclaimable by compaction.
    public var wastedFraction: Double {
        guard containerBytes > 0 else { return 0 }
        return max(0, Double(containerBytes - liveBytes) / Double(containerBytes))
    }
}
