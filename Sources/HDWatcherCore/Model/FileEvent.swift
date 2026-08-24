import Foundation

/// The kind of filesystem change observed. Derived from FSEvents item flags,
/// then refined by the transfer detector (which can promote a create into a
/// `.copiedIn` / `.movedIn` once it identifies a probable source).
public enum EventKind: String, Codable, Sendable, CaseIterable, Hashable {
    case created
    case modified
    case removed
    case renamed
    case cloned
    case metadata          // inode meta, owner, xattr, Finder info
    /// A file was held open by a process. Reads change nothing on disk, so
    /// FSEvents never reports them; these come from sampling open descriptors.
    case read
    case mounted
    case unmounted
    case copiedIn          // inferred: content arrived from another volume
    case copiedOut         // inferred: content left for another volume
    case movedIn
    case movedOut
    case rescan            // FSEvents dropped events; a subtree must be rescanned
    case monitoringStarted // recording began, possibly after a gap
    case monitoringStopped // recording ended cleanly
    case tamperDetected    // the audit trail itself was interfered with

    public var displayName: String {
        switch self {
        case .created:   return "Created"
        case .modified:  return "Modified"
        case .removed:   return "Deleted"
        case .renamed:   return "Renamed"
        case .cloned:    return "Cloned"
        case .metadata:  return "Metadata"
        case .read:      return "Read"
        case .mounted:   return "Volume Mounted"
        case .unmounted: return "Volume Ejected"
        case .copiedIn:  return "Copied In"
        case .copiedOut: return "Copied Out"
        case .movedIn:   return "Moved In"
        case .movedOut:  return "Moved Out"
        case .rescan:    return "Rescan Required"
        case .monitoringStarted: return "Monitoring Started"
        case .monitoringStopped: return "Monitoring Stopped"
        case .tamperDetected:    return "Audit Trail Tampering"
        }
    }

    public var symbolName: String {
        switch self {
        case .created:   return "plus.circle"
        case .modified:  return "pencil.circle"
        case .removed:   return "minus.circle"
        case .renamed:   return "character.cursor.ibeam"
        case .cloned:    return "doc.on.doc"
        case .metadata:  return "tag"
        case .read:      return "eye"
        case .mounted:   return "externaldrive.badge.plus"
        case .unmounted: return "externaldrive.badge.minus"
        case .copiedIn:  return "arrow.down.doc"
        case .copiedOut: return "arrow.up.doc"
        case .movedIn:   return "arrow.down.right.circle"
        case .movedOut:  return "arrow.up.right.circle"
        case .rescan:    return "exclamationmark.arrow.circlepath"
        case .monitoringStarted: return "play.circle"
        case .monitoringStopped: return "stop.circle"
        case .tamperDetected:    return "exclamationmark.shield.fill"
        }
    }

    /// Events that represent content leaving the machine's internal storage.
    public var isEgress: Bool { self == .copiedOut || self == .movedOut }

    public var isTransfer: Bool {
        switch self {
        case .copiedIn, .copiedOut, .movedIn, .movedOut: return true
        default: return false
        }
    }
}

public enum Severity: Int, Codable, Sendable, Comparable, CaseIterable {
    case trace = 0
    case info = 1
    case notice = 2
    case warning = 3
    case critical = 4

    public static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }

    public var displayName: String {
        switch self {
        case .trace:    return "Trace"
        case .info:     return "Info"
        case .notice:   return "Notice"
        case .warning:  return "Warning"
        case .critical: return "Critical"
        }
    }
}

/// How confident the transfer detector is that an inferred copy/move is real.
public enum Confidence: Int, Codable, Sendable, Comparable {
    case none = 0
    case low = 1        // heuristic: name match only
    case medium = 2     // name + size match on another volume
    case high = 3       // content signature match, or paired create/delete
    case certain = 4    // same-inode rename observed directly

    public static func < (a: Confidence, b: Confidence) -> Bool { a.rawValue < b.rawValue }

    public var displayName: String {
        switch self {
        case .none:    return "—"
        case .low:     return "Low"
        case .medium:  return "Medium"
        case .high:    return "High"
        case .certain: return "Certain"
        }
    }
}

/// One observed filesystem change. This is the unit that gets encrypted and
/// appended to the log, so it is kept compact — short CodingKeys, optionals
/// omitted when nil.
public struct FileEvent: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    public var timestamp: Date
    public var kind: EventKind
    public var path: String
    /// For renames/transfers: where the content came from.
    public var sourcePath: String?
    public var volumeID: String?
    public var sourceVolumeID: String?
    public var size: Int64?
    public var inode: UInt64?
    public var isDirectory: Bool
    public var severity: Severity
    public var confidence: Confidence
    /// Names of the alert rules this event matched.
    public var ruleHits: [String]
    /// FSEvents raw flag bits, kept for forensic fidelity.
    public var rawFlags: UInt32
    public var eventID: UInt64
    /// Processes implicated in this change, when attribution was attempted.
    public var attribution: AttributionResult?

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        kind: EventKind,
        path: String,
        sourcePath: String? = nil,
        volumeID: String? = nil,
        sourceVolumeID: String? = nil,
        size: Int64? = nil,
        inode: UInt64? = nil,
        isDirectory: Bool = false,
        severity: Severity = .info,
        confidence: Confidence = .none,
        ruleHits: [String] = [],
        rawFlags: UInt32 = 0,
        eventID: UInt64 = 0,
        attribution: AttributionResult? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.kind = kind
        self.path = path
        self.sourcePath = sourcePath
        self.volumeID = volumeID
        self.sourceVolumeID = sourceVolumeID
        self.size = size
        self.inode = inode
        self.isDirectory = isDirectory
        self.severity = severity
        self.confidence = confidence
        self.ruleHits = ruleHits
        self.rawFlags = rawFlags
        self.eventID = eventID
        self.attribution = attribution
    }

    public var fileName: String { (path as NSString).lastPathComponent }
    public var directory: String { (path as NSString).deletingLastPathComponent }
    public var fileExtension: String { (path as NSString).pathExtension.lowercased() }

    enum CodingKeys: String, CodingKey {
        case id = "i", timestamp = "t", kind = "k", path = "p", sourcePath = "sp"
        case volumeID = "v", sourceVolumeID = "sv", size = "s", inode = "n"
        case isDirectory = "d", severity = "sev", confidence = "c", ruleHits = "r"
        case rawFlags = "f", eventID = "e", attribution = "a"
    }
}

/// A rule match, surfaced in the Alerts feed and (optionally) as a
/// user notification.
public struct SecurityAlert: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    public var timestamp: Date
    public var ruleID: UUID
    public var ruleName: String
    public var severity: Severity
    public var title: String
    public var detail: String
    public var event: FileEvent?
    /// For burst rules: how many events tripped the threshold.
    public var matchCount: Int
    public var acknowledged: Bool

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        ruleID: UUID,
        ruleName: String,
        severity: Severity,
        title: String,
        detail: String,
        event: FileEvent? = nil,
        matchCount: Int = 1,
        acknowledged: Bool = false
    ) {
        self.id = id
        self.timestamp = timestamp
        self.ruleID = ruleID
        self.ruleName = ruleName
        self.severity = severity
        self.title = title
        self.detail = detail
        self.event = event
        self.matchCount = matchCount
        self.acknowledged = acknowledged
    }
}
