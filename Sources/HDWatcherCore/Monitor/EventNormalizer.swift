import Foundation
import CoreServices

/// Controls what the watcher reports. Filesystems are astonishingly noisy —
/// caches, temp files and Spotlight churn can generate tens of thousands of
/// events a minute — so filtering happens before anything is logged.
public struct FilterSettings: Codable, Sendable, Equatable {
    public var excludePatterns: [GlobPattern]
    /// When non-empty, only paths matching one of these are reported.
    public var includeOnlyPatterns: [GlobPattern]
    public var ignoreHiddenFiles: Bool
    public var ignoreMetadataOnlyChanges: Bool
    public var ignoreDirectoryEvents: Bool
    /// Stat each file to record its size. Slightly more I/O, much better alerts.
    public var resolveFileSizes: Bool
    /// Report nothing smaller than this (0 = report everything).
    public var minimumSizeBytes: Int64

    public init(
        excludePatterns: [GlobPattern] = FilterSettings.defaultExclusions,
        includeOnlyPatterns: [GlobPattern] = [],
        ignoreHiddenFiles: Bool = false,
        ignoreMetadataOnlyChanges: Bool = true,
        ignoreDirectoryEvents: Bool = false,
        resolveFileSizes: Bool = true,
        minimumSizeBytes: Int64 = 0
    ) {
        self.excludePatterns = excludePatterns
        self.includeOnlyPatterns = includeOnlyPatterns
        self.ignoreHiddenFiles = ignoreHiddenFiles
        self.ignoreMetadataOnlyChanges = ignoreMetadataOnlyChanges
        self.ignoreDirectoryEvents = ignoreDirectoryEvents
        self.resolveFileSizes = resolveFileSizes
        self.minimumSizeBytes = minimumSizeBytes
    }

    /// Machine churn that would otherwise drown out real activity. Every entry
    /// is user-editable; "Raw mode" in Settings clears the list entirely.
    public static let defaultExclusions: [GlobPattern] = [
        // System internals and virtual filesystems
        "/System/**", "/dev/**", "/private/var/db/**", "/private/var/folders/**",
        "/private/var/vm/**", "/private/var/log/**", "/private/var/run/**",
        "/private/tmp/**", "/usr/**", "/bin/**", "/sbin/**", "/cores/**",
        // Spotlight, Time Machine and FSEvents bookkeeping
        "**/.Spotlight-V100/**", "**/.fseventsd/**", "**/.DocumentRevisions-V100/**",
        "**/.TemporaryItems/**", "**/.Trashes/**", "**/.MobileBackups/**",
        // Per-file noise
        "**/.DS_Store", "**/*.swp", "**/*.swx", "**/~$*", "**/*.crdownload",
        "**/*.part", "**/*.download",
        // Application caches and derived data
        "**/Library/Caches/**", "**/Library/Logs/**",
        "**/Library/Containers/*/Data/Library/Caches/**",
        "**/Library/Developer/Xcode/DerivedData/**",
        "**/Library/Application Support/CrashReporter/**",
        "**/Library/Saved Application State/**",
        // Build and dependency directories
        "**/node_modules/**", "**/.git/objects/**", "**/.build/**",
        "**/DerivedData/**", "**/__pycache__/**", "**/.venv/**",
    ].map { GlobPattern($0) }

    public static let `default` = FilterSettings()

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = FilterSettings()
        excludePatterns = try c.decodeIfPresent([GlobPattern].self, forKey: .excludePatterns) ?? d.excludePatterns
        includeOnlyPatterns = try c.decodeIfPresent([GlobPattern].self, forKey: .includeOnlyPatterns) ?? d.includeOnlyPatterns
        ignoreHiddenFiles = try c.decodeIfPresent(Bool.self, forKey: .ignoreHiddenFiles) ?? d.ignoreHiddenFiles
        ignoreMetadataOnlyChanges = try c.decodeIfPresent(Bool.self, forKey: .ignoreMetadataOnlyChanges) ?? d.ignoreMetadataOnlyChanges
        ignoreDirectoryEvents = try c.decodeIfPresent(Bool.self, forKey: .ignoreDirectoryEvents) ?? d.ignoreDirectoryEvents
        resolveFileSizes = try c.decodeIfPresent(Bool.self, forKey: .resolveFileSizes) ?? d.resolveFileSizes
        minimumSizeBytes = try c.decodeIfPresent(Int64.self, forKey: .minimumSizeBytes) ?? d.minimumSizeBytes
    }

    /// Watch absolutely everything, including system churn.
    public static let raw = FilterSettings(
        excludePatterns: [],
        ignoreMetadataOnlyChanges: false,
        resolveFileSizes: true
    )
}

/// Turns raw FSEvents records into classified `FileEvent`s, dropping anything
/// the filter excludes.
///
/// Holds a short memory of recently created paths. FSEvents accumulates item
/// flags per path, so a file that is created and then saved again keeps
/// arriving with `ItemCreated` still set; without this, an editor autosaving
/// would log "Created" over and over instead of "Modified".
public final class EventNormalizer: @unchecked Sendable {

    private let settings: FilterSettings
    private let excludedSelfPaths: [String]
    private let mutex = NSLock()
    private var recentCreations: [String: Date] = [:]
    private var lastPrune = Date()
    private let creationMemory: TimeInterval = 30

    public init(settings: FilterSettings, excludedSelfPaths: [String] = AppPaths.selfPaths) {
        self.settings = settings
        self.excludedSelfPaths = excludedSelfPaths
    }

    public func shouldReport(path: String) -> Bool {
        // Never report our own vault writes — that would feed the log into itself.
        for own in excludedSelfPaths where path.hasPrefix(own) { return false }

        if settings.ignoreHiddenFiles {
            let name = (path as NSString).lastPathComponent
            if name.hasPrefix(".") { return false }
        }
        if !settings.includeOnlyPatterns.isEmpty {
            return settings.includeOnlyPatterns.matchesAny(path)
        }
        return !settings.excludePatterns.matchesAny(path)
    }

    /// Classifies one raw event. Returns nil when the event is filtered out.
    public func normalize(_ raw: RawFSEvent, volume: VolumeInfo?) -> FileEvent? {
        guard shouldReport(path: raw.path) else { return nil }

        let flags = raw.flags
        var stat = statbuf(for: raw.path)
        let exists = stat != nil
        let isDirectory = stat.map { ($0.st_mode & S_IFMT) == S_IFDIR } ?? flags.isDirectory

        if isDirectory && settings.ignoreDirectoryEvents { return nil }

        guard let kind = classify(flags: flags, exists: exists, path: raw.path) else { return nil }
        if kind == .metadata && settings.ignoreMetadataOnlyChanges { return nil }

        var size: Int64?
        if settings.resolveFileSizes, !isDirectory, let s = stat {
            size = Int64(s.st_size)
        }
        if settings.minimumSizeBytes > 0, let size, size < settings.minimumSizeBytes,
           kind != .removed {
            return nil
        }

        let severity: Severity = {
            switch kind {
            case .removed:  return .notice
            case .metadata: return .trace
            default:        return .info
            }
        }()

        stat = nil
        return FileEvent(
            timestamp: Date(),
            kind: kind,
            path: raw.path,
            volumeID: volume?.id,
            size: size,
            inode: raw.inode,
            isDirectory: isDirectory,
            severity: severity,
            rawFlags: UInt32(raw.flags),
            eventID: raw.eventID
        )
    }

    /// FSEvents coalesces several changes into one delivery, so more than one
    /// item flag can be set at once. Whether the path still exists is the
    /// tiebreaker that decides which one actually happened last.
    private func classify(flags: FSEventStreamEventFlags, exists: Bool, path: String) -> EventKind? {
        if flags.needsRescan { return .rescan }
        // Mount and unmount are reported by VolumeRegistry instead. FSEvents
        // raises them too, and emitting both produced two alerts for a single
        // drive being plugged in.
        if flags.isMount || flags.isUnmount { return nil }

        if flags.isRenamed { return .renamed }
        if flags.isRemoved && !exists {
            forgetCreation(path)
            return .removed
        }
        if flags.isCloned && exists { return .cloned }
        if flags.isCreated && exists {
            // The create bit stays set on later deliveries for the same path,
            // so a subsequent write must be reported as a modification.
            if flags.isModified, hasRecentCreation(path) { return .modified }
            noteCreation(path)
            return .created
        }
        if flags.isModified && exists { return .modified }
        if flags.isRemoved { forgetCreation(path); return .removed }
        if flags.isCreated { noteCreation(path); return .created }
        if flags.isMetadataChange { return .metadata }
        return nil
    }

    // MARK: - Creation memory

    private func hasRecentCreation(_ path: String) -> Bool {
        mutex.lock(); defer { mutex.unlock() }
        guard let seen = recentCreations[path] else { return false }
        return Date().timeIntervalSince(seen) < creationMemory
    }

    private func noteCreation(_ path: String) {
        mutex.lock(); defer { mutex.unlock() }
        recentCreations[path] = Date()
        pruneLocked()
    }

    private func forgetCreation(_ path: String) {
        mutex.lock(); defer { mutex.unlock() }
        recentCreations.removeValue(forKey: path)
    }

    private func pruneLocked() {
        let now = Date()
        guard now.timeIntervalSince(lastPrune) > 10 || recentCreations.count > 20_000 else { return }
        let cutoff = now.addingTimeInterval(-creationMemory)
        recentCreations = recentCreations.filter { $0.value > cutoff }
        lastPrune = now
    }

    private func statbuf(for path: String) -> stat? {
        var s = stat()
        return lstat(path, &s) == 0 ? s : nil
    }
}
