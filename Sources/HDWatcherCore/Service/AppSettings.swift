import Foundation

public enum WatchScope: String, Codable, Sendable, CaseIterable {
    case allVolumes
    case internalOnly
    case externalOnly
    case customPaths

    public var displayName: String {
        switch self {
        case .allVolumes:   return "All mounted volumes"
        case .internalOnly: return "Internal disk only"
        case .externalOnly: return "External and removable only"
        case .customPaths:  return "Specific folders"
        }
    }

    public var explanation: String {
        switch self {
        case .allVolumes:   return "Watch everything currently mounted, and pick up new drives as they appear."
        case .internalOnly: return "Watch only this Mac's built-in storage."
        case .externalOnly: return "Watch only attached drives, cards and disk images."
        case .customPaths:  return "Watch a hand-picked list of folders."
        }
    }
}

public struct AppSettings: Codable, Sendable, Equatable {
    // Monitoring
    public var watchScope: WatchScope
    public var customWatchPaths: [String]
    public var filter: FilterSettings
    /// Hard ceiling on events processed per second; excess is counted and dropped
    /// so a runaway process cannot fill the disk with log segments.
    public var maxEventsPerSecond: Int
    public var monitorOnUnlock: Bool

    // Transfers
    public var transferSettleSeconds: Double
    public var transferCorrelationWindowSeconds: Double
    public var detectContentSignatures: Bool

    // Analytics
    public var hotspotHalfLifeMinutes: Int

    /// Whether the user wants the recorder running in the background.
    /// On by default and persisted, so it survives quitting the app; the
    /// registration state is a consequence of this, never the source of it.
    public var backgroundRecordingEnabled: Bool

    // Reads
    /// Whether to record which files are *read*, and by what.
    ///
    /// FSEvents cannot see reads — nothing changes on disk — so this is done by
    /// sampling the kernel's list of open file descriptors. It catches anything
    /// held open when a sample runs and misses a file opened and closed between
    /// two of them.
    public var trackFileReads: Bool
    /// How often to sample. Shorter catches more and costs more.
    public var readSampleSeconds: Double
    /// Where to look. Everything reads /usr/lib all day; that is not a finding.
    public var readRoots: [String]
    /// Noise to leave out: caches, code, temporary files, our own storage.
    public var readExcludePatterns: [GlobPattern]

    // Storage
    // The event log has no retention setting: it is a permanent audit trail.

    // Captured file contents
    public var captureFileContents: Bool
    public var contentRetention: SnapshotRetention
    /// Files larger than this are not captured at all — a partial copy would be
    /// useless to restore from.
    public var maxCaptureFileBytes: Int64
    public var maxContentVaultMegabytes: Int
    /// Minimum gap between captures of the same path.
    public var captureDebounceSeconds: Double
    /// When non-empty, only these paths are captured.
    public var captureIncludePatterns: [GlobPattern]
    public var captureExcludePatterns: [GlobPattern]

    // Security
    public var autoLockMinutes: Int
    public var lockOnSleep: Bool
    public var lockOnScreensaver: Bool
    public var clearClipboardOnLock: Bool

    // Interface
    public var showDockIcon: Bool
    public var showMenuBarExtra: Bool
    public var launchAtLogin: Bool
    public var notificationsEnabled: Bool
    public var liveFeedPaused: Bool
    public var minimumDisplayedSeverity: Severity

    public init(
        watchScope: WatchScope = .allVolumes,
        customWatchPaths: [String] = [],
        filter: FilterSettings = .default,
        maxEventsPerSecond: Int = 4000,
        monitorOnUnlock: Bool = true,
        backgroundRecordingEnabled: Bool = true,
        transferSettleSeconds: Double = 2.0,
        transferCorrelationWindowSeconds: Double = 90,
        detectContentSignatures: Bool = true,
        hotspotHalfLifeMinutes: Int = 15,
        trackFileReads: Bool = true,
        readSampleSeconds: Double = 2,
        readRoots: [String] = FileAccessMonitor.defaultRoots,
        readExcludePatterns: [GlobPattern] = FileAccessMonitor.defaultExclusions,
        captureFileContents: Bool = true,
        contentRetention: SnapshotRetention = .oneDay,
        maxCaptureFileBytes: Int64 = 32 * 1024 * 1024,
        maxContentVaultMegabytes: Int = 512,
        captureDebounceSeconds: Double = 5,
        captureIncludePatterns: [GlobPattern] = [],
        captureExcludePatterns: [GlobPattern] = ContentCapturePolicy.defaultExclusions,
        autoLockMinutes: Int = 15,
        lockOnSleep: Bool = true,
        lockOnScreensaver: Bool = true,
        clearClipboardOnLock: Bool = false,
        showDockIcon: Bool = true,
        showMenuBarExtra: Bool = true,
        launchAtLogin: Bool = false,
        notificationsEnabled: Bool = true,
        liveFeedPaused: Bool = false,
        minimumDisplayedSeverity: Severity = .info
    ) {
        self.watchScope = watchScope
        self.customWatchPaths = customWatchPaths
        self.filter = filter
        self.maxEventsPerSecond = maxEventsPerSecond
        self.monitorOnUnlock = monitorOnUnlock
        self.backgroundRecordingEnabled = backgroundRecordingEnabled
        self.transferSettleSeconds = transferSettleSeconds
        self.transferCorrelationWindowSeconds = transferCorrelationWindowSeconds
        self.detectContentSignatures = detectContentSignatures
        self.hotspotHalfLifeMinutes = hotspotHalfLifeMinutes
        self.trackFileReads = trackFileReads
        self.readSampleSeconds = readSampleSeconds
        self.readRoots = readRoots
        self.readExcludePatterns = readExcludePatterns
        self.captureFileContents = captureFileContents
        self.contentRetention = contentRetention
        self.maxCaptureFileBytes = maxCaptureFileBytes
        self.maxContentVaultMegabytes = maxContentVaultMegabytes
        self.captureDebounceSeconds = captureDebounceSeconds
        self.captureIncludePatterns = captureIncludePatterns
        self.captureExcludePatterns = captureExcludePatterns
        self.autoLockMinutes = autoLockMinutes
        self.lockOnSleep = lockOnSleep
        self.lockOnScreensaver = lockOnScreensaver
        self.clearClipboardOnLock = clearClipboardOnLock
        self.showDockIcon = showDockIcon
        self.showMenuBarExtra = showMenuBarExtra
        self.launchAtLogin = launchAtLogin
        self.notificationsEnabled = notificationsEnabled
        self.liveFeedPaused = liveFeedPaused
        self.minimumDisplayedSeverity = minimumDisplayedSeverity
    }

    public static let `default` = AppSettings()

    /// Decoded field by field with defaults, so settings saved by an earlier
    /// version survive an upgrade that adds new options. Without this, one
    /// missing key would throw and quietly reset everything to defaults.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = AppSettings()

        watchScope = try c.decodeIfPresent(WatchScope.self, forKey: .watchScope) ?? d.watchScope
        customWatchPaths = try c.decodeIfPresent([String].self, forKey: .customWatchPaths) ?? d.customWatchPaths
        filter = try c.decodeIfPresent(FilterSettings.self, forKey: .filter) ?? d.filter
        maxEventsPerSecond = try c.decodeIfPresent(Int.self, forKey: .maxEventsPerSecond) ?? d.maxEventsPerSecond
        monitorOnUnlock = try c.decodeIfPresent(Bool.self, forKey: .monitorOnUnlock) ?? d.monitorOnUnlock
        backgroundRecordingEnabled = try c.decodeIfPresent(Bool.self, forKey: .backgroundRecordingEnabled) ?? d.backgroundRecordingEnabled

        transferSettleSeconds = try c.decodeIfPresent(Double.self, forKey: .transferSettleSeconds) ?? d.transferSettleSeconds
        transferCorrelationWindowSeconds = try c.decodeIfPresent(Double.self, forKey: .transferCorrelationWindowSeconds) ?? d.transferCorrelationWindowSeconds
        detectContentSignatures = try c.decodeIfPresent(Bool.self, forKey: .detectContentSignatures) ?? d.detectContentSignatures

        hotspotHalfLifeMinutes = try c.decodeIfPresent(Int.self, forKey: .hotspotHalfLifeMinutes) ?? d.hotspotHalfLifeMinutes

        trackFileReads = try c.decodeIfPresent(Bool.self, forKey: .trackFileReads) ?? d.trackFileReads
        readSampleSeconds = try c.decodeIfPresent(Double.self, forKey: .readSampleSeconds) ?? d.readSampleSeconds
        readRoots = try c.decodeIfPresent([String].self, forKey: .readRoots) ?? d.readRoots
        readExcludePatterns = try c.decodeIfPresent([GlobPattern].self, forKey: .readExcludePatterns)
            ?? d.readExcludePatterns
        captureFileContents = try c.decodeIfPresent(Bool.self, forKey: .captureFileContents) ?? d.captureFileContents
        contentRetention = try c.decodeIfPresent(SnapshotRetention.self, forKey: .contentRetention) ?? d.contentRetention
        maxCaptureFileBytes = try c.decodeIfPresent(Int64.self, forKey: .maxCaptureFileBytes) ?? d.maxCaptureFileBytes
        maxContentVaultMegabytes = try c.decodeIfPresent(Int.self, forKey: .maxContentVaultMegabytes) ?? d.maxContentVaultMegabytes
        captureDebounceSeconds = try c.decodeIfPresent(Double.self, forKey: .captureDebounceSeconds) ?? d.captureDebounceSeconds
        captureIncludePatterns = try c.decodeIfPresent([GlobPattern].self, forKey: .captureIncludePatterns) ?? d.captureIncludePatterns
        captureExcludePatterns = try c.decodeIfPresent([GlobPattern].self, forKey: .captureExcludePatterns) ?? d.captureExcludePatterns

        autoLockMinutes = try c.decodeIfPresent(Int.self, forKey: .autoLockMinutes) ?? d.autoLockMinutes
        lockOnSleep = try c.decodeIfPresent(Bool.self, forKey: .lockOnSleep) ?? d.lockOnSleep
        lockOnScreensaver = try c.decodeIfPresent(Bool.self, forKey: .lockOnScreensaver) ?? d.lockOnScreensaver
        clearClipboardOnLock = try c.decodeIfPresent(Bool.self, forKey: .clearClipboardOnLock) ?? d.clearClipboardOnLock

        showDockIcon = try c.decodeIfPresent(Bool.self, forKey: .showDockIcon) ?? d.showDockIcon
        showMenuBarExtra = try c.decodeIfPresent(Bool.self, forKey: .showMenuBarExtra) ?? d.showMenuBarExtra
        launchAtLogin = try c.decodeIfPresent(Bool.self, forKey: .launchAtLogin) ?? d.launchAtLogin
        notificationsEnabled = try c.decodeIfPresent(Bool.self, forKey: .notificationsEnabled) ?? d.notificationsEnabled
        liveFeedPaused = try c.decodeIfPresent(Bool.self, forKey: .liveFeedPaused) ?? d.liveFeedPaused
        minimumDisplayedSeverity = try c.decodeIfPresent(Severity.self, forKey: .minimumDisplayedSeverity) ?? d.minimumDisplayedSeverity
    }
}
