import Foundation
import CryptoKit

/// Files the app and the background agent use to talk to each other.
///
/// They are deliberately files rather than XPC: the agent has to keep recording
/// whether or not the app is running, and a dropped connection must never cost
/// an audit event.
public enum AgentPaths {
    public static let label = "co.pixelworship.hdwatcher.daemon"
    public static let plistName = "co.pixelworship.hdwatcher.daemon.plist"
    /// The launchd label, which is what `launchctl` commands need.
    public static let serviceLabel = "co.pixelworship.hdwatcher.daemon"

    /// The daemon pins the first ingest key it sees into its own root-owned
    /// directory. After that it ignores the copy in the user's home, so a local
    /// attacker cannot substitute their own key and have future events sealed
    /// to them instead.
    public static var pinnedIngestKey: URL {
        AppPaths.systemSupportDirectory.appendingPathComponent("ingest.pub")
    }

    /// Public half of the ingest key. Safe to leave in the clear — it can only
    /// be used to *write* events.
    public static var ingestPublicKey: URL {
        AppPaths.supportDirectory.appendingPathComponent("ingest.pub")
    }
    /// What the daemon is doing, sealed to the ingest public key. Even the
    /// watched-path list would disclose what is monitored, so none of it is
    /// left in the clear.
    public static var status: URL {
        AppPaths.supportDirectory.appendingPathComponent("agent-status.enc")
    }
    /// What the daemon should watch, sealed to the daemon's own enclave key.
    public static var configuration: URL {
        AppPaths.supportDirectory.appendingPathComponent("agent-config.enc")
    }
    /// Where the app leaves configuration for a daemon running out of /Library.
    public static var systemConfiguration: URL {
        AppPaths.systemSupportDirectory.appendingPathComponent("agent-config.enc")
    }
    /// Manifest for agent-written segments, sealed to the ingest public key.
    public static var agentManifest: URL {
        AppPaths.logDirectory.appendingPathComponent("manifest-agent.enc")
    }
    public static var logFile: URL {
        AppPaths.supportDirectory.appendingPathComponent("agent.log")
    }
}

/// What the agent reports about itself.
public struct AgentStatus: Codable, Sendable {
    public var pid: Int32
    public var startedAt: Date
    public var heartbeat: Date
    public var eventsRecorded: UInt64
    public var eventsFiltered: UInt64
    public var eventsDropped: UInt64
    public var transfersDetected: Int
    public var alertsRaised: Int
    public var watchedPaths: [String]
    public var isMonitoring: Bool
    public var lastError: String?
    public var version: String
    public var runningAsRoot: Bool
    public var logDirectory: String

    public init(pid: Int32 = 0, startedAt: Date = Date(), heartbeat: Date = Date(),
                eventsRecorded: UInt64 = 0, eventsFiltered: UInt64 = 0,
                eventsDropped: UInt64 = 0, transfersDetected: Int = 0,
                alertsRaised: Int = 0, watchedPaths: [String] = [],
                isMonitoring: Bool = false, lastError: String? = nil,
                version: String = "1.0", runningAsRoot: Bool = false,
                logDirectory: String = "") {
        self.pid = pid
        self.startedAt = startedAt
        self.heartbeat = heartbeat
        self.eventsRecorded = eventsRecorded
        self.eventsFiltered = eventsFiltered
        self.eventsDropped = eventsDropped
        self.transfersDetected = transfersDetected
        self.alertsRaised = alertsRaised
        self.watchedPaths = watchedPaths
        self.isMonitoring = isMonitoring
        self.lastError = lastError
        self.version = version
        self.runningAsRoot = runningAsRoot
        self.logDirectory = logDirectory
    }

    // Lenient so a status file written by an older build still parses.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        pid = try c.decodeIfPresent(Int32.self, forKey: .pid) ?? 0
        startedAt = try c.decodeIfPresent(Date.self, forKey: .startedAt) ?? Date()
        heartbeat = try c.decodeIfPresent(Date.self, forKey: .heartbeat) ?? .distantPast
        eventsRecorded = try c.decodeIfPresent(UInt64.self, forKey: .eventsRecorded) ?? 0
        eventsFiltered = try c.decodeIfPresent(UInt64.self, forKey: .eventsFiltered) ?? 0
        eventsDropped = try c.decodeIfPresent(UInt64.self, forKey: .eventsDropped) ?? 0
        transfersDetected = try c.decodeIfPresent(Int.self, forKey: .transfersDetected) ?? 0
        alertsRaised = try c.decodeIfPresent(Int.self, forKey: .alertsRaised) ?? 0
        watchedPaths = try c.decodeIfPresent([String].self, forKey: .watchedPaths) ?? []
        isMonitoring = try c.decodeIfPresent(Bool.self, forKey: .isMonitoring) ?? false
        lastError = try c.decodeIfPresent(String.self, forKey: .lastError)
        version = try c.decodeIfPresent(String.self, forKey: .version) ?? "1.0"
        runningAsRoot = try c.decodeIfPresent(Bool.self, forKey: .runningAsRoot) ?? false
        logDirectory = try c.decodeIfPresent(String.self, forKey: .logDirectory) ?? ""
    }

    /// The agent writes a heartbeat every few seconds; a stale one means it
    /// died rather than stopped cleanly.
    public var isAlive: Bool {
        guard Date().timeIntervalSince(heartbeat) < 30 else { return false }
        return AgentStatus.processExists(pid)
    }

    /// Whether a pid is live.
    ///
    /// `kill(pid, 0)` succeeds only if we are allowed to signal the target. The
    /// daemon runs as root and the app does not, so the call fails with EPERM
    /// even though the process is plainly there — reading that as "dead" made a
    /// perfectly healthy daemon show as unresponsive. EPERM is proof of
    /// existence; only ESRCH means gone.
    public static func processExists(_ pid: Int32) -> Bool {
        guard pid > 0 else { return false }
        if kill(pid, 0) == 0 { return true }
        return errno == EPERM
    }

    public var uptime: TimeInterval { Date().timeIntervalSince(startedAt) }

    /// Opens the sealed status. Needs the ingest private key, so only the
    /// unlocked app can do this.
    public static func read(from url: URL = AgentPaths.status,
                            using ingest: P256.KeyAgreement.PrivateKey?) -> AgentStatus? {
        guard let sealed = try? Data(contentsOf: url) else { return nil }
        guard let ingest,
              let plaintext = try? PublicKeyBox.open(sealed, with: ingest,
                                                     context: "hdwatcher.agent.status")
        else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(AgentStatus.self, from: plaintext)
    }

    /// Whether the daemon is running with privileges, which is what makes the
    /// log tamper-resistant and full process attribution possible.
    public var isPrivileged: Bool { runningAsRoot }

    /// Seals the status to the ingest public key before writing it.
    ///
    /// The daemon cannot read back what it wrote, which is fine — it keeps its
    /// own copy in memory. The file is 0644 so the unlocked app can open it,
    /// and that is safe precisely because it is sealed.
    public func write(sealingTo recipient: P256.KeyAgreement.PublicKey?) {
        guard let recipient else { return }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        guard let plaintext = try? encoder.encode(self),
              let sealed = try? PublicKeyBox.seal(plaintext, to: recipient,
                                                  context: "hdwatcher.agent.status")
        else { return }
        try? sealed.write(to: AgentPaths.status, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: AppPaths.filePermissions],
                                               ofItemAtPath: AgentPaths.status.path)
    }

    public static func clear() {
        try? FileManager.default.removeItem(at: AgentPaths.status)
    }
}

/// The subset of settings the agent needs in order to watch.
///
/// This file is **not encrypted**, and cannot be: the agent starts at login with
/// no user present, so there is no key available to it. It holds configuration
/// only — watch scope, exclusion globs and rule definitions — never any recorded
/// activity. Someone who reads it learns what you monitor, not what happened.
/// The audit trail itself stays sealed to a key the agent does not possess.
public struct AgentConfiguration: Codable, Sendable {
    public var enabled: Bool
    public var watchScope: WatchScope
    public var customWatchPaths: [String]
    public var filter: FilterSettings
    public var maxEventsPerSecond: Int
    public var transferSettleSeconds: Double
    public var transferCorrelationWindowSeconds: Double
    public var hotspotHalfLifeMinutes: Int
    public var rules: [AlertRule]
    public var postsNotifications: Bool
    public var captureFileContents: Bool
    public var contentRetention: SnapshotRetention
    public var maxCaptureFileBytes: Int64
    public var maxContentVaultMegabytes: Int
    public var captureDebounceSeconds: Double
    public var captureExcludePatterns: [GlobPattern]
    public var updatedAt: Date

    public init(enabled: Bool = true,
                watchScope: WatchScope = .allVolumes,
                customWatchPaths: [String] = [],
                filter: FilterSettings = .default,
                maxEventsPerSecond: Int = 4000,
                transferSettleSeconds: Double = 2,
                transferCorrelationWindowSeconds: Double = 90,
                hotspotHalfLifeMinutes: Int = 15,
                rules: [AlertRule] = [],
                postsNotifications: Bool = false,
                captureFileContents: Bool = true,
                contentRetention: SnapshotRetention = .oneDay,
                maxCaptureFileBytes: Int64 = 32 * 1024 * 1024,
                maxContentVaultMegabytes: Int = 512,
                captureDebounceSeconds: Double = 5,
                captureExcludePatterns: [GlobPattern] = ContentCapturePolicy.defaultExclusions,
                updatedAt: Date = Date()) {
        self.enabled = enabled
        self.watchScope = watchScope
        self.customWatchPaths = customWatchPaths
        self.filter = filter
        self.maxEventsPerSecond = maxEventsPerSecond
        self.transferSettleSeconds = transferSettleSeconds
        self.transferCorrelationWindowSeconds = transferCorrelationWindowSeconds
        self.hotspotHalfLifeMinutes = hotspotHalfLifeMinutes
        self.rules = rules
        self.postsNotifications = postsNotifications
        self.captureFileContents = captureFileContents
        self.contentRetention = contentRetention
        self.maxCaptureFileBytes = maxCaptureFileBytes
        self.maxContentVaultMegabytes = maxContentVaultMegabytes
        self.captureDebounceSeconds = captureDebounceSeconds
        self.captureExcludePatterns = captureExcludePatterns
        self.updatedAt = updatedAt
    }

    /// Builds the agent's view of the user's settings.
    public init(from settings: AppSettings, rules: [AlertRule], enabled: Bool) {
        self.init(enabled: enabled,
                  watchScope: settings.watchScope,
                  customWatchPaths: settings.customWatchPaths,
                  filter: settings.filter,
                  maxEventsPerSecond: settings.maxEventsPerSecond,
                  transferSettleSeconds: settings.transferSettleSeconds,
                  transferCorrelationWindowSeconds: settings.transferCorrelationWindowSeconds,
                  hotspotHalfLifeMinutes: settings.hotspotHalfLifeMinutes,
                  rules: rules,
                  postsNotifications: settings.notificationsEnabled,
                  captureFileContents: settings.captureFileContents,
                  contentRetention: settings.contentRetention,
                  maxCaptureFileBytes: settings.maxCaptureFileBytes,
                  maxContentVaultMegabytes: settings.maxContentVaultMegabytes,
                  captureDebounceSeconds: settings.captureDebounceSeconds,
                  captureExcludePatterns: settings.captureExcludePatterns)
    }

    /// The engine settings the agent should run with.
    public var appSettings: AppSettings {
        var settings = AppSettings.default
        settings.watchScope = watchScope
        settings.customWatchPaths = customWatchPaths
        settings.filter = filter
        settings.maxEventsPerSecond = maxEventsPerSecond
        settings.transferSettleSeconds = transferSettleSeconds
        settings.transferCorrelationWindowSeconds = transferCorrelationWindowSeconds
        settings.hotspotHalfLifeMinutes = hotspotHalfLifeMinutes
        settings.notificationsEnabled = postsNotifications
        // The daemon captures contents too, sealed to the ingest key: without
        // it, recovery simply stops the moment the app is quit.
        settings.captureFileContents = captureFileContents
        settings.contentRetention = contentRetention
        settings.maxCaptureFileBytes = maxCaptureFileBytes
        settings.maxContentVaultMegabytes = maxContentVaultMegabytes
        settings.captureDebounceSeconds = captureDebounceSeconds
        settings.captureExcludePatterns = captureExcludePatterns
        return settings
    }

    /// Opens configuration sealed to the daemon's own key. Root only.
    public static func read(from url: URL = AgentPaths.configuration) -> AgentConfiguration? {
        guard let sealed = try? Data(contentsOf: url),
              let plaintext = DaemonIdentity.open(sealed, context: "hdwatcher.agent.config")
        else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(AgentConfiguration.self, from: plaintext)
    }

    /// Seals configuration so only the daemon can read it. Returns false when
    /// the daemon has not published its key yet — it has to run once first —
    /// or when the file could not be written.
    ///
    /// Reporting the write honestly matters more than it looks: the app cannot
    /// write into `/Library`, and swallowing that failure left the daemon
    /// running on defaults for days while the app believed it had published
    /// every setting the user had chosen.
    @discardableResult
    public func write(to url: URL = AgentPaths.configuration) -> Bool {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        guard let plaintext = try? encoder.encode(self),
              let sealed = DaemonIdentity.seal(plaintext, context: "hdwatcher.agent.config")
        else { return false }
        do {
            try sealed.write(to: url, options: [.atomic])
        } catch {
            return false
        }
        try? FileManager.default.setAttributes([.posixPermissions: 0o644],
                                               ofItemAtPath: url.path)
        return true
    }

    /// Reads whichever copy is newer.
    ///
    /// There are two: one in `/Library` that only root can write, and one in
    /// the owner's home that the app writes for itself. Preferring the
    /// privileged copy unconditionally means a stale root-owned file outranks
    /// everything the user has changed since.
    public static func readNewest(system: URL = AgentPaths.systemConfiguration,
                                  user: URL?) -> AgentConfiguration? {
        let candidates = [system, user].compactMap { $0 }
        let dated = candidates.compactMap { url -> (URL, Date)? in
            guard let modified = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
            else { return nil }
            return (url, modified)
        }
        for (url, _) in dated.sorted(by: { $0.1 > $1.1 }) {
            if let configuration = read(from: url) { return configuration }
        }
        return nil
    }
}

public enum LegacyPlaintextCleanup {
    /// Files an earlier build left in the clear. Superseding them with sealed
    /// versions is not enough — the readable copies have to go, or the state
    /// they disclose is still sitting on disk.
    private static let obsoleteNames = [
        "cursor.json", "agent-status.json", "agent-config.json",
    ]

    /// Removes them from whichever directory this process owns.
    @discardableResult
    public static func run() -> [String] {
        var removed: [String] = []
        for directory in [AppPaths.supportDirectory, AppPaths.systemSupportDirectory] {
            for name in obsoleteNames {
                let url = directory.appendingPathComponent(name)
                guard FileManager.default.isDeletableFile(atPath: url.path),
                      FileManager.default.fileExists(atPath: url.path) else { continue }
                if (try? FileManager.default.removeItem(at: url)) != nil {
                    removed.append(url.path)
                }
            }
        }
        return removed
    }
}

public enum IngestKeyFile {
    /// Publishes the public half so the agent can seal events to it.
    public static func export(_ key: P256.KeyAgreement.PublicKey) {
        AppPaths.ensureDirectories()
        try? key.rawRepresentation.write(to: AgentPaths.ingestPublicKey, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o644],
                                               ofItemAtPath: AgentPaths.ingestPublicKey.path)
    }

    public static func read() -> P256.KeyAgreement.PublicKey? {
        guard let data = try? Data(contentsOf: AgentPaths.ingestPublicKey) else { return nil }
        return try? P256.KeyAgreement.PublicKey(rawRepresentation: data)
    }

    public static var exists: Bool {
        FileManager.default.fileExists(atPath: AgentPaths.ingestPublicKey.path)
    }
}
