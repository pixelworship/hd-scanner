import Foundation

/// Fires when the same rule matches repeatedly in a short window — the shape of
/// a mass deletion or a bulk copy, as opposed to one ordinary file operation.
public struct BurstCondition: Codable, Sendable, Hashable {
    public enum Grouping: String, Codable, Sendable, CaseIterable {
        case global, directory, volume, fileExtension

        public var displayName: String {
            switch self {
            case .global:        return "Anywhere"
            case .directory:     return "Per directory"
            case .volume:        return "Per volume"
            case .fileExtension: return "Per file type"
            }
        }
    }
    public var threshold: Int
    public var windowSeconds: TimeInterval
    public var grouping: Grouping

    public init(threshold: Int, windowSeconds: TimeInterval, grouping: Grouping = .global) {
        self.threshold = threshold
        self.windowSeconds = windowSeconds
        self.grouping = grouping
    }
}

/// Restricts a rule to (or away from) a range of hours.
public struct TimeWindowCondition: Codable, Sendable, Hashable {
    public var startHour: Int
    public var endHour: Int
    /// When true the rule fires *outside* the window — the "off-hours" case.
    public var inverted: Bool
    public var weekendsCount: Bool

    public init(startHour: Int = 8, endHour: Int = 19, inverted: Bool = true, weekendsCount: Bool = true) {
        self.startHour = startHour
        self.endHour = endHour
        self.inverted = inverted
        self.weekendsCount = weekendsCount
    }

    public func admits(_ date: Date, calendar: Calendar = .current) -> Bool {
        let components = calendar.dateComponents([.hour, .weekday], from: date)
        let hour = components.hour ?? 0
        let weekday = components.weekday ?? 1
        let isWeekend = (weekday == 1 || weekday == 7)

        // A weekend counts as outside working hours when the rule says so.
        if inverted, weekendsCount, isWeekend { return true }

        let inside = startHour <= endHour
            ? (hour >= startHour && hour < endHour)
            : (hour >= startHour || hour < endHour)   // window spans midnight
        return inverted ? !inside : inside
    }

    public var describedWindow: String {
        let range = String(format: "%02d:00–%02d:00", startHour, endHour)
        return inverted ? "outside \(range)" : "during \(range)"
    }
}

public struct RuleConditions: Codable, Sendable, Hashable {
    /// Empty means "any kind".
    public var eventKinds: Set<EventKind>
    public var pathIncludes: [GlobPattern]
    public var pathExcludes: [GlobPattern]
    /// Lowercased, without the dot. Empty means "any type".
    public var fileExtensions: Set<String>
    public var sourceVolumeClasses: Set<VolumeClass>
    public var destinationVolumeClasses: Set<VolumeClass>
    public var specificVolumeIDs: Set<String>
    public var minSize: Int64?
    public var maxSize: Int64?
    /// Ignore weakly-inferred transfers below this bar.
    public var minConfidence: Confidence
    public var directoriesOnly: Bool
    public var filesOnly: Bool
    public var burst: BurstCondition?
    public var timeWindow: TimeWindowCondition?

    public init(
        eventKinds: Set<EventKind> = [],
        pathIncludes: [GlobPattern] = [],
        pathExcludes: [GlobPattern] = [],
        fileExtensions: Set<String> = [],
        sourceVolumeClasses: Set<VolumeClass> = [],
        destinationVolumeClasses: Set<VolumeClass> = [],
        specificVolumeIDs: Set<String> = [],
        minSize: Int64? = nil,
        maxSize: Int64? = nil,
        minConfidence: Confidence = .none,
        directoriesOnly: Bool = false,
        filesOnly: Bool = false,
        burst: BurstCondition? = nil,
        timeWindow: TimeWindowCondition? = nil
    ) {
        self.eventKinds = eventKinds
        self.pathIncludes = pathIncludes
        self.pathExcludes = pathExcludes
        self.fileExtensions = fileExtensions
        self.sourceVolumeClasses = sourceVolumeClasses
        self.destinationVolumeClasses = destinationVolumeClasses
        self.specificVolumeIDs = specificVolumeIDs
        self.minSize = minSize
        self.maxSize = maxSize
        self.minConfidence = minConfidence
        self.directoriesOnly = directoriesOnly
        self.filesOnly = filesOnly
        self.burst = burst
        self.timeWindow = timeWindow
    }
}

public struct RuleActions: Codable, Sendable, Hashable {
    public var notify: Bool
    public var playSound: Bool
    public var soundName: String?
    /// Raise the stored event's severity to the rule's own severity.
    public var elevateEventSeverity: Bool
    /// Opt-in outbound webhook. Off unless the user configures it.
    public var webhookURL: String?
    /// Identify the process responsible. Costs a scan of every reachable
    /// process, so it is reserved for rules that warrant it.
    public var auditProcesses: Bool

    public init(notify: Bool = true, playSound: Bool = false, soundName: String? = nil,
                elevateEventSeverity: Bool = true, webhookURL: String? = nil,
                auditProcesses: Bool = false) {
        self.notify = notify
        self.playSound = playSound
        self.soundName = soundName
        self.elevateEventSeverity = elevateEventSeverity
        self.webhookURL = webhookURL
        self.auditProcesses = auditProcesses
    }

    // Decoded leniently so that adding a field in a later version does not make
    // a user's saved rules unreadable — which would silently reset them to the
    // built-in set.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        notify = try container.decodeIfPresent(Bool.self, forKey: .notify) ?? true
        playSound = try container.decodeIfPresent(Bool.self, forKey: .playSound) ?? false
        soundName = try container.decodeIfPresent(String.self, forKey: .soundName)
        elevateEventSeverity = try container.decodeIfPresent(Bool.self, forKey: .elevateEventSeverity) ?? true
        webhookURL = try container.decodeIfPresent(String.self, forKey: .webhookURL)
        auditProcesses = try container.decodeIfPresent(Bool.self, forKey: .auditProcesses) ?? false
    }
}

public struct AlertRule: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    public var name: String
    public var detail: String
    public var enabled: Bool
    public var severity: Severity
    public var conditions: RuleConditions
    public var actions: RuleActions
    /// Minimum gap between firings, so one noisy operation cannot spam.
    public var cooldownSeconds: TimeInterval
    public var isBuiltIn: Bool
    public var createdAt: Date
    public var lastTriggeredAt: Date?
    public var triggerCount: Int

    public init(
        id: UUID = UUID(),
        name: String,
        detail: String = "",
        enabled: Bool = true,
        severity: Severity = .warning,
        conditions: RuleConditions = RuleConditions(),
        actions: RuleActions = RuleActions(),
        cooldownSeconds: TimeInterval = 30,
        isBuiltIn: Bool = false,
        createdAt: Date = Date(),
        lastTriggeredAt: Date? = nil,
        triggerCount: Int = 0
    ) {
        self.id = id
        self.name = name
        self.detail = detail
        self.enabled = enabled
        self.severity = severity
        self.conditions = conditions
        self.actions = actions
        self.cooldownSeconds = cooldownSeconds
        self.isBuiltIn = isBuiltIn
        self.createdAt = createdAt
        self.lastTriggeredAt = lastTriggeredAt
        self.triggerCount = triggerCount
    }

    /// Plain-language summary of what the rule watches for, shown under its name.
    public var summary: String {
        var parts: [String] = []
        if !conditions.eventKinds.isEmpty {
            parts.append(conditions.eventKinds.map(\.displayName).sorted().joined(separator: ", "))
        }
        if !conditions.fileExtensions.isEmpty {
            let exts = conditions.fileExtensions.sorted().prefix(6).map { ".\($0)" }.joined(separator: " ")
            parts.append("types \(exts)")
        }
        if !conditions.pathIncludes.isEmpty {
            parts.append("in \(conditions.pathIncludes.prefix(2).map(\.pattern).joined(separator: ", "))")
        }
        if !conditions.destinationVolumeClasses.isEmpty {
            parts.append("to \(conditions.destinationVolumeClasses.map(\.displayName).sorted().joined(separator: "/"))")
        }
        if let minSize = conditions.minSize {
            parts.append("over \(Format.bytes(minSize))")
        }
        if let burst = conditions.burst {
            parts.append("\(burst.threshold)+ within \(Int(burst.windowSeconds))s \(burst.grouping.displayName.lowercased())")
        }
        if let window = conditions.timeWindow {
            parts.append(window.describedWindow)
        }
        return parts.isEmpty ? "Any filesystem activity" : parts.joined(separator: " · ")
    }
}

// MARK: - Built-in rules

public extension AlertRule {

    /// Extensions that usually mean credentials, keys or whole databases.
    static let sensitiveExtensions: Set<String> = [
        "pem", "key", "p12", "pfx", "kdbx", "keychain", "jks", "ppk",
        "env", "sqlite", "sqlite3", "db", "sql", "dump", "bak",
        "gpg", "asc", "ovpn", "mobileprovision", "cer", "crt"
    ]

    /// A starting set that covers the common exfiltration and destruction
    /// patterns. All are editable and individually switchable.
    static func builtInRules() -> [AlertRule] {
        [
            AlertRule(
                name: "Data copied to external drive",
                detail: "A file was copied or moved from this Mac onto external or removable media.",
                severity: .warning,
                conditions: RuleConditions(
                    eventKinds: [.copiedOut, .movedOut],
                    destinationVolumeClasses: [.externalDisk, .removable, .diskImage],
                    // Low rather than medium: a file appearing on removable media
                    // is worth reporting even when its source cannot be pinned
                    // down, which is the whole point of the alert.
                    minConfidence: .low
                ),
                actions: RuleActions(notify: true, auditProcesses: true),
                cooldownSeconds: 20,
                isBuiltIn: true
            ),
            AlertRule(
                name: "Credentials or database left the machine",
                detail: "A key, certificate, password vault or database file was transferred off this Mac.",
                severity: .critical,
                conditions: RuleConditions(
                    eventKinds: [.copiedOut, .movedOut],
                    fileExtensions: sensitiveExtensions,
                    minConfidence: .low
                ),
                actions: RuleActions(notify: true, playSound: true, auditProcesses: true),
                cooldownSeconds: 5,
                isBuiltIn: true
            ),
            AlertRule(
                name: "Audit trail tampered with",
                detail: "The audit log's own storage was altered — permissions widened, a segment deleted, or a segment truncated. Only an administrator can do this.",
                severity: .critical,
                conditions: RuleConditions(eventKinds: [.tamperDetected]),
                actions: RuleActions(notify: true, playSound: true, auditProcesses: true),
                cooldownSeconds: 0,
                isBuiltIn: true
            ),
            AlertRule(
                name: "Mass deletion",
                detail: "Many files removed from one directory in quick succession.",
                severity: .critical,
                conditions: RuleConditions(
                    eventKinds: [.removed],
                    burst: BurstCondition(threshold: 100, windowSeconds: 60, grouping: .directory)
                ),
                actions: RuleActions(notify: true, playSound: true, auditProcesses: true),
                cooldownSeconds: 120,
                isBuiltIn: true
            ),
            AlertRule(
                name: "Bulk copy to one destination",
                detail: "A large number of files arrived in a single directory — the signature of a bulk transfer.",
                severity: .warning,
                conditions: RuleConditions(
                    eventKinds: [.created, .copiedIn, .copiedOut, .movedIn, .movedOut],
                    burst: BurstCondition(threshold: 200, windowSeconds: 60, grouping: .directory)
                ),
                cooldownSeconds: 120,
                isBuiltIn: true
            ),
            AlertRule(
                name: "New volume connected",
                detail: "A drive, card or disk image was mounted.",
                severity: .notice,
                conditions: RuleConditions(eventKinds: [.mounted]),
                actions: RuleActions(notify: true, elevateEventSeverity: false),
                cooldownSeconds: 0,
                isBuiltIn: true
            ),
            AlertRule(
                name: "Volume disconnected",
                detail: "A drive, card or disk image was ejected or unplugged.",
                severity: .notice,
                conditions: RuleConditions(eventKinds: [.unmounted]),
                actions: RuleActions(notify: true, elevateEventSeverity: false),
                cooldownSeconds: 0,
                isBuiltIn: true
            ),
            AlertRule(
                name: "Large file transfer",
                detail: "A transfer larger than 1 GB crossed between volumes.",
                severity: .warning,
                conditions: RuleConditions(
                    eventKinds: [.copiedOut, .copiedIn, .movedOut, .movedIn],
                    minSize: 1_073_741_824,
                    minConfidence: .low
                ),
                cooldownSeconds: 30,
                isBuiltIn: true
            ),
            AlertRule(
                name: "SSH and cloud credentials touched",
                detail: "Something read from or wrote to a credential directory.",
                severity: .critical,
                conditions: RuleConditions(
                    pathIncludes: ["~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "~/.kube/**",
                                   "~/.config/gh/**", "~/Library/Keychains/**"].map { GlobPattern($0) }
                ),
                actions: RuleActions(notify: true, auditProcesses: true),
                cooldownSeconds: 60,
                isBuiltIn: true
            ),
            AlertRule(
                name: "Application directory modified",
                detail: "Contents of /Applications or /Library changed.",
                severity: .warning,
                conditions: RuleConditions(
                    eventKinds: [.created, .removed, .modified],
                    pathIncludes: ["/Applications/**", "/Library/LaunchAgents/**",
                                   "/Library/LaunchDaemons/**", "~/Library/LaunchAgents/**"].map { GlobPattern($0) }
                ),
                cooldownSeconds: 60,
                isBuiltIn: true
            ),
            AlertRule(
                name: "Executable saved to Downloads",
                detail: "An installer or script landed in the Downloads folder.",
                severity: .notice,
                conditions: RuleConditions(
                    eventKinds: [.created, .copiedIn, .movedIn],
                    pathIncludes: [GlobPattern("~/Downloads/**")],
                    fileExtensions: ["app", "dmg", "pkg", "sh", "command", "scpt", "jar", "iso"]
                ),
                cooldownSeconds: 15,
                isBuiltIn: true
            ),
            AlertRule(
                name: "Off-hours file activity",
                detail: "Writes or deletions outside normal working hours.",
                enabled: false,
                severity: .notice,
                conditions: RuleConditions(
                    eventKinds: [.created, .modified, .removed],
                    burst: BurstCondition(threshold: 50, windowSeconds: 300, grouping: .global),
                    timeWindow: TimeWindowCondition(startHour: 8, endHour: 19,
                                                    inverted: true, weekendsCount: true)
                ),
                cooldownSeconds: 600,
                isBuiltIn: true
            ),
        ]
    }
}
