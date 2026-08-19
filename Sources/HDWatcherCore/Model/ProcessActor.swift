import Foundation

/// Why a process is being named in connection with a filesystem event.
///
/// macOS does not tell an ordinary app which process changed a file — that
/// needs an Endpoint Security entitlement Apple grants case by case. Everything
/// here is therefore evidence of varying strength, and each actor carries the
/// reason it was implicated so a reader can judge it.
public enum AttributionEvidence: String, Codable, Sendable, CaseIterable {
    /// The process had the exact file open when we looked. Strongest signal.
    case holdsFileOpen
    /// The process had the enclosing directory open.
    case holdsParentDirectory
    /// The process started or exited within moments of the event.
    case startedNearEvent
    /// The system log named this process alongside the path.
    case namedInSystemLog
    /// Present and running, nothing more.
    case running

    public var displayName: String {
        switch self {
        case .holdsFileOpen:       return "Had the file open"
        case .holdsParentDirectory:return "Had the folder open"
        case .startedNearEvent:    return "Started moments before"
        case .namedInSystemLog:    return "Named in the system log"
        case .running:             return "Running at the time"
        }
    }

    /// Rough ordering so the most compelling candidate is shown first.
    public var weight: Int {
        switch self {
        case .holdsFileOpen:        return 5
        case .namedInSystemLog:     return 4
        case .holdsParentDirectory: return 3
        case .startedNearEvent:     return 2
        case .running:              return 1
        }
    }

    public var confidence: Confidence {
        switch self {
        case .holdsFileOpen:        return .high
        case .namedInSystemLog:     return .medium
        case .holdsParentDirectory: return .medium
        case .startedNearEvent:     return .low
        case .running:              return .none
        }
    }
}

/// A process implicated in a filesystem event.
public struct ProcessActor: Codable, Sendable, Hashable, Identifiable {
    public var id: String { "\(pid)-\(evidence.rawValue)" }
    public var pid: Int32
    public var parentPID: Int32
    public var name: String
    public var executablePath: String?
    public var bundleIdentifier: String?
    /// Code-signing identifier, e.g. com.apple.Safari.
    public var signingIdentifier: String?
    /// Developer team, when the binary carries one. Apple platform binaries
    /// do not.
    public var teamIdentifier: String?
    public var isAppleSigned: Bool
    public var userID: UInt32
    public var userName: String?
    public var startedAt: Date?
    public var arguments: String?
    public var evidence: AttributionEvidence

    public init(pid: Int32, parentPID: Int32 = 0, name: String,
                executablePath: String? = nil, bundleIdentifier: String? = nil,
                signingIdentifier: String? = nil, teamIdentifier: String? = nil,
                isAppleSigned: Bool = false, userID: UInt32 = 0, userName: String? = nil,
                startedAt: Date? = nil, arguments: String? = nil,
                evidence: AttributionEvidence) {
        self.pid = pid
        self.parentPID = parentPID
        self.name = name
        self.executablePath = executablePath
        self.bundleIdentifier = bundleIdentifier
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.isAppleSigned = isAppleSigned
        self.userID = userID
        self.userName = userName
        self.startedAt = startedAt
        self.arguments = arguments
        self.evidence = evidence
    }

    /// Short description of who this is, for one-line display.
    public var summary: String {
        var parts = [name]
        if let team = teamIdentifier { parts.append("team \(team)") }
        else if isAppleSigned { parts.append("Apple") }
        if let userName { parts.append("as \(userName)") }
        return parts.joined(separator: " · ")
    }

    public var isSystemProcess: Bool { userID == 0 }
}

/// The result of trying to attribute one event to a process.
public struct AttributionResult: Codable, Sendable, Hashable {
    public var actors: [ProcessActor]
    /// True when the scan ran but every candidate process was invisible to us —
    /// almost always because a root-owned daemon did the work.
    public var blockedByPrivileges: Bool
    public var scannedProcesses: Int
    public var attemptedAt: Date

    public init(actors: [ProcessActor] = [], blockedByPrivileges: Bool = false,
                scannedProcesses: Int = 0, attemptedAt: Date = Date()) {
        self.actors = actors
        self.blockedByPrivileges = blockedByPrivileges
        self.scannedProcesses = scannedProcesses
        self.attemptedAt = attemptedAt
    }

    public var best: ProcessActor? {
        actors.max { $0.evidence.weight < $1.evidence.weight }
    }

    public var isEmpty: Bool { actors.isEmpty }
}
