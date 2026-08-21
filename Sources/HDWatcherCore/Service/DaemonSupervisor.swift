import Foundation

/// Decides whether the daemon is genuinely recording, and what to do when it
/// is not.
///
/// `SMAppService` reports its own bookkeeping, not reality. It says `enabled`
/// for a service that launchd has since dropped — which is what a macOS update
/// does — and the app took that at face value and reported "Installed, starting
/// up" indefinitely while nothing was recording at all. `launchctl kickstart`
/// then fails with "Could not find service ... in domain for system", because
/// there is no such service to kick.
///
/// The only trustworthy evidence that a daemon is recording is a recent
/// heartbeat, written by the daemon itself. Registration state says what is
/// *supposed* to be true; the heartbeat says what is.
public struct DaemonSupervisor: Sendable {

    /// How long a freshly registered daemon is given to write its first
    /// heartbeat before that silence is treated as a failure. It has to boot,
    /// find its key, and open the log.
    public static let startupGrace: TimeInterval = 45
    /// A running daemon writes a heartbeat well inside this.
    public static let heartbeatDeadline: TimeInterval = 60
    /// Re-registering is worth trying, but not on a loop.
    public static let maximumRepairAttempts = 2

    public enum Health: Equatable, Sendable {
        case recording
        case startingUp
        /// Registered as far as macOS is concerned, but nothing is running.
        case droppedByLaunchd
        case needsApproval
        case notInstalled
        case disabledByUser
        case unsupported

        public var isHealthy: Bool { self == .recording }
    }

    public enum Repair: Equatable, Sendable {
        case none
        case wait
        /// Unregister and register again: the fix for a service launchd has
        /// forgotten.
        case reregister
        case openLoginItems
        /// Tried and failed enough times to stop and tell the user.
        case askForHelp
    }

    public struct Verdict: Equatable, Sendable {
        public let health: Health
        public let repair: Repair
        public let summary: String
        public let detail: String

        public init(health: Health, repair: Repair, summary: String, detail: String) {
            self.health = health
            self.repair = repair
            self.summary = summary
            self.detail = detail
        }
    }

    public struct Input: Sendable {
        public let state: BackgroundService.State
        public let wanted: Bool
        public let heartbeat: Date?
        public let processAlive: Bool
        public let registeredAt: Date?
        public let repairAttempts: Int
        public let now: Date

        public init(state: BackgroundService.State, wanted: Bool, heartbeat: Date?,
                    processAlive: Bool, registeredAt: Date?, repairAttempts: Int = 0,
                    now: Date = Date()) {
            self.state = state
            self.wanted = wanted
            self.heartbeat = heartbeat
            self.processAlive = processAlive
            self.registeredAt = registeredAt
            self.repairAttempts = repairAttempts
            self.now = now
        }
    }

    public static func assess(_ input: Input) -> Verdict {
        switch input.state {
        case .unsupported:
            return Verdict(health: .unsupported, repair: .none,
                           summary: "Not available on this macOS",
                           detail: "Background recording needs macOS 13 or later. Activity is recorded while this app is open.")

        case .requiresApproval:
            return Verdict(health: .needsApproval, repair: .openLoginItems,
                           summary: "Waiting for your approval",
                           detail: "macOS needs you to allow HDWatcher in Login Items before the daemon can run. A system update can withdraw an approval that was already given.")

        case .notRegistered, .notFound:
            guard input.wanted else {
                return Verdict(health: .disabledByUser, repair: .none,
                               summary: "Background recording is off",
                               detail: "Activity is recorded only while this app is open.")
            }
            return Verdict(health: .notInstalled, repair: .reregister,
                           summary: "Not installed",
                           detail: "The daemon is not registered with macOS. Installing it needs an administrator.")

        case .enabled:
            // A heartbeat is the only proof. Everything else is bookkeeping.
            if let heartbeat = input.heartbeat,
               input.now.timeIntervalSince(heartbeat) < heartbeatDeadline {
                return Verdict(health: .recording, repair: .none,
                               summary: "Recording in the background",
                               detail: "Activity is being recorded whether or not this window is open, and from boot onward.")
            }

            if input.processAlive {
                return Verdict(health: .startingUp, repair: .wait,
                               summary: "Starting up",
                               detail: "The daemon is running and has not written its first heartbeat yet.")
            }

            let waited = input.registeredAt.map { input.now.timeIntervalSince($0) } ?? .greatestFiniteMagnitude
            if waited < startupGrace {
                return Verdict(health: .startingUp, repair: .wait,
                               summary: "Starting up",
                               detail: "The daemon has just been registered and should begin recording within a few seconds.")
            }

            if input.repairAttempts >= maximumRepairAttempts {
                return Verdict(health: .droppedByLaunchd, repair: .askForHelp,
                               summary: "Registered, but macOS will not start it",
                               detail: "macOS lists the daemon as installed but launchd has no such service, and re-registering did not fix it. Approving HDWatcher again in Login Items usually does; otherwise remove and reinstall the daemon here.")
            }

            return Verdict(health: .droppedByLaunchd, repair: .reregister,
                           summary: "Registered, but not running",
                           detail: "macOS lists the daemon as installed while launchd has no such service — which is what a system update leaves behind. Re-registering it now.")
        }
    }

    /// Whether the app should attempt a repair itself rather than wait for the
    /// user to press something.
    public static func shouldRepairAutomatically(_ verdict: Verdict) -> Bool {
        verdict.repair == .reregister
    }
}
