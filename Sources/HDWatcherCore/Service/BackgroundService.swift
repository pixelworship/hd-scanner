import Foundation
import ServiceManagement

/// Registers and inspects the privileged recording daemon.
///
/// The daemon ships inside the app bundle and is registered with `SMAppService`
/// as a system LaunchDaemon, which macOS gates behind administrator approval.
/// Running with privileges buys three things a per-user agent cannot have:
///
/// - it starts at **boot**, before anyone logs in;
/// - its log lives in `/Library`, owned by root, so the logged-in user cannot
///   delete or rewrite their own audit trail;
/// - it can inspect **every** process, including root-owned daemons, which is
///   what makes attribution work for things like `securityd`.
public enum BackgroundService {

    public enum State: String, Sendable {
        case notRegistered
        case enabled
        case requiresApproval
        case notFound
        case unsupported

        public var displayName: String {
            switch self {
            case .notRegistered:    return "Not installed"
            case .enabled:          return "Installed"
            case .requiresApproval: return "Waiting for approval"
            case .notFound:         return "Not found"
            case .unsupported:      return "Unsupported on this macOS"
            }
        }

        public var needsAttention: Bool { self == .requiresApproval || self == .notFound }
    }

    public static var isSupported: Bool {
        if #available(macOS 13.0, *) { return true }
        return false
    }

    @available(macOS 13.0, *)
    private static var service: SMAppService {
        SMAppService.daemon(plistName: AgentPaths.plistName)
    }

    /// macOS refuses to run a root daemon out of a user-writable location, and
    /// rightly so — anyone able to edit the bundle would be editing root code.
    public static var isInTrustedLocation: Bool {
        Bundle.main.bundleURL.path.hasPrefix("/Applications/")
    }

    public static var bundleLocation: String { Bundle.main.bundleURL.path }

    public static var state: State {
        guard #available(macOS 13.0, *) else { return .unsupported }
        switch service.status {
        case .enabled:           return .enabled
        case .requiresApproval:  return .requiresApproval
        case .notRegistered:     return .notRegistered
        case .notFound:          return .notFound
        @unknown default:        return .notRegistered
        }
    }

    /// Installs and starts the daemon. macOS prompts for administrator approval.
    public static func install() throws {
        guard #available(macOS 13.0, *) else {
            throw CryptoError.secureEnclaveFailed("background daemons need macOS 13 or later")
        }
        guard isInTrustedLocation else {
            throw CryptoError.secureEnclaveFailed(
                "Move HDWatcher to /Applications first. macOS will not run a root daemon from \(bundleLocation), because anything that can edit the app could edit code running as root."
            )
        }
        try service.register()
    }

    public static func uninstall() throws {
        guard #available(macOS 13.0, *) else { return }
        try service.unregister()
        AgentStatus.clear()
    }

    /// Opens the Login Items pane, where macOS asks the user to approve the agent.
    public static func openLoginItemsSettings() {
        guard #available(macOS 13.0, *) else { return }
        SMAppService.openSystemSettingsLoginItems()
    }

    /// The daemon's status is sealed to the ingest key, so reading it needs the
    /// unlocked vault.
    public static func status(using keys: VaultKeys?) -> AgentStatus? {
        guard let ingest = keys?.ingest else { return nil }
        if let systemStatus = AgentStatus.read(from: systemStatusURL, using: ingest) {
            return systemStatus
        }
        return AgentStatus.read(using: ingest)
    }

    private static var systemStatusURL: URL {
        AppPaths.systemSupportDirectory.appendingPathComponent("agent-status.enc")
    }

    /// Publishes everything the daemon needs. Called whenever the vault unlocks
    /// or the user changes settings.
    ///
    /// `enabled` comes from the user's saved preference, never from the
    /// registration state — deriving it from registration meant a moment of
    /// "not yet approved" was published as "the user turned this off", which
    /// stopped the daemon.
    /// Returns false when the daemon has not yet published the key needed to
    /// seal configuration for it — it has to run once before that can happen.
    @discardableResult
    public static func publishConfiguration(settings: AppSettings, rules: [AlertRule]) -> Bool {
        let configuration = AgentConfiguration(from: settings, rules: rules,
                                               enabled: settings.backgroundRecordingEnabled)
        // A daemon in /Library reads from there; a recorder in the user's own
        // directory reads from the user's copy.
        let target = DaemonIdentity.exists && AppPaths.systemSupportDirectory.path
            != AppPaths.supportDirectory.path
            ? AgentPaths.systemConfiguration
            : AgentPaths.configuration
        return configuration.write(to: target)
    }

    /// Registers the daemon if the user wants it and it is not already set up.
    /// Called on every unlock so background recording resumes by itself.
    @discardableResult
    public static func ensureInstalledIfWanted(settings: AppSettings) -> String? {
        guard settings.backgroundRecordingEnabled else { return nil }
        guard isSupported, isInTrustedLocation else { return nil }
        switch state {
        case .enabled, .requiresApproval:
            return nil                     // already registered, or waiting on the user
        case .notRegistered, .notFound, .unsupported:
            do {
                try install()
                return nil
            } catch {
                return error.localizedDescription
            }
        }
    }

    /// Removes a LaunchAgent left behind by an earlier version.
    ///
    /// Before the move to a privileged daemon the recorder was registered as a
    /// per-user agent under a different label. Left in place it keeps running,
    /// duplicating work and reporting a conflicting status.
    public static func removeLegacyAgent() {
        guard #available(macOS 13.0, *) else { return }
        let legacy = SMAppService.agent(plistName: "co.pixelworship.hdwatcher.agent.plist")
        if legacy.status != .notFound {
            try? legacy.unregister()
        }
        // Its plist no longer ships in the bundle, so SMAppService may not be
        // able to reach it; ask launchd directly as well.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["bootout", "gui/\(getuid())/co.pixelworship.hdwatcher.agent"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
    }
}
