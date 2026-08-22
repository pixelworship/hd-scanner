import Foundation
import AppKit
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

    // MARK: - The durable installation

    /// A plain system LaunchDaemon, installed once with administrator rights.
    ///
    /// `SMAppService` keeps its registration in macOS's Background Task
    /// Management database, tied to the app's code signature and to an approval
    /// the user grants in Login Items. Rebuild the app and the signature
    /// changes; install a system update and the approval can be withdrawn.
    /// Either way the daemon quietly stops starting at boot — which is the one
    /// thing it exists for, and it fails silently, which is worse.
    ///
    /// This is the older mechanism: binary in a stable root-owned location,
    /// plist in `/Library/LaunchDaemons`, bootstrapped into the system domain.
    /// It survives reboots, rebuilds and OS updates, and asks for a password
    /// exactly once.
    /// What went wrong installing the service, in the words of the thing that
    /// refused. Every failure here used to arrive dressed as a Secure Enclave
    /// error, which sent everyone looking in the wrong place.
    public struct InstallError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
        public init(_ message: String) { self.message = message }
    }

    public enum Durable {
        /// Deliberately not the SMAppService label: Background Task Management
        /// keeps its own claim on that one, and launchd refuses to bootstrap a
        /// label BTM already owns.
        public static let label = "co.pixelworship.hdwatcherd"
        public static let plistPath = "/Library/LaunchDaemons/\(label).plist"
        public static let binaryPath = "/usr/local/libexec/hdwatcherd"

        /// The installer, shipped inside the app so its path never moves.
        public static var scriptPath: String {
            Bundle.main.bundleURL
                .appendingPathComponent("Contents/Resources/install-daemon.sh").path
        }

        public static var isInstalled: Bool {
            FileManager.default.fileExists(atPath: plistPath)
                && FileManager.default.isExecutableFile(atPath: binaryPath)
        }

        /// True when the app bundle carries a different build of the daemon
        /// than the one installed — after a rebuild, the installed copy is the
        /// one still running.
        public static var isOutOfDate: Bool {
            guard isInstalled else { return false }
            let bundled = Bundle.main.bundleURL
                .appendingPathComponent("Contents/MacOS/hdwatcherd").path
            guard let a = try? Data(contentsOf: URL(fileURLWithPath: bundled)),
                  let b = try? Data(contentsOf: URL(fileURLWithPath: binaryPath))
            else { return false }
            return CryptoPrimitives.sha256(a) != CryptoPrimitives.sha256(b)
        }

        public static var command: String { "sudo \"\(scriptPath)\"" }

        /// Runs the installer, prompting once for an administrator password
        /// through the system dialog rather than sending the user to Terminal.
        ///
        /// `osascript` is launched as a subprocess rather than run in-process:
        /// its output — including whatever launchd said when it refused — is
        /// then readable, which is the difference between a fix and another
        /// round of guessing.
        public static func install(uninstall: Bool = false) throws {
            let script = scriptPath
            guard FileManager.default.isExecutableFile(atPath: script) else {
                throw InstallError("The installer is missing from the app bundle. Rebuild with ./build-app.sh --install.")
            }

            // Only one recorder. The SMAppService registration is the app's to
            // withdraw, and leaving it in place would mean two daemons writing
            // the same log.
            if #available(macOS 13.0, *), service.status != .notRegistered {
                try? service.unregister()
            }

            let quoted = script.replacingOccurrences(of: "\"", with: "\\\"")
            let arguments = uninstall ? " --uninstall" : ""
            let source = "do shell script \"'\(quoted)'\(arguments)\" with administrator privileges"

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", source]
            let output = Pipe()
            let errors = Pipe()
            process.standardOutput = output
            process.standardError = errors

            do { try process.run() } catch {
                throw InstallError("Could not start the installer: \(error.localizedDescription)")
            }
            let combined = (String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")
                + (String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")
            process.waitUntilExit()

            guard process.terminationStatus == 0 else {
                if combined.contains("User canceled") || combined.contains("-128") {
                    throw InstallError("Cancelled.")
                }
                let detail = combined.trimmingCharacters(in: .whitespacesAndNewlines)
                throw InstallError(detail.isEmpty
                                   ? "The installer exited with status \(process.terminationStatus)."
                                   : detail)
            }

            guard uninstall || isInstalled else {
                throw InstallError("The installer reported success but the service is not there:\n\(combined)")
            }
        }
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
        // A daemon installed the durable way is not registered with
        // SMAppService at all, and asking it would report "not installed" about
        // a daemon that is running right now.
        if Durable.isInstalled { return .enabled }
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

    /// Re-registers a service macOS has forgotten.
    ///
    /// After a system update `SMAppService` can report `enabled` for a daemon
    /// launchd has no record of — `launchctl kickstart` answers "Could not find
    /// service ... in domain for system". Unregistering first clears the stale
    /// bookkeeping so the fresh registration takes.
    public static func repair() throws {
        // Never re-register through SMAppService while the durable daemon is in
        // place: unregistering discards the approval and starts the whole
        // approval dance again.
        if Durable.isInstalled { return }
        guard #available(macOS 13.0, *) else {
            throw CryptoError.secureEnclaveFailed("background daemons need macOS 13 or later")
        }
        guard isInTrustedLocation else {
            throw CryptoError.secureEnclaveFailed(
                "Move HDWatcher to /Applications first — macOS will not run a root daemon from \(bundleLocation)."
            )
        }
        // Expected to fail when launchd has already dropped it; that is the
        // situation being repaired, not an error.
        try? service.unregister()
        do {
            try service.register()
        } catch {
            throw InstallError(explain(error))
        }
    }

    /// Turns the terse errors this API produces into something actionable.
    private static func explain(_ error: Error) -> String {
        let text = error.localizedDescription
        if text.contains("Operation not permitted") || (error as NSError).code == 1 {
            return "macOS refused to register the daemon. It is most likely disabled at the launchd level; an administrator can clear that with: sudo launchctl enable system/\(AgentPaths.serviceLabel)"
        }
        return text
    }

    public static func uninstall() throws {
        guard #available(macOS 13.0, *) else { return }
        try service.unregister()
        AgentStatus.clear()
    }

    /// Opens the Full Disk Access pane. The daemon runs from its own path once
    /// installed permanently, so it needs a grant of its own — the app's does
    /// not cover it.
    public static func openFullDiskAccessSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
        else { return }
        NSWorkspace.shared.open(url)
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

        // The copy in the user's own directory is the one that always works:
        // this app runs unprivileged and cannot write into /Library, and a
        // root daemon can read any file. The privileged copy is still written
        // when it can be — it outranks the user's own when it is newer — but
        // publishing must not depend on it.
        var published = configuration.write(to: AgentPaths.configuration)
        if AppPaths.systemSupportDirectory.path != AppPaths.supportDirectory.path,
           configuration.write(to: AgentPaths.systemConfiguration) {
            published = true
        }
        return published
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
