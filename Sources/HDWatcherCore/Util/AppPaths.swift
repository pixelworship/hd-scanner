import Foundation

public enum AppPaths {
    public static let bundleIdentifier = "co.pixelworship.hdwatcher"

    /// Reads an environment variable directly.
    ///
    /// `ProcessInfo.processInfo.environment` snapshots the environment the first
    /// time it is touched, so a `setenv` after that point is invisible. That
    /// silently defeated the storage override and let a test read the live
    /// daemon's log. `getenv` always reflects the current value.
    private static func environmentValue(_ key: String) -> String? {
        guard let raw = getenv(key) else { return nil }
        let value = String(cString: raw)
        return value.isEmpty ? nil : value
    }

    /// Overrides the storage location. Set only by tests and the smoke harness;
    /// `FileManager` resolves the user domain from the account rather than from
    /// `HOME`, so there is otherwise no way to run against a scratch directory.
    public static let overrideEnvironmentKey = "HDWATCHER_SUPPORT_DIR"

    /// True when this process is the root daemon rather than the user's app.
    public static var isRunningAsRoot: Bool { geteuid() == 0 }

    /// /Library/Application Support/co.pixelworship.hdwatcher
    ///
    /// Where the privileged daemon keeps the audit trail. Root-owned, so the
    /// logged-in user cannot delete or rewrite their own history — the point of
    /// running the recorder with privileges in the first place.
    public static let systemOverrideEnvironmentKey = "HDWATCHER_SYSTEM_DIR"

    public static var systemSupportDirectory: URL {
        if let override = environmentValue(systemOverrideEnvironmentKey) {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return URL(fileURLWithPath: "/Library/Application Support", isDirectory: true)
            .appendingPathComponent(bundleIdentifier, isDirectory: true)
    }

    public static var systemLogDirectory: URL {
        systemSupportDirectory.appendingPathComponent("log", isDirectory: true)
    }

    /// A specific user's support directory, for the daemon to read the ingest
    /// key and configuration the app published.
    public static func userSupportDirectory(home: String) -> URL {
        URL(fileURLWithPath: home, isDirectory: true)
            .appendingPathComponent("Library/Application Support", isDirectory: true)
            .appendingPathComponent(bundleIdentifier, isDirectory: true)
    }

    /// Where this process reads and writes. The daemon works out of /Library;
    /// the app works out of the user's home.
    public static var supportDirectory: URL {
        if let override = environmentValue(overrideEnvironmentKey) {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        if isRunningAsRoot { return systemSupportDirectory }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent(bundleIdentifier, isDirectory: true)
    }

    public static var vaultFile: URL { supportDirectory.appendingPathComponent("vault.json") }
    public static var logDirectory: URL { supportDirectory.appendingPathComponent("log", isDirectory: true) }
    public static var settingsFile: URL { supportDirectory.appendingPathComponent("settings.enc") }
    public static var rulesFile: URL { supportDirectory.appendingPathComponent("rules.enc") }
    public static var statsFile: URL { supportDirectory.appendingPathComponent("stats.enc") }
    public static var alertsFile: URL { supportDirectory.appendingPathComponent("alerts.enc") }
    public static var volumesFile: URL { supportDirectory.appendingPathComponent("volumes.enc") }
    /// Single encrypted container holding captured file contents plus their
    /// accounting.
    public static var contentVaultFile: URL { supportDirectory.appendingPathComponent("contents.hdw") }
    /// Contents captured by the privileged daemon, sealed to the ingest key.
    public static var agentContentVaultFile: URL {
        supportDirectory.appendingPathComponent("contents-agent.hdw")
    }
    /// Where the app looks for the daemon's captures.
    public static var systemAgentContentVaultFile: URL {
        systemSupportDirectory.appendingPathComponent("contents-agent.hdw")
    }
    public static var exportDirectory: URL { supportDirectory.appendingPathComponent("exports", isDirectory: true) }

    @discardableResult
    public static func ensureDirectories() -> Bool {
        let fm = FileManager.default
        // The daemon's directories are readable by everyone but writable only by
        // root: the contents are sealed to a key nobody else holds, so exposure
        // costs nothing, while root ownership is what makes the trail
        // tamper-resistant. The app's own directories stay private.
        let mode = isRunningAsRoot ? 0o755 : 0o700
        for dir in [supportDirectory, logDirectory, exportDirectory] {
            do {
                try fm.createDirectory(at: dir, withIntermediateDirectories: true,
                                       attributes: [.posixPermissions: mode])
            } catch {
                return false
            }
        }
        for dir in [supportDirectory, logDirectory, exportDirectory] {
            try? fm.setAttributes([.posixPermissions: mode], ofItemAtPath: dir.path)
        }
        return true
    }

    /// True when storage has been redirected, which only tests and the smoke
    /// harness do. Used to keep them from reaching into real system state.
    public static var isUsingOverride: Bool {
        environmentValue(overrideEnvironmentKey) != nil
            || environmentValue(systemOverrideEnvironmentKey) != nil
    }

    /// File permissions for anything this process writes.
    public static var filePermissions: Int { isRunningAsRoot ? 0o644 : 0o600 }

    /// Paths the watcher must never report on, or it would observe its own
    /// writes and feed itself in a loop.
    public static var selfPaths: [String] { [supportDirectory.path] }

    /// The fully resolved path, matching what FSEvents reports.
    ///
    /// `URL.resolvingSymlinksInPath()` is the wrong tool here: it deliberately
    /// *strips* a leading `/private`, turning `/private/var/x` into `/var/x` —
    /// the reverse of what FSEvents does. `realpath(3)` resolves every symlink
    /// the way the kernel does, so `/tmp/x` becomes `/private/tmp/x` and paths
    /// line up with reported events.
    public static func canonicalPath(_ path: String) -> String {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard realpath(path, &buffer) != nil else { return path }
        return String(cString: buffer)
    }
}
