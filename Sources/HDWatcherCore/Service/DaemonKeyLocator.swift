import Foundation
import CryptoKit
import SystemConfiguration

/// How the privileged daemon finds the ingest key and configuration.
///
/// The daemon runs as root with no user session, so it cannot be handed a key
/// interactively. It reads the public key the app published into the user's home
/// — root can read any file — and then **pins** a root-owned copy of it.
///
/// The pin is the important part. Without it, anyone able to write to the user's
/// home could substitute their own public key and have every subsequent event
/// sealed to them instead. Once pinned, the daemon uses only its own copy, and
/// changing it takes root.
public enum DaemonKeyLocator {

    public struct Resolution: Sendable {
        public let key: P256.KeyAgreement.PublicKey
        public let ownerHome: String?
        public let wasPinnedNow: Bool
        /// Set when the user's copy no longer matches what was pinned.
        public let substitutionDetected: Bool
    }

    /// The console user's home, then any other user home, in that order.
    public static func candidateHomes() -> [String] {
        var homes: [String] = []
        var uid: uid_t = 0
        if let name = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String?,
           name != "loginwindow", !name.isEmpty {
            if let entry = getpwnam(name), let dir = entry.pointee.pw_dir {
                homes.append(String(cString: dir))
            }
        }
        let others = ((try? FileManager.default.contentsOfDirectory(atPath: "/Users")) ?? [])
            .filter { !$0.hasPrefix(".") && $0 != "Shared" }
            .map { "/Users/" + $0 }
        for home in others where !homes.contains(home) { homes.append(home) }
        return homes
    }

    /// Finds a usable ingest key, pinning it on first use.
    /// `homes` is injectable so tests can run against a fixture rather than the
    /// machine's real accounts.
    public static func resolve(homes: [String]? = nil) -> Resolution? {
        let fileManager = FileManager.default

        // A pinned key always wins.
        var pinned: P256.KeyAgreement.PublicKey?
        if let data = try? Data(contentsOf: AgentPaths.pinnedIngestKey),
           let key = try? P256.KeyAgreement.PublicKey(rawRepresentation: data) {
            pinned = key
        }

        // Locate the app's published key, for pinning or for comparison.
        var published: (key: P256.KeyAgreement.PublicKey, home: String)?
        for home in homes ?? candidateHomes() {
            let candidate = AppPaths.userSupportDirectory(home: home)
                .appendingPathComponent("ingest.pub")
            guard let data = try? Data(contentsOf: candidate),
                  let key = try? P256.KeyAgreement.PublicKey(rawRepresentation: data) else { continue }
            published = (key, home)
            break
        }

        if let pinned {
            let mismatch = published.map {
                $0.key.rawRepresentation != pinned.rawRepresentation
            } ?? false
            return Resolution(key: pinned, ownerHome: published?.home,
                              wasPinnedNow: false, substitutionDetected: mismatch)
        }

        guard let published else { return nil }

        AppPaths.ensureDirectories()
        try? published.key.rawRepresentation.write(to: AgentPaths.pinnedIngestKey, options: [.atomic])
        try? fileManager.setAttributes([.posixPermissions: 0o644],
                                       ofItemAtPath: AgentPaths.pinnedIngestKey.path)
        return Resolution(key: published.key, ownerHome: published.home,
                          wasPinnedNow: true, substitutionDetected: false)
    }

    /// Configuration published by the app for the given user, sealed to this
    /// daemon's key.
    public static func configuration(ownerHome: String?) -> AgentConfiguration? {
        guard let ownerHome else { return AgentConfiguration.read() }
        let url = AppPaths.userSupportDirectory(home: ownerHome)
            .appendingPathComponent("agent-config.enc")
        return AgentConfiguration.read(from: url)
    }
}
