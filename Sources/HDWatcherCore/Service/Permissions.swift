import Foundation
import AppKit

/// Full Disk Access is what separates "watches your home folder" from "watches
/// the disk". macOS offers no API to query it, so this probes paths that are
/// only readable once the permission is granted.
public enum Permissions {

    public enum FullDiskAccess: String, Sendable {
        case granted = "Granted"
        case denied = "Not granted"
        case unknown = "Unknown"
    }

    /// Reads a TCC-protected location. Success means Full Disk Access is on.
    public static func fullDiskAccessStatus() -> FullDiskAccess {
        let probes = [
            NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db",
            "/Library/Application Support/com.apple.TCC/TCC.db",
            NSHomeDirectory() + "/Library/Safari/CloudTabs.db",
        ]
        var sawExisting = false
        for probe in probes {
            guard FileManager.default.fileExists(atPath: probe) else { continue }
            sawExisting = true
            if FileManager.default.isReadableFile(atPath: probe) {
                // isReadableFile can be optimistic; confirm with a real open.
                if let handle = FileHandle(forReadingAtPath: probe) {
                    try? handle.close()
                    return .granted
                }
            }
        }
        return sawExisting ? .denied : .unknown
    }

    public static func openFullDiskAccessSettings() {
        let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!
        NSWorkspace.shared.open(url)
    }

    public static func openNotificationSettings() {
        let url = URL(string: "x-apple.systempreferences:com.apple.preference.notifications")!
        NSWorkspace.shared.open(url)
    }

    public struct ProbeResult: Sendable, Identifiable {
        public var id: String { path }
        public var path: String
        public var readable: Bool
        public var exists: Bool
        /// Why this location is worth checking.
        public var note: String
    }

    /// Spot-checks locations macOS protects behind TCC.
    ///
    /// This answers "can we see into the places macOS hides?", which is a
    /// different question from "what are we watching?". Full Disk Access is
    /// all-or-nothing, so a handful of representative protected paths is enough
    /// to tell whether it is really in effect — several of these are readable
    /// *without* it and act as controls.
    public static func readableProbe() -> [ProbeResult] {
        let home = NSHomeDirectory()
        let paths: [(String, String)] = [
            (home + "/Library/Mail", "TCC-protected: only readable with Full Disk Access"),
            (home + "/Library/Messages", "TCC-protected: only readable with Full Disk Access"),
            (home + "/Library/Safari", "TCC-protected: only readable with Full Disk Access"),
            (home + "/Library/Application Support/com.apple.TCC",
             "TCC's own database — the strongest signal that access is granted"),
            (home + "/Library/Containers", "Other apps' sandboxed data"),
            (home + "/Desktop", "Readable without Full Disk Access — a control"),
            ("/Users", "Other user accounts on this Mac"),
            ("/Library/Application Support", "System-wide application data"),
        ]
        return paths.map { path, note in
            var isDirectory: ObjCBool = false
            let exists = FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
            guard exists else { return ProbeResult(path: path, readable: false, exists: false, note: note) }
            let readable = (try? FileManager.default.contentsOfDirectory(atPath: path)) != nil
            return ProbeResult(path: path, readable: readable, exists: true, note: note)
        }
    }
}
