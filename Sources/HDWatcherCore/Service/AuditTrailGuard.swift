import Foundation

/// Watches the audit trail's own storage for interference.
///
/// File permissions already stop an ordinary user from touching the trail: the
/// directory and every segment are owned by root, so nothing short of `sudo`
/// can modify, delete or forge one. That leaves root itself, and nothing
/// running on the machine can be protected from root.
///
/// What *can* be done is make interference impossible to hide. This re-asserts
/// the expected ownership and permissions, and reports — into the trail itself —
/// when the storage is loosened, or when a segment it wrote disappears or
/// shrinks. Combined with the per-block hash chain, that covers the three ways
/// history can be attacked: rewriting it, deleting it, and quietly opening the
/// door for later.
public final class AuditTrailGuard: @unchecked Sendable {

    public struct Expectation: Sendable {
        public var directoryMode: Int
        public var fileMode: Int
        public var ownerUID: uid_t
        public init(directoryMode: Int = 0o755, fileMode: Int = 0o644, ownerUID: uid_t = 0) {
            self.directoryMode = directoryMode
            self.fileMode = fileMode
            self.ownerUID = ownerUID
        }
    }

    private let mutex = NSLock()
    private let logDirectory: URL
    private let supportDirectory: URL
    private let expectation: Expectation
    /// Segment sizes as last seen. A segment being written grows; one that
    /// shrinks has been rewritten.
    private var knownSizes: [String: Int64] = [:]
    private var reportedMissing = Set<String>()

    public init(logDirectory: URL = AppPaths.logDirectory,
                supportDirectory: URL = AppPaths.supportDirectory,
                expectation: Expectation = Expectation()) {
        self.logDirectory = logDirectory
        self.supportDirectory = supportDirectory
        self.expectation = expectation
    }

    /// Runs one pass. Returns events to record; an empty array means all well.
    public func inspect() -> [FileEvent] {
        var findings: [FileEvent] = []
        findings.append(contentsOf: checkPermissions())
        findings.append(contentsOf: checkSegments())
        return findings
    }

    // MARK: - Permissions

    private func checkPermissions() -> [FileEvent] {
        // Only meaningful for the privileged daemon: when the app runs the
        // recorder itself the trail lives in the user's own home and these
        // guarantees do not apply.
        guard AppPaths.isRunningAsRoot else { return [] }

        var findings: [FileEvent] = []
        let fileManager = FileManager.default

        for directory in [supportDirectory, logDirectory] {
            guard let attributes = try? fileManager.attributesOfItem(atPath: directory.path) else { continue }
            let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value ?? 0
            let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0

            if owner != expectation.ownerUID {
                findings.append(finding(
                    path: directory.path,
                    detail: "Directory owner changed to uid \(owner); expected root. Someone with elevated privileges altered the audit storage.",
                    severity: .critical))
                try? fileManager.setAttributes([.ownerAccountID: expectation.ownerUID],
                                               ofItemAtPath: directory.path)
            }
            // Group- or world-writable means anyone could delete history.
            if mode & 0o022 != 0 {
                findings.append(finding(
                    path: directory.path,
                    detail: String(format: "Directory permissions widened to %o; expected %o. Restored.",
                                   mode, expectation.directoryMode),
                    severity: .critical))
                try? fileManager.setAttributes([.posixPermissions: expectation.directoryMode],
                                               ofItemAtPath: directory.path)
            }
        }

        let segments = (try? fileManager.contentsOfDirectory(atPath: logDirectory.path))?
            .filter { $0.hasSuffix(".hdwseg") } ?? []
        for name in segments {
            let path = logDirectory.appendingPathComponent(name).path
            guard let attributes = try? fileManager.attributesOfItem(atPath: path) else { continue }
            let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
            if mode & 0o022 != 0 {
                findings.append(finding(
                    path: path,
                    detail: String(format: "Segment became writable (%o). Restored to %o.",
                                   mode, expectation.fileMode),
                    severity: .critical))
                try? fileManager.setAttributes([.posixPermissions: expectation.fileMode],
                                               ofItemAtPath: path)
            }
        }
        return findings
    }

    // MARK: - Segments

    private func checkSegments() -> [FileEvent] {
        var findings: [FileEvent] = []
        let fileManager = FileManager.default
        let present = Set((try? fileManager.contentsOfDirectory(atPath: logDirectory.path))?
            .filter { $0.hasSuffix(".hdwseg") } ?? [])

        mutex.lock()
        let known = knownSizes
        mutex.unlock()

        // Anything we saw before and cannot see now was removed out from under us.
        for (name, _) in known where !present.contains(name) {
            mutex.lock()
            let alreadyReported = reportedMissing.contains(name)
            if !alreadyReported { reportedMissing.insert(name) }
            mutex.unlock()
            guard !alreadyReported else { continue }
            findings.append(finding(
                path: logDirectory.appendingPathComponent(name).path,
                detail: "A recorded segment was deleted from the audit trail. Only root can do this; the events it held are gone.",
                severity: .critical))
        }

        var updated = known
        for name in present {
            let path = logDirectory.appendingPathComponent(name).path
            let size = ((try? fileManager.attributesOfItem(atPath: path)[.size]) as? NSNumber)?
                .int64Value ?? 0
            if let previous = known[name], size < previous {
                findings.append(finding(
                    path: path,
                    detail: "A segment shrank from \(previous) to \(size) bytes. Append-only storage never loses bytes; this was truncated.",
                    severity: .critical))
            }
            updated[name] = size
        }

        mutex.lock()
        knownSizes = updated
        mutex.unlock()
        return findings
    }

    private func finding(path: String, detail: String, severity: Severity) -> FileEvent {
        FileEvent(kind: .tamperDetected, path: path, isDirectory: false,
                  severity: severity, ruleHits: [detail])
    }
}
