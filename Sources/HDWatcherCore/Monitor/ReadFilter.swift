import Foundation

/// Decides whether a path being read is worth recording.
///
/// Both read mechanisms — the audit pipe and descriptor sampling — face the
/// same firehose: every process reads its caches, its frameworks, its
/// preference files, constantly. Recording those buries the one read a person
/// actually cares about and bloats a permanent log. This is the shared judgment
/// that keeps the signal: a real file, under a watched root, that is not
/// application plumbing.
public struct ReadFilter: Sendable {
    public let roots: [String]
    public let excludePatterns: [GlobPattern]
    private let canonicalRoots: [String]

    public init(roots: [String], excludePatterns: [GlobPattern]) {
        self.roots = roots
        self.excludePatterns = excludePatterns
        self.canonicalRoots = roots.map { AppPaths.canonicalPath($0) }
    }

    private func underRoot(_ path: String) -> Bool {
        canonicalRoots.contains { path == $0 || path.hasPrefix($0 + "/") }
    }

    /// True when a read of this path is worth a record. `checkIsRegularFile`
    /// costs an lstat; the audit pipe already knows it saw a file open, but a
    /// directory can be opened too, so the check still earns its place.
    public func admits(_ path: String, checkIsRegularFile: Bool = true) -> Bool {
        guard !path.isEmpty, path.hasPrefix("/") else { return false }
        // Kernel paths are already canonical; a caller's may not be, and `/var`
        // is a symlink into `/private`.
        var candidate = path
        if !underRoot(candidate) {
            candidate = AppPaths.canonicalPath(path)
            guard underRoot(candidate) else { return false }
        }
        if excludePatterns.contains(where: { $0.matches(candidate) }) { return false }
        if checkIsRegularFile {
            var info = stat()
            guard lstat(candidate, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return false }
        }
        return true
    }
}
