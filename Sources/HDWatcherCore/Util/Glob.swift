import Foundation

/// Shell-style path matching backed by POSIX `fnmatch`.
///
/// Patterns without a `/` match against the file's last path component, which
/// makes `*.pem` behave the way people expect. Patterns containing a `/` match
/// against the full path. A trailing `/**` matches a directory and everything
/// beneath it.
public struct GlobPattern: Codable, Sendable, Hashable {
    public var pattern: String
    public var caseSensitive: Bool

    public init(_ pattern: String, caseSensitive: Bool = false) {
        self.pattern = pattern
        self.caseSensitive = caseSensitive
    }

    /// `~/Documents/**` is expanded against the current user's home directory,
    /// so rules stay portable between accounts.
    private var expanded: String {
        pattern.hasPrefix("~/")
            ? NSHomeDirectory() + pattern.dropFirst(1)
            : pattern
    }

    public func matches(_ path: String) -> Bool {
        guard !pattern.isEmpty else { return false }
        let pattern = expanded
        var flags: Int32 = 0
        if !caseSensitive { flags |= FNM_CASEFOLD }

        // "/dir/**" -> match the directory itself and any descendant.
        if pattern.hasSuffix("/**") {
            let base = String(pattern.dropLast(3))
            if fnmatch(base, path, flags) == 0 { return true }
            return fnmatch(base + "/*", path, flags) == 0
                || path.hasPrefix(base.hasSuffix("/") ? base : base + "/")
        }

        let target = pattern.contains("/") ? path : (path as NSString).lastPathComponent
        // FNM_PATHNAME is deliberately omitted so `*` spans separators, which
        // matches how users write these patterns in practice.
        return fnmatch(pattern, target, flags) == 0
    }
}

public extension Array where Element == GlobPattern {
    func matchesAny(_ path: String) -> Bool { contains { $0.matches(path) } }
}
