import Foundation

public enum ContentCapturePolicy {
    /// Content capture is far more expensive than event logging, so the default
    /// scope is narrower: binaries, media containers and package internals are
    /// skipped because they are large, rarely worth reviewing, and would fill
    /// the container quickly.
    /// Deliberately short.
    ///
    /// Anything in any directory is eligible; the size cap is what keeps the
    /// container in hand, not a list of file types. Excluding formats by
    /// extension meant a photo or a recording the user actually wanted was
    /// silently skipped while a 3 KB preferences file was kept. What remains
    /// here is only what is genuinely useless to recover: package internals,
    /// system-owned files, and application state that rewrites itself
    /// constantly.
    public static let defaultExclusions: [GlobPattern] = [
        // Package internals — thousands of files, none individually meaningful.
        "**/*.app/**", "**/*.framework/**", "**/*.bundle/**", "**/*.xcodeproj/**",
        "**/*.fcpbundle/**", "**/*.photoslibrary/**", "**/*.sparsebundle/**",
        // Not files in any useful sense.
        "**/*.sock", "**/*.pid", "**/*.lock",
        // System-owned, replaceable from the installer.
        "/Applications/**", "/System/**", "/usr/**", "/bin/**", "/sbin/**",
        // Application-internal state. These rewrite themselves constantly — a
        // sync client's metrics file can produce dozens of versions an hour —
        // and a copy of one is of no use to anybody. The *events* are still
        // recorded; only the contents are skipped.
        "**/Library/Group Containers/**", "**/Library/Containers/**",
        "**/Library/HTTPStorages/**", "**/Library/Biome/**",
        "**/Library/Metadata/**", "**/Library/Suggestions/**",
        "**/Library/Cookies/**", "**/Library/CoreFollowUp/**",
        "**/Library/Application Support/CloudDocs/**",
        "**/.git/**", "**/.svn/**",
    ].map { GlobPattern($0) }

    /// Whether a path is eligible for content capture.
    public static func allows(path: String,
                              include: [GlobPattern],
                              exclude: [GlobPattern]) -> Bool {
        if !include.isEmpty { return include.matchesAny(path) }
        return !exclude.matchesAny(path)
    }
}
