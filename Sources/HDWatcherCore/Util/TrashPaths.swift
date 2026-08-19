import Foundation

/// Recognises the Trash.
///
/// This matters more than it looks. "Delete" in the Finder is a *rename* into
/// `~/.Trash`, not an unlink — the bytes are still on disk at that moment. It is
/// the last opportunity to capture a file that was never written while the
/// watcher was running, which is otherwise the common case for anything that has
/// simply been sitting in a folder.
public enum TrashPaths {

    /// True when the path is inside a trash directory.
    public static func isTrash(_ path: String) -> Bool {
        let components = (path as NSString).pathComponents
        return components.contains(".Trash") || components.contains(".Trashes")
    }

    /// The original path a file had before being moved to the Trash, when it can
    /// be worked out. Falls back to the trash path itself.
    public static func originalPath(movedFrom source: String?, to trashPath: String) -> String {
        source ?? trashPath
    }
}
