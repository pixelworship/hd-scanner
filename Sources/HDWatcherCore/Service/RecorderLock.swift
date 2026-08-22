import Foundation

/// Guarantees that only one process is recording into the audit log.
///
/// Two recorders writing the same log is not a tidiness problem. Each keeps its
/// own hash chain and its own idea of where the manifest is up to, so they
/// interleave into a log that cannot be verified afterwards — which is exactly
/// the state this vault was found in, reported as tampering.
///
/// It can happen easily: the app registers a daemon through SMAppService, the
/// user installs the permanent one, and for a while launchd is happily running
/// both. Rather than rely on every install path getting the sequence right, the
/// recorders themselves settle it with an advisory lock on a file. The loser
/// does not exit — it waits, and takes over if the holder goes away.
public final class RecorderLock: @unchecked Sendable {

    private let url: URL
    private var descriptor: Int32 = -1
    private let mutex = NSLock()

    public init(url: URL = AppPaths.supportDirectory.appendingPathComponent("recorder.lock")) {
        self.url = url
    }

    deinit { release() }

    public var isHeld: Bool {
        mutex.lock(); defer { mutex.unlock() }
        return descriptor >= 0
    }

    /// Takes the lock if nothing else holds it. Never blocks.
    @discardableResult
    public func acquire() -> Bool {
        mutex.lock(); defer { mutex.unlock() }
        if descriptor >= 0 { return true }

        AppPaths.ensureDirectories()
        // `open` is variadic and unavailable to Swift; the file is created
        // first so the two-argument form is enough.
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil,
                                           attributes: [.posixPermissions: AppPaths.filePermissions])
        }
        let fd = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return Darwin.open(path, O_RDWR)
        }
        guard fd >= 0 else { return false }

        // Exclusive and non-blocking: if another recorder holds it, say so now
        // rather than waiting behind it.
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            return false
        }

        // Leave the pid behind so a human looking at the file can tell who has
        // it. The lock itself is the flock, not the contents.
        ftruncate(fd, 0)
        let note = "\(ProcessInfo.processInfo.processIdentifier)\n"
        _ = note.withCString { write(fd, $0, strlen($0)) }
        fchmod(fd, mode_t(AppPaths.filePermissions))

        descriptor = fd
        return true
    }

    public func release() {
        mutex.lock(); defer { mutex.unlock() }
        guard descriptor >= 0 else { return }
        flock(descriptor, LOCK_UN)
        close(descriptor)
        descriptor = -1
    }

    /// The pid recorded by whoever holds it, when there is one.
    public var holder: Int32? {
        guard let text = try? String(contentsOf: url, encoding: .utf8),
              let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)),
              pid > 0 else { return nil }
        return pid
    }
}
