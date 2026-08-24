import Foundation

/// Turns the raw audit-pipe firehose into the reads worth recording.
///
/// The pipe reports every open()-for-read on the machine — thousands a second —
/// so this sits between it and the log doing three things: dropping everything
/// the `ReadFilter` rejects (caches, frameworks, files outside the watched
/// roots), collapsing a process that reopens the same file in a tight loop into
/// one event per window, and reporting only successful opens. What survives is
/// "this process read this file, once, at this time" — including the reads no
/// sampler could see because they were over in a millisecond.
public final class AuditReadMonitor: @unchecked Sendable {

    public struct Read: Sendable {
        public let path: String
        public let pid: Int32
        public let euid: UInt32
        public let at: Date
    }

    public struct Configuration: Sendable {
        public var roots: [String]
        public var excludePatterns: [GlobPattern]
        /// The same (path, pid) within this window is one event, not many.
        public var debounceInterval: TimeInterval = 30
        public init(roots: [String],
                    excludePatterns: [GlobPattern] = FileAccessMonitor.defaultExclusions,
                    debounceInterval: TimeInterval = 30) {
            self.roots = roots
            self.excludePatterns = excludePatterns
            self.debounceInterval = debounceInterval
        }
    }

    private let reader: AuditPipeReader
    private let filter: ReadFilter
    private let debounceInterval: TimeInterval
    private let lock = NSLock()
    private var recentlyRecorded: [String: Date] = [:]
    private var lastSweep = Date()
    // ReadFilter.admits() falls through to realpath() for any path not already
    // under a watched root — which is almost everything the fr audit class
    // delivers, thousands a second. The firehose reopens the same handful of
    // system files endlessly, so caching the admit decision per path collapses
    // that syscall cost without changing what is admitted. Bounded so it cannot
    // grow without limit.
    private var admitCache: [String: Bool] = [:]
    private let admitCacheLimit = 8_192

    public var onRead: (@Sendable (Read) -> Void)?
    public private(set) var recordsSeen = 0
    public private(set) var recorded = 0
    /// Records the kernel dropped under load; zero means complete capture.
    public var kernelDrops: UInt64 { reader.kernelDrops }

    public init(configuration: Configuration, reader: AuditPipeReader = AuditPipeReader()) {
        self.reader = reader
        self.filter = ReadFilter(roots: configuration.roots,
                                 excludePatterns: configuration.excludePatterns)
        self.debounceInterval = configuration.debounceInterval
    }

    /// Starts the tap. The result says plainly whether kernel-level read
    /// capture is actually running, so the UI can stop claiming completeness it
    /// does not have.
    public func start() -> AuditPipeReader.StartResult {
        reader.onRead = { [weak self] raw in self?.handle(raw) }
        return reader.start()
    }

    public func stop() { reader.stop() }

    /// Exposed for tests: run one raw read through the same path the pipe uses.
    public func handle(_ raw: AuditPipeReader.Read) {
        recordsSeen += 1
        guard raw.succeeded else { return }
        guard admits(raw.path) else { return }

        let key = "\(raw.path)|\(raw.pid)"
        lock.lock()
        if lastSweep.timeIntervalSinceNow < -300 { sweep() }
        if let previous = recentlyRecorded[key], raw.at.timeIntervalSince(previous) < debounceInterval {
            lock.unlock()
            return
        }
        recentlyRecorded[key] = raw.at
        lock.unlock()

        recorded += 1
        onRead?(Read(path: raw.path, pid: raw.pid, euid: raw.euid, at: raw.at))
    }

    /// Admit decision, memoised. The result depends only on the path (roots,
    /// exclusions, and whether it is a regular file), so a repeat is free.
    private func admits(_ path: String) -> Bool {
        lock.lock()
        if let cached = admitCache[path] { lock.unlock(); return cached }
        lock.unlock()

        let verdict = filter.admits(path)

        lock.lock()
        if admitCache.count >= admitCacheLimit { admitCache.removeAll(keepingCapacity: true) }
        admitCache[path] = verdict
        lock.unlock()
        return verdict
    }

    /// Forgets debounce entries past their window so the map cannot grow without
    /// bound. Caller holds the lock.
    private func sweep() {
        let cutoff = Date().addingTimeInterval(-debounceInterval)
        recentlyRecorded = recentlyRecorded.filter { $0.value > cutoff }
        lastSweep = Date()
    }
}
