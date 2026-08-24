import Foundation
import Darwin

/// Records which files are being **read**, and by what.
///
/// FSEvents cannot help here. It reports changes to the filesystem, and reading
/// a file changes nothing — which is why copying a file to a USB stick leaves
/// no trace on the source side. For an audit tool that is a real gap: reading
/// is how data leaves, and "who opened this document" is often the whole
/// question.
///
/// The complete answer is Endpoint Security, which reports every open as it
/// happens. It needs an entitlement Apple grants by application, so this uses
/// what is available to any process: the kernel's own list of open file
/// descriptors, sampled. What that catches is every file held open at the
/// moment of a sample, with the process holding it. What it misses is a file
/// opened and closed entirely between two samples — a very small read of a
/// small file. The tab says so rather than implying completeness.
public final class FileAccessMonitor: @unchecked Sendable {

    public struct Access: Sendable, Codable, Hashable, Identifiable {
        public var id: String { "\(path)|\(pid)|\(Int(openedAt.timeIntervalSince1970))" }
        public let path: String
        public let pid: Int32
        public let processName: String
        public let openedAt: Date
        public var lastSeen: Date
        /// How many samples saw it open, which is a rough measure of how long
        /// it was held rather than how much was read.
        public var samples: Int
        public var bundleIdentifier: String?

        public var duration: TimeInterval { lastSeen.timeIntervalSince(openedAt) }
        public var fileName: String { (path as NSString).lastPathComponent }
        public var directory: String { (path as NSString).deletingLastPathComponent }
    }

    public struct Configuration: Sendable {
        /// How often to look. Sampling is the whole mechanism, so this is the
        /// resolution: anything opened and closed inside one interval is
        /// missed. It is also the cost: as root, one pass means asking the
        /// kernel about every descriptor of every process on the machine.
        public var interval: TimeInterval = 10
        /// A pass that cannot finish inside this is abandoned rather than
        /// allowed to run into the next one. Measured on a busy Mac, a full
        /// sweep as root is not cheap, and two of them overlapping is how a
        /// sampler turns into a runaway.
        public var timeBudget: TimeInterval = 1.5
        /// Processes holding more descriptors than this are skipped. A browser
        /// or a database with thousands of open files costs a great deal to
        /// walk and never holds the document anyone is asking about.
        public var maximumDescriptorsPerProcess = 512
        /// Only these roots are considered.
        ///
        /// Not the whole home: measured on a real machine, `~/Library` alone
        /// produces around eleven thousand opens a minute — app databases,
        /// group containers, sync state — which would bury the reads a person
        /// actually cares about and bloat a permanent log. What is left is
        /// where documents live.
        public var roots: [String] = FileAccessMonitor.defaultRoots
        public var excludePatterns: [GlobPattern] = FileAccessMonitor.defaultExclusions
        /// Guards against a runaway: a process opening tens of thousands of
        /// files should not be able to fill the log.
        public var maximumTrackedAccesses = 20_000
        public init() {}
    }

    /// Where a person's own files live, which is what "who read this" is
    /// asking about.
    public static var defaultRoots: [String] {
        let home = NSHomeDirectory()
        return ["Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Public"]
            .map { home + "/" + $0 } + ["/Volumes"]
    }

    /// Noise that would drown everything worth seeing: code, caches, and the
    /// app's own bookkeeping.
    public static let defaultExclusions: [GlobPattern] = [
        "**/Library/Caches/**", "**/Caches/**", "**/*.dylib", "**/*.so",
        "**/.DS_Store", "**/Library/Saved Application State/**",
        "**/Library/Containers/**/Data/Library/Caches/**",
        "**/co.pixelworship.hdwatcher/**", "**/*.hdwseg", "**/*.hdw",
        "**/Library/Metadata/**", "**/Library/Preferences/**",
        "**/Library/Application Support/CloudDocs/**",
        "**/*.sock", "/dev/**", "/private/var/folders/**",
        // App plumbing rather than anyone's documents.
        "**/Library/**", "**/.git/**", "**/node_modules/**",
        // Media libraries are a bundle around a database that their own
        // daemons read constantly; the photos in them are not being opened by
        // anyone.
        "**/*.photoslibrary/**", "**/*.photolibrary/**", "**/*.musiclibrary/**",
        "**/*.tvlibrary/**", "**/*.imovielibrary/**", "**/*.fcpbundle/**",
        "**/*.logicx/**", "**/*.aplibrary/**",
    ].map { GlobPattern($0) }

    private let configuration: Configuration
    private let filter: ReadFilter
    private let mutex = NSLock()
    private var open: [String: Access] = [:]           // key: path|pid
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "co.pixelworship.hdwatcher.reads", qos: .utility)

    /// Called when a file stops being held open — the point at which the read
    /// is a complete fact rather than something in progress.
    public var onAccessFinished: (@Sendable (Access) -> Void)?
    /// Called the first time a file is seen open, for a live view.
    public var onAccessStarted: (@Sendable (Access) -> Void)?

    public private(set) var samplesTaken = 0
    public private(set) var accessesSeen = 0
    /// The first sample records what is already open without reporting it: we
    /// did not observe those opens, and announcing them as reads that happened
    /// now would be a lie the log keeps forever.
    private var primed = false

    public init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
        self.filter = ReadFilter(roots: configuration.roots,
                                 excludePatterns: configuration.excludePatterns)
    }

    public func start() {
        stop()
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + 0.5, repeating: configuration.interval)
        source.setEventHandler { [weak self] in self?.sample() }
        source.resume()
        timer = source
    }

    public func stop() {
        timer?.cancel()
        timer = nil
        // Everything still open at shutdown is finished as far as we know.
        mutex.lock()
        let remaining = Array(open.values)
        open.removeAll()
        mutex.unlock()
        for access in remaining { onAccessFinished?(access) }
    }

    /// One pass over every process. Public so a test can drive it directly
    /// rather than waiting on a timer.
    @discardableResult
    public func sample(now: Date = Date()) -> [Access] {
        let seen = currentlyOpen()
        var started: [Access] = []
        var finished: [Access] = []

        mutex.lock()
        samplesTaken += 1
        var stillOpen: [String: Access] = [:]
        stillOpen.reserveCapacity(seen.count)

        for entry in seen {
            let key = "\(entry.path)|\(entry.pid)"
            if var existing = open.removeValue(forKey: key) {
                existing.lastSeen = now
                existing.samples += 1
                stillOpen[key] = existing
            } else if open.count + stillOpen.count < configuration.maximumTrackedAccesses {
                let access = Access(path: entry.path, pid: entry.pid,
                                    processName: entry.name, openedAt: now, lastSeen: now,
                                    samples: 1, bundleIdentifier: nil)
                stillOpen[key] = access
                if primed {
                    started.append(access)
                    accessesSeen += 1
                }
            }
        }
        // Whatever was open last time and is not open now has been closed.
        finished = primed ? Array(open.values) : []
        open = stillOpen
        primed = true
        mutex.unlock()

        for access in started { onAccessStarted?(access) }
        for access in finished { onAccessFinished?(access) }
        return started
    }

    /// Files currently held open, across every process the kernel will tell us
    /// about. Root sees everything; a user process sees its own.
    private func currentlyOpen() -> [(path: String, pid: Int32, name: String)] {
        var results: [(String, Int32, String)] = []
        let count = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard count > 0 else { return [] }
        let capacity = Int(count) / MemoryLayout<pid_t>.size
        var pids = [pid_t](repeating: 0, count: capacity)
        let written = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids, count)
        guard written > 0 else { return [] }

        let mine = ProcessInfo.processInfo.processIdentifier
        let deadline = Date().addingTimeInterval(configuration.timeBudget)
        var skipped = 0

        for pid in pids where pid > 0 && pid != mine {
            // Abandon the pass rather than let it overrun into the next one.
            if Date() > deadline {
                skipped += 1
                continue
            }
            guard let paths = ProcessAuditor.openPaths(
                pid: pid, limit: configuration.maximumDescriptorsPerProcess),
                  !paths.isEmpty else { continue }
            // Only look up the name for a process that actually holds something
            // interesting: it is another two syscalls per process otherwise.
            var name: String?
            for path in paths where isInteresting(path) {
                if name == nil {
                    name = ProcessAuditor.bsdInfo(pid: pid).flatMap(ProcessAuditor.processName)
                        ?? "pid \(pid)"
                }
                results.append((path, pid, name!))
            }
        }
        if skipped > 0 { unfinishedPasses += 1 }
        return results
    }

    /// How many passes ran out of time. Visible rather than silent: it means
    /// reads are being missed.
    public private(set) var unfinishedPasses = 0

    func isInteresting(_ path: String) -> Bool {
        filter.admits(path)
    }
}
