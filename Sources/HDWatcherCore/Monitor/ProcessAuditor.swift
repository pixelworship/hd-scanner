import Foundation
import Darwin
import Security
import OSLog

/// Works out which process is responsible for a filesystem change.
///
/// ## What is possible without Endpoint Security
///
/// Apple exposes no supported way for an ordinary app to be told which process
/// touched a file; that requires an Endpoint Security entitlement issued case by
/// case. Three unprivileged sources get surprisingly far when combined:
///
/// 1. **Open file descriptors** (`libproc`). Scanning every reachable process
///    for one holding the path is the strongest available signal. It works for
///    processes running as the current user — root-owned daemons refuse, which
///    is why a keychain write usually cannot be pinned on `securityd` from here.
/// 2. **A rolling process table.** Sampling the process list a few times a
///    second catches short-lived commands that have already exited by the time
///    the file event is delivered.
/// 3. **The unified log.** Readable system-wide on most installs, and often
///    names the process behind a security-sensitive operation.
///
/// Timing is the real enemy: FSEvents coalesces with a latency, and by then a
/// process may have closed the file. `WatcherEngine` therefore runs a separate
/// near-zero-latency stream over audited paths and calls in here immediately.
public final class ProcessAuditor: @unchecked Sendable {

    public struct Configuration: Sendable {
        /// How often the background process table is resampled.
        public var samplingInterval: TimeInterval = 2
        /// A process starting within this window of an event is worth naming.
        public var startProximity: TimeInterval = 6
        /// Minimum gap between full descriptor scans.
        public var minimumScanInterval: TimeInterval = 0.25
        public var consultSystemLog: Bool = true
        public var maximumActors: Int = 8
        public init() {}
    }

    private struct ProcessRecord {
        var actor: ProcessActor
        var firstSeen: Date
        var lastSeen: Date
    }

    private let mutex = NSLock()
    private var config: Configuration
    private var table: [Int32: ProcessRecord] = [:]
    /// Signing lookups are expensive and an executable's identity is fixed.
    private var signingCache: [String: (id: String?, team: String?, apple: Bool)] = [:]
    private var userNameCache: [UInt32: String] = [:]
    private var lastScan = Date.distantPast
    private var samplingTimer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "co.pixelworship.hdwatcher.procaudit", qos: .utility)
    private var systemLogUsable = true

    public init(config: Configuration = Configuration()) {
        self.config = config
        sampleProcessTable()
        startSampling()
    }

    deinit { samplingTimer?.cancel() }

    private func startSampling() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + config.samplingInterval, repeating: config.samplingInterval)
        timer.setEventHandler { [weak self] in self?.sampleProcessTable() }
        timer.resume()
        samplingTimer = timer
    }

    // MARK: - Attribution

    /// Identifies processes connected to `path`. Call as soon as possible after
    /// the change — evidence decays within seconds.
    /// Describes one known process. Used where the holder is not in doubt —
    /// a read is attributed to whichever process had the descriptor, which is
    /// evidence rather than inference.
    public func describe(pid: Int32, evidence: AttributionEvidence) -> AttributionResult {
        guard let actor = actorFor(pid: pid, evidence: evidence) else {
            return AttributionResult(actors: [], blockedByPrivileges: true, scannedProcesses: 1)
        }
        return AttributionResult(actors: [actor], scannedProcesses: 1)
    }

    public func attribute(path: String, at eventTime: Date = Date()) -> AttributionResult {
        let parent = (path as NSString).deletingLastPathComponent
        var actors: [ProcessActor] = []
        var scanned = 0
        var sawDenied = false

        let pids = Self.allPIDs()
        for pid in pids where pid != getpid() {
            guard let descriptors = Self.openPaths(pid: pid) else {
                sawDenied = true
                continue
            }
            scanned += 1
            if descriptors.contains(path) {
                if let actor = actorFor(pid: pid, evidence: .holdsFileOpen) { actors.append(actor) }
            } else if !parent.isEmpty, descriptors.contains(parent) {
                if let actor = actorFor(pid: pid, evidence: .holdsParentDirectory) { actors.append(actor) }
            }
        }

        // Nothing holds it now — look for something that ran at the right moment.
        if actors.isEmpty {
            actors.append(contentsOf: processesStartedNear(eventTime))
        }

        if actors.isEmpty, config.consultSystemLog {
            actors.append(contentsOf: processesNamedInLog(for: path, around: eventTime))
        }

        // Strongest evidence first, de-duplicated by pid.
        var seen = Set<Int32>()
        let ranked = actors
            .sorted { $0.evidence.weight > $1.evidence.weight }
            .filter { seen.insert($0.pid).inserted }
            .prefix(config.maximumActors)

        mutex.lock(); lastScan = Date(); mutex.unlock()

        return AttributionResult(
            actors: Array(ranked),
            blockedByPrivileges: ranked.isEmpty && sawDenied,
            scannedProcesses: scanned
        )
    }

    /// Processes that appeared or vanished around the event.
    private func processesStartedNear(_ eventTime: Date) -> [ProcessActor] {
        mutex.lock()
        let records = table.values
        mutex.unlock()

        return records.compactMap { record in
            guard let started = record.actor.startedAt else { return nil }
            guard abs(started.timeIntervalSince(eventTime)) <= config.startProximity else { return nil }
            var actor = record.actor
            actor.evidence = .startedNearEvent
            return actor
        }
    }

    /// Asks the unified log whether anything mentioned this path. Best effort:
    /// on installs where the log is not readable this quietly returns nothing.
    private func processesNamedInLog(for path: String, around date: Date) -> [ProcessActor] {
        guard systemLogUsable, #available(macOS 12.0, *) else { return [] }
        let name = (path as NSString).lastPathComponent
        guard name.count > 3 else { return [] }

        do {
            let store = try OSLogStore(scope: .system)
            let start = store.position(date: date.addingTimeInterval(-4))
            let predicate = NSPredicate(format: "composedMessage CONTAINS[c] %@", name)
            let entries = try store.getEntries(at: start, matching: predicate)

            var actors: [ProcessActor] = []
            var inspected = 0
            for case let entry as OSLogEntryLog in entries {
                inspected += 1
                if inspected > 200 { break }
                guard entry.date <= date.addingTimeInterval(4) else { break }
                let pid = entry.processIdentifier
                guard pid > 0, pid != getpid() else { continue }
                if var actor = actorFor(pid: pid, evidence: .namedInSystemLog) {
                    actor.name = entry.process.isEmpty ? actor.name : entry.process
                    actors.append(actor)
                } else {
                    // The process is gone; the log still tells us its name.
                    actors.append(ProcessActor(pid: pid, name: entry.process,
                                               evidence: .namedInSystemLog))
                }
                if actors.count >= 4 { break }
            }
            return actors
        } catch {
            mutex.lock(); systemLogUsable = false; mutex.unlock()
            return []
        }
    }

    // MARK: - Process table

    private func sampleProcessTable() {
        let now = Date()
        var updated: [Int32: ProcessRecord] = [:]

        mutex.lock()
        let existing = table
        mutex.unlock()

        for pid in Self.allPIDs() {
            if var record = existing[pid] {
                record.lastSeen = now
                updated[pid] = record
                continue
            }
            guard let actor = actorFor(pid: pid, evidence: .running) else { continue }
            updated[pid] = ProcessRecord(actor: actor, firstSeen: now, lastSeen: now)
        }

        mutex.lock()
        // Keep recently-exited processes around briefly so a short-lived command
        // can still be named after the fact.
        for (pid, record) in existing where updated[pid] == nil {
            if now.timeIntervalSince(record.lastSeen) < config.startProximity * 2 {
                updated[pid] = record
            }
        }
        table = updated
        mutex.unlock()
    }

    public var trackedProcessCount: Int {
        mutex.lock(); defer { mutex.unlock() }
        return table.count
    }

    private var actorCache: [String: CachedActor] = [:]

    /// A snapshot of everything running, for the audit record.
    public func runningProcesses() -> [ProcessActor] {
        mutex.lock(); defer { mutex.unlock() }
        return table.values.map(\.actor).sorted { $0.name < $1.name }
    }

    // MARK: - Building an actor

    /// Describing a process is not cheap — code signing, arguments, the
    /// executable path — and read tracking asks for the same handful of
    /// processes over and over. Without this, attributing a few hundred reads a
    /// second pushed the daemon to 140% CPU and gigabytes resident: the
    /// Security framework holds on to what it is asked about.
    private struct CachedActor {
        let actor: ProcessActor
        let at: Date
    }
    private static let actorCacheTTL: TimeInterval = 60
    private static let actorCacheLimit = 512

    private func actorFor(pid: Int32, evidence: AttributionEvidence) -> ProcessActor? {
        let key = "\(pid)|\(evidence.rawValue)"
        mutex.lock()
        if let cached = actorCache[key], Date().timeIntervalSince(cached.at) < Self.actorCacheTTL {
            mutex.unlock()
            return cached.actor
        }
        mutex.unlock()

        guard let built = buildActor(pid: pid, evidence: evidence) else { return nil }

        mutex.lock()
        if actorCache.count >= Self.actorCacheLimit {
            // Cheap eviction: the oldest half goes, rather than tracking usage.
            let cutoff = Date().addingTimeInterval(-Self.actorCacheTTL / 2)
            actorCache = actorCache.filter { $0.value.at > cutoff }
            if actorCache.count >= Self.actorCacheLimit { actorCache.removeAll() }
        }
        actorCache[key] = CachedActor(actor: built, at: Date())
        mutex.unlock()
        return built
    }

    private func buildActor(pid: Int32, evidence: AttributionEvidence) -> ProcessActor? {
        guard let info = Self.bsdInfo(pid: pid) else { return nil }
        let executable = Self.executablePath(pid: pid)
        let name = Self.processName(info) ?? (executable as NSString?)?.lastPathComponent ?? "pid \(pid)"

        var signingID: String?
        var teamID: String?
        var apple = false
        if let executable {
            mutex.lock()
            let cached = signingCache[executable]
            mutex.unlock()
            if let cached {
                signingID = cached.id; teamID = cached.team; apple = cached.apple
            } else {
                let resolved = Self.signingInformation(path: executable)
                mutex.lock()
                signingCache[executable] = resolved
                if signingCache.count > 2_000 { signingCache.removeAll() }
                mutex.unlock()
                signingID = resolved.id; teamID = resolved.team; apple = resolved.apple
            }
        }

        let uid = info.pbi_uid
        mutex.lock()
        var userName = userNameCache[uid]
        mutex.unlock()
        if userName == nil {
            userName = Self.userName(for: uid)
            mutex.lock(); userNameCache[uid] = userName ?? "uid \(uid)"; mutex.unlock()
        }

        let started = info.pbi_start_tvsec > 0
            ? Date(timeIntervalSince1970: TimeInterval(info.pbi_start_tvsec)
                   + TimeInterval(info.pbi_start_tvusec) / 1_000_000)
            : nil

        return ProcessActor(
            pid: pid,
            parentPID: Int32(info.pbi_ppid),
            name: name,
            executablePath: executable,
            bundleIdentifier: executable.flatMap(Self.bundleIdentifier(forExecutable:)),
            signingIdentifier: signingID,
            teamIdentifier: teamID,
            isAppleSigned: apple,
            userID: uid,
            userName: userName,
            startedAt: started,
            arguments: Self.arguments(pid: pid),
            evidence: evidence
        )
    }

    // MARK: - libproc

    static func allPIDs() -> [Int32] {
        let size = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard size > 0 else { return [] }
        var pids = [Int32](repeating: 0, count: Int(size) / MemoryLayout<Int32>.size)
        let written = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids, size)
        guard written > 0 else { return [] }
        return pids.filter { $0 > 0 }
    }

    static func executablePath(pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let written = proc_pidpath(pid, &buffer, 4096)
        return written > 0 ? String(cString: buffer) : nil
    }

    static func bsdInfo(pid: Int32) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let written = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        return written == size ? info : nil
    }

    static func processName(_ info: proc_bsdinfo) -> String? {
        var copy = info
        let name = withUnsafePointer(to: &copy.pbi_name) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: 2 * Int(MAXCOMLEN)) {
                String(cString: $0)
            }
        }
        if !name.isEmpty { return name }
        let comm = withUnsafePointer(to: &copy.pbi_comm) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) {
                String(cString: $0)
            }
        }
        return comm.isEmpty ? nil : comm
    }

    /// Paths this process currently has open. Returns nil when the kernel
    /// refuses, which is how root-owned processes present to us.
    /// Why a process's open files could not be listed. The difference matters:
    /// a process we *chose* not to walk still holds its files, while one the
    /// kernel will not describe is gone or beyond our reach.
    enum OpenPathsOutcome {
        case paths(Set<String>)
        /// Holds more descriptors than the caller was willing to walk.
        case tooManyDescriptors
        /// Gone, or invisible to this process.
        case unavailable
    }

    static func probeOpenPaths(pid: Int32, limit: Int) -> OpenPathsOutcome {
        let bufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bufferSize > 0 else { return .unavailable }
        if Int(bufferSize) / MemoryLayout<proc_fdinfo>.size > limit { return .tooManyDescriptors }
        guard let paths = openPaths(pid: pid) else { return .unavailable }
        return .paths(paths)
    }

    static func openPaths(pid: Int32, limit: Int = .max) -> Set<String>? {
        let bufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bufferSize > 0 else { return nil }
        let capacity = Int(bufferSize) / MemoryLayout<proc_fdinfo>.size
        var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: capacity)
        let written = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &descriptors, bufferSize)
        guard written > 0 else { return nil }

        var paths = Set<String>()
        let count = Int(written) / MemoryLayout<proc_fdinfo>.size
        // A process with thousands of open files costs a great deal to walk.
        guard count <= limit else { return nil }
        for index in 0..<min(count, capacity) {
            let descriptor = descriptors[index]
            guard descriptor.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) else { continue }
            var info = vnode_fdinfowithpath()
            let size = Int32(MemoryLayout<vnode_fdinfowithpath>.size)
            guard proc_pidfdinfo(pid, descriptor.proc_fd, PROC_PIDFDVNODEPATHINFO, &info, size) > 0
            else { continue }
            let path = withUnsafePointer(to: &info.pvip.vip_path) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                    String(cString: $0)
                }
            }
            if !path.isEmpty { paths.insert(path) }
        }
        return paths
    }

    static func arguments(pid: Int32) -> String? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return nil }

        // Layout: argc (4 bytes), executable path, NULs, then the arguments.
        let body = buffer.dropFirst(4)
        let pieces = body.split(separator: 0, omittingEmptySubsequences: true)
            .compactMap { String(bytes: $0, encoding: .utf8) }
        guard pieces.count > 1 else { return nil }
        let joined = pieces.dropFirst().joined(separator: " ")
        return joined.isEmpty ? nil : String(joined.prefix(512))
    }

    static func userName(for uid: UInt32) -> String? {
        guard let entry = getpwuid(uid_t(uid)), let name = entry.pointee.pw_name else { return nil }
        return String(cString: name)
    }

    static func bundleIdentifier(forExecutable path: String) -> String? {
        // .../Foo.app/Contents/MacOS/Foo -> .../Foo.app
        var url = URL(fileURLWithPath: path)
        for _ in 0..<4 {
            url = url.deletingLastPathComponent()
            if url.pathExtension == "app" {
                return Bundle(url: url)?.bundleIdentifier
            }
        }
        return nil
    }

    static func signingInformation(path: String) -> (id: String?, team: String?, apple: Bool) {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return (nil, nil, false) }

        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            code, SecCSFlags(rawValue: kSecCSSigningInformation), &information
        ) == errSecSuccess, let dictionary = information as? [String: Any] else {
            return (nil, nil, false)
        }
        let identifier = dictionary["identifier"] as? String
        let team = dictionary["teamid"] as? String
        // Apple's own binaries carry no team identifier but do sign with an
        // apple-internal anchor; the identifier prefix is the practical tell.
        let apple = team == nil && (identifier?.hasPrefix("com.apple.") ?? false)
        return (identifier, team, apple)
    }
}
