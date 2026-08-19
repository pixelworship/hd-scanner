import Foundation

/// Activity accumulated for one directory.
public struct DirectoryHeat: Codable, Sendable, Identifiable, Hashable {
    public var id: String { path }
    public var path: String
    /// Events whose immediate parent is this directory.
    public var directEvents: Int
    /// Events anywhere beneath this directory, including itself.
    public var subtreeEvents: Int
    public var creates: Int
    public var modifies: Int
    public var deletes: Int
    public var renames: Int
    public var transfers: Int
    public var bytesTouched: Int64
    public var lastActivity: Date
    public var firstActivity: Date
    /// Time-decayed score: recent churn outranks a directory that was busy an
    /// hour ago and has been quiet since.
    public var heat: Double
    public var volumeID: String?

    public init(path: String, volumeID: String? = nil, at: Date = Date()) {
        self.path = path
        self.volumeID = volumeID
        self.directEvents = 0
        self.subtreeEvents = 0
        self.creates = 0
        self.modifies = 0
        self.deletes = 0
        self.renames = 0
        self.transfers = 0
        self.bytesTouched = 0
        self.lastActivity = at
        self.firstActivity = at
        self.heat = 0
    }

    public var name: String {
        let base = (path as NSString).lastPathComponent
        return base.isEmpty ? path : base
    }

    /// Share of this directory's activity that is destructive.
    public var deleteRatio: Double {
        directEvents > 0 ? Double(deletes) / Double(directEvents) : 0
    }
}

/// Maintains a decaying heat map of directory activity, so the UI can answer
/// "where is all the traffic going right now?".
///
/// Every event bumps its own directory plus each ancestor, which is what makes
/// a treemap possible: a parent's subtree count is the sum of everything below it.
public final class HotspotTracker: @unchecked Sendable {

    public struct Configuration: Sendable {
        /// Time for a directory's heat to fall by half with no new activity.
        public var halfLife: TimeInterval = 15 * 60
        /// Ancestors to credit above each event. Deep trees would otherwise
        /// make every event O(depth).
        public var ancestorDepth: Int = 8
        /// Cap on tracked directories; coldest are evicted first.
        public var maxDirectories: Int = 20_000
        public init() {}
    }

    private let mutex = NSLock()
    private var directories: [String: DirectoryHeat] = [:]
    private var config: Configuration
    private var lastDecay = Date()

    public init(config: Configuration = Configuration()) {
        self.config = config
    }

    private var decayConstant: Double { config.halfLife / log(2) }

    // MARK: - Ingestion

    public func record(_ event: FileEvent) {
        let directory = event.isDirectory ? event.path : event.directory
        guard !directory.isEmpty, directory != "/" || event.isDirectory else { return }

        // Decay always advances against the wall clock, never against an event
        // timestamp — otherwise a batch of backdated events would rewind it.
        let now = Date()
        // An event's contribution is discounted by its own age, so replaying
        // history (or a late FSEvents batch) cannot make a stale directory look
        // hot right now.
        let age = max(0, now.timeIntervalSince(event.timestamp))
        let weight = exp(-age / decayConstant)

        mutex.lock()
        defer { mutex.unlock() }

        applyDecayLocked(to: now)

        // The directory that directly contains the change.
        updateLocked(path: directory, event: event, direct: true,
                     now: event.timestamp, weight: weight)

        // Credit ancestors so subtree totals roll up.
        var current = directory
        var depth = 0
        while depth < config.ancestorDepth {
            let parent = (current as NSString).deletingLastPathComponent
            if parent.isEmpty || parent == current { break }
            updateLocked(path: parent, event: event, direct: false,
                         now: event.timestamp, weight: weight)
            current = parent
            if parent == "/" { break }
            depth += 1
        }
    }

    public func record(_ events: [FileEvent]) {
        for event in events { record(event) }
    }

    private func updateLocked(path: String, event: FileEvent, direct: Bool,
                              now: Date, weight: Double) {
        var entry = directories[path] ?? DirectoryHeat(path: path, volumeID: event.volumeID, at: now)
        entry.subtreeEvents += 1
        entry.lastActivity = max(entry.lastActivity, now)
        entry.heat += direct ? weight : weight * 0.35   // ancestors warm up, but less

        if direct {
            entry.directEvents += 1
            switch event.kind {
            case .created, .cloned:      entry.creates += 1
            case .modified:              entry.modifies += 1
            case .removed:               entry.deletes += 1
            case .renamed:               entry.renames += 1
            case .copiedIn, .copiedOut, .movedIn, .movedOut:
                entry.transfers += 1
            default: break
            }
            if let size = event.size { entry.bytesTouched += size }
        }
        directories[path] = entry
    }

    // MARK: - Decay

    private func applyDecayLocked(to now: Date) {
        let elapsed = now.timeIntervalSince(lastDecay)
        guard elapsed >= 5 else { return }   // batch decay; per-event would be wasteful
        let factor = exp(-elapsed / decayConstant)
        guard factor < 0.999 else { lastDecay = now; return }

        for (key, var value) in directories {
            value.heat *= factor
            if value.heat < 0.01 && now.timeIntervalSince(value.lastActivity) > config.halfLife * 4 {
                directories.removeValue(forKey: key)
            } else {
                directories[key] = value
            }
        }
        lastDecay = now
        evictIfNeededLocked()
    }

    private func evictIfNeededLocked() {
        guard directories.count > config.maxDirectories else { return }
        let sorted = directories.sorted { $0.value.heat < $1.value.heat }
        for (key, _) in sorted.prefix(directories.count - config.maxDirectories) {
            directories.removeValue(forKey: key)
        }
    }

    // MARK: - Queries

    public enum Ranking: String, CaseIterable, Sendable {
        case heat = "Heat"
        case totalEvents = "Total Events"
        case writes = "Writes"
        case deletes = "Deletes"
        case transfers = "Transfers"
        case bytes = "Bytes"

        public var explanation: String {
            switch self {
            case .heat:        return "Recent activity, weighted so newer changes count for more"
            case .totalEvents: return "All events recorded in this directory"
            case .writes:      return "Files created or modified"
            case .deletes:     return "Files removed"
            case .transfers:   return "Copies and moves across volumes"
            case .bytes:       return "Total size of files touched"
            }
        }
    }

    public func topDirectories(_ limit: Int = 25, by ranking: Ranking = .heat,
                               volumeID: String? = nil, directOnly: Bool = true) -> [DirectoryHeat] {
        mutex.lock()
        applyDecayLocked(to: Date())
        var values = Array(directories.values)
        mutex.unlock()

        if let volumeID { values = values.filter { $0.volumeID == volumeID } }
        if directOnly { values = values.filter { $0.directEvents > 0 } }

        switch ranking {
        case .heat:        values.sort { $0.heat > $1.heat }
        case .totalEvents: values.sort { $0.directEvents > $1.directEvents }
        case .writes:      values.sort { ($0.creates + $0.modifies) > ($1.creates + $1.modifies) }
        case .deletes:     values.sort { $0.deletes > $1.deletes }
        case .transfers:   values.sort { $0.transfers > $1.transfers }
        case .bytes:       values.sort { $0.bytesTouched > $1.bytesTouched }
        }
        return Array(values.prefix(limit))
    }

    /// Immediate children of `path` that have activity — the drill-down step
    /// for the treemap.
    public func children(of path: String, limit: Int = 40) -> [DirectoryHeat] {
        mutex.lock()
        let values = Array(directories.values)
        mutex.unlock()
        let prefix = path == "/" ? "/" : path + "/"
        let kids = values.filter { entry in
            guard entry.path != path, entry.path.hasPrefix(prefix) else { return false }
            let remainder = entry.path.dropFirst(prefix.count)
            return !remainder.contains("/")
        }
        return Array(kids.sorted { $0.subtreeEvents > $1.subtreeEvents }.prefix(limit))
    }

    public func heat(for path: String) -> DirectoryHeat? {
        mutex.lock(); defer { mutex.unlock() }
        return directories[path]
    }

    public var trackedDirectoryCount: Int {
        mutex.lock(); defer { mutex.unlock() }
        return directories.count
    }

    // MARK: - Persistence

    public func snapshot() -> [DirectoryHeat] {
        mutex.lock(); defer { mutex.unlock() }
        // Persist only what is worth reloading.
        return directories.values.filter { $0.directEvents > 0 }
            .sorted { $0.subtreeEvents > $1.subtreeEvents }
            .prefix(5_000).map { $0 }
    }

    public func restore(_ snapshot: [DirectoryHeat]) {
        mutex.lock(); defer { mutex.unlock() }
        for entry in snapshot { directories[entry.path] = entry }
        lastDecay = Date()
    }

    public func reset() {
        mutex.lock(); defer { mutex.unlock() }
        directories.removeAll()
        lastDecay = Date()
    }
}
