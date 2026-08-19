import Foundation

/// One minute of aggregated activity, used for the sparklines and the
/// activity chart.
public struct ActivityBucket: Codable, Sendable, Identifiable, Hashable {
    public var id: Date { start }
    public var start: Date
    public var total: Int
    public var creates: Int
    public var modifies: Int
    public var deletes: Int
    public var transfers: Int
    public var alerts: Int
    public var bytes: Int64

    public init(start: Date) {
        self.start = start
        total = 0; creates = 0; modifies = 0; deletes = 0
        transfers = 0; alerts = 0; bytes = 0
    }
}

public struct ExtensionStat: Codable, Sendable, Identifiable, Hashable {
    public var id: String { ext }
    public var ext: String
    public var count: Int
    public var bytes: Int64
}

public struct VolumeStat: Codable, Sendable, Identifiable, Hashable {
    public var id: String { volumeID }
    public var volumeID: String
    public var reads: Int
    public var writes: Int
    public var deletes: Int
    public var transfersIn: Int
    public var transfersOut: Int
    public var bytes: Int64
}

public struct StatsSnapshot: Codable, Sendable {
    public var buckets: [ActivityBucket] = []
    public var extensions: [String: ExtensionStat] = [:]
    public var volumes: [String: VolumeStat] = [:]
    public var hotspots: [DirectoryHeat] = []
    public var totalEvents: Int = 0
    public var savedAt: Date = Date()
}

/// Rolling counters behind the dashboard: a 24-hour minute-resolution time
/// series plus breakdowns by file type and volume.
public final class ActivityStats: @unchecked Sendable {

    private let mutex = NSLock()
    private var buckets: [Date: ActivityBucket] = [:]
    private var extensions: [String: ExtensionStat] = [:]
    private var volumes: [String: VolumeStat] = [:]
    private var total: Int = 0
    private let retainedMinutes = 24 * 60

    public init() {}

    private func bucketStart(_ date: Date) -> Date {
        Date(timeIntervalSince1970: floor(date.timeIntervalSince1970 / 60) * 60)
    }

    // MARK: - Ingestion

    public func record(_ event: FileEvent) {
        let slot = bucketStart(event.timestamp)
        mutex.lock()
        defer { mutex.unlock() }

        var bucket = buckets[slot] ?? ActivityBucket(start: slot)
        bucket.total += 1
        switch event.kind {
        case .created, .cloned: bucket.creates += 1
        case .modified:         bucket.modifies += 1
        case .removed:          bucket.deletes += 1
        case .copiedIn, .copiedOut, .movedIn, .movedOut: bucket.transfers += 1
        default: break
        }
        if let size = event.size { bucket.bytes += size }
        buckets[slot] = bucket
        total += 1

        if !event.isDirectory {
            let ext = event.fileExtension.isEmpty ? "(none)" : event.fileExtension
            var stat = extensions[ext] ?? ExtensionStat(ext: ext, count: 0, bytes: 0)
            stat.count += 1
            stat.bytes += event.size ?? 0
            extensions[ext] = stat
        }

        if let volumeID = event.volumeID {
            var stat = volumes[volumeID] ?? VolumeStat(volumeID: volumeID, reads: 0, writes: 0,
                                                       deletes: 0, transfersIn: 0, transfersOut: 0, bytes: 0)
            switch event.kind {
            case .created, .modified, .cloned: stat.writes += 1
            case .removed:                     stat.deletes += 1
            case .copiedIn, .movedIn:          stat.transfersIn += 1
            case .copiedOut, .movedOut:        stat.transfersOut += 1
            default:                           stat.reads += 1
            }
            stat.bytes += event.size ?? 0
            volumes[volumeID] = stat
        }

        pruneLocked()
    }

    public func recordAlert(at date: Date = Date()) {
        let slot = bucketStart(date)
        mutex.lock(); defer { mutex.unlock() }
        var bucket = buckets[slot] ?? ActivityBucket(start: slot)
        bucket.alerts += 1
        buckets[slot] = bucket
    }

    private func pruneLocked() {
        guard buckets.count > retainedMinutes else { return }
        let cutoff = Date().addingTimeInterval(-Double(retainedMinutes) * 60)
        buckets = buckets.filter { $0.key >= cutoff }
    }

    // MARK: - Queries

    /// Contiguous buckets for the last `minutes`, with gaps filled by zeroes so
    /// charts show quiet periods rather than interpolating across them.
    public func series(minutes: Int = 60, now: Date = Date()) -> [ActivityBucket] {
        mutex.lock()
        let snapshot = buckets
        mutex.unlock()

        let end = bucketStart(now)
        return (0..<minutes).reversed().map { offset in
            let slot = end.addingTimeInterval(-Double(offset) * 60)
            return snapshot[slot] ?? ActivityBucket(start: slot)
        }
    }

    public func eventsPerMinute(window: Int = 5, now: Date = Date()) -> Double {
        let recent = series(minutes: window, now: now)
        guard !recent.isEmpty else { return 0 }
        return Double(recent.reduce(0) { $0 + $1.total }) / Double(recent.count)
    }

    public func topExtensions(_ limit: Int = 12) -> [ExtensionStat] {
        mutex.lock(); defer { mutex.unlock() }
        return Array(extensions.values.sorted { $0.count > $1.count }.prefix(limit))
    }

    public func volumeStats() -> [VolumeStat] {
        mutex.lock(); defer { mutex.unlock() }
        return Array(volumes.values)
    }

    public func volumeStat(_ id: String) -> VolumeStat? {
        mutex.lock(); defer { mutex.unlock() }
        return volumes[id]
    }

    public var totalEvents: Int {
        mutex.lock(); defer { mutex.unlock() }
        return total
    }

    /// Total activity in the trailing window, used for burst comparisons.
    public func totalInLast(minutes: Int) -> Int {
        series(minutes: minutes).reduce(0) { $0 + $1.total }
    }

    // MARK: - Persistence

    public func snapshot(hotspots: [DirectoryHeat]) -> StatsSnapshot {
        mutex.lock(); defer { mutex.unlock() }
        var snap = StatsSnapshot()
        snap.buckets = Array(buckets.values.sorted { $0.start < $1.start }.suffix(retainedMinutes))
        snap.extensions = extensions
        snap.volumes = volumes
        snap.hotspots = hotspots
        snap.totalEvents = total
        return snap
    }

    public func restore(_ snapshot: StatsSnapshot) {
        mutex.lock(); defer { mutex.unlock() }
        for bucket in snapshot.buckets { buckets[bucket.start] = bucket }
        extensions = snapshot.extensions
        volumes = snapshot.volumes
        total = snapshot.totalEvents
        pruneLocked()
    }

    public func reset() {
        mutex.lock(); defer { mutex.unlock() }
        buckets.removeAll(); extensions.removeAll(); volumes.removeAll(); total = 0
    }
}
