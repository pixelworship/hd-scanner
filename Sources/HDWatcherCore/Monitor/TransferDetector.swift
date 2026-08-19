import Foundation
import CryptoKit

/// Reconstructs copies and moves from the raw stream of creates and deletes.
///
/// ## Why this is inference
///
/// FSEvents reports *that* a file appeared, never *where it came from* — and it
/// reports no reads at all. True provenance would need an Endpoint Security
/// client, which requires an entitlement Apple grants only to approved
/// developers. So the detector correlates observable facts and reports how sure
/// it is, rather than pretending to certainty it does not have:
///
/// | Signal                                                  | Confidence |
/// |---------------------------------------------------------|------------|
/// | Two rename events sharing one inode                       | certain    |
/// | Arrival matches a departure (same name + size, elsewhere) | high       |
/// | Arrival's head/tail/size digest matches a live source     | high       |
/// | Arrival matches a known file by name and size only        | medium     |
/// | Arrival on removable media with no identifiable source    | low        |
///
/// Arrivals are held for a short settle window first, because a Finder copy
/// lands as a create followed by a burst of writes; measuring it immediately
/// would read a zero-byte file.
public final class TransferDetector: @unchecked Sendable {

    public struct Configuration: Sendable {
        /// How long to wait for a newly created file to stop growing.
        public var settleInterval: TimeInterval = 2.0
        /// How far back to look for a matching source.
        public var correlationWindow: TimeInterval = 90
        /// Files at or below this size are digested whole.
        public var wholeFileDigestLimit: Int64 = 128 * 1024
        /// Bytes sampled from each end for larger files.
        public var digestSampleBytes: Int = 64 * 1024
        /// Skip digesting on network volumes, where reads are expensive.
        public var skipDigestOnNetwork: Bool = true
        public var maxTrackedFiles: Int = 20_000
        /// Ask Spotlight for a source when no observed candidate exists. This is
        /// what makes "copied from my disk to a USB stick" resolvable at all,
        /// since the read on the source side is invisible to FSEvents.
        public var useSpotlightFallback: Bool = true
        public init() {}
    }

    private struct Candidate {
        var path: String
        var volumeID: String?
        var volumeClass: VolumeClass
        var size: Int64
        var seenAt: Date
        var inode: UInt64?
        var departed: Bool      // the file was deleted after we saw it
    }

    private struct PendingArrival {
        var event: FileEvent
        var volumeClass: VolumeClass
        var arrivedAt: Date
    }

    private let mutex = NSLock()
    private let queue = DispatchQueue(label: "co.pixelworship.hdwatcher.transfers", qos: .utility)
    private var config: Configuration
    private weak var registry: VolumeRegistry?

    /// basename+size -> recently observed files carrying that signature
    private var byNameSize: [String: [Candidate]] = [:]
    /// inode -> the half of a rename we have seen so far
    private var pendingRenames: [UInt64: FileEvent] = [:]
    private var pendingArrivals: [String: PendingArrival] = [:]
    /// Suppresses duplicate findings for a path we already resolved.
    private var recentlyResolved: [String: Date] = [:]
    private var timer: DispatchSourceTimer?
    private let locator = SpotlightLocator()
    /// Spotlight lookups touch the disk, so they run off the detector's queue to
    /// keep the settle timer responsive.
    private let lookupQueue = DispatchQueue(label: "co.pixelworship.hdwatcher.transfers.lookup",
                                            qos: .utility, attributes: .concurrent)

    public private(set) var transfersDetected: Int = 0

    /// Fires once an arrival settles and a source has (or has not) been found.
    public var onTransfer: (@Sendable (FileEvent) -> Void)?

    public init(registry: VolumeRegistry?, config: Configuration = Configuration()) {
        self.registry = registry
        self.config = config
        startTimer()
    }

    deinit { timer?.cancel() }

    private func startTimer() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 1, repeating: 1.0)
        t.setEventHandler { [weak self] in self?.drainSettled() }
        t.resume()
        timer = t
    }

    // MARK: - Ingestion

    /// Feeds one normalized event in. Returns the event, possibly rewritten —
    /// for instance a pair of rename halves collapses into a single event that
    /// carries both the old and new path.
    public func ingest(_ event: FileEvent) -> FileEvent? {
        let klass = registry?.volume(id: event.volumeID ?? "")?.volumeClass
            ?? registry?.volumeClass(for: event.path)
            ?? .unknown

        switch event.kind {
        case .renamed:
            return handleRename(event, klass: klass)

        case .created, .cloned:
            recordCandidate(event, klass: klass, departed: false)
            holdArrival(event, klass: klass)
            return event

        case .modified:
            recordCandidate(event, klass: klass, departed: false)
            // A file still being written keeps its settle timer alive.
            mutex.lock()
            if var pending = pendingArrivals[event.path] {
                pending.arrivedAt = Date()
                pendingArrivals[event.path] = pending
            }
            mutex.unlock()
            return event

        case .removed:
            markDeparted(event, klass: klass)
            return event

        default:
            return event
        }
    }

    // MARK: - Renames

    /// Both halves of a rename carry the same inode, which makes this the one
    /// case where provenance is certain rather than inferred.
    private func handleRename(_ event: FileEvent, klass: VolumeClass) -> FileEvent? {
        guard let inode = event.inode else { return event }

        mutex.lock()
        let partner = pendingRenames.removeValue(forKey: inode)
        if partner == nil {
            pendingRenames[inode] = event
        }
        mutex.unlock()

        guard let partner else {
            // Hold the first half briefly; if no partner arrives it is reported
            // on its own by `drainSettled`.
            return nil
        }

        let firstExists = FileManager.default.fileExists(atPath: partner.path)
        let secondExists = FileManager.default.fileExists(atPath: event.path)

        let source: FileEvent
        let destination: FileEvent
        if secondExists && !firstExists {
            source = partner; destination = event
        } else if firstExists && !secondExists {
            source = event; destination = partner
        } else {
            // Ambiguous (both or neither present) — order of arrival is the
            // best remaining guess.
            source = partner; destination = event
        }

        let sourceClass = registry?.volume(id: source.volumeID ?? "")?.volumeClass ?? .unknown
        let destClass = registry?.volume(id: destination.volumeID ?? "")?.volumeClass ?? klass

        var result = destination
        result.sourcePath = source.path
        result.sourceVolumeID = source.volumeID
        result.confidence = .certain
        result.kind = Self.transferKind(sourceClass: sourceClass, destClass: destClass,
                                        isMove: true, sameVolume: source.volumeID == destination.volumeID)
        result.severity = Self.severity(for: result.kind, destClass: destClass)

        if result.kind.isTransfer {
            mutex.lock(); transfersDetected += 1; mutex.unlock()
        }
        return result
    }

    // MARK: - Arrival handling

    private func holdArrival(_ event: FileEvent, klass: VolumeClass) {
        guard !event.isDirectory else { return }
        mutex.lock()
        pendingArrivals[event.path] = PendingArrival(event: event, volumeClass: klass, arrivedAt: Date())
        mutex.unlock()
    }

    private func recordCandidate(_ event: FileEvent, klass: VolumeClass, departed: Bool) {
        guard !event.isDirectory, let size = event.size, size > 0 else { return }
        let key = Self.key(name: (event.path as NSString).lastPathComponent, size: size)
        let candidate = Candidate(path: event.path, volumeID: event.volumeID, volumeClass: klass,
                                  size: size, seenAt: Date(), inode: event.inode, departed: departed)
        mutex.lock()
        var list = byNameSize[key] ?? []
        list.removeAll { $0.path == event.path }
        list.append(candidate)
        byNameSize[key] = list
        mutex.unlock()
    }

    /// A deletion right before or after an arrival elsewhere is what
    /// distinguishes a move from a copy.
    private func markDeparted(_ event: FileEvent, klass: VolumeClass) {
        guard let size = event.size, size > 0 else {
            // The file is already gone, so its size is unknown; fall back to
            // flagging every same-named candidate as departed.
            mutex.lock()
            let name = (event.path as NSString).lastPathComponent
            for (key, var list) in byNameSize where key.hasPrefix(name + "\u{1}") {
                for i in list.indices where list[i].path == event.path {
                    list[i].departed = true
                }
                byNameSize[key] = list
            }
            mutex.unlock()
            return
        }
        let key = Self.key(name: (event.path as NSString).lastPathComponent, size: size)
        mutex.lock()
        if var list = byNameSize[key] {
            for i in list.indices where list[i].path == event.path {
                list[i].departed = true
                list[i].seenAt = Date()
            }
            byNameSize[key] = list
        }
        mutex.unlock()
    }

    // MARK: - Settle and resolve

    private func drainSettled() {
        let now = Date()
        var toResolve: [PendingArrival] = []
        var orphanRenames: [FileEvent] = []

        mutex.lock()
        for (path, pending) in pendingArrivals
        where now.timeIntervalSince(pending.arrivedAt) >= config.settleInterval {
            pendingArrivals.removeValue(forKey: path)
            toResolve.append(pending)
        }
        // Rename halves that never found their partner.
        for (inode, event) in pendingRenames
        where now.timeIntervalSince(event.timestamp) >= config.settleInterval {
            pendingRenames.removeValue(forKey: inode)
            orphanRenames.append(event)
        }
        // Expire stale bookkeeping.
        let cutoff = now.addingTimeInterval(-config.correlationWindow)
        for (key, list) in byNameSize {
            let kept = list.filter { $0.seenAt > cutoff }
            if kept.isEmpty { byNameSize.removeValue(forKey: key) } else { byNameSize[key] = kept }
        }
        recentlyResolved = recentlyResolved.filter { $0.value > cutoff }
        if byNameSize.count > config.maxTrackedFiles {
            let sorted = byNameSize.sorted { ($0.value.last?.seenAt ?? .distantPast) < ($1.value.last?.seenAt ?? .distantPast) }
            for (key, _) in sorted.prefix(byNameSize.count - config.maxTrackedFiles) {
                byNameSize.removeValue(forKey: key)
            }
        }
        mutex.unlock()

        for orphan in orphanRenames { onTransfer?(orphan) }
        for pending in toResolve {
            if let finding = resolve(pending) { onTransfer?(finding) }
        }
    }

    /// Looks for the source of a settled arrival.
    private func resolve(_ pending: PendingArrival) -> FileEvent? {
        var event = pending.event
        let path = event.path

        mutex.lock()
        let alreadyDone = recentlyResolved[path] != nil
        mutex.unlock()
        if alreadyDone { return nil }

        // Re-stat: the file has finished being written, so this is its real size.
        var finalSize = event.size ?? 0
        var st = stat()
        if lstat(path, &st) == 0 {
            finalSize = Int64(st.st_size)
            event.size = finalSize
        } else {
            return nil  // vanished during the settle window; nothing to report
        }
        guard finalSize > 0 else { return nil }

        let destClass = pending.volumeClass
        let key = Self.key(name: (path as NSString).lastPathComponent, size: finalSize)

        mutex.lock()
        let candidates = (byNameSize[key] ?? []).filter {
            $0.path != path && $0.volumeID != event.volumeID
        }
        mutex.unlock()

        // Prefer a departed source (that makes it a move) over a live one.
        let ordered = candidates.sorted { a, b in
            if a.departed != b.departed { return a.departed }
            return a.seenAt > b.seenAt
        }

        guard let source = ordered.first else {
            // Nothing observed. For arrivals on off-machine media it is worth
            // asking Spotlight, because a plain copy leaves no event on the
            // source side for the index to have picked up.
            guard destClass.isOffMachine, destClass != .network else { return nil }
            mutex.lock(); recentlyResolved[path] = Date(); mutex.unlock()

            if config.useSpotlightFallback {
                let snapshot = event
                lookupQueue.async { [weak self] in
                    guard let self else { return }
                    let finding = self.locateViaSpotlight(event: snapshot, destClass: destClass)
                        ?? self.unattributedArrival(snapshot, destClass: destClass)
                    self.mutex.lock(); self.transfersDetected += 1; self.mutex.unlock()
                    self.onTransfer?(finding)
                }
                return nil   // delivered asynchronously once the lookup finishes
            }
            mutex.lock(); transfersDetected += 1; mutex.unlock()
            return unattributedArrival(event, destClass: destClass)
        }

        let isMove = source.departed && !FileManager.default.fileExists(atPath: source.path)
        var confidence: Confidence = isMove ? .high : .medium

        // Upgrade a name+size match to a content match when the source is still
        // readable and cheap to sample.
        if !isMove, FileManager.default.fileExists(atPath: source.path) {
            let skip = config.skipDigestOnNetwork &&
                (source.volumeClass == .network || destClass == .network)
            if !skip,
               let a = contentDigest(path: source.path, size: source.size),
               let b = contentDigest(path: path, size: finalSize) {
                confidence = (a == b) ? .high : .low
                if confidence == .low {
                    // Same name and size but different bytes — not a copy.
                    mutex.lock(); recentlyResolved[path] = Date(); mutex.unlock()
                    return nil
                }
            }
        }

        event.sourcePath = source.path
        event.sourceVolumeID = source.volumeID
        event.confidence = confidence
        event.kind = Self.transferKind(sourceClass: source.volumeClass, destClass: destClass,
                                       isMove: isMove, sameVolume: source.volumeID == event.volumeID)
        event.severity = Self.severity(for: event.kind, destClass: destClass)

        mutex.lock()
        recentlyResolved[path] = Date()
        transfersDetected += 1
        mutex.unlock()
        return event
    }

    // MARK: - Spotlight fallback

    /// A file appeared on external media and we never saw where it came from.
    ///
    /// Framing matters: from this Mac's point of view a file landing on
    /// removable media is data leaving, not arriving, so it is reported as
    /// Copied Out even though the source is unknown.
    func testUnattributedArrival(_ event: FileEvent, destClass: VolumeClass) -> FileEvent {
        unattributedArrival(event, destClass: destClass)
    }

    private func unattributedArrival(_ event: FileEvent, destClass: VolumeClass) -> FileEvent {
        var result = event
        result.kind = .copiedOut
        result.sourcePath = nil
        result.sourceVolumeID = nil
        result.confidence = .low
        result.severity = .notice
        return result
    }

    /// Asks Spotlight for same-named files elsewhere and confirms one by size
    /// and content digest.
    private func locateViaSpotlight(event: FileEvent, destClass: VolumeClass) -> FileEvent? {
        let name = (event.path as NSString).lastPathComponent
        guard let size = event.size, size > 0 else { return nil }

        let candidates = locator.findByName(name)
            .filter { $0.path != event.path && $0.size == size }
        guard !candidates.isEmpty else { return nil }

        let destinationDigest = contentDigest(path: event.path, size: size)

        for candidate in candidates {
            guard let volume = registry?.volume(for: candidate.path) else { continue }
            // Must be a different volume, or it is not a transfer at all.
            guard volume.id != event.volumeID else { continue }

            var confidence: Confidence = .medium
            if let destinationDigest,
               let sourceDigest = contentDigest(path: candidate.path, size: candidate.size) {
                guard sourceDigest == destinationDigest else { continue }
                confidence = .high
            }

            var result = event
            result.sourcePath = candidate.path
            result.sourceVolumeID = volume.id
            result.confidence = confidence
            result.kind = Self.transferKind(sourceClass: volume.volumeClass, destClass: destClass,
                                            isMove: false, sameVolume: false)
            result.severity = Self.severity(for: result.kind, destClass: destClass)
            return result
        }
        return nil
    }

    // MARK: - Digest

    /// Size plus the head and tail of the file. Cheap regardless of file size and
    /// good enough to tell two same-named, same-sized files apart.
    private func contentDigest(path: String, size: Int64) -> Data? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        withUnsafeBytes(of: size.littleEndian) { hasher.update(bufferPointer: $0) }

        if size <= config.wholeFileDigestLimit {
            guard let data = try? handle.readToEnd() else { return nil }
            hasher.update(data: data)
        } else {
            guard let head = try? handle.read(upToCount: config.digestSampleBytes) else { return nil }
            hasher.update(data: head)
            let tailOffset = UInt64(max(0, size - Int64(config.digestSampleBytes)))
            guard (try? handle.seek(toOffset: tailOffset)) != nil,
                  let tail = try? handle.read(upToCount: config.digestSampleBytes) else { return nil }
            hasher.update(data: tail)
        }
        return Data(hasher.finalize())
    }

    // MARK: - Helpers

    private static func key(name: String, size: Int64) -> String { "\(name)\u{1}\(size)" }

    static func transferKind(sourceClass: VolumeClass, destClass: VolumeClass,
                             isMove: Bool, sameVolume: Bool) -> EventKind {
        if sameVolume { return isMove ? .renamed : .cloned }
        // Frame the event from the machine's point of view: data leaving the
        // internal disk is the case that matters.
        if !sourceClass.isOffMachine && destClass.isOffMachine {
            return isMove ? .movedOut : .copiedOut
        }
        if sourceClass.isOffMachine && !destClass.isOffMachine {
            return isMove ? .movedIn : .copiedIn
        }
        return isMove ? .movedIn : .copiedIn
    }

    static func severity(for kind: EventKind, destClass: VolumeClass) -> Severity {
        switch kind {
        case .copiedOut, .movedOut: return .warning
        case .copiedIn, .movedIn:   return destClass.isOffMachine ? .notice : .info
        default:                    return .info
        }
    }
}
