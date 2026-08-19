import Foundation
import CoreServices

/// A single raw change straight out of FSEvents, before classification.
public struct RawFSEvent: Sendable {
    public let path: String
    public let flags: FSEventStreamEventFlags
    public let eventID: FSEventStreamEventId
    public let inode: UInt64?
}

/// Wraps an FSEventStream covering every watched volume.
///
/// The stream is created with `FileEvents` (per-file rather than per-directory
/// granularity) and `UseExtendedData`, which adds the file's inode to each
/// event — that inode is what lets the transfer detector pair a rename's before
/// and after paths with certainty.
public final class FSEventsMonitor: @unchecked Sendable {

    public struct Statistics: Sendable {
        public var eventsReceived: UInt64 = 0
        public var batchesReceived: UInt64 = 0
        public var droppedNotifications: UInt64 = 0
        public var lastEventAt: Date?
        public var startedAt: Date?
    }

    private var stream: FSEventStreamRef?
    private let queue = DispatchQueue(label: "co.pixelworship.hdwatcher.fsevents", qos: .utility)
    private let mutex = NSLock()
    private var watchedPaths: [String] = []
    private var stats = Statistics()
    private var running = false

    /// Delivers each batch of raw events on the monitor's private queue.
    public var onEvents: (@Sendable ([RawFSEvent]) -> Void)?
    /// Fires when FSEvents reports it dropped events and a subtree needs rescanning.
    public var onRescanRequired: (@Sendable (String) -> Void)?

    public init() {}
    deinit { stop() }

    public var isRunning: Bool {
        mutex.lock(); defer { mutex.unlock() }
        return running
    }

    public var statistics: Statistics {
        mutex.lock(); defer { mutex.unlock() }
        return stats
    }

    public var currentPaths: [String] {
        mutex.lock(); defer { mutex.unlock() }
        return watchedPaths
    }

    // MARK: - Lifecycle

    @discardableResult
    public func start(paths: [String], sinceWhen: FSEventStreamEventId = FSEventStreamEventId(kFSEventStreamEventIdSinceNow), latency: CFTimeInterval = 0.3) -> Bool {
        stop()
        guard !paths.isEmpty else { return false }

        let flags = FSEventStreamCreateFlags(
            kFSEventStreamCreateFlagUseCFTypes |
            kFSEventStreamCreateFlagFileEvents |
            kFSEventStreamCreateFlagNoDefer |
            kFSEventStreamCreateFlagWatchRoot |
            kFSEventStreamCreateFlagUseExtendedData
        )

        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil, release: nil, copyDescription: nil
        )

        let callback: FSEventStreamCallback = { _, info, numEvents, eventPaths, eventFlags, eventIDs in
            guard let info else { return }
            let monitor = Unmanaged<FSEventsMonitor>.fromOpaque(info).takeUnretainedValue()
            monitor.handle(numEvents: numEvents, eventPaths: eventPaths,
                           eventFlags: eventFlags, eventIDs: eventIDs)
        }

        guard let stream = FSEventStreamCreate(
            kCFAllocatorDefault, callback, &context,
            paths as CFArray, sinceWhen, latency, flags
        ) else { return false }

        FSEventStreamSetDispatchQueue(stream, queue)
        guard FSEventStreamStart(stream) else {
            FSEventStreamInvalidate(stream)
            FSEventStreamRelease(stream)
            return false
        }

        mutex.lock()
        self.stream = stream
        self.watchedPaths = paths
        self.running = true
        self.stats.startedAt = Date()
        mutex.unlock()
        return true
    }

    public func stop() {
        mutex.lock()
        let existing = stream
        stream = nil
        running = false
        mutex.unlock()

        guard let existing else { return }
        FSEventStreamStop(existing)
        FSEventStreamInvalidate(existing)
        FSEventStreamRelease(existing)
    }

    /// Restarts the stream against a new path set — used when a volume is
    /// mounted or the user changes the watch scope.
    public func updatePaths(_ paths: [String]) {
        guard Set(paths) != Set(currentPaths) else { return }
        start(paths: paths)
    }

    // MARK: - Callback

    private func handle(
        numEvents: Int,
        eventPaths: UnsafeMutableRawPointer,
        eventFlags: UnsafePointer<FSEventStreamEventFlags>,
        eventIDs: UnsafePointer<FSEventStreamEventId>
    ) {
        guard numEvents > 0 else { return }
        // With UseCFTypes + UseExtendedData each entry is a dictionary carrying
        // the path and the file's inode.
        let array = Unmanaged<CFArray>.fromOpaque(eventPaths).takeUnretainedValue() as NSArray

        var batch: [RawFSEvent] = []
        batch.reserveCapacity(numEvents)
        var dropped: UInt64 = 0

        for i in 0..<numEvents {
            let flags = eventFlags[i]
            let eventID = eventIDs[i]

            var path: String?
            var inode: UInt64?
            if let dict = array[i] as? NSDictionary {
                path = dict[kFSEventStreamEventExtendedDataPathKey] as? String
                if let number = dict[kFSEventStreamEventExtendedFileIDKey] as? NSNumber {
                    inode = number.uint64Value
                }
            } else if let plain = array[i] as? String {
                path = plain
            }
            guard let path else { continue }

            // FSEvents overflowed its buffer; anything under this path may have
            // changed without us hearing about it.
            let mustScan = flags & FSEventStreamEventFlags(
                kFSEventStreamEventFlagMustScanSubDirs |
                kFSEventStreamEventFlagUserDropped |
                kFSEventStreamEventFlagKernelDropped
            )
            if mustScan != 0 {
                dropped += 1
                onRescanRequired?(path)
            }

            batch.append(RawFSEvent(path: path, flags: flags, eventID: eventID, inode: inode))
        }

        mutex.lock()
        stats.eventsReceived += UInt64(batch.count)
        stats.batchesReceived += 1
        stats.droppedNotifications += dropped
        stats.lastEventAt = Date()
        mutex.unlock()

        if !batch.isEmpty { onEvents?(batch) }
    }
}

// MARK: - Flag helpers

public extension FSEventStreamEventFlags {
    func has(_ flag: Int) -> Bool { self & FSEventStreamEventFlags(flag) != 0 }

    var isFile: Bool { has(kFSEventStreamEventFlagItemIsFile) }
    var isDirectory: Bool { has(kFSEventStreamEventFlagItemIsDir) }
    var isSymlink: Bool { has(kFSEventStreamEventFlagItemIsSymlink) }
    var isCreated: Bool { has(kFSEventStreamEventFlagItemCreated) }
    var isRemoved: Bool { has(kFSEventStreamEventFlagItemRemoved) }
    var isRenamed: Bool { has(kFSEventStreamEventFlagItemRenamed) }
    var isModified: Bool { has(kFSEventStreamEventFlagItemModified) }
    var isCloned: Bool { has(kFSEventStreamEventFlagItemCloned) }
    var isMetadataChange: Bool {
        has(kFSEventStreamEventFlagItemInodeMetaMod) ||
        has(kFSEventStreamEventFlagItemChangeOwner) ||
        has(kFSEventStreamEventFlagItemXattrMod) ||
        has(kFSEventStreamEventFlagItemFinderInfoMod)
    }
    var isMount: Bool { has(kFSEventStreamEventFlagMount) }
    var isUnmount: Bool { has(kFSEventStreamEventFlagUnmount) }
    var needsRescan: Bool {
        has(kFSEventStreamEventFlagMustScanSubDirs) ||
        has(kFSEventStreamEventFlagUserDropped) ||
        has(kFSEventStreamEventFlagKernelDropped)
    }

    /// Human-readable flag list, shown in the event inspector.
    var describedFlags: [String] {
        var out: [String] = []
        let map: [(Int, String)] = [
            (kFSEventStreamEventFlagItemCreated, "Created"),
            (kFSEventStreamEventFlagItemRemoved, "Removed"),
            (kFSEventStreamEventFlagItemRenamed, "Renamed"),
            (kFSEventStreamEventFlagItemModified, "Modified"),
            (kFSEventStreamEventFlagItemCloned, "Cloned"),
            (kFSEventStreamEventFlagItemInodeMetaMod, "InodeMetaMod"),
            (kFSEventStreamEventFlagItemChangeOwner, "ChangeOwner"),
            (kFSEventStreamEventFlagItemXattrMod, "XattrMod"),
            (kFSEventStreamEventFlagItemFinderInfoMod, "FinderInfoMod"),
            (kFSEventStreamEventFlagItemIsFile, "IsFile"),
            (kFSEventStreamEventFlagItemIsDir, "IsDir"),
            (kFSEventStreamEventFlagItemIsSymlink, "IsSymlink"),
            (kFSEventStreamEventFlagItemIsHardlink, "IsHardlink"),
            (kFSEventStreamEventFlagItemIsLastHardlink, "IsLastHardlink"),
            (kFSEventStreamEventFlagMount, "Mount"),
            (kFSEventStreamEventFlagUnmount, "Unmount"),
            (kFSEventStreamEventFlagRootChanged, "RootChanged"),
            (kFSEventStreamEventFlagMustScanSubDirs, "MustScanSubDirs"),
            (kFSEventStreamEventFlagUserDropped, "UserDropped"),
            (kFSEventStreamEventFlagKernelDropped, "KernelDropped"),
        ]
        for (bit, name) in map where has(bit) { out.append(name) }
        return out
    }
}
