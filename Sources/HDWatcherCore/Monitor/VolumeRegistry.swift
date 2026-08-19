import Foundation
import AppKit
import DiskArbitration

/// Tracks mounted volumes and answers "which volume does this path live on?"
///
/// Attribution has to be cheap: at peak the monitor sees thousands of paths a
/// second, so per-event `URLResourceValues` lookups are out. Instead the registry
/// builds a mount-point prefix table whenever the mount set changes and does a
/// pure string longest-prefix match per event.
public final class VolumeRegistry: @unchecked Sendable {

    private let mutex = NSLock()
    private var volumes: [String: VolumeInfo] = [:]          // id -> info
    private var prefixTable: [(mount: String, id: String)] = []   // longest first
    private var history: [VolumeInfo] = []
    private var lastMountPoints: Set<String> = []
    /// Disk-image detection goes through DiskArbitration, which is too costly to
    /// repeat every poll. A mount point's nature does not change while mounted.
    private var diskImageCache: [String: Bool] = [:]
    private var hasCompletedInitialRefresh = false
    private var pollTimer: DispatchSourceTimer?
    private var observers: [NSObjectProtocol] = []
    private let pollQueue = DispatchQueue(label: "co.pixelworship.hdwatcher.volumes", qos: .utility)

    /// Fires once per actual change, with the volume and whether it was mounted.
    public var onVolumeChange: (@Sendable (VolumeInfo, Bool) -> Void)?

    public init() {
        refresh()
        subscribeToWorkspace()
        startPolling()
    }

    deinit {
        pollTimer?.cancel()
        let center = NSWorkspace.shared.notificationCenter
        for observer in observers { center.removeObserver(observer) }
    }

    /// Mount notifications can be missed — a drive yanked without ejecting, a
    /// notification dropped while the app was busy. Polling the mount table is
    /// the ground truth, and it is only a syscall plus a set comparison.
    private func startPolling() {
        let timer = DispatchSource.makeTimerSource(queue: pollQueue)
        timer.schedule(deadline: .now() + 3, repeating: 3)
        timer.setEventHandler { [weak self] in self?.refreshIfChanged() }
        timer.resume()
        pollTimer = timer
    }

    /// Cheap check: only does the real work when the mount table actually moved.
    public func refreshIfChanged() {
        let current = Set(Self.allMountPoints())
        mutex.lock()
        let known = lastMountPoints
        mutex.unlock()
        guard current != known else { return }
        refresh()
    }

    // MARK: - Lookup

    /// Volumes a person would recognise: the startup disk, external drives,
    /// removable media, network shares and mounted images.
    public var mountedVolumes: [VolumeInfo] {
        mutex.lock(); defer { mutex.unlock() }
        return Self.sorted(volumes.values.filter { $0.isMounted && !$0.isSystemVolume })
    }

    /// The macOS plumbing, available behind a toggle.
    public var systemVolumes: [VolumeInfo] {
        mutex.lock(); defer { mutex.unlock() }
        return Self.sorted(volumes.values.filter { $0.isMounted && $0.isSystemVolume })
    }

    private static func sorted(_ values: [VolumeInfo]) -> [VolumeInfo] {
        values.sorted { a, b in
            if a.isRootVolume != b.isRootVolume { return a.isRootVolume }
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
    }

    public var volumeHistory: [VolumeInfo] {
        mutex.lock(); defer { mutex.unlock() }
        return history.sorted { $0.firstSeen > $1.firstSeen }
    }

    public func volume(for path: String) -> VolumeInfo? {
        mutex.lock()
        let table = prefixTable
        let vols = volumes
        mutex.unlock()

        for entry in table {
            if entry.mount == "/" {
                if let v = vols[entry.id] { return v }
                continue
            }
            if path.hasPrefix(entry.mount),
               path.count == entry.mount.count || path[path.index(path.startIndex, offsetBy: entry.mount.count)] == "/" {
                return vols[entry.id]
            }
        }
        return nil
    }

    /// Falls back to the session's volume history, so a drive that has since
    /// been ejected still shows its name against past events instead of
    /// appearing as an unknown volume.
    public func volume(id: String) -> VolumeInfo? {
        mutex.lock(); defer { mutex.unlock() }
        if let mounted = volumes[id] { return mounted }
        return history.first { $0.id == id }
    }

    public func volumeClass(for path: String) -> VolumeClass {
        volume(for: path)?.volumeClass ?? .unknown
    }

    /// Mount points worth handing to FSEvents. Watching a volume root covers
    /// everything beneath it, so nested mounts are dropped.
    public var watchRoots: [String] {
        let mounts = mountedVolumes.map(\.mountPath).sorted { $0.count < $1.count }
        var roots: [String] = []
        for mount in mounts {
            let covered = roots.contains { root in
                root == "/" || mount == root || mount.hasPrefix(root + "/")
            }
            if !covered { roots.append(mount) }
        }
        return roots
    }

    // MARK: - Refresh

    public func refresh() {
        let keys: [URLResourceKey] = [
            .volumeNameKey, .volumeIsRemovableKey, .volumeIsEjectableKey,
            .volumeIsInternalKey, .volumeIsLocalKey, .volumeTotalCapacityKey,
            .volumeAvailableCapacityKey, .volumeUUIDStringKey,
            .volumeIsRootFileSystemKey, .volumeLocalizedFormatDescriptionKey
        ]

        var discovered: [String: VolumeInfo] = [:]
        var table: [(mount: String, id: String)] = []
        let mountPoints = Self.allMountPoints()

        mutex.lock()
        let cache = diskImageCache
        mutex.unlock()
        var updatedCache = cache

        // `.skipHiddenVolumes` is what separates "a volume" in the everyday
        // sense from the Preboot/VM/Update partitions macOS keeps mounted.
        // Without it the list fills with plumbing the user never asked about.
        let urls = FileManager.default.mountedVolumeURLs(
            includingResourceValuesForKeys: keys, options: [.skipHiddenVolumes]
        ) ?? []

        var rootVolumeID: String?
        for url in urls {
            guard let info = Self.describe(url: url, keys: keys, cache: &updatedCache) else { continue }
            discovered[info.id] = info
            table.append((info.mountPath, info.id))
            if info.isRootVolume { rootVolumeID = info.id }
        }

        // Everything else in the mount table is system plumbing. It still needs
        // to be in the prefix table so paths resolve, but it is flagged so the
        // UI can keep it out of the way.
        for mount in mountPoints {
            if table.contains(where: { $0.mount == mount }) { continue }
            if mount == "/System/Volumes/Data", let rootID = rootVolumeID {
                // To a user, files under /Users live on the startup disk.
                table.append((mount, rootID))
            } else if var info = Self.describe(url: URL(fileURLWithPath: mount),
                                               keys: keys, cache: &updatedCache) {
                info.isSystemVolume = true
                discovered[info.id] = info
                table.append((mount, info.id))
            }
        }

        table.sort { $0.mount.count > $1.mount.count }

        mutex.lock()
        let previous = volumes
        let firstRun = !hasCompletedInitialRefresh
        hasCompletedInitialRefresh = true

        for (id, info) in discovered where !info.isSystemVolume {
            if !history.contains(where: { $0.id == id }) { history.append(info) }
        }
        for i in history.indices {
            history[i].isMounted = discovered[history[i].id] != nil
        }
        volumes = discovered
        prefixTable = table
        lastMountPoints = Set(mountPoints)
        diskImageCache = updatedCache.filter { entry in mountPoints.contains(entry.key) }
        mutex.unlock()

        guard !firstRun else { return }

        // Mount and unmount events come from this diff alone. Deriving them here
        // rather than from the workspace notification means one physical action
        // produces exactly one event, however the change was noticed.
        for (id, info) in discovered where !info.isSystemVolume && previous[id] == nil {
            onVolumeChange?(info, true)
        }
        for (id, info) in previous where !info.isSystemVolume && discovered[id] == nil {
            onVolumeChange?(info, false)
        }
    }

    private static func describe(url: URL, keys: [URLResourceKey],
                                 cache: inout [String: Bool]) -> VolumeInfo? {
        guard let values = try? url.resourceValues(forKeys: Set(keys)) else { return nil }
        let mountPath = url.path
        let id = values.volumeUUIDString ?? mountPath
        let isRoot = values.volumeIsRootFileSystem ?? (mountPath == "/")
        let isLocal = values.volumeIsLocal ?? true
        let isInternal = values.volumeIsInternal ?? false
        let isEjectable = values.volumeIsEjectable ?? false
        let isRemovable = values.volumeIsRemovable ?? false

        var klass: VolumeClass
        if !isLocal {
            klass = .network
        } else if isRoot || isInternal {
            klass = .internalDisk
        } else if Self.cachedIsDiskImage(mountPath: mountPath, cache: &cache) {
            klass = .diskImage
        } else if isRemovable || isEjectable {
            klass = .removable
        } else {
            klass = .externalDisk
        }

        return VolumeInfo(
            id: id,
            name: values.volumeName ?? (mountPath as NSString).lastPathComponent,
            mountPath: mountPath,
            volumeClass: klass,
            isRootVolume: isRoot,
            totalCapacity: Int64(values.volumeTotalCapacity ?? 0),
            availableCapacity: Int64(values.volumeAvailableCapacity ?? 0),
            formatDescription: values.volumeLocalizedFormatDescription ?? ""
        )
    }

    private static func cachedIsDiskImage(mountPath: String, cache: inout [String: Bool]) -> Bool {
        if let known = cache[mountPath] { return known }
        let result = isDiskImage(mountPath: mountPath)
        cache[mountPath] = result
        return result
    }

    /// Disk images surface through DiskArbitration as a virtual interface, which
    /// distinguishes a mounted .dmg from a real USB drive.
    private static func isDiskImage(mountPath: String) -> Bool {
        guard let session = DASessionCreate(kCFAllocatorDefault),
              let url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, mountPath as CFString, .cfurlposixPathStyle, true),
              let disk = DADiskCreateFromVolumePath(kCFAllocatorDefault, session, url),
              let desc = DADiskCopyDescription(disk) as? [String: Any] else {
            return false
        }
        let protocolName = desc[kDADiskDescriptionDeviceProtocolKey as String] as? String ?? ""
        let model = desc[kDADiskDescriptionDeviceModelKey as String] as? String ?? ""
        return protocolName == "Virtual Interface" || model == "Disk Image"
    }

    /// Every mount point, including ones `mountedVolumeURLs` hides such as
    /// /System/Volumes/Data.
    private static func allMountPoints() -> [String] {
        var buffer: UnsafeMutablePointer<statfs>?
        let count = getmntinfo(&buffer, MNT_NOWAIT)
        guard count > 0, let buffer else { return [] }
        var out: [String] = []
        for i in 0..<Int(count) {
            var entry = buffer[i]
            let path = withUnsafePointer(to: &entry.f_mntonname) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
            }
            out.append(path)
        }
        return out
    }

    // MARK: - Mount notifications

    private func subscribeToWorkspace() {
        let center = NSWorkspace.shared.notificationCenter
        // These only make the poll react faster; `refresh()` is what decides
        // what actually changed, so a missed notification costs latency, not
        // correctness.
        for name in [NSWorkspace.didMountNotification, NSWorkspace.didUnmountNotification] {
            let token = center.addObserver(forName: name, object: nil, queue: nil) { [weak self] _ in
                self?.refresh()
            }
            observers.append(token)
        }
    }
}
