import Foundation
import CryptoKit

/// The running system: takes raw FSEvents, classifies them, infers transfers,
/// evaluates alert rules, and fans the result out to the encrypted log, the
/// analytics counters and the UI.
///
/// Everything downstream of the FSEvents callback happens on a private serial
/// queue, so a burst of filesystem activity never touches the main thread.
public final class WatcherEngine: @unchecked Sendable {

    public struct Status: Sendable {
        public var isMonitoring = false
        public var watchedPaths: [String] = []
        public var eventsProcessed: UInt64 = 0
        public var eventsDropped: UInt64 = 0
        public var eventsFiltered: UInt64 = 0
        public var transfersDetected: Int = 0
        public var alertsRaised: Int = 0
        public var startedAt: Date?
        public var lastEventAt: Date?
        public var pendingWrites: Int = 0
        public init() {}
    }

    // Components
    public let registry = VolumeRegistry()
    public let hotspots: HotspotTracker
    public let stats = ActivityStats()
    public let notifier = Notifier()
    public private(set) var ruleEngine: RuleEngine!
    private let monitor = FSEventsMonitor()
    /// A second stream, near-zero latency, over the handful of paths worth
    /// auditing. Attribution evidence decays in seconds, so the main stream's
    /// coalescing latency is too slow to catch the responsible process.
    private let sentinel = FSEventsMonitor()
    public let processAuditor = ProcessAuditor()
    private var detector: TransferDetector!
    private var normalizer: EventNormalizer
    private let store: EventStore
    public let contentVault: ContentVault?
    /// Content capture reads and hashes files, so it never runs on the pipeline
    /// queue where it would delay logging and alerting.
    private let captureQueue = DispatchQueue(label: "co.pixelworship.hdwatcher.capture", qos: .background)
    private var captureBacklog = 0
    private let captureBacklogLimit = 512

    private let queue = DispatchQueue(label: "co.pixelworship.hdwatcher.engine", qos: .utility)
    private let mutex = NSLock()
    private var settings: AppSettings
    private var status = Status()
    private var maintenanceTimer: DispatchSourceTimer?

    // Rate limiting
    private var rateWindowStart = Date()
    private var rateWindowCount = 0

    /// Highest FSEvents id seen, persisted so a restart can resume from it.
    private var highestEventID: UInt64 = 0
    private var lastCursorSave = Date.distantPast

    /// Attribution captured by the sentinel, keyed by path, waiting for the
    /// matching event to come through the main pipeline.
    private var pendingAttribution: [String: AttributionResult] = [:]
    private var lastSentinelScan: [String: Date] = [:]
    private let attributionQueue = DispatchQueue(label: "co.pixelworship.hdwatcher.attribution",
                                                 qos: .userInitiated)

    // Callbacks to the UI layer
    public var onEvents: (@Sendable ([FileEvent]) -> Void)?
    public var onAlert: (@Sendable (SecurityAlert) -> Void)?
    public var onVolumeChange: (@Sendable (VolumeInfo, Bool) -> Void)?
    public var onStatusChange: (@Sendable (Status) -> Void)?

    /// Seals the cursor: the app uses its settings key, the daemon its own
    /// enclave identity.
    private let cursorKey: SymmetricKey?

    public init(store: EventStore, settings: AppSettings, rules: [AlertRule],
                keys: VaultKeys? = nil,
                contentRecipient: P256.KeyAgreement.PublicKey? = nil) {
        self.cursorKey = keys?.settings
        self.store = store
        self.settings = settings
        self.normalizer = EventNormalizer(settings: settings.filter)

        if settings.captureFileContents {
            var vaultConfig = ContentVault.Configuration()
            vaultConfig.retention = settings.contentRetention
            vaultConfig.maxFileBytes = settings.maxCaptureFileBytes
            vaultConfig.maxContainerBytes = Int64(settings.maxContentVaultMegabytes) * 1_048_576
            vaultConfig.debounceSeconds = settings.captureDebounceSeconds
            vaultConfig.includePatterns = settings.captureIncludePatterns
            vaultConfig.excludePatterns = settings.captureExcludePatterns

            if let keys {
                self.contentVault = ContentVault(keys: keys, config: vaultConfig)
            } else if let contentRecipient {
                // The daemon: captures it cannot read back, exactly like the log.
                self.contentVault = ContentVault(sealMode: .writeOnly(recipient: contentRecipient),
                                                 url: AppPaths.agentContentVaultFile,
                                                 config: vaultConfig)
            } else {
                self.contentVault = nil
            }
        } else {
            self.contentVault = nil
        }

        var hotspotConfig = HotspotTracker.Configuration()
        hotspotConfig.halfLife = TimeInterval(settings.hotspotHalfLifeMinutes * 60)
        self.hotspots = HotspotTracker(config: hotspotConfig)

        self.ruleEngine = RuleEngine(registry: registry, rules: rules)

        var detectorConfig = TransferDetector.Configuration()
        detectorConfig.settleInterval = settings.transferSettleSeconds
        detectorConfig.correlationWindow = settings.transferCorrelationWindowSeconds
        self.detector = TransferDetector(registry: registry, config: detectorConfig)

        wireUp()
    }

    deinit {
        maintenanceTimer?.cancel()
        monitor.stop()
    }

    private func wireUp() {
        monitor.onEvents = { [weak self] raw in
            self?.queue.async { self?.process(raw: raw) }
        }
        monitor.onRescanRequired = { [weak self] path in
            guard let self else { return }
            let event = FileEvent(kind: .rescan, path: path,
                                  volumeID: self.registry.volume(for: path)?.id,
                                  isDirectory: true, severity: .warning)
            self.queue.async { self.emit([event]) }
        }
        // Deferred transfer findings arrive after the settle window.
        detector.onTransfer = { [weak self] event in
            self?.queue.async { self?.emit([event]) }
        }
        registry.onVolumeChange = { [weak self] volume, mounted in
            self?.handleVolumeChange(volume, mounted: mounted)
        }
        // The sentinel exists purely to run attribution while the evidence is
        // still there; its events are not logged from here.
        sentinel.onEvents = { [weak self] raw in
            self?.attributionQueue.async { self?.captureAttribution(for: raw) }
        }
    }

    // MARK: - Process attribution

    /// Directories the sentinel watches: the parents of every audited pattern.
    private func sentinelPaths() -> [String] {
        let patterns = ruleEngine.auditedPathPatterns().map(\.pattern)
        var roots = Set<String>()
        for pattern in patterns {
            // Reduce "~/.ssh/**" to the deepest real directory we can watch.
            var candidate = pattern.hasPrefix("~/")
                ? NSHomeDirectory() + pattern.dropFirst(1)
                : pattern
            while let range = candidate.range(of: "/", options: .backwards) {
                if !candidate.contains("*") { break }
                candidate = String(candidate[candidate.startIndex..<range.lowerBound])
            }
            guard !candidate.isEmpty, !candidate.contains("*") else { continue }
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: candidate, isDirectory: &isDirectory),
               isDirectory.boolValue {
                roots.insert(AppPaths.canonicalPath(candidate))
            }
        }
        return Array(roots)
    }

    /// Attributes a fresh arrival on off-machine media, before the process that
    /// wrote it moves on.
    private func captureArrivalAttribution(for event: FileEvent) {
        guard contentVaultIsIrrelevant(event) else { return }
        guard event.kind == .created || event.kind == .modified || event.kind == .cloned else { return }
        guard !event.isDirectory else { return }
        let klass = registry.volume(id: event.volumeID ?? "")?.volumeClass
            ?? registry.volumeClass(for: event.path)
        guard klass.isOffMachine, klass != .network else { return }

        let now = Date()
        mutex.lock()
        let recent = lastSentinelScan[event.path]
        let saturated = pendingAttribution.count > 400
        if recent == nil && !saturated { lastSentinelScan[event.path] = now }
        mutex.unlock()
        guard recent == nil || now.timeIntervalSince(recent!) > 1.0, !saturated else { return }

        let path = event.path
        attributionQueue.async { [weak self] in
            guard let self else { return }
            let result = self.processAuditor.attribute(path: path, at: now)
            guard !result.isEmpty || result.blockedByPrivileges else { return }
            self.mutex.lock(); self.pendingAttribution[path] = result; self.mutex.unlock()
        }
    }

    /// Small readability helper: attribution here is about transfers, not the
    /// content vault.
    private func contentVaultIsIrrelevant(_ event: FileEvent) -> Bool { true }

    /// Looks for a just-deleted file in the Trash, so its contents can still be
    /// captured. Only the same file name is considered, and only if it appeared
    /// recently enough to plausibly be the same file.
    static func trashCandidate(for path: String) -> String? {
        let name = (path as NSString).lastPathComponent
        guard !name.isEmpty, !TrashPaths.isTrash(path) else { return nil }

        var candidates = [URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent(".Trash", isDirectory: true)
            .appendingPathComponent(name)]
        // Volumes keep their own per-user trash.
        if path.hasPrefix("/Volumes/") {
            let parts = (path as NSString).pathComponents
            if parts.count > 2 {
                candidates.append(URL(fileURLWithPath: "/Volumes/\(parts[2])/.Trashes/\(getuid())")
                    .appendingPathComponent(name))
            }
        }

        for candidate in candidates {
            var info = stat()
            guard lstat(candidate.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { continue }
            // Must have arrived in the last little while, or it is a different
            // file that merely shares a name.
            let changed = Date(timeIntervalSince1970: TimeInterval(info.st_ctimespec.tv_sec))
            guard Date().timeIntervalSince(changed) < 60 else { continue }
            return candidate.path
        }
        return nil
    }

    private func captureAttribution(for batch: [RawFSEvent]) {
        let now = Date()
        for raw in batch {
            mutex.lock()
            let recent = lastSentinelScan[raw.path]
            mutex.unlock()
            // One scan per path per second is plenty; a burst of writes to the
            // same file does not need re-scanning each time.
            if let recent, now.timeIntervalSince(recent) < 1.0 { continue }

            mutex.lock(); lastSentinelScan[raw.path] = now; mutex.unlock()

            let result = processAuditor.attribute(path: raw.path, at: now)
            guard !result.isEmpty || result.blockedByPrivileges else { continue }

            mutex.lock()
            pendingAttribution[raw.path] = result
            if pendingAttribution.count > 512 {
                let cutoff = now.addingTimeInterval(-120)
                pendingAttribution = pendingAttribution.filter { _ in true }
                lastSentinelScan = lastSentinelScan.filter { $0.value > cutoff }
            }
            mutex.unlock()
        }
    }

    /// Attaches attribution to an event: the sentinel's capture if there is one,
    /// otherwise a fresh scan for events that asked for it.
    private func attachAttribution(to event: inout FileEvent) {
        mutex.lock()
        let captured = pendingAttribution.removeValue(forKey: event.path)
        mutex.unlock()

        if let captured {
            event.attribution = captured
            return
        }
        // Cross-volume movement is inherently worth attributing, so it does not
        // depend on a rule opting in.
        guard event.kind.isTransfer || ruleEngine.wantsProcessAudit(for: event) else { return }
        event.attribution = processAuditor.attribute(path: event.path, at: event.timestamp)
    }

    // MARK: - Lifecycle

    @discardableResult
    public func start() -> Bool {
        registry.refresh()
        let paths = resolveWatchPaths()
        guard !paths.isEmpty else { return false }

        // Resume where we left off so changes made while the watcher was down
        // are replayed rather than silently missed.
        let cursor = EventCursor.load(settingsKey: cursorKey)
        let resumeFrom = cursor?.lastEventID ?? 0
        let sinceWhen = resumeFrom > 0
            ? FSEventStreamEventId(resumeFrom)
            : FSEventStreamEventId(kFSEventStreamEventIdSinceNow)

        let ok = monitor.start(paths: paths, sinceWhen: sinceWhen)
        // Latency near zero, so a process can still be holding the file when
        // we look.
        let audited = sentinelPaths()
        if !audited.isEmpty {
            sentinel.start(paths: audited, latency: 0.02)
        }
        mutex.lock()
        status.isMonitoring = ok
        status.watchedPaths = paths
        status.startedAt = ok ? Date() : nil
        let snapshot = status
        mutex.unlock()

        if ok {
            startMaintenance()
            recordMonitoringMarker(.monitoringStarted, cursor: cursor, paths: paths)
        }
        onStatusChange?(snapshot)
        return ok
    }

    /// Writes a marker so the log itself says when recording began or ended, and
    /// how long the gap before it was. An audit trail with unexplained holes is
    /// worse than one that admits to them.
    private func recordMonitoringMarker(_ kind: EventKind, cursor: EventCursor?,
                                        paths: [String], synchronously: Bool = false) {
        var detail: [String] = []
        if kind == .monitoringStarted {
            if let gap = cursor?.gapDuration, gap > 60 {
                detail.append("resumed after \(Self.describe(gap)) not watching")
                if (cursor?.lastEventID ?? 0) > 0 {
                    detail.append("replaying changes since the last recorded event")
                }
            } else if cursor?.lastEventID ?? 0 > 0 {
                detail.append("resumed from the saved position")
            } else {
                detail.append("started from now; earlier activity was not recorded")
            }
            detail.append("watching \(paths.count) root(s)")
        } else {
            detail.append("recording stopped")
        }

        let severity: Severity = (cursor?.gapDuration ?? 0) > 300 ? .notice : .info
        let event = FileEvent(
            kind: kind,
            path: paths.first ?? "/",
            isDirectory: true,
            severity: severity,
            ruleHits: detail
        )
        if synchronously {
            emit([event])
        } else {
            queue.async { [weak self] in self?.emit([event]) }
        }
    }

    static func describe(_ interval: TimeInterval) -> String {
        if interval < 90 { return "\(Int(interval))s" }
        if interval < 3_600 { return "\(Int(interval / 60))m" }
        if interval < 172_800 { return "\(Int(interval / 3_600))h" }
        return "\(Int(interval / 86_400))d"
    }

    public func stop() {
        // Persist the position first: if anything below throws or hangs, the
        // cursor is still correct.
        persistCursor(stopping: true)
        mutex.lock()
        let wasMonitoring = status.isMonitoring
        let paths = status.watchedPaths
        mutex.unlock()
        if wasMonitoring {
            recordMonitoringMarker(.monitoringStopped, cursor: nil, paths: paths,
                                   synchronously: true)
        }

        monitor.stop()
        sentinel.stop()
        maintenanceTimer?.cancel()
        maintenanceTimer = nil
        store.flush()
        contentVault?.close()

        mutex.lock()
        status.isMonitoring = false
        let snapshot = status
        mutex.unlock()
        onStatusChange?(snapshot)
    }

    public var currentStatus: Status {
        mutex.lock()
        var snapshot = status
        mutex.unlock()
        snapshot.transfersDetected = detector.transfersDetected
        return snapshot
    }

    public var monitorStatistics: FSEventsMonitor.Statistics { monitor.statistics }

    public func updateSettings(_ newSettings: AppSettings) {
        let scopeChanged = newSettings.watchScope != settings.watchScope
            || newSettings.customWatchPaths != settings.customWatchPaths
        let filterChanged = newSettings.filter != settings.filter

        mutex.lock()
        settings = newSettings
        mutex.unlock()

        if filterChanged {
            normalizer = EventNormalizer(settings: newSettings.filter)
        }
        if let contentVault {
            var vaultConfig = ContentVault.Configuration()
            vaultConfig.retention = newSettings.contentRetention
            vaultConfig.maxFileBytes = newSettings.maxCaptureFileBytes
            vaultConfig.maxContainerBytes = Int64(newSettings.maxContentVaultMegabytes) * 1_048_576
            vaultConfig.debounceSeconds = newSettings.captureDebounceSeconds
            vaultConfig.includePatterns = newSettings.captureIncludePatterns
            vaultConfig.excludePatterns = newSettings.captureExcludePatterns
            contentVault.updateConfiguration(vaultConfig)
        }
        if scopeChanged, monitor.isRunning {
            monitor.updatePaths(resolveWatchPaths())
            mutex.lock()
            status.watchedPaths = monitor.currentPaths
            mutex.unlock()
        }
    }

    /// The set of roots handed to FSEvents for the configured scope.
    public func resolveWatchPaths() -> [String] {
        mutex.lock(); let settings = self.settings; mutex.unlock()

        switch settings.watchScope {
        case .allVolumes:
            return registry.watchRoots
        case .internalOnly:
            return registry.mountedVolumes
                .filter { $0.volumeClass == .internalDisk }
                .map(\.mountPath)
        case .externalOnly:
            return registry.mountedVolumes
                .filter { $0.volumeClass.isOffMachine && $0.volumeClass != .network }
                .map(\.mountPath)
        case .customPaths:
            // FSEvents resolves symlinks before reporting, so "/tmp/x" comes
            // back as "/private/tmp/x". Canonicalise here so watch roots,
            // reported paths and user-written rules all agree.
            return settings.customWatchPaths
                .filter { FileManager.default.fileExists(atPath: $0) }
                .map { AppPaths.canonicalPath($0) }
        }
    }

    // MARK: - Pipeline

    private func process(raw batch: [RawFSEvent]) {
        mutex.lock()
        let cap = settings.maxEventsPerSecond
        mutex.unlock()

        var normalized: [FileEvent] = []
        normalized.reserveCapacity(batch.count)
        var filtered: UInt64 = 0
        var dropped: UInt64 = 0

        // Track the stream position even for events we filter out, or a quiet
        // period of pure noise would rewind the cursor.
        if let highest = batch.map(\.eventID).max() {
            mutex.lock()
            // kFSEventStreamEventIdSinceNow is UInt64.max and must never be stored.
            if highest > highestEventID, highest != UInt64.max { highestEventID = highest }
            mutex.unlock()
        }

        for raw in batch {
            guard allowRate(cap: cap) else { dropped += 1; continue }

            let volume = registry.volume(for: raw.path)
            guard let event = normalizer.normalize(raw, volume: volume) else {
                filtered += 1
                continue
            }
            // Something arriving on external media is a candidate transfer, and
            // the copying process is only still holding the file *now* — by the
            // time the settle window closes and the transfer is confirmed, the
            // evidence is usually gone. So attribute at arrival and attach it
            // later.
            captureArrivalAttribution(for: event)

            // The detector may withhold an event (one half of a rename) or
            // rewrite it with provenance.
            if let resolved = detector.ingest(event) {
                normalized.append(resolved)
            }
        }

        mutex.lock()
        status.eventsFiltered += filtered
        status.eventsDropped += dropped
        mutex.unlock()

        persistCursor(stopping: false)
        emit(normalized)
    }

    /// Applies rules, persists, and updates analytics. All emitted events pass
    /// through here — including transfer findings that surface late.
    private func emit(_ events: [FileEvent]) {
        guard !events.isEmpty else { return }

        var finalEvents: [FileEvent] = []
        finalEvents.reserveCapacity(events.count)
        var alerts: [SecurityAlert] = []

        for event in events {
            var candidate = event
            attachAttribution(to: &candidate)
            let (annotated, produced) = ruleEngine.evaluate(candidate)
            finalEvents.append(annotated)
            alerts.append(contentsOf: produced)
        }

        store.record(finalEvents)
        hotspots.record(finalEvents)
        for event in finalEvents { stats.record(event) }
        scheduleContentCapture(for: finalEvents)

        mutex.lock()
        status.eventsProcessed += UInt64(finalEvents.count)
        status.lastEventAt = Date()
        status.alertsRaised += alerts.count
        let notificationsOn = settings.notificationsEnabled
        mutex.unlock()

        onEvents?(finalEvents)

        for alert in alerts {
            stats.recordAlert(at: alert.timestamp)
            if notificationsOn {
                notifier.post(alert)
                if let rule = ruleEngine.allRules.first(where: { $0.id == alert.ruleID }),
                   let webhook = rule.actions.webhookURL, !webhook.isEmpty {
                    notifier.deliverWebhook(alert, urlString: webhook)
                }
            } else {
                notifier.onAlertPosted?(alert)
            }
            onAlert?(alert)
        }
    }

    /// Sliding one-second budget. Prevents a pathological writer from
    /// overwhelming the log.
    private func allowRate(cap: Int) -> Bool {
        guard cap > 0 else { return true }
        let now = Date()
        if now.timeIntervalSince(rateWindowStart) >= 1.0 {
            rateWindowStart = now
            rateWindowCount = 0
        }
        rateWindowCount += 1
        return rateWindowCount <= cap
    }

    /// Saves the stream position, at most once every few seconds.
    private func persistCursor(stopping: Bool) {
        mutex.lock()
        let highest = highestEventID
        let due = stopping || Date().timeIntervalSince(lastCursorSave) > 5
        if due { lastCursorSave = Date() }
        mutex.unlock()

        guard due, highest > 0 else { return }
        EventCursor(lastEventID: highest, savedAt: Date(),
                    stoppedAt: stopping ? Date() : nil).save(settingsKey: cursorKey)
    }

    // MARK: - Content capture

    /// Queues content work for the events that warrant it. A deletion cannot be
    /// read, so the useful moment to capture is when a file is written; a delete
    /// only marks the versions already held.
    private func scheduleContentCapture(for events: [FileEvent]) {
        guard let contentVault else { return }
        mutex.lock()
        let enabled = settings.captureFileContents && settings.contentRetention.capturesAnything
        mutex.unlock()
        guard enabled else { return }

        for event in events where !event.isDirectory {
            switch event.kind {
            case .copiedOut, .movedOut:
                // Something left the machine. Keep the bytes, not just the
                // hash: reviewing what was taken is the whole point of noticing.
                let destination = event.path
                let source = event.sourcePath
                let volumeID = event.volumeID
                mutex.lock()
                let saturated = captureBacklog >= captureBacklogLimit
                if !saturated { captureBacklog += 1 }
                mutex.unlock()
                guard !saturated else { continue }

                captureQueue.async { [weak self] in
                    guard let self else { return }
                    // Prefer the copy still on this machine; fall back to the
                    // one that landed elsewhere, filed under where it came from.
                    if let source, FileManager.default.fileExists(atPath: source) {
                        contentVault.capture(path: source, volumeID: volumeID,
                                             reason: .beforeOverwrite)
                    } else if FileManager.default.fileExists(atPath: destination) {
                        contentVault.capture(path: destination, volumeID: volumeID,
                                             reason: .beforeOverwrite,
                                             recordAs: source ?? destination)
                    }
                    self.mutex.lock(); self.captureBacklog -= 1; self.mutex.unlock()
                }

            case .created, .modified, .cloned, .copiedIn, .movedIn:
                mutex.lock()
                let saturated = captureBacklog >= captureBacklogLimit
                if !saturated { captureBacklog += 1 }
                mutex.unlock()
                guard !saturated else { continue }

                let path = event.path
                let volumeID = event.volumeID
                let reason: SnapshotReason = (event.kind == .created) ? .created : .modified
                captureQueue.async { [weak self] in
                    guard let self else { return }
                    contentVault.capture(path: path, volumeID: volumeID, reason: reason)
                    self.mutex.lock(); self.captureBacklog -= 1; self.mutex.unlock()
                }

            case .removed:
                let path = event.path
                let when = event.timestamp
                let volumeID = event.volumeID
                captureQueue.async {
                    // If nothing was ever captured, the file may still be
                    // sitting in the Trash under the same name — a plain
                    // unlink event can follow the move.
                    if !contentVault.hasContent(for: path),
                       let rescued = Self.trashCandidate(for: path) {
                        contentVault.capture(path: rescued, volumeID: volumeID,
                                             reason: .beforeOverwrite, recordAs: path)
                    }
                    contentVault.markDeleted(path: path, at: when)
                }

            case .renamed, .movedOut:
                guard let source = event.sourcePath else { break }
                let destination = event.path

                if TrashPaths.isTrash(destination), !TrashPaths.isTrash(source) {
                    // The file was just deleted in the Finder, which means it
                    // still exists — in the Trash. This is the last chance to
                    // capture something that was never written while we were
                    // watching, and it is exactly the case people care about.
                    let volumeID = event.volumeID
                    let when = event.timestamp
                    captureQueue.async {
                        contentVault.capture(path: destination, volumeID: volumeID,
                                             reason: .beforeOverwrite, recordAs: source)
                        contentVault.markDeleted(path: source, at: when)
                    }
                } else {
                    captureQueue.async {
                        contentVault.notePathMoved(from: source, to: destination)
                        // A plain rename is also a chance to capture a file we
                        // have never seen written.
                        if !contentVault.hasContent(for: destination) {
                            contentVault.capture(path: destination, volumeID: event.volumeID,
                                                 reason: .modified)
                        }
                    }
                }

            default:
                break
            }
        }
    }

    // MARK: - Volumes

    private func handleVolumeChange(_ volume: VolumeInfo, mounted: Bool) {
        let event = FileEvent(
            kind: mounted ? .mounted : .unmounted,
            path: volume.mountPath,
            volumeID: volume.id,
            isDirectory: true,
            severity: volume.volumeClass.isOffMachine ? .notice : .info
        )
        queue.async { [weak self] in
            guard let self else { return }
            self.emit([event])
            if self.monitor.isRunning {
                self.monitor.updatePaths(self.resolveWatchPaths())
                self.mutex.lock()
                self.status.watchedPaths = self.monitor.currentPaths
                self.mutex.unlock()
            }
        }
        onVolumeChange?(volume, mounted)
    }

    // MARK: - Maintenance

    private func startMaintenance() {
        maintenanceTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.ruleEngine.pruneState()
            self.store.flush()

            self.mutex.lock()
            self.status.pendingWrites = 0
            let snapshot = self.status
            self.mutex.unlock()

            // Nothing is pruned here — the event log is append-only by design.
            self.onStatusChange?(snapshot)
        }
        timer.resume()
        maintenanceTimer = timer
    }

    /// Persists analytics so the dashboard is not empty after a restart.
    public func persistStats(key: VaultKeys) {
        let snapshot = stats.snapshot(hotspots: hotspots.snapshot())
        try? EncryptedFileBox.write(snapshot, to: AppPaths.statsFile,
                                    key: key.settings, context: "stats")
    }

    public func restoreStats(key: VaultKeys) {
        let loaded = try? EncryptedFileBox.read(
            StatsSnapshot.self, from: AppPaths.statsFile,
            key: key.settings, context: "stats"
        )
        guard let snapshot = loaded ?? nil else { return }
        stats.restore(snapshot)
        hotspots.restore(snapshot.hotspots)
    }
}
