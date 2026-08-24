import Foundation
import SwiftUI
import Observation
import CoreGraphics
import AppKit
import HDWatcherCore

/// Which screen the app is showing at the top level.
enum AppPhase: Equatable {
    case loading
    case setup          // no vault yet
    case locked
    case unlocked
}

enum SidebarSection: String, CaseIterable, Identifiable, Hashable {
    case dashboard, live, hotspots, transfers, reads, recovery, alerts, rules, volumes, forensics, integrity, settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dashboard: return "Dashboard"
        case .live:      return "Live Feed"
        case .hotspots:  return "Hotspots"
        case .transfers: return "Transfers"
        case .reads:     return "Reads"
        case .recovery:  return "Recovery"
        case .alerts:    return "Alerts"
        case .rules:     return "Rules"
        case .volumes:   return "Volumes"
        case .forensics: return "Search"
        case .integrity: return "Integrity"
        case .settings:  return "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .dashboard: return "square.grid.2x2"
        case .live:      return "waveform.path.ecg"
        case .hotspots:  return "flame"
        case .transfers: return "arrow.left.arrow.right"
        case .reads:     return "eye"
        case .recovery:  return "clock.arrow.circlepath"
        case .alerts:    return "bell"
        case .rules:     return "slider.horizontal.3"
        case .volumes:   return "externaldrive"
        case .forensics: return "magnifyingglass"
        case .integrity: return "checkmark.seal"
        case .settings:  return "gearshape"
        }
    }
}

/// Central coordinator: owns the vault, the engine and all UI-facing state.
@MainActor
@Observable
final class AppModel {

    // Phase and navigation
    var phase: AppPhase = .loading
    var selection: SidebarSection = .dashboard

    // Vault
    let vault = VaultKeyManager()
    var unlockError: String?
    var isWorking = false
    var protectionTier: KeyProtectionTier = .passwordOnly
    var biometryName: String = "Touch ID"
    var quickUnlockAvailable = false

    // Engine
    private(set) var store: EventStore?
    private(set) var engine: WatcherEngine?

    // Live state
    var liveEvents: [FileEvent] = []
    var alerts: [SecurityAlert] = []
    var volumes: [VolumeInfo] = []
    var systemVolumes: [VolumeInfo] = []
    var volumeHistory: [VolumeInfo] = []
    var status = WatcherEngine.Status()
    var activitySeries: [ActivityBucket] = []
    /// False until the first background aggregation lands, so the dashboard can
    /// say "loading" instead of "nothing here".
    var hasLoadedDerivedState = false
    var hotspotRows: [DirectoryHeat] = []
    var topExtensions: [ExtensionStat] = []
    var transfers: [FileEvent] = []
    /// Everything in the vault, grouped. Rebuilt only when the vault changes.
    // MARK: - Reads

    /// One file, and every time something was seen holding it open.
    struct ReadGroup: Identifiable, Sendable {
        var id: String { path }
        let path: String
        let events: [FileEvent]        // newest first

        var fileName: String { (path as NSString).lastPathComponent }
        var directory: String { (path as NSString).deletingLastPathComponent }
        var lastRead: Date { events.first?.timestamp ?? .distantPast }
        var readers: [String] {
            var seen: [String] = []
            for event in events {
                guard let name = event.attribution?.best?.name else { continue }
                if !seen.contains(name) { seen.append(name) }
            }
            return seen
        }
    }

    var readGroups: [ReadGroup] = []
    var isLoadingReads = false
    private var readsTask: Task<Void, Never>?
    private var readsSignature: String?

    /// Rebuilds the list of files that were read. Reads are ordinary events in
    /// the same encrypted log, so this is a query rather than another store.
    func refreshReads(search: String? = nil, limit: Int = 20_000, force: Bool = false) {
        guard let store else { return }
        let signature = "\(store.totalEventCount)|\(search ?? "")"
        guard force || signature != readsSignature else { return }

        readsTask?.cancel()
        if readGroups.isEmpty { isLoadingReads = true }
        readsTask = Task { [weak self] in
            let groups = await Task.detached(priority: .userInitiated) { () -> [ReadGroup] in
                var query = EventQuery()
                query.kinds = [.read]
                query.limit = limit
                query.newestFirst = true
                if let search, !search.isEmpty { query.pathContains = search }

                var byPath: [String: [FileEvent]] = [:]
                for event in store.query(query) { byPath[event.path, default: []].append(event) }
                return byPath
                    .map { ReadGroup(path: $0.key, events: $0.value.sorted { $0.timestamp > $1.timestamp }) }
                    .sorted { $0.lastRead > $1.lastRead }
            }.value
            guard !Task.isCancelled, let self else { return }
            self.readGroups = groups
            self.isLoadingReads = false
            self.readsSignature = signature
        }
    }

    /// Results of searching inside captured contents, which is a scan rather
    /// than a filter and so is kept separate from the grouped list.
    var contentHits: [ContentSearchEngine.Hit] = []
    var contentSearchScanned = 0
    var contentSearchTotal = 0
    var isSearchingContents = false
    var contentSearchQuery = ""
    private var contentSearchTask: Task<Void, Never>?
    private var searchEngine: ContentSearchEngine?

    var allRecoveryGroups: [SnapshotGroup] = []
    /// What the list is showing, after the search box and scope are applied.
    var recoveryGroups: [SnapshotGroup] = []
    var isLoadingRecovery = false
    var isFilteringRecovery = false
    private var recoveryRevision: Int = -1
    private var recoveryFilter: (deletedOnly: Bool, search: String?) = (false, nil)
    private var regroupTask: Task<Void, Never>?
    private var filterTask: Task<Void, Never>?
    /// Last vault revision and filter the recovery list was built from, so a
    /// once-a-second poll can skip the expensive work when nothing changed.
    private var recoveryGate = RecoveryRefreshGate()
    var contentStats = ContentVaultStats()

    // Configuration
    var settings: AppSettings = .default
    var rules: [AlertRule] = []

    // Background agent
    var backgroundServiceState: BackgroundService.State = .notRegistered
    var backgroundServiceError: String?
    var agentStatus: AgentStatus?
    /// True when the agent is recording, so the app stays out of its way.
    var isViewerMode: Bool { agentStatus?.isAlive == true }

    /// Coverage as reported by whoever is holding the FSEvents stream, which is
    /// usually the daemon rather than this app.
    var coverage: CoverageReport {
        CoverageReport.resolve(agent: agentStatus, engine: status)
    }

    // Environment
    var fullDiskAccess: Permissions.FullDiskAccess = .unknown
    var notificationStatus: Notifier.Availability = .unknown

    // Housekeeping
    private var refreshTimer: Timer?
    private var autoLockTimer: Timer?
    /// The Live Feed is a rolling in-memory window; the encrypted log keeps
    /// everything, and Search reads from it.
    private let liveEventCapacity = 25_000
    private let alertCapacity = 1_000
    private let inbox = EventInbox()

    init() {
        protectionTier = vault.protectionTier
        biometryName = SecureEnclaveKeyStore.biometryDescription()
        quickUnlockAvailable = vault.quickUnlockEnabled
        fullDiskAccess = Permissions.fullDiskAccessStatus()
        phase = vault.vaultExists ? .locked : .setup
        observeSystemEvents()
    }

    // MARK: - Vault lifecycle

    func createVault(password: String, hint: String?, enableQuickUnlock: Bool) async {
        isWorking = true
        unlockError = nil
        defer { isWorking = false }

        let vault = self.vault
        do {
            // PBKDF2 is deliberately slow; keep it off the main actor.
            try await Task.detached(priority: .userInitiated) {
                try vault.createVault(password: password, hint: hint,
                                      enableQuickUnlock: enableQuickUnlock)
            }.value
            protectionTier = vault.protectionTier
            quickUnlockAvailable = vault.quickUnlockEnabled
            await startSession()
        } catch {
            unlockError = error.localizedDescription
        }
    }

    func unlock(password: String) async {
        isWorking = true
        unlockError = nil
        defer { isWorking = false }

        let vault = self.vault
        do {
            try await Task.detached(priority: .userInitiated) {
                try vault.unlock(password: password)
            }.value
            await startSession()
        } catch {
            unlockError = error.localizedDescription
        }
    }

    func unlockWithBiometrics() async {
        isWorking = true
        unlockError = nil
        defer { isWorking = false }

        let vault = self.vault
        do {
            try await Task.detached(priority: .userInitiated) {
                try vault.unlockWithBiometrics(reason: "Unlock the HDWatcher vault")
            }.value
            await startSession()
        } catch {
            unlockError = error.localizedDescription
        }
    }

    func lock() {
        engine?.stop()
        if let keys = vault.currentKeys {
            engine?.persistStats(key: keys)
            persistSettings(keys: keys)
        }
        store?.close()
        engine = nil
        store = nil
        vault.lock()

        // Drop anything decrypted from memory.
        liveEvents.removeAll()
        alerts.removeAll()
        transfers.removeAll()
        regroupTask?.cancel(); regroupTask = nil
        filterTask?.cancel(); filterTask = nil
        recoveryRevision = -1
        recoveryGate.reset()
        allRecoveryGroups.removeAll()
        recoveryGroups.removeAll()
        cancelContentSearch()
        contentHits.removeAll()
        contentSearchQuery = ""
        searchEngine = nil
        contentStats = ContentVaultStats()
        hotspotRows.removeAll()
        activitySeries.removeAll()
        hasLoadedDerivedState = false
        topExtensions.removeAll()

        // Locking must not leave decrypted previews lying around.
        ContentVault.clearTemporaryCopies()
        refreshTimer?.invalidate(); refreshTimer = nil
        autoLockTimer?.invalidate(); autoLockTimer = nil
        phase = .locked
    }

    /// Builds the store and engine once the vault is open.
    private func startSession() async {
        guard let keys = vault.currentKeys else { return }
        do {
            let store = try EventStore(keys: keys)
            self.store = store

            loadSettings(keys: keys)
            loadRules(keys: keys)
            loadAlerts(keys: keys)

            let engine = WatcherEngine(store: store, settings: settings, rules: rules, keys: keys)
            engine.restoreStats(key: keys)
            wire(engine)
            self.engine = engine

            volumes = engine.registry.mountedVolumes
            systemVolumes = engine.registry.systemVolumes
            volumeHistory = engine.registry.volumeHistory

            // Publishing the public half is what lets the daemon record at all.
            IngestKeyFile.export(keys.ingestPublicKey)
            // A leftover per-user agent from an earlier version would duplicate
            // everything the daemon does.
            BackgroundService.removeLegacyAgent()
            LegacyPlaintextCleanup.run()
            // Background recording is meant to be permanent: if the user has it
            // switched on, put it back without making them ask again.
            backgroundServiceError = BackgroundService.ensureInstalledIfWanted(settings: settings)
            refreshBackgroundService()
            publishAgentConfiguration()

            openDaemonContentVault(keys: keys)
            store.primeTail()
            liveEvents = store.recentEvents(limit: 2_000)

            // Two watchers would double every event, so the app only monitors
            // when the agent is not already doing it.
            if settings.monitorOnUnlock, !isViewerMode {
                _ = engine.start()
            }
            if settings.notificationsEnabled {
                engine.notifier.requestAuthorization()
                engine.notifier.refreshStatus { [weak self] value in
                    Task { @MainActor in self?.notificationStatus = value }
                }
            }
            applyDockPolicy()
            startTimers()
            refreshDerivedState()
            phase = .unlocked
            preloadSections()
        } catch {
            unlockError = error.localizedDescription
            phase = .locked
        }
    }

    private func wire(_ engine: WatcherEngine) {
        // The engine calls back from its own queue, so events land in a
        // thread-safe inbox and the main actor drains it on a timer.
        let inbox = self.inbox
        engine.onEvents = { events in inbox.deposit(events) }
        engine.onAlert = { [weak self] alert in
            Task { @MainActor in
                guard let self else { return }
                self.alerts.insert(alert, at: 0)
                if self.alerts.count > self.alertCapacity {
                    self.alerts.removeLast(self.alerts.count - self.alertCapacity)
                }
            }
        }
        engine.onVolumeChange = { [weak self] _, _ in
            Task { @MainActor in
                guard let self, let engine = self.engine else { return }
                self.volumes = engine.registry.mountedVolumes
                self.volumeHistory = engine.registry.volumeHistory
            }
        }
        engine.onStatusChange = { [weak self] status in
            Task { @MainActor in self?.status = status }
        }
    }

    // MARK: - Monitoring control

    /// Whether anything is recording — this process, or the daemon on its
    /// behalf. Reporting "paused" while the daemon records is both wrong and
    /// alarming, since the whole point is that it never stops.
    var isMonitoring: Bool { status.isMonitoring || isViewerMode }

    /// True only when nothing at all is watching.
    var isFullyPaused: Bool { !status.isMonitoring && !isViewerMode }

    /// What is doing the recording, for display.
    var recordingSummary: String {
        if isViewerMode {
            let events = agentStatus.map { Format.count(Int($0.eventsRecorded)) } ?? "0"
            return "Background daemon · \(events) events"
        }
        if status.isMonitoring {
            return "\(Format.count(Int(status.eventsProcessed))) events recorded"
        }
        return "Not recording"
    }

    // MARK: - Background agent

    /// What the daemon is really doing, as opposed to what macOS says about it.
    var daemonVerdict = DaemonSupervisor.Verdict(health: .startingUp, repair: .wait,
                                                 summary: "Checking…", detail: "")
    private var daemonRegisteredAt: Date?
    private var daemonRepairAttempts = 0
    private var lastDaemonRepair: Date?

    func refreshBackgroundService() {
        backgroundServiceState = BackgroundService.state
        agentStatus = BackgroundService.status(using: vault.currentKeys)

        let verdict = DaemonSupervisor.assess(.init(
            state: backgroundServiceState,
            wanted: settings.backgroundRecordingEnabled,
            heartbeat: agentStatus?.heartbeat,
            processAlive: agentStatus.map { AgentStatus.processExists($0.pid) } ?? false,
            registeredAt: daemonRegisteredAt,
            repairAttempts: daemonRepairAttempts,
            isDurable: BackgroundService.Durable.isInstalled))
        daemonVerdict = verdict

        if verdict.health == .recording { daemonRepairAttempts = 0 }

        // Repair without being asked: a daemon macOS has dropped is not
        // something the user can be expected to notice, and the whole point of
        // it is that it runs without anyone watching.
        // A durably installed daemon is launchd's business, not ours: kicking
        // SMAppService here would throw away an approval and start the loop the
        // user has already been through too many times.
        if DaemonSupervisor.shouldRepairAutomatically(verdict),
           !BackgroundService.Durable.isInstalled,
           settings.backgroundRecordingEnabled,
           lastDaemonRepair.map({ Date().timeIntervalSince($0) > DaemonSupervisor.startupGrace }) ?? true {
            repairBackgroundService()
        }
    }

    /// Installs the daemon the durable way: one administrator prompt, then it
    /// starts at every boot regardless of what happens to the app bundle.
    @discardableResult
    func installDaemonPermanently(uninstall: Bool = false) -> String? {
        do {
            try BackgroundService.Durable.install(uninstall: uninstall)
            daemonRepairAttempts = 0
            daemonRegisteredAt = Date()
            refreshBackgroundService()
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    /// Unregisters and registers again, which is what fixes a service launchd
    /// has forgotten.
    @discardableResult
    func repairBackgroundService() -> String? {
        daemonRepairAttempts += 1
        lastDaemonRepair = Date()
        do {
            try BackgroundService.repair()
            daemonRegisteredAt = Date()
            backgroundServiceState = BackgroundService.state
            return nil
        } catch {
            daemonVerdict = DaemonSupervisor.Verdict(
                health: daemonVerdict.health, repair: .askForHelp,
                summary: "Could not re-register the daemon",
                detail: error.localizedDescription)
            return error.localizedDescription
        }
    }

    /// True when the daemon has actually been given the current settings. The
    /// app cannot write into /Library, so this is not a formality.
    var agentConfigurationPublished = false

    func publishAgentConfiguration() {
        agentConfigurationPublished =
            BackgroundService.publishConfiguration(settings: settings, rules: rules)
    }

    func setBackgroundRecording(_ enabled: Bool) -> String? {
        settings.backgroundRecordingEnabled = enabled
        persistSettings()
        return enabled ? installBackgroundService() : removeBackgroundService()
    }

    func installBackgroundService() -> String? {
        settings.backgroundRecordingEnabled = true
        persistSettings()
        do {
            try BackgroundService.install()
            refreshBackgroundService()
            publishAgentConfiguration()
            // Hand recording over rather than having both watch.
            if let engine, engine.currentStatus.isMonitoring {
                engine.stop()
                status = engine.currentStatus
            }
            return nil
        } catch {
            refreshBackgroundService()
            return error.localizedDescription
        }
    }

    func removeBackgroundService() -> String? {
        settings.backgroundRecordingEnabled = false
        persistSettings()
        do {
            try BackgroundService.uninstall()
            refreshBackgroundService()
            publishAgentConfiguration()
            // Take recording back so nothing goes unwatched.
            if let engine, settings.monitorOnUnlock, !engine.currentStatus.isMonitoring {
                _ = engine.start()
                status = engine.currentStatus
            }
            return nil
        } catch {
            refreshBackgroundService()
            return error.localizedDescription
        }
    }

    func toggleMonitoring() {
        guard let engine else { return }
        if status.isMonitoring {
            engine.stop()
        } else {
            _ = engine.start()
        }
        status = engine.currentStatus
    }

    /// Warms the data behind each sidebar section.
    ///
    /// Every section used to begin its own load when first opened, so the first
    /// visit to each always stalled. Doing the work up front, in the background
    /// and in rough order of likely use, means switching is instant.
    private func preloadSections() {
        // Recovery: grouping thousands of versions is the slowest of these.
        refreshRecovery(force: true)

        // Transfers: reads the encrypted log.
        Task { [weak self] in
            guard let self, let store = self.store else { return }
            var query = EventQuery()
            query.transfersOnly = true
            query.limit = 500
            let found = await Task.detached(priority: .utility) { store.query(query) }.value
            self.preloadedTransfers = found
        }
    }

    /// Transfer history fetched ahead of the user opening that tab.
    var preloadedTransfers: [FileEvent] = []

    // MARK: - Periodic refresh

    private func startTimers() {
        refreshTimer?.invalidate()
        // Events are drained on a cadence rather than per batch, so a burst of
        // filesystem activity cannot drive the UI at hundreds of updates a second.
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.drainPending() }
        }
        autoLockTimer?.invalidate()
        autoLockTimer = Timer.scheduledTimer(withTimeInterval: 20, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkAutoLock() }
        }
    }

    private var refreshTick = 0

    private func drainPending() {
        let batch = inbox.drain()

        if !batch.isEmpty {
            if !settings.liveFeedPaused {
                liveEvents.append(contentsOf: batch)
                if liveEvents.count > liveEventCapacity {
                    liveEvents.removeFirst(liveEvents.count - liveEventCapacity)
                }
            }
            let newTransfers = batch.filter { $0.kind.isTransfer }
            if !newTransfers.isEmpty {
                transfers.insert(contentsOf: newTransfers.reversed(), at: 0)
                if transfers.count > 500 { transfers.removeLast(transfers.count - 500) }
            }
        }

        // In viewer mode the events come from the agent's log rather than from
        // a monitor in this process.
        if isViewerMode, let store, let tailed = Optional(store.tailNewEvents()), !tailed.isEmpty {
            if !settings.liveFeedPaused {
                liveEvents.append(contentsOf: tailed)
                if liveEvents.count > liveEventCapacity {
                    liveEvents.removeFirst(liveEvents.count - liveEventCapacity)
                }
            }
            let newTransfers = tailed.filter { $0.kind.isTransfer }
            if !newTransfers.isEmpty {
                transfers.insert(contentsOf: newTransfers.reversed(), at: 0)
                if transfers.count > 500 { transfers.removeLast(transfers.count - 500) }
            }
            for event in tailed {
                engine?.hotspots.record(event)
                engine?.stats.record(event)
            }
        }

        refreshTick += 1
        if let engine { status = engine.currentStatus }
        // Heavier aggregations run every ~2 seconds.
        if refreshTick % 5 == 0 {
            refreshDerivedState()
            refreshBackgroundService()
        }
    }

    var contentVault: ContentVault? { engine?.contentVault }

    /// Read-only view of what the privileged daemon captured. Its container is
    /// sealed to the ingest key, so the app can open it even though the daemon
    /// cannot read its own.
    private(set) var daemonContentVault: ContentVault?

    /// Set when the daemon's container exists but cannot be opened — almost
    /// always a permissions problem, which otherwise looks like "no captures".
    var daemonCaptureProblem: String?

    private func openDaemonContentVault(keys: VaultKeys) {
        let candidates = [AppPaths.systemAgentContentVaultFile, AppPaths.agentContentVaultFile]
        for url in candidates where FileManager.default.fileExists(atPath: url.path) {
            guard FileManager.default.isReadableFile(atPath: url.path) else {
                daemonCaptureProblem = "The background daemon is capturing file contents, but this app cannot read them: \(url.path) is not readable. Restart the daemon to repair its permissions:\n\nsudo launchctl kickstart -k system/co.pixelworship.hdwatcher.daemon"
                daemonContentVault = nil
                return
            }
            daemonCaptureProblem = nil
            daemonContentVault = ContentVault(sealMode: .readIngest(keys.ingest), url: url)
            return
        }
        daemonCaptureProblem = nil
        daemonContentVault = nil
    }

    /// Rebuilds the recovery list.
    ///
    /// Two costs are deliberately separated. *Grouping* — copying every stored
    /// snapshot, bucketing by path and sorting each file's versions — depends
    /// only on what is in the vault, so it runs at most once per change. 
    /// *Filtering* by the search box is cheap by comparison and runs per
    /// keystroke. Doing both on every keystroke is what made typing crawl with
    /// thousands of files.
    func refreshRecovery(deletedOnly: Bool = false, search: String? = nil, force: Bool = false) {
        guard let vault = contentVault else {
            allRecoveryGroups = []
            recoveryGroups = []
            contentStats = ContentVaultStats()
            return
        }

        // Notice anything the daemon has captured since we last looked. Cheap:
        // it compares the file's size and timestamp before doing any work.
        if daemonContentVault == nil, let keys = self.vault.currentKeys {
            openDaemonContentVault(keys: keys)
        }
        daemonContentVault?.reloadIfChanged()

        let revision = vault.revision &+ (daemonContentVault?.revision ?? 0)
        let needsRegroup = force || revision != recoveryRevision
        recoveryFilter = (deletedOnly: deletedOnly, search: search)

        // Nothing has moved since the last pass: same vault revision, same
        // filter. The list polls once a second to stay live, and without this
        // every tick re-filtered thousands of groups and flashed the spinner
        // in the search box for no reason at all.
        guard needsRegroup || recoveryGate.needsPass(revision: revision,
                                                     deletedOnly: deletedOnly,
                                                     search: search, force: force)
        else { return }

        if needsRegroup {
            recoveryRevision = revision
            if allRecoveryGroups.isEmpty { isLoadingRecovery = true }
            regroupTask?.cancel()
            let daemonVault = daemonContentVault
            regroupTask = Task { [weak self] in
                let result = await Task.detached(priority: .userInitiated) {
                    () -> (groups: [SnapshotGroup], stats: ContentVaultStats) in
                    // Everything the app captured, plus everything the daemon
                    // captured while the app was closed.
                    var merged = vault.groups()
                    var stats = vault.currentStats
                    if let daemonVault {
                        let theirs = daemonVault.groups()
                        let theirStats = daemonVault.currentStats
                        var byPath = Dictionary(uniqueKeysWithValues: merged.map { ($0.path, $0) })
                        for group in theirs {
                            if let existing = byPath[group.path] {
                                let combined = (existing.versions + group.versions)
                                    .sorted { $0.capturedAt > $1.capturedAt }
                                byPath[group.path] = SnapshotGroup(path: group.path, versions: combined)
                            } else {
                                byPath[group.path] = group
                            }
                        }
                        merged = Array(byPath.values)
                            .sorted { ($0.latest?.capturedAt ?? .distantPast) > ($1.latest?.capturedAt ?? .distantPast) }
                        stats.snapshotCount += theirStats.snapshotCount
                        stats.uniqueFileCount = merged.count
                        stats.deletedFileCount = merged.filter(\.isDeleted).count
                        stats.liveBytes += theirStats.liveBytes
                        stats.containerBytes += theirStats.containerBytes
                    }
                    return (merged, stats)
                }.value
                guard !Task.isCancelled, let self else { return }
                self.allRecoveryGroups = result.groups
                self.contentStats = result.stats
                self.isLoadingRecovery = false
                self.applyRecoveryFilter()
            }
        } else {
            applyRecoveryFilter()
        }
    }

    // MARK: - Searching inside contents

    /// Reads every captured version looking for the query.
    ///
    /// Unlike the filename filter this is genuinely expensive — it decrypts and
    /// examines the stored bytes — so it reports progress, streams matches as
    /// they are found, and can be stopped. Newest versions are examined first.
    func searchContents(_ query: String, deletedOnly: Bool) {
        contentSearchTask?.cancel()
        contentSearchQuery = query
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 2, let vault = contentVault else {
            contentHits = []
            isSearchingContents = false
            contentSearchScanned = 0
            contentSearchTotal = 0
            return
        }

        let engine = searchEngine ?? ContentSearchEngine(
            vaults: [vault, daemonContentVault].compactMap { $0 })
        searchEngine = engine

        var groups = allRecoveryGroups
        if deletedOnly { groups = groups.filter(\.isDeleted) }
        let snapshots = groups.flatMap(\.versions).sorted { $0.capturedAt > $1.capturedAt }

        contentHits = []
        contentSearchScanned = 0
        contentSearchTotal = snapshots.count
        isSearchingContents = true

        contentSearchTask = Task { [weak self] in
            // A pause before starting keeps a burst of typing from launching a
            // scan per character.
            try? await Task.sleep(for: .milliseconds(350))
            guard !Task.isCancelled, let model = self else { return }

            await Task.detached(priority: .userInitiated) {
                engine.run(query: trimmed,
                           snapshots: snapshots,
                           isCancelled: { Task.isCancelled },
                           progress: { update in
                    Task { @MainActor in model.applyContentSearch(update, for: query) }
                })
            }.value

            guard !Task.isCancelled else { return }
            model.isSearchingContents = false
        }
    }

    /// Takes one batch of results, ignoring anything from a search the user has
    /// already moved on from.
    fileprivate func applyContentSearch(_ update: ContentSearchEngine.Progress, for query: String) {
        guard contentSearchQuery == query else { return }
        contentHits = update.hits
        contentSearchScanned = update.scanned
        contentSearchTotal = update.total
        if update.finished { isSearchingContents = false }
    }

    func cancelContentSearch() {
        contentSearchTask?.cancel()
        contentSearchTask = nil
        isSearchingContents = false
    }

    /// Applies the search box to the already-grouped list, debounced so a burst
    /// of keystrokes results in one pass rather than one pass per character.
    func applyRecoveryFilter() {
        let filter = recoveryFilter
        let source = allRecoveryGroups
        let revision = recoveryRevision
        filterTask?.cancel()
        // The spinner means "working on what you just typed". A refresh caused
        // by new captures arriving re-filters silently: nobody asked for it and
        // nobody is waiting on it.
        isFilteringRecovery = recoveryGate.showsProgress(for: filter.search)
        filterTask = Task { [weak self] in
            // Cancelled by the next keystroke before this elapses.
            try? await Task.sleep(for: .milliseconds(180))
            guard !Task.isCancelled else { return }
            let filtered = await Task.detached(priority: .userInitiated) {
                Self.filterGroups(source, deletedOnly: filter.deletedOnly, search: filter.search)
            }.value
            guard !Task.isCancelled, let self else { return }
            self.recoveryGroups = filtered
            self.isFilteringRecovery = false
            // Recorded only now the results are on screen: a pass cancelled by
            // the next keystroke must be repeated, not assumed done.
            self.recoveryGate.finished(revision: revision,
                                       deletedOnly: filter.deletedOnly,
                                       search: filter.search)
        }
    }



    nonisolated private static func filterGroups(_ groups: [SnapshotGroup],
                                                 deletedOnly: Bool,
                                                 search: String?) -> [SnapshotGroup] {
        var result = groups
        if deletedOnly { result = result.filter(\.isDeleted) }
        if let search, !search.isEmpty {
            result = result.filter { $0.path.range(of: search, options: .caseInsensitive) != nil }
        }
        return result
    }

    func refreshDerivedState() {
        guard let engine else { return }
        Task { [weak self] in
            let aggregate = await Self.computeDerivedState(engine: engine)
            guard let self else { return }
            self.activitySeries = aggregate.series
            self.systemVolumes = aggregate.systemVolumes
            self.volumeHistory = aggregate.volumeHistory
            self.hotspotRows = aggregate.hotspots
            self.topExtensions = aggregate.extensions
            self.volumes = aggregate.volumes
            if let stats = aggregate.contentStats { self.contentStats = stats }
            self.hasLoadedDerivedState = true
        }
    }

    private struct DerivedState: Sendable {
        var series: [ActivityBucket]
        var hotspots: [DirectoryHeat]
        var extensions: [ExtensionStat]
        var volumes: [VolumeInfo]
        var systemVolumes: [VolumeInfo]
        var volumeHistory: [VolumeInfo]
        var contentStats: ContentVaultStats?
    }

    private nonisolated static func computeDerivedState(engine: WatcherEngine) async -> DerivedState {
        await Task.detached(priority: .userInitiated) {
            DerivedState(
                series: engine.stats.series(minutes: 60),
                hotspots: engine.hotspots.topDirectories(30, by: .heat),
                extensions: engine.stats.topExtensions(10),
                volumes: engine.registry.mountedVolumes,
                systemVolumes: engine.registry.systemVolumes,
                volumeHistory: engine.registry.volumeHistory,
                contentStats: engine.contentVault?.currentStats
            )
        }.value
    }

    var eventsPerMinute: Double { engine?.stats.eventsPerMinute() ?? 0 }

    // MARK: - Auto-lock

    private func checkAutoLock() {
        guard phase == .unlocked, settings.autoLockMinutes > 0 else { return }
        let idle = CGEventSource.secondsSinceLastEventType(
            .combinedSessionState,
            eventType: CGEventType(rawValue: ~0)!
        )
        if idle >= Double(settings.autoLockMinutes * 60) {
            lock()
        }
    }

    private func observeSystemEvents() {
        let workspace = NSWorkspace.shared.notificationCenter
        workspace.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.settings.lockOnSleep, self.phase == .unlocked else { return }
                self.lock()
            }
        }
        let distributed = DistributedNotificationCenter.default()
        distributed.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.settings.lockOnScreensaver, self.phase == .unlocked else { return }
                self.lock()
            }
        }
    }

    func applyDockPolicy() {
        NSApp.setActivationPolicy(settings.showDockIcon ? .regular : .accessory)
    }

    // MARK: - Settings and rules persistence

    private func loadSettings(keys: VaultKeys) {
        let loaded = try? EncryptedFileBox.read(AppSettings.self, from: AppPaths.settingsFile,
                                                key: keys.settings, context: "settings")
        settings = (loaded ?? nil) ?? .default
    }

    func persistSettings(keys: VaultKeys? = nil) {
        guard let keys = keys ?? vault.currentKeys else { return }
        try? EncryptedFileBox.write(settings, to: AppPaths.settingsFile,
                                    key: keys.settings, context: "settings")
    }

    func applySettings() {
        engine?.updateSettings(settings)
        applyDockPolicy()
        persistSettings()
        publishAgentConfiguration()
    }

    private func loadRules(keys: VaultKeys) {
        let loaded = try? EncryptedFileBox.read([AlertRule].self, from: AppPaths.rulesFile,
                                                key: keys.settings, context: "rules")
        if let existing = loaded ?? nil, !existing.isEmpty {
            rules = existing
        } else {
            rules = AlertRule.builtInRules()
            try? EncryptedFileBox.write(rules, to: AppPaths.rulesFile,
                                        key: keys.settings, context: "rules")
        }
    }

    func persistRules() {
        guard let keys = vault.currentKeys else { return }
        engine?.ruleEngine.setRules(rules)
        try? EncryptedFileBox.write(rules, to: AppPaths.rulesFile,
                                    key: keys.settings, context: "rules")
        publishAgentConfiguration()
    }

    func upsertRule(_ rule: AlertRule) {
        if let index = rules.firstIndex(where: { $0.id == rule.id }) {
            rules[index] = rule
        } else {
            rules.append(rule)
        }
        persistRules()
    }

    func deleteRule(_ rule: AlertRule) {
        rules.removeAll { $0.id == rule.id }
        persistRules()
    }

    func restoreBuiltInRules() {
        let custom = rules.filter { !$0.isBuiltIn }
        rules = AlertRule.builtInRules() + custom
        persistRules()
    }

    private func loadAlerts(keys: VaultKeys) {
        let loaded = try? EncryptedFileBox.read([SecurityAlert].self, from: AppPaths.alertsFile,
                                                key: keys.settings, context: "alerts")
        alerts = (loaded ?? nil) ?? []
    }

    func persistAlerts() {
        guard let keys = vault.currentKeys else { return }
        let recent = Array(alerts.prefix(alertCapacity))
        try? EncryptedFileBox.write(recent, to: AppPaths.alertsFile,
                                    key: keys.settings, context: "alerts")
    }

    func acknowledgeAlert(_ alert: SecurityAlert) {
        if let index = alerts.firstIndex(where: { $0.id == alert.id }) {
            alerts[index].acknowledged = true
            persistAlerts()
        }
    }

    func acknowledgeAllAlerts() {
        for index in alerts.indices { alerts[index].acknowledged = true }
        persistAlerts()
    }

    func clearAlerts() {
        alerts.removeAll()
        persistAlerts()
    }

    var unacknowledgedAlertCount: Int { alerts.filter { !$0.acknowledged }.count }

    // MARK: - Queries

    /// Synchronous form, for callers already off the main thread.
    nonisolated func runQuery(_ query: EventQuery, store: EventStore) -> [FileEvent] {
        store.query(query)
    }

    /// Runs a query without blocking the interface. Decrypting segments can take
    /// seconds on a large log.
    func runQueryAsync(_ query: EventQuery) async -> [FileEvent] {
        guard let store else { return [] }
        return await Task.detached(priority: .userInitiated) { store.query(query) }.value
    }

    func verifyIntegrityAsync() async -> IntegrityReport? {
        guard let store else { return nil }
        return await Task.detached(priority: .userInitiated) { store.verifyIntegrity() }.value
    }

    func refreshPermissions() {
        fullDiskAccess = Permissions.fullDiskAccessStatus()
        engine?.notifier.refreshStatus { [weak self] value in
            Task { @MainActor in self?.notificationStatus = value }
        }
    }

    // MARK: - Shutdown

    func shutdown() {
        // Decrypted previews are the one place plaintext touches disk.
        ContentVault.clearTemporaryCopies()
        if let keys = vault.currentKeys {
            engine?.persistStats(key: keys)
            persistSettings(keys: keys)
            persistAlerts()
        }
        engine?.stop()
        store?.close()
    }
}


/// A hand-off point between the engine's background queue and the main actor.
/// The engine only ever appends; the UI drains on a timer.
final class EventInbox: @unchecked Sendable {
    private let mutex = NSLock()
    private var pending: [FileEvent] = []

    func deposit(_ events: [FileEvent]) {
        mutex.lock(); defer { mutex.unlock() }
        pending.append(contentsOf: events)
        // Bound the backlog: if the UI stalls, keep the newest rather than
        // growing without limit.
        if pending.count > 20_000 {
            pending.removeFirst(pending.count - 20_000)
        }
    }

    func drain() -> [FileEvent] {
        mutex.lock(); defer { mutex.unlock() }
        let batch = pending
        pending.removeAll(keepingCapacity: true)
        return batch
    }
}
