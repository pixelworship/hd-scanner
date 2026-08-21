import Foundation
import CryptoKit
import HDWatcherCore

/// HDWatcher's background agent.
///
/// Runs as a LaunchAgent from login, independent of the main app, and records
/// filesystem activity into the encrypted audit log. It holds only the *public*
/// half of the ingest key: it can append events, and cannot read back a single
/// one of them. Viewing history requires the app and the user's password.
///
/// Everything it needs to keep working is on disk, so the app starting, quitting
/// or crashing never interrupts recording.
final class Agent {

    private let logHandle: FileHandle?
    private var engine: WatcherEngine?
    private var store: EventStore?
    private var status = AgentStatus(pid: getpid())
    private var configuration = AgentConfiguration()
    private var configurationStamp: Date?
    private var ownerHome: String?
    private let trailGuard = AuditTrailGuard()
    private var ingestKey: P256.KeyAgreement.PublicKey?
    private let mutex = NSLock()
    private var shuttingDown = false

    init() {
        AppPaths.ensureDirectories()
        if !FileManager.default.fileExists(atPath: AgentPaths.logFile.path) {
            // Readable by the user: this is the file you look at when the
            // daemon will not start, and it holds no recorded activity.
            FileManager.default.createFile(atPath: AgentPaths.logFile.path, contents: nil,
                                           attributes: [.posixPermissions: AppPaths.filePermissions])
        }
        // Attributes only apply at creation, so an existing log keeps whatever
        // mode an earlier build gave it.
        try? FileManager.default.setAttributes(
            [.posixPermissions: AppPaths.filePermissions],
            ofItemAtPath: AgentPaths.logFile.path)
        logHandle = try? FileHandle(forWritingTo: AgentPaths.logFile)
        try? logHandle?.seekToEnd()
    }

    // MARK: - Logging

    func log(_ message: String) {
        let line = "[\(Format.fullTimestamp(Date()))] \(message)\n"
        FileHandle.standardError.write(Data(line.utf8))
        guard let logHandle else { return }
        try? logHandle.write(contentsOf: Data(line.utf8))
        // Keep the agent's own log from growing without bound.
        if let size = try? logHandle.offset(), size > 4 * 1024 * 1024 {
            try? logHandle.truncate(atOffset: 0)
            try? logHandle.seek(toOffset: 0)
        }
    }

    // MARK: - Lifecycle

    func run() {
        log("agent starting (pid \(getpid()))")
        // Publish the key the app needs in order to seal configuration for us.
        DaemonIdentity.loadOrCreate()
        for path in LegacyPlaintextCleanup.run() {
            log("removed clear-text state left by an earlier build: \(path)")
        }
        installSignalHandlers()
        scheduleHeartbeat()
        scheduleConfigurationWatch()
        scheduleTrailGuard()

        // The app must unlock once to publish the ingest public key. Waiting is
        // done on a timer rather than by sleeping the main thread, so signals
        // (launchd's SIGTERM in particular) are still serviced meanwhile.
        if AppPaths.isRunningAsRoot {
            log("running as root; audit trail at \(AppPaths.logDirectory.path)")
        } else {
            log("running as uid \(getuid()); audit trail at \(AppPaths.logDirectory.path)")
        }

        if resolveIngestKey() != nil {
            reloadConfiguration(force: true)
            startEngine()
        } else {
            announceWaitingForKey()
            scheduleIngestKeyWatch()
        }

        log("agent running")
        RunLoop.current.run()
    }

    private func announceWaitingForKey() {
        log("waiting for the ingest key — open HDWatcher and unlock the vault once")
        var pending = AgentStatus(pid: getpid())
        pending.lastError = "Waiting for the vault to be unlocked once so the ingest key can be published."
        // Nothing is written until the key exists: with no recipient there is
        // no way to seal it, and status is not worth leaving in the clear.
        pending.write(sealingTo: ingestKey)
    }

    /// Resolves and pins the ingest key, recording anything suspicious.
    private func resolveIngestKey() -> P256.KeyAgreement.PublicKey? {
        guard let resolution = DaemonKeyLocator.resolve() else { return nil }
        ownerHome = resolution.ownerHome
        ingestKey = resolution.key
        if resolution.wasPinnedNow {
            log("pinned the ingest key from \(resolution.ownerHome ?? "unknown home")")
        }
        if resolution.substitutionDetected {
            // Someone replaced the published key. Keep using the pinned one and
            // make the discrepancy visible rather than silently switching.
            let warning = "The published ingest key no longer matches the pinned one. Still recording to the original key; this may indicate tampering."
            log("WARNING: \(warning)")
            mutex.lock(); status.lastError = warning; mutex.unlock()
        }
        return resolution.key
    }

    private func scheduleIngestKeyWatch() {
        let timer = Timer(timeInterval: 5, repeats: true) { [weak self] timer in
            guard let self else { timer.invalidate(); return }
            guard self.resolveIngestKey() != nil else { return }
            timer.invalidate()
            self.log("ingest key appeared; beginning to record")
            self.mutex.lock(); self.status.lastError = nil; self.mutex.unlock()
            self.reloadConfiguration(force: true)
            self.startEngine()
        }
        RunLoop.current.add(timer, forMode: .common)
    }

    private func startEngine() {
        guard let publicKey = DaemonKeyLocator.resolve()?.key else {
            log("ingest key unreadable; not recording")
            return
        }
        guard configuration.enabled else {
            log("agent disabled in configuration; idling")
            return
        }

        do {
            let store = try EventStore(writeOnlyRecipient: publicKey)
            self.store = store

            let engine = WatcherEngine(store: store,
                                       settings: configuration.appSettings,
                                       rules: configuration.rules,
                                       contentRecipient: publicKey)
            engine.onStatusChange = { [weak self] _ in self?.refreshStatus() }
            self.engine = engine

            if engine.start() {
                log("watching \(engine.currentStatus.watchedPaths.count) path(s)")
            } else {
                log("failed to start the filesystem monitor")
                mutex.lock(); status.lastError = "Could not start the filesystem monitor."; mutex.unlock()
            }
        } catch {
            log("could not open the log: \(error.localizedDescription)")
            mutex.lock(); status.lastError = error.localizedDescription; mutex.unlock()
        }
        refreshStatus()
    }

    private func stopEngine() {
        engine?.stop()
        engine = nil
        store?.close()
        store = nil
    }

    // MARK: - Configuration

    private func scheduleConfigurationWatch() {
        let timer = Timer(timeInterval: 5, repeats: true) { [weak self] _ in
            self?.reloadConfiguration(force: false)
        }
        RunLoop.current.add(timer, forMode: .common)
    }

    /// Picks up changes the app makes without needing to be restarted.
    private func reloadConfiguration(force: Bool) {
        guard let loaded = AgentConfiguration.readNewest(user: ownerConfigurationURL) else {
            if force { log("no configuration found; using defaults") }
            return
        }
        if !force, loaded.updatedAt == configurationStamp { return }
        configurationStamp = loaded.updatedAt

        let wasEnabled = configuration.enabled
        configuration = loaded

        if !loaded.enabled {
            if wasEnabled || force {
                log("configuration disabled the agent; stopping")
                stopEngine()
                refreshStatus()
            }
            return
        }
        if engine == nil {
            if !force { log("configuration re-enabled the agent") }
            startEngine()
        } else {
            engine?.updateSettings(loaded.appSettings)
            engine?.ruleEngine.setRules(loaded.rules)
            if !force { log("configuration reloaded") }
        }
    }

    /// Where the app publishes configuration for this daemon: the home of the
    /// user whose ingest key was pinned.
    private var ownerConfigurationURL: URL? {
        guard let ownerHome else { return nil }
        return AppPaths.userSupportDirectory(home: ownerHome)
            .appendingPathComponent("agent-config.enc")
    }

    /// Periodically checks that nothing has interfered with the audit storage.
    private func scheduleTrailGuard() {
        let timer = Timer(timeInterval: 15, repeats: true) { [weak self] _ in
            guard let self, let store = self.store else { return }
            // Re-assert permissions on everything the app has to read. A
            // container created by an earlier build keeps its old mode
            // otherwise, and recovery silently shows nothing.
            for url in [AppPaths.agentContentVaultFile, AgentPaths.status,
                        EventCursor.fileURL, AgentPaths.logFile] {
                guard FileManager.default.fileExists(atPath: url.path) else { continue }
                let current = (try? FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions]
                               as? NSNumber)?.intValue
                if current != AppPaths.filePermissions {
                    try? FileManager.default.setAttributes(
                        [.posixPermissions: AppPaths.filePermissions], ofItemAtPath: url.path)
                    self.log("repaired permissions on \(url.lastPathComponent)")
                }
            }

            let findings = self.trailGuard.inspect()
            guard !findings.isEmpty else { return }
            for finding in findings {
                self.log("TAMPER: \(finding.ruleHits.first ?? finding.path)")
            }
            // Written into the trail itself, so the evidence survives alongside
            // whatever it is evidence of.
            store.record(findings)
            store.flush()
            self.mutex.lock()
            self.status.lastError = findings.first?.ruleHits.first
            self.mutex.unlock()
        }
        RunLoop.current.add(timer, forMode: .common)
    }

    // MARK: - Status

    private func scheduleHeartbeat() {
        let timer = Timer(timeInterval: 5, repeats: true) { [weak self] _ in
            self?.refreshStatus()
        }
        RunLoop.current.add(timer, forMode: .common)
        refreshStatus()
    }

    private func refreshStatus() {
        mutex.lock()
        var snapshot = status
        snapshot.pid = getpid()
        snapshot.heartbeat = Date()
        snapshot.runningAsRoot = AppPaths.isRunningAsRoot
        snapshot.logDirectory = AppPaths.logDirectory.path
        if let engine {
            let engineStatus = engine.currentStatus
            snapshot.eventsRecorded = engineStatus.eventsProcessed
            snapshot.eventsFiltered = engineStatus.eventsFiltered
            snapshot.eventsDropped = engineStatus.eventsDropped
            snapshot.transfersDetected = engineStatus.transfersDetected
            snapshot.alertsRaised = engineStatus.alertsRaised
            snapshot.watchedPaths = engineStatus.watchedPaths
            snapshot.isMonitoring = engineStatus.isMonitoring
        } else {
            snapshot.isMonitoring = false
        }
        status = snapshot
        let recipient = ingestKey
        mutex.unlock()
        snapshot.write(sealingTo: recipient)
    }

    // MARK: - Shutdown

    private func installSignalHandlers() {
        // launchd sends SIGTERM; flush rather than lose buffered events.
        for signalNumber in [SIGTERM, SIGINT] {
            signal(signalNumber, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .main)
            source.setEventHandler { [weak self] in self?.shutdown() }
            source.resume()
            signalSources.append(source)
        }
    }

    private var signalSources: [DispatchSourceSignal] = []

    private func shutdown() {
        guard !shuttingDown else { return }
        shuttingDown = true
        log("agent stopping; flushing")
        stopEngine()
        AgentStatus.clear()
        log("agent stopped")
        exit(0)
    }
}

let agent = Agent()
agent.run()
