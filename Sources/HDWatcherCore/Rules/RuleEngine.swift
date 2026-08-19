import Foundation

/// Evaluates every event against the active rule set.
///
/// Two mechanisms keep alerts useful rather than overwhelming: a per-rule
/// cooldown, and burst conditions that only fire once a threshold is crossed
/// inside a sliding window. Both are tracked per group key, so a mass deletion
/// in one folder does not mute the same rule for a different folder.
public final class RuleEngine: @unchecked Sendable {

    private let mutex = NSLock()
    private var rules: [AlertRule] = []
    private weak var registry: VolumeRegistry?

    /// ruleID|groupKey -> timestamps inside the burst window
    private var burstWindows: [String: [Date]] = [:]
    /// ruleID|groupKey -> when the rule last fired
    private var cooldowns: [String: Date] = [:]

    public init(registry: VolumeRegistry?, rules: [AlertRule] = []) {
        self.registry = registry
        self.rules = rules
    }

    // MARK: - Rule management

    public var allRules: [AlertRule] {
        mutex.lock(); defer { mutex.unlock() }
        return rules
    }

    public func setRules(_ newRules: [AlertRule]) {
        mutex.lock(); defer { mutex.unlock() }
        rules = newRules
    }

    public func upsert(_ rule: AlertRule) {
        mutex.lock(); defer { mutex.unlock() }
        if let index = rules.firstIndex(where: { $0.id == rule.id }) {
            rules[index] = rule
        } else {
            rules.append(rule)
        }
    }

    public func remove(id: UUID) {
        mutex.lock(); defer { mutex.unlock() }
        rules.removeAll { $0.id == id }
    }

    public func setEnabled(_ enabled: Bool, id: UUID) {
        mutex.lock(); defer { mutex.unlock() }
        if let index = rules.firstIndex(where: { $0.id == id }) {
            rules[index].enabled = enabled
        }
    }

    // MARK: - Evaluation

    /// Paths worth watching at low latency, gathered from rules that ask for
    /// process attribution. Used to seed the sentinel stream.
    public func auditedPathPatterns() -> [GlobPattern] {
        mutex.lock(); defer { mutex.unlock() }
        return rules
            .filter { $0.enabled && $0.actions.auditProcesses }
            .flatMap { $0.conditions.pathIncludes }
    }

    /// True when any enabled rule that matches this event wants attribution.
    public func wantsProcessAudit(for event: FileEvent) -> Bool {
        mutex.lock()
        let candidates = rules.filter { $0.enabled && $0.actions.auditProcesses }
        mutex.unlock()
        return candidates.contains { matches(rule: $0, event: event) }
    }

    /// Returns the event (with severity raised and rule names attached where
    /// applicable) plus any alerts it produced.
    public func evaluate(_ event: FileEvent) -> (event: FileEvent, alerts: [SecurityAlert]) {
        mutex.lock()
        let active = rules.filter(\.enabled)
        mutex.unlock()

        var result = event
        var alerts: [SecurityAlert] = []

        for rule in active {
            guard matches(rule: rule, event: event) else { continue }

            let groupKey = burstGroupKey(rule: rule, event: event)
            let stateKey = "\(rule.id.uuidString)|\(groupKey)"

            var matchCount = 1
            if let burst = rule.conditions.burst {
                guard let count = registerBurst(key: stateKey, burst: burst, at: event.timestamp) else {
                    continue   // threshold not reached yet
                }
                matchCount = count
            }

            guard passesCooldown(key: stateKey, rule: rule, at: event.timestamp) else { continue }

            result.ruleHits.append(rule.name)
            if rule.actions.elevateEventSeverity, rule.severity > result.severity {
                result.severity = rule.severity
            }

            alerts.append(SecurityAlert(
                timestamp: event.timestamp,
                ruleID: rule.id,
                ruleName: rule.name,
                severity: rule.severity,
                title: title(for: rule, event: event, matchCount: matchCount),
                detail: detail(for: rule, event: event, matchCount: matchCount),
                event: result,
                matchCount: matchCount
            ))

            mutex.lock()
            if let index = rules.firstIndex(where: { $0.id == rule.id }) {
                rules[index].lastTriggeredAt = event.timestamp
                rules[index].triggerCount += 1
            }
            mutex.unlock()
        }

        return (result, alerts)
    }

    // MARK: - Matching

    private func matches(rule: AlertRule, event: FileEvent) -> Bool {
        let c = rule.conditions

        if !c.eventKinds.isEmpty, !c.eventKinds.contains(event.kind) { return false }
        if c.filesOnly, event.isDirectory { return false }
        if c.directoriesOnly, !event.isDirectory { return false }
        if event.kind.isTransfer, event.confidence < c.minConfidence { return false }

        if !c.pathIncludes.isEmpty {
            let hit = c.pathIncludes.matchesAny(event.path)
                || (event.sourcePath.map { c.pathIncludes.matchesAny($0) } ?? false)
            if !hit { return false }
        }
        if !c.pathExcludes.isEmpty, c.pathExcludes.matchesAny(event.path) { return false }

        if !c.fileExtensions.isEmpty, !c.fileExtensions.contains(event.fileExtension) { return false }

        if let minSize = c.minSize, (event.size ?? 0) < minSize { return false }
        if let maxSize = c.maxSize, (event.size ?? Int64.max) > maxSize { return false }

        if !c.specificVolumeIDs.isEmpty {
            let ids = [event.volumeID, event.sourceVolumeID].compactMap { $0 }
            if !ids.contains(where: { c.specificVolumeIDs.contains($0) }) { return false }
        }
        if !c.destinationVolumeClasses.isEmpty {
            let klass = volumeClass(id: event.volumeID, path: event.path)
            if !c.destinationVolumeClasses.contains(klass) { return false }
        }
        if !c.sourceVolumeClasses.isEmpty {
            let klass = volumeClass(id: event.sourceVolumeID, path: event.sourcePath)
            if !c.sourceVolumeClasses.contains(klass) { return false }
        }
        if let window = c.timeWindow, !window.admits(event.timestamp) { return false }

        return true
    }

    private func volumeClass(id: String?, path: String?) -> VolumeClass {
        if let id, let volume = registry?.volume(id: id) { return volume.volumeClass }
        if let path, let volume = registry?.volume(for: path) { return volume.volumeClass }
        return .unknown
    }

    // MARK: - Burst and cooldown

    private func burstGroupKey(rule: AlertRule, event: FileEvent) -> String {
        switch rule.conditions.burst?.grouping {
        case .directory:     return event.directory
        case .volume:        return event.volumeID ?? "-"
        case .fileExtension: return event.fileExtension
        case .global, .none: return "*"
        }
    }

    /// Records a match and returns the window count once the threshold is met.
    private func registerBurst(key: String, burst: BurstCondition, at date: Date) -> Int? {
        mutex.lock(); defer { mutex.unlock() }
        let cutoff = date.addingTimeInterval(-burst.windowSeconds)
        var window = (burstWindows[key] ?? []).filter { $0 > cutoff }
        window.append(date)
        burstWindows[key] = window

        guard window.count >= burst.threshold else { return nil }
        // Reset so the next alert needs a fresh threshold rather than firing on
        // every subsequent event.
        burstWindows[key] = []
        return window.count
    }

    private func passesCooldown(key: String, rule: AlertRule, at date: Date) -> Bool {
        guard rule.cooldownSeconds > 0 else { return true }
        mutex.lock(); defer { mutex.unlock() }
        if let last = cooldowns[key], date.timeIntervalSince(last) < rule.cooldownSeconds {
            return false
        }
        cooldowns[key] = date
        return true
    }

    /// Drops tracking state for windows that can no longer matter.
    public func pruneState(now: Date = Date()) {
        mutex.lock(); defer { mutex.unlock() }
        let cutoff = now.addingTimeInterval(-3600)
        burstWindows = burstWindows.compactMapValues { window in
            let kept = window.filter { $0 > cutoff }
            return kept.isEmpty ? nil : kept
        }
        cooldowns = cooldowns.filter { $0.value > cutoff }
    }

    // MARK: - Messages

    private func title(for rule: AlertRule, event: FileEvent, matchCount: Int) -> String {
        if rule.conditions.burst != nil, matchCount > 1 {
            return "\(rule.name) — \(matchCount) events"
        }
        return rule.name
    }

    private func detail(for rule: AlertRule, event: FileEvent, matchCount: Int) -> String {
        var parts: [String] = []

        if let source = event.sourcePath {
            parts.append("\(Format.abbreviatePath(source)) → \(Format.abbreviatePath(event.path))")
        } else {
            parts.append(Format.abbreviatePath(event.path))
        }
        if let size = event.size, size > 0 { parts.append(Format.bytes(size)) }

        if let volumeID = event.volumeID, let volume = registry?.volume(id: volumeID) {
            parts.append("on \(volume.name)")
        }
        if event.kind.isTransfer, event.confidence != .none {
            parts.append("\(event.confidence.displayName) confidence")
        }
        if rule.conditions.burst != nil, matchCount > 1 {
            parts.append("\(matchCount) matches in window")
        }
        return parts.joined(separator: " · ")
    }
}
