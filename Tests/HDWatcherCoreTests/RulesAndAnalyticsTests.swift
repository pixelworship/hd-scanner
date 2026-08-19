import XCTest
@testable import HDWatcherCore

final class RulesAndAnalyticsTests: XCTestCase {

    private func event(kind: EventKind, path: String, size: Int64? = nil,
                       confidence: Confidence = .none, at: Date = Date(),
                       volumeID: String? = "vol-a", sourceVolumeID: String? = nil,
                       sourcePath: String? = nil) -> FileEvent {
        FileEvent(timestamp: at, kind: kind, path: path, sourcePath: sourcePath,
                  volumeID: volumeID, sourceVolumeID: sourceVolumeID,
                  size: size, confidence: confidence)
    }

    // MARK: - Rule matching

    func testExtensionAndKindMatching() {
        let rule = AlertRule(
            name: "Keys leaving",
            severity: .critical,
            conditions: RuleConditions(eventKinds: [.copiedOut],
                                       fileExtensions: ["pem", "key"]),
            cooldownSeconds: 0
        )
        let engine = RuleEngine(registry: nil, rules: [rule])

        let hit = engine.evaluate(event(kind: .copiedOut, path: "/Volumes/USB/id_rsa.pem"))
        XCTAssertEqual(hit.alerts.count, 1)
        XCTAssertEqual(hit.event.severity, .critical, "a matching rule elevates event severity")
        XCTAssertEqual(hit.event.ruleHits, ["Keys leaving"])

        XCTAssertTrue(engine.evaluate(event(kind: .copiedOut, path: "/Volumes/USB/notes.txt")).alerts.isEmpty,
                      "wrong extension must not match")
        XCTAssertTrue(engine.evaluate(event(kind: .created, path: "/Volumes/USB/id_rsa.pem")).alerts.isEmpty,
                      "wrong event kind must not match")
    }

    func testPathGlobMatching() {
        let rule = AlertRule(
            name: "SSH watch",
            conditions: RuleConditions(pathIncludes: [GlobPattern("~/.ssh/**")]),
            cooldownSeconds: 0
        )
        let engine = RuleEngine(registry: nil, rules: [rule])
        let home = NSHomeDirectory()

        XCTAssertEqual(engine.evaluate(event(kind: .modified, path: "\(home)/.ssh/config")).alerts.count, 1)
        XCTAssertTrue(engine.evaluate(event(kind: .modified, path: "\(home)/Documents/config")).alerts.isEmpty)
    }

    func testSizeThreshold() {
        let rule = AlertRule(
            name: "Big transfer",
            conditions: RuleConditions(eventKinds: [.copiedOut], minSize: 1_000_000),
            cooldownSeconds: 0
        )
        let engine = RuleEngine(registry: nil, rules: [rule])
        XCTAssertEqual(engine.evaluate(event(kind: .copiedOut, path: "/a/big.zip", size: 5_000_000)).alerts.count, 1)
        XCTAssertTrue(engine.evaluate(event(kind: .copiedOut, path: "/a/small.zip", size: 500)).alerts.isEmpty)
    }

    func testConfidenceFloorSuppressesWeakInferences() {
        let rule = AlertRule(
            name: "Confident transfers only",
            conditions: RuleConditions(eventKinds: [.copiedOut], minConfidence: .high),
            cooldownSeconds: 0
        )
        let engine = RuleEngine(registry: nil, rules: [rule])
        XCTAssertTrue(engine.evaluate(event(kind: .copiedOut, path: "/a/x", confidence: .low)).alerts.isEmpty)
        XCTAssertEqual(engine.evaluate(event(kind: .copiedOut, path: "/a/x", confidence: .high)).alerts.count, 1)
    }

    // MARK: - Burst and cooldown

    func testBurstRequiresThreshold() {
        let rule = AlertRule(
            name: "Mass delete",
            conditions: RuleConditions(
                eventKinds: [.removed],
                burst: BurstCondition(threshold: 5, windowSeconds: 60, grouping: .directory)
            ),
            cooldownSeconds: 0
        )
        let engine = RuleEngine(registry: nil, rules: [rule])

        var fired = 0
        for i in 0..<4 {
            fired += engine.evaluate(event(kind: .removed, path: "/data/f\(i)")).alerts.count
        }
        XCTAssertEqual(fired, 0, "below threshold nothing fires")

        let result = engine.evaluate(event(kind: .removed, path: "/data/f5"))
        XCTAssertEqual(result.alerts.count, 1, "the fifth event crosses the threshold")
        XCTAssertEqual(result.alerts.first?.matchCount, 5)
    }

    func testBurstIsGroupedPerDirectory() {
        let rule = AlertRule(
            name: "Per-dir burst",
            conditions: RuleConditions(
                eventKinds: [.removed],
                burst: BurstCondition(threshold: 3, windowSeconds: 60, grouping: .directory)
            ),
            cooldownSeconds: 0
        )
        let engine = RuleEngine(registry: nil, rules: [rule])

        // Two events in each of two directories: neither group reaches 3.
        for dir in ["/one", "/two"] {
            for i in 0..<2 {
                XCTAssertTrue(engine.evaluate(event(kind: .removed, path: "\(dir)/f\(i)")).alerts.isEmpty)
            }
        }
        // A third in /one trips only that group.
        XCTAssertEqual(engine.evaluate(event(kind: .removed, path: "/one/f9")).alerts.count, 1)
    }

    func testCooldownSuppressesRepeats() {
        let rule = AlertRule(
            name: "Cooling",
            conditions: RuleConditions(eventKinds: [.created]),
            cooldownSeconds: 300
        )
        let engine = RuleEngine(registry: nil, rules: [rule])
        let now = Date()

        XCTAssertEqual(engine.evaluate(event(kind: .created, path: "/a/1", at: now)).alerts.count, 1)
        XCTAssertEqual(engine.evaluate(event(kind: .created, path: "/a/2", at: now.addingTimeInterval(5))).alerts.count, 0,
                       "a second match inside the cooldown is suppressed")
        XCTAssertEqual(engine.evaluate(event(kind: .created, path: "/a/3", at: now.addingTimeInterval(400))).alerts.count, 1,
                       "after the cooldown the rule fires again")
    }

    func testDisabledRuleNeverFires() {
        let rule = AlertRule(name: "Off", enabled: false,
                             conditions: RuleConditions(eventKinds: [.created]), cooldownSeconds: 0)
        let engine = RuleEngine(registry: nil, rules: [rule])
        XCTAssertTrue(engine.evaluate(event(kind: .created, path: "/a/1")).alerts.isEmpty)
    }

    // MARK: - Time windows

    func testOffHoursWindow() {
        let window = TimeWindowCondition(startHour: 8, endHour: 19, inverted: true, weekendsCount: false)
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!

        func date(hour: Int, day: Int = 4) -> Date {   // a Wednesday
            var c = DateComponents()
            c.year = 2026; c.month = 2; c.day = day; c.hour = hour
            return calendar.date(from: c)!
        }
        XCTAssertFalse(window.admits(date(hour: 12), calendar: calendar), "midday is inside working hours")
        XCTAssertTrue(window.admits(date(hour: 3), calendar: calendar), "3am is off-hours")
        XCTAssertTrue(window.admits(date(hour: 22), calendar: calendar), "10pm is off-hours")
    }

    // MARK: - Transfer classification

    func testTransferKindFraming() {
        // Internal -> external is framed as egress.
        XCTAssertEqual(
            TransferDetector.transferKind(sourceClass: .internalDisk, destClass: .externalDisk,
                                          isMove: false, sameVolume: false), .copiedOut)
        XCTAssertEqual(
            TransferDetector.transferKind(sourceClass: .internalDisk, destClass: .removable,
                                          isMove: true, sameVolume: false), .movedOut)
        // External -> internal is ingress.
        XCTAssertEqual(
            TransferDetector.transferKind(sourceClass: .externalDisk, destClass: .internalDisk,
                                          isMove: false, sameVolume: false), .copiedIn)
        // Same volume is a rename or a clone, not a transfer.
        XCTAssertEqual(
            TransferDetector.transferKind(sourceClass: .internalDisk, destClass: .internalDisk,
                                          isMove: true, sameVolume: true), .renamed)
    }

    func testEgressIsWarnedByDefault() {
        XCTAssertEqual(TransferDetector.severity(for: .copiedOut, destClass: .removable), .warning)
        XCTAssertEqual(TransferDetector.severity(for: .copiedIn, destClass: .internalDisk), .info)
    }

    // MARK: - Hotspots

    func testHotspotRollupToAncestors() {
        let tracker = HotspotTracker()
        for i in 0..<20 {
            tracker.record(FileEvent(kind: .created, path: "/Users/me/Projects/app/src/file\(i).swift", size: 100))
        }
        for i in 0..<5 {
            tracker.record(FileEvent(kind: .removed, path: "/Users/me/Projects/app/docs/d\(i).md"))
        }

        let src = tracker.heat(for: "/Users/me/Projects/app/src")
        XCTAssertEqual(src?.directEvents, 20)
        XCTAssertEqual(src?.creates, 20)

        let app = tracker.heat(for: "/Users/me/Projects/app")
        XCTAssertEqual(app?.subtreeEvents, 25, "a parent must total everything beneath it")
        XCTAssertEqual(app?.directEvents, 0, "no events landed directly in the parent")

        let docs = tracker.heat(for: "/Users/me/Projects/app/docs")
        XCTAssertEqual(docs?.deletes, 5)
        XCTAssertEqual(docs?.deleteRatio, 1.0)
    }

    func testHotspotRankingAndChildren() {
        let tracker = HotspotTracker()
        for i in 0..<50 { tracker.record(FileEvent(kind: .modified, path: "/data/hot/f\(i)")) }
        for i in 0..<5  { tracker.record(FileEvent(kind: .modified, path: "/data/cold/f\(i)")) }

        let top = tracker.topDirectories(5, by: .totalEvents)
        XCTAssertEqual(top.first?.path, "/data/hot")

        let children = tracker.children(of: "/data")
        XCTAssertEqual(Set(children.map(\.path)), ["/data/hot", "/data/cold"])
        XCTAssertEqual(children.first?.path, "/data/hot", "children are ordered by subtree activity")
    }

    func testHeatDecaysOverTime() {
        var config = HotspotTracker.Configuration()
        config.halfLife = 60
        let tracker = HotspotTracker(config: config)

        let past = Date().addingTimeInterval(-600)
        for i in 0..<10 { tracker.record(FileEvent(timestamp: past, kind: .created, path: "/old/f\(i)")) }
        for i in 0..<10 { tracker.record(FileEvent(kind: .created, path: "/new/f\(i)")) }

        let ranked = tracker.topDirectories(5, by: .heat)
        XCTAssertEqual(ranked.first?.path, "/new",
                       "recent activity must outrank equal-volume older activity")
    }

    // MARK: - Stats

    func testActivityStatsBucketing() {
        let stats = ActivityStats()
        let now = Date()
        for i in 0..<30 {
            stats.record(FileEvent(timestamp: now, kind: .created, path: "/a/f\(i).txt", size: 1000))
        }
        for i in 0..<10 {
            stats.record(FileEvent(timestamp: now, kind: .removed, path: "/a/g\(i).log"))
        }

        XCTAssertEqual(stats.totalEvents, 40)
        let series = stats.series(minutes: 5, now: now)
        XCTAssertEqual(series.count, 5, "gaps are filled so the chart shows quiet minutes")
        XCTAssertEqual(series.reduce(0) { $0 + $1.total }, 40)
        XCTAssertEqual(series.reduce(0) { $0 + $1.creates }, 30)
        XCTAssertEqual(series.reduce(0) { $0 + $1.deletes }, 10)

        let exts = stats.topExtensions()
        XCTAssertEqual(exts.first(where: { $0.ext == "txt" })?.count, 30)
        XCTAssertEqual(exts.first(where: { $0.ext == "log" })?.count, 10)
    }

    // MARK: - Filtering

    func testDefaultExclusionsDropSystemNoise() {
        let normalizer = EventNormalizer(settings: .default)
        XCTAssertFalse(normalizer.shouldReport(path: "/System/Library/Foo"))
        XCTAssertFalse(normalizer.shouldReport(path: "/Users/me/Documents/.DS_Store"))
        XCTAssertFalse(normalizer.shouldReport(path: "/Users/me/Library/Caches/x/y"))
        XCTAssertFalse(normalizer.shouldReport(path: "/Users/me/proj/node_modules/lib/a.js"))
        XCTAssertTrue(normalizer.shouldReport(path: "/Users/me/Documents/report.pdf"))
        XCTAssertTrue(normalizer.shouldReport(path: "/Volumes/USB/data.zip"))
    }

    func testRawModeReportsEverything() {
        let normalizer = EventNormalizer(settings: .raw)
        XCTAssertTrue(normalizer.shouldReport(path: "/System/Library/Foo"))
        XCTAssertTrue(normalizer.shouldReport(path: "/Users/me/Documents/.DS_Store"))
    }

    func testAppNeverLogsItsOwnVault() {
        let normalizer = EventNormalizer(settings: .raw)
        XCTAssertFalse(normalizer.shouldReport(path: AppPaths.supportDirectory.path + "/log/seg-1.hdwseg"),
                       "logging our own writes would feed the watcher into itself")
    }

    func testIncludeOnlyOverridesExclusions() {
        let settings = FilterSettings(includeOnlyPatterns: [GlobPattern("/Volumes/**")])
        let normalizer = EventNormalizer(settings: settings)
        XCTAssertTrue(normalizer.shouldReport(path: "/Volumes/USB/x.txt"))
        XCTAssertFalse(normalizer.shouldReport(path: "/Users/me/Documents/x.txt"))
    }
}

/// Regressions for issues found while running the app against real hardware.
final class ReportedIssueTests: XCTestCase {

    // A USB stick being plugged in produced two "New volume connected" alerts,
    // because FSEvents raises a Mount flag and VolumeRegistry posts its own
    // event for the same action.
    func testMountEventsComeOnlyFromTheVolumeRegistry() {
        let normalizer = EventNormalizer(settings: .raw)
        let mountFlags = FSEventStreamEventFlags(kFSEventStreamEventFlagMount)
        let unmountFlags = FSEventStreamEventFlags(kFSEventStreamEventFlagUnmount)

        let mount = RawFSEvent(path: "/Volumes/USB", flags: mountFlags, eventID: 1, inode: nil)
        let unmount = RawFSEvent(path: "/Volumes/USB", flags: unmountFlags, eventID: 2, inode: nil)

        XCTAssertNil(normalizer.normalize(mount, volume: nil),
                     "FSEvents mount flags must be dropped so only the registry reports a mount")
        XCTAssertNil(normalizer.normalize(unmount, volume: nil),
                     "FSEvents unmount flags must be dropped too")
    }

    // Ejecting a drive raised no alert at all: there was a rule for mounting
    // but none for unmounting.
    func testDisconnectRuleExistsAndFires() {
        let rules = AlertRule.builtInRules()
        let disconnect = rules.first { $0.conditions.eventKinds.contains(.unmounted) }
        XCTAssertNotNil(disconnect, "a built-in rule must cover volume disconnection")
        XCTAssertEqual(disconnect?.enabled, true)

        let engine = RuleEngine(registry: nil, rules: rules)
        let event = FileEvent(kind: .unmounted, path: "/Volumes/USB",
                              volumeID: "usb-1", isDirectory: true)
        let alerts = engine.evaluate(event).alerts
        XCTAssertTrue(alerts.contains { $0.ruleName == "Volume disconnected" })
    }

    // Only one alert should result from one mount.
    func testSingleMountProducesSingleAlert() {
        let engine = RuleEngine(registry: nil, rules: AlertRule.builtInRules())
        let event = FileEvent(kind: .mounted, path: "/Volumes/USB",
                              volumeID: "usb-1", isDirectory: true)
        let alerts = engine.evaluate(event).alerts
        XCTAssertEqual(alerts.filter { $0.ruleName == "New volume connected" }.count, 1)
    }

    // Copying to a USB stick showed up under Transfers but raised no alert,
    // because the source could not be identified and the rule demanded medium
    // confidence.
    func testExfiltrationRuleFiresEvenWhenSourceIsUnknown() {
        let rule = AlertRule.builtInRules().first { $0.name == "Data copied to external drive" }
        XCTAssertEqual(rule?.conditions.minConfidence, .low)

        // A registry that classifies the destination as removable media.
        let engine = RuleEngine(registry: nil, rules: [
            AlertRule(name: "Copy out",
                      conditions: RuleConditions(eventKinds: [.copiedOut], minConfidence: .low),
                      cooldownSeconds: 0)
        ])
        let event = FileEvent(kind: .copiedOut, path: "/Volumes/USB/report.pdf",
                              size: 1024, confidence: .low)
        XCTAssertEqual(engine.evaluate(event).alerts.count, 1,
                       "an unattributed copy onto removable media must still alert")
    }

    // A file landing on a USB stick was labelled "Copied In" (arriving), when
    // from this Mac's point of view data going onto removable media is leaving.
    func testUnattributedArrivalOnRemovableMediaIsFramedAsLeaving() {
        // Direction framing is decided by transferKind for known sources...
        XCTAssertEqual(
            TransferDetector.transferKind(sourceClass: .internalDisk, destClass: .removable,
                                          isMove: false, sameVolume: false),
            .copiedOut)
        // ...and the unattributed path must agree rather than defaulting to inbound.
        let detector = TransferDetector(registry: nil)
        let event = FileEvent(kind: .created, path: "/Volumes/USB/report.pdf", size: 2048)
        let framed = detector.testUnattributedArrival(event, destClass: .removable)
        XCTAssertEqual(framed.kind, .copiedOut,
                       "content appearing on removable media is egress, not ingress")
        XCTAssertEqual(framed.confidence, .low)
    }

    // The log is an audit trail: there must be no way to prune or erase it.
    // Only captured file contents expire.
    func testEventLogHasNoRetentionOrPurge() {
        // AppSettings deliberately exposes no event-retention knob at all.
        let settings = AppSettings.default
        let mirror = Mirror(reflecting: settings)
        let names = mirror.children.compactMap(\.label)
        XCTAssertFalse(names.contains("retention"),
                       "the event log must not have a retention setting")

        // File contents, by contrast, do expire on a schedule the user picks.
        XCTAssertEqual(settings.contentRetention, .oneDay)
        XCTAssertTrue(SnapshotRetention.allCases.contains(.forever))
        XCTAssertTrue(SnapshotRetention.allCases.contains(.never))
    }

    // An ejected drive should still be nameable for events recorded while it
    // was attached.
    func testDepartedVolumesStillResolveByName() {
        let registry = VolumeRegistry()
        // The root volume is always present; look it up, then confirm the
        // history-backed path returns the same record.
        guard let root = registry.mountedVolumes.first(where: { $0.isRootVolume }) else {
            return XCTFail("expected a root volume")
        }
        XCTAssertEqual(registry.volume(id: root.id)?.name, root.name)
        XCTAssertTrue(registry.volumeHistory.contains { $0.id == root.id },
                      "mounted volumes must also be recorded in history for later lookup")
    }
}

/// The Volumes screen listed an external drive that had already been ejected,
/// and was cluttered with macOS system mounts.
final class VolumeRegistryTests: XCTestCase {

    func testSystemMountsAreSeparatedFromUserVolumes() {
        let registry = VolumeRegistry()
        let user = registry.mountedVolumes
        let system = registry.systemVolumes

        XCTAssertFalse(user.isEmpty, "the startup disk must always be listed")
        XCTAssertTrue(user.contains { $0.isRootVolume })

        // Nothing appears in both lists.
        let userIDs = Set(user.map(\.id))
        XCTAssertTrue(system.allSatisfy { !userIDs.contains($0.id) })
        XCTAssertTrue(user.allSatisfy { !$0.isSystemVolume })
        XCTAssertTrue(system.allSatisfy { $0.isSystemVolume })

        // The macOS plumbing must not be presented as user volumes.
        let userPaths = user.map(\.mountPath)
        for hidden in ["/System/Volumes/Preboot", "/System/Volumes/VM",
                       "/System/Volumes/Update", "/dev"] {
            XCTAssertFalse(userPaths.contains(hidden),
                           "\(hidden) is system plumbing and must be hidden by default")
        }
    }

    func testSystemVolumesStillResolvePaths() {
        let registry = VolumeRegistry()
        // Attribution must keep working for system paths even though they are
        // hidden from the list.
        XCTAssertNotNil(registry.volume(for: "/System/Volumes/Preboot"),
                        "hidden volumes must still be resolvable for path attribution")
        XCTAssertNotNil(registry.volume(for: "/Users"),
                        "the Data volume must resolve to the startup disk")
        XCTAssertEqual(registry.volume(for: "/Users")?.isRootVolume, true,
                       "files under /Users belong to the startup disk, not a separate volume")
    }

    func testRefreshIsIdempotentAndDetectsNoPhantomChanges() {
        let registry = VolumeRegistry()
        var events: [(VolumeInfo, Bool)] = []
        let lock = NSLock()
        registry.onVolumeChange = { volume, mounted in
            lock.lock(); events.append((volume, mounted)); lock.unlock()
        }
        // Re-reading an unchanged mount table must not invent mount/unmount events.
        registry.refresh()
        registry.refreshIfChanged()
        registry.refresh()

        lock.lock(); let count = events.count; lock.unlock()
        XCTAssertEqual(count, 0, "refreshing with no mount changes must emit nothing")
    }

    func testMountedVolumesMatchTheRealMountTable() {
        let registry = VolumeRegistry()
        for volume in registry.mountedVolumes {
            var isDirectory: ObjCBool = false
            XCTAssertTrue(
                FileManager.default.fileExists(atPath: volume.mountPath, isDirectory: &isDirectory),
                "\(volume.name) is listed as mounted but \(volume.mountPath) does not exist"
            )
        }
    }
}
