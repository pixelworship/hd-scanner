import SwiftUI
import HDWatcherCore

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var tab: Tab = .monitoring

    enum Tab: String, CaseIterable, Identifiable {
        case monitoring = "Monitoring"
        case service = "Background"
        case filters = "Filters"
        case security = "Security"
        case storage = "Storage"
        case about = "About"
        var id: String { rawValue }

        var symbol: String {
            switch self {
            case .monitoring: return "eye"
            case .service:    return "bolt.horizontal.circle"
            case .filters:    return "line.3.horizontal.decrease.circle"
            case .security:   return "lock.shield"
            case .storage:    return "internaldrive"
            case .about:      return "info.circle"
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $tab) {
                ForEach(Tab.allCases) { tab in
                    Label(tab.rawValue, systemImage: tab.symbol).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(12)

            Divider()

            ScrollView {
                Group {
                    switch tab {
                    case .monitoring: MonitoringSettings()
                    case .service:    BackgroundServiceSettings()
                    case .filters:    FilterSettingsView()
                    case .security:   SecuritySettings()
                    case .storage:    StorageSettings()
                    case .about:      AboutSettings()
                    }
                }
                .padding(18)
            }
        }
    }
}

struct MonitoringSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model

        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Watch scope",
                              subtitle: "Which volumes HDWatcher hands to FSEvents")

                Picker("", selection: $model.settings.watchScope) {
                    ForEach(WatchScope.allCases, id: \.self) { scope in
                        Text(scope.displayName).tag(scope)
                    }
                }
                .pickerStyle(.radioGroup)
                .labelsHidden()
                .onChange(of: model.settings.watchScope) { _, _ in model.applySettings() }

                Text(model.settings.watchScope.explanation)
                    .font(.caption).foregroundStyle(.secondary)

                if model.settings.watchScope == .customPaths {
                    customPathsEditor
                }
            }
            .card()

            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Transfer detection",
                              subtitle: "How copies and moves between volumes are inferred")

                LabeledContent("Settle window") {
                    HStack {
                        Slider(value: $model.settings.transferSettleSeconds, in: 0.5...10, step: 0.5)
                            .frame(width: 200)
                        Text("\(model.settings.transferSettleSeconds, specifier: "%.1f")s")
                            .monospacedDigit().frame(width: 44, alignment: .trailing)
                    }
                }
                Text("How long to wait for a newly created file to finish being written before looking for its source.")
                    .font(.caption).foregroundStyle(.secondary)

                LabeledContent("Correlation window") {
                    HStack {
                        Slider(value: $model.settings.transferCorrelationWindowSeconds, in: 10...600, step: 10)
                            .frame(width: 200)
                        Text("\(Int(model.settings.transferCorrelationWindowSeconds))s")
                            .monospacedDigit().frame(width: 44, alignment: .trailing)
                    }
                }
                Text("How far back to look for a matching source file.")
                    .font(.caption).foregroundStyle(.secondary)

                Toggle("Compare file contents to confirm copies", isOn: $model.settings.detectContentSignatures)
                Text("Hashes the first and last 64 KB plus the size. Raises confidence from Medium to High, at the cost of a little disk I/O.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .card()

            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Performance")
                LabeledContent("Event ceiling") {
                    HStack {
                        Slider(value: Binding(
                            get: { Double(model.settings.maxEventsPerSecond) },
                            set: { model.settings.maxEventsPerSecond = Int($0) }
                        ), in: 200...20_000, step: 100)
                        .frame(width: 200)
                        Text("\(model.settings.maxEventsPerSecond)/s")
                            .monospacedDigit().frame(width: 66, alignment: .trailing)
                    }
                }
                Text("Events beyond this rate are counted and dropped rather than logged, so a runaway process cannot fill the disk. Currently dropped: \(Format.count(Int(model.status.eventsDropped))).")
                    .font(.caption).foregroundStyle(.secondary)

                LabeledContent("Hotspot half-life") {
                    HStack {
                        Slider(value: Binding(
                            get: { Double(model.settings.hotspotHalfLifeMinutes) },
                            set: { model.settings.hotspotHalfLifeMinutes = Int($0) }
                        ), in: 1...120, step: 1)
                        .frame(width: 200)
                        Text("\(model.settings.hotspotHalfLifeMinutes) min")
                            .monospacedDigit().frame(width: 60, alignment: .trailing)
                    }
                }
                Text("How quickly a directory cools down once activity stops.")
                    .font(.caption).foregroundStyle(.secondary)

                Toggle("Start monitoring automatically after unlocking", isOn: $model.settings.monitorOnUnlock)
            }
            .card()

            readsCard
            coverageCard
            permissionsCard
        }
        .onChange(of: model.settings) { _, _ in model.applySettings() }
    }

    private var customPathsEditor: some View {
        @Bindable var model = model

        return VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(model.settings.customWatchPaths.enumerated()), id: \.offset) { index, path in
                HStack {
                    Text(path).font(.caption.monospaced()).lineLimit(1).truncationMode(.head)
                    Spacer()
                    Button {
                        model.settings.customWatchPaths.remove(at: index)
                        model.applySettings()
                    } label: { Image(systemName: "minus.circle") }
                    .buttonStyle(.borderless)
                }
            }
            Button("Add Folder…") {
                let panel = NSOpenPanel()
                panel.canChooseDirectories = true
                panel.canChooseFiles = false
                panel.allowsMultipleSelection = true
                if panel.runModal() == .OK {
                    model.settings.customWatchPaths.append(contentsOf: panel.urls.map(\.path))
                    model.applySettings()
                }
            }
            .controlSize(.small)
        }
        .padding(.leading, 18)
    }

    private var permissionsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Permissions")

            HStack {
                Label("Full Disk Access", systemImage: model.fullDiskAccess == .granted ? "checkmark.shield.fill" : "exclamationmark.shield")
                    .foregroundStyle(model.fullDiskAccess == .granted ? .green : .orange)
                Spacer()
                Text(model.fullDiskAccess.rawValue).foregroundStyle(.secondary)
                Button("Open Settings") { Permissions.openFullDiskAccessSettings() }
                    .controlSize(.small)
            }
            Text("Without it, macOS hides protected folders such as Mail, Messages and other apps' containers from the watcher.")
                .font(.caption).foregroundStyle(.secondary)

            Divider()

            HStack {
                Label("Notifications", systemImage: "bell")
                Spacer()
                Text(model.notificationStatus.rawValue).foregroundStyle(.secondary)
                Button("Open Settings") { Permissions.openNotificationSettings() }
                    .controlSize(.small)
            }

            Button("Re-check permissions") { model.refreshPermissions() }
                .controlSize(.small)

            Divider()
            VStack(alignment: .leading, spacing: 5) {
                Text("Protected-location spot check").font(.caption.weight(.medium))
                Text("Whether macOS is letting us see into the folders it normally hides. This is about permission, not about which volumes are being watched — see Disk coverage below for that.")
                    .font(.caption2).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(Permissions.readableProbe()) { probe in
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: probe.exists
                              ? (probe.readable ? "checkmark.circle.fill" : "xmark.circle.fill")
                              : "minus.circle")
                            .font(.caption2)
                            .foregroundStyle(probe.exists
                                             ? (probe.readable ? Color.green : Color.red)
                                             : Color.secondary)
                        VStack(alignment: .leading, spacing: 0) {
                            Text(probe.path).font(.caption.monospaced())
                            Text(probe.exists ? probe.note : "not present on this Mac")
                                .font(.system(size: 9)).foregroundStyle(.tertiary)
                        }
                    }
                }
            }
        }
        .card()
    }

    /// One line on what the watch roots amount to.
    private func coverageDetail(_ coverage: CoverageReport, watched: [String]) -> String {
        guard !watched.isEmpty else {
            return "Nothing is holding an FSEvents stream, so no changes are being recorded."
        }
        if watched.contains("/") {
            return "A watch on / covers every volume mounted beneath it, including external drives."
        }
        return "Watching \(watched.count) specific root\(watched.count == 1 ? "" : "s")."
    }

    /// Reads are a different mechanism from everything else here, and the
    /// difference is worth stating where it is switched on.
    private var readsCard: some View {
        @Bindable var model = model
        return VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Reading",
                          subtitle: "Which files are opened, and by what")

            Toggle("Record which files are read", isOn: $model.settings.trackFileReads)
                .onChange(of: model.settings.trackFileReads) { _, _ in model.applySettings() }

            Text("Nothing changes on disk when a file is read, so FSEvents cannot report it. The background daemon, running as root, taps the kernel audit trail instead and catches every open() — including a file opened and closed in a millisecond, like `cat image.png` in Terminal. Without the daemon this app falls back to sampling open files, which misses those brief reads; the Reads tab says which is active.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 10) {
                Text("Sample every").font(.callout)
                Picker("", selection: $model.settings.readSampleSeconds) {
                    Text("5 seconds").tag(5.0)
                    Text("10 seconds").tag(10.0)
                    Text("30 seconds").tag(30.0)
                    Text("1 minute").tag(60.0)
                }
                .labelsHidden()
                .frame(width: 140)
                .onChange(of: model.settings.readSampleSeconds) { _, _ in model.applySettings() }
                Text("shorter catches more, and costs more")
                    .font(.caption).foregroundStyle(.tertiary)
                Spacer()
            }
            .disabled(!model.settings.trackFileReads)

            VStack(alignment: .leading, spacing: 3) {
                Text("Where it looks").font(.caption.weight(.medium))
                ForEach(model.settings.readRoots, id: \.self) { root in
                    Text(root).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Text("Every process reads /usr/lib all day; that is not a finding. Caches, code and the app's own files are excluded.")
                    .font(.system(size: 9)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .card()
    }

    /// Answers the question the permission probe does not: what is actually
    /// being watched, and is anything being left out?
    private var coverageCard: some View {
        // Asked of whoever is actually recording. When the daemon is running,
        // the app's own engine is deliberately idle, and reporting its roots
        // here would say "not watching anything" about a Mac being watched
        // continuously by a root process.
        let coverage = model.coverage
        let watched = coverage.watchedPaths
        let volumes = model.volumes
        let uncovered = volumes.filter { !coverage.covers(mountPath: $0.mountPath) }

        return VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Disk coverage",
                          subtitle: coverage.isRecording
                            ? "Which volumes \(coverage.recorder.displayName) is recording right now"
                            : "Which volumes are being recorded right now")

            HStack(spacing: 10) {
                let healthy = coverage.isRecording && uncovered.isEmpty && !watched.isEmpty
                Image(systemName: healthy ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.title2)
                    .foregroundStyle(healthy ? .green : .orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text(watched.isEmpty
                         ? "Not watching anything"
                         : (uncovered.isEmpty
                            ? "All \(volumes.count) mounted volume\(volumes.count == 1 ? "" : "s") covered"
                            : "\(uncovered.count) volume\(uncovered.count == 1 ? "" : "s") not covered"))
                        .font(.callout.weight(.medium))
                    Text(coverageDetail(coverage, watched: watched))
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }

            Divider()

            ForEach(volumes) { volume in
                let isCovered = watched.contains { root in
                    root == "/" || volume.mountPath == root || volume.mountPath.hasPrefix(root + "/")
                }
                HStack(spacing: 7) {
                    Image(systemName: isCovered ? "checkmark.circle.fill" : "xmark.circle")
                        .font(.caption2)
                        .foregroundStyle(isCovered ? Color.green : Color.orange)
                    Image(systemName: volume.volumeClass.symbolName)
                        .font(.caption2).foregroundStyle(volume.volumeClass.tint)
                    Text(volume.name).font(.caption.weight(.medium))
                    Text(volume.mountPath).font(.caption2.monospaced()).foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text(volume.volumeClass.displayName)
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }

            Divider()
            VStack(alignment: .leading, spacing: 3) {
                Text("Watch roots handed to FSEvents").font(.caption.weight(.medium))
                if watched.isEmpty {
                    Text("none — monitoring is not running")
                        .font(.caption).foregroundStyle(.orange)
                } else if !coverage.isRecording {
                    Text("\(watched.count) root\(watched.count == 1 ? "" : "s"), but recording is paused")
                        .font(.caption).foregroundStyle(.orange)
                    ForEach(watched, id: \.self) { path in
                        Text(path).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                } else {
                    ForEach(watched, id: \.self) { path in
                        Text(path).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
                Text("Nested volumes are deliberately not listed separately: watching both a parent and a child reports every change twice.")
                    .font(.system(size: 9)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()
            VStack(alignment: .leading, spacing: 3) {
                Text("Coverage over time").font(.caption.weight(.medium))
                if let started = coverage.startedAt {
                    Text("\(coverage.recorder.displayName.capitalizedFirst) has been recording since \(Format.fullTimestamp(started)).")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Not currently recording.")
                        .font(.caption).foregroundStyle(.orange)
                }
                Text(model.isViewerMode
                     ? "The background daemon is recording, so coverage continues while this app is closed."
                     : "Recording only happens while this app is open and unlocked. Changes made in between are replayed from the saved position where macOS still has them, and any gap is written into the log as a Monitoring Started marker.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .card()
    }
}

struct FilterSettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var excludeText = ""
    @State private var includeText = ""
    @State private var loaded = false

    var body: some View {
        @Bindable var model = model

        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Noise reduction",
                              subtitle: "Filesystems generate enormous background churn. These rules keep the log meaningful.")

                Toggle("Ignore metadata-only changes", isOn: $model.settings.filter.ignoreMetadataOnlyChanges)
                Toggle("Ignore hidden files", isOn: $model.settings.filter.ignoreHiddenFiles)
                Toggle("Ignore directory events", isOn: $model.settings.filter.ignoreDirectoryEvents)
                Toggle("Record file sizes", isOn: $model.settings.filter.resolveFileSizes)
                Text("Recording sizes costs one stat() per event but makes size-based rules and byte totals possible.")
                    .font(.caption).foregroundStyle(.secondary)

                HStack {
                    Button("Use Recommended Filters") {
                        model.settings.filter = .default
                        syncText()
                        model.applySettings()
                    }
                    Button("Raw Mode (log everything)") {
                        model.settings.filter = .raw
                        syncText()
                        model.applySettings()
                    }
                    .help("Removes all exclusions. Expect a very high event rate and rapid log growth.")
                }
                .controlSize(.small)
            }
            .card()

            VStack(alignment: .leading, spacing: 8) {
                SectionHeader(title: "Exclusions",
                              subtitle: "One glob per line. Anything matching is never recorded.")
                TextEditor(text: $excludeText)
                    .font(.caption.monospaced())
                    .frame(height: 210)
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
                HStack {
                    Text("\(excludeText.split(separator: "\n").count) patterns")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Apply") { applyPatterns() }
                        .controlSize(.small)
                }
            }
            .card()

            VStack(alignment: .leading, spacing: 8) {
                SectionHeader(title: "Watch only these",
                              subtitle: "When non-empty, everything else is ignored. Overrides exclusions.")
                TextEditor(text: $includeText)
                    .font(.caption.monospaced())
                    .frame(height: 90)
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
                Button("Apply") { applyPatterns() }
                    .controlSize(.small)
            }
            .card()
        }
        .onAppear { if !loaded { syncText(); loaded = true } }
    }

    private func syncText() {
        excludeText = model.settings.filter.excludePatterns.map(\.pattern).joined(separator: "\n")
        includeText = model.settings.filter.includeOnlyPatterns.map(\.pattern).joined(separator: "\n")
    }

    private func applyPatterns() {
        model.settings.filter.excludePatterns = excludeText.split(separator: "\n")
            .map { GlobPattern($0.trimmingCharacters(in: .whitespaces)) }
            .filter { !$0.pattern.isEmpty }
        model.settings.filter.includeOnlyPatterns = includeText.split(separator: "\n")
            .map { GlobPattern($0.trimmingCharacters(in: .whitespaces)) }
            .filter { !$0.pattern.isEmpty }
        model.applySettings()
    }
}

struct SecuritySettings: View {
    @Environment(AppModel.self) private var model

    @State private var currentPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var message: String?
    @State private var messageIsError = false
    @State private var working = false

    var body: some View {
        @Bindable var model = model

        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Vault protection")
                HStack(spacing: 10) {
                    Image(systemName: model.protectionTier.isHardwareBacked ? "lock.shield.fill" : "lock.shield")
                        .font(.title2)
                        .foregroundStyle(model.protectionTier.isHardwareBacked ? .green : .orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(model.protectionTier.displayName).font(.callout.weight(.medium))
                        Text(model.protectionTier.isHardwareBacked
                             ? "The master key is wrapped by both your password and a key that never leaves this Mac's Secure Enclave. Moving the log to another machine makes it unreadable."
                             : "The master key is protected by your password alone.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if let created = model.vault.createdAt {
                    Text("Vault created \(Format.fullTimestamp(created))")
                        .font(.caption).foregroundStyle(.tertiary)
                }
            }
            .card()

            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Auto-lock")
                LabeledContent("Lock after inactivity") {
                    HStack {
                        Slider(value: Binding(
                            get: { Double(model.settings.autoLockMinutes) },
                            set: { model.settings.autoLockMinutes = Int($0) }
                        ), in: 0...120, step: 5)
                        .frame(width: 200)
                        Text(model.settings.autoLockMinutes == 0 ? "Never" : "\(model.settings.autoLockMinutes) min")
                            .monospacedDigit().frame(width: 60, alignment: .trailing)
                    }
                }
                Toggle("Lock when the Mac sleeps", isOn: $model.settings.lockOnSleep)
                Toggle("Lock when the screen locks", isOn: $model.settings.lockOnScreensaver)
                Text("Locking stops monitoring, flushes pending writes and clears decrypted events from memory.")
                    .font(.caption).foregroundStyle(.secondary)

                if SecureEnclaveKeyStore.userPresenceAvailable() {
                    Divider()
                    Toggle("Allow unlocking with \(model.biometryName)", isOn: Binding(
                        get: { model.quickUnlockAvailable },
                        set: { enabled in
                            do {
                                try model.vault.setQuickUnlock(enabled)
                                model.quickUnlockAvailable = model.vault.quickUnlockEnabled
                                message = enabled ? "Quick unlock enabled." : "Quick unlock disabled."
                                messageIsError = false
                            } catch {
                                message = error.localizedDescription
                                messageIsError = true
                            }
                        }
                    ))
                }
            }
            .card()

            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Change password",
                              subtitle: "Re-wraps the master key. Existing history stays readable.")
                SecureField("Current password", text: $currentPassword).textFieldStyle(.roundedBorder)
                SecureField("New password", text: $newPassword).textFieldStyle(.roundedBorder)
                PasswordStrengthBar(strength: PasswordStrength.evaluate(newPassword))
                SecureField("Confirm new password", text: $confirmPassword).textFieldStyle(.roundedBorder)

                HStack {
                    Button("Change Password") { changePassword() }
                        .disabled(!canChange || working)
                    if working { ProgressView().controlSize(.small) }
                }

                if let message {
                    Text(message)
                        .font(.caption)
                        .foregroundStyle(messageIsError ? .red : .green)
                }
            }
            .card()

            VStack(alignment: .leading, spacing: 8) {
                SectionHeader(title: "Notifications")
                Toggle("Send system notifications for alerts", isOn: $model.settings.notificationsEnabled)
                Text("Status: \(model.notificationStatus.rawValue)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .card()
        }
        .onChange(of: model.settings) { _, _ in model.applySettings() }
    }

    private var canChange: Bool {
        !currentPassword.isEmpty && newPassword.count >= 8 && newPassword == confirmPassword
    }

    private func changePassword() {
        working = true
        message = nil
        let vault = model.vault
        let current = currentPassword
        let updated = newPassword

        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    try vault.changePassword(current: current, new: updated)
                }.value
                await MainActor.run {
                    message = "Password changed."
                    messageIsError = false
                    currentPassword = ""; newPassword = ""; confirmPassword = ""
                    working = false
                }
            } catch {
                await MainActor.run {
                    message = error.localizedDescription
                    messageIsError = true
                    working = false
                }
            }
        }
    }
}

struct StorageSettings: View {
    @Environment(AppModel.self) private var model
    @State private var message: String?

    var body: some View {
        @Bindable var model = model

        VStack(alignment: .leading, spacing: 16) {
            eventLogCard
            contentCard
            usageCard
            if let message {
                Text(message).font(.caption).foregroundStyle(.secondary)
            }
        }
        .onChange(of: model.settings) { _, _ in model.applySettings() }
    }

    // MARK: - Event log

    private var eventLogCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Event log",
                          subtitle: "Every filesystem change, kept permanently.")

            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "lock.doc.fill")
                    .font(.title2).foregroundStyle(.green)
                VStack(alignment: .leading, spacing: 2) {
                    Text("This log is append-only").font(.callout.weight(.medium))
                    Text("Events are never pruned, expired or deleted — that is what makes it an audit trail. Only captured file contents expire, on the schedule you choose below.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Button("Archive a Copy of the Log…") { archiveLog() }
                .controlSize(.small)
            Text("Copies the encrypted segments somewhere else. Nothing is removed.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .card()
    }

    // MARK: - Captured contents

    private var contentCard: some View {
        @Bindable var model = model
        let stats = model.contentStats

        return VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Contents of changed and deleted files",
                          subtitle: "Keep a copy of file contents so you can review changes and recover deleted files.")

            Toggle("Keep contents of changed and deleted files",
                   isOn: $model.settings.captureFileContents)

            Picker("Keep contents for", selection: $model.settings.contentRetention) {
                ForEach(SnapshotRetention.allCases) { option in
                    Text(option.displayName).tag(option)
                }
            }
            .disabled(!model.settings.captureFileContents)
            .onChange(of: model.settings.contentRetention) { _, newValue in
                // Shortening the window must apply to what is already stored,
                // not only to future captures.
                model.contentVault?.applyRetention(newValue)
                model.refreshRecovery()
            }

            LabeledContent("Largest file to keep") {
                HStack {
                    Slider(value: Binding(
                        get: { Double(model.settings.maxCaptureFileBytes) / 1_048_576 },
                        set: { model.settings.maxCaptureFileBytes = Int64($0 * 1_048_576) }
                    ), in: 0.25...128, step: 0.25)
                    .frame(width: 200)
                    Text(Format.bytes(model.settings.maxCaptureFileBytes))
                        .monospacedDigit().frame(width: 76, alignment: .trailing)
                }
            }
            .disabled(!model.settings.captureFileContents)
            Text("Files above this size are skipped entirely — a partial copy would be useless to restore from.")
                .font(.caption).foregroundStyle(.secondary)

            LabeledContent("Space for stored contents") {
                HStack {
                    Slider(value: Binding(
                        get: { Double(model.settings.maxContentVaultMegabytes) },
                        set: { model.settings.maxContentVaultMegabytes = Int($0) }
                    ), in: 64...20_480, step: 64)
                    .frame(width: 200)
                    Text(Format.bytes(Int64(model.settings.maxContentVaultMegabytes) * 1_048_576))
                        .monospacedDigit().frame(width: 76, alignment: .trailing)
                }
            }
            .disabled(!model.settings.captureFileContents)

            Divider()

            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                GridRow {
                    Text("Files held").font(.caption).foregroundStyle(.secondary)
                    Text("\(stats.uniqueFileCount)  (\(stats.deletedFileCount) deleted)")
                }
                GridRow {
                    Text("Versions").font(.caption).foregroundStyle(.secondary)
                    Text("\(stats.snapshotCount)")
                }
                GridRow {
                    Text("Stored size").font(.caption).foregroundStyle(.secondary)
                    Text("\(Format.bytes(stats.liveBytes)) of \(Format.bytes(stats.containerBytes)) on disk")
                }
                GridRow {
                    Text("Skipped").font(.caption).foregroundStyle(.secondary)
                    Text("\(stats.capturesSkippedTooLarge) too large · \(stats.capturesSkippedUnchanged) unchanged")
                }
            }

            HStack {
                Button("Reclaim Space Now") {
                    try? model.contentVault?.compact()
                    model.refreshRecovery()
                }
                Button("Delete All Stored Contents", role: .destructive) {
                    model.contentVault?.clearAll()
                    model.refreshRecovery()
                }
            }
            .controlSize(.small)
            .disabled(model.contentVault == nil)
            Text("Deleting stored contents does not touch the event log — the record that a change happened is permanent either way.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Text("Contents are captured when a file is written. macOS reports a deletion only after the file is gone, so what can be recovered afterwards is the most recent version captured while it still existed.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .card()
    }

    // MARK: - Usage

    private var usageCard: some View {
        let manifest = model.store?.currentManifest

        return VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "On disk")
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                GridRow {
                    Text("Events").font(.caption).foregroundStyle(.secondary)
                    Text(Format.count(manifest?.totalEvents ?? 0))
                }
                GridRow {
                    Text("Segments").font(.caption).foregroundStyle(.secondary)
                    Text("\(manifest?.segments.count ?? 0)")
                }
                GridRow {
                    Text("Log size").font(.caption).foregroundStyle(.secondary)
                    Text(Format.bytes(manifest?.totalBytes ?? 0))
                }
                if let oldest = manifest?.oldestEvent {
                    GridRow {
                        Text("History since").font(.caption).foregroundStyle(.secondary)
                        Text(Format.fullTimestamp(oldest))
                    }
                }
                GridRow {
                    Text("Location").font(.caption).foregroundStyle(.secondary)
                    Text(AppPaths.supportDirectory.path)
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            Button("Reveal in Finder") {
                NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: AppPaths.supportDirectory.path)
            }
            .controlSize(.small)
        }
        .card()
    }

    private func archiveLog() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "Archive Here"
        panel.message = "Choose where to place a copy of the encrypted log. The originals stay in place."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let folder = url.appendingPathComponent("HDWatcher-log-archive-\(Int(Date().timeIntervalSince1970))")
            let count = try model.store?.archive(to: folder) ?? 0
            message = "Archived \(count) segment(s) to \(folder.lastPathComponent). Nothing was removed."
        } catch {
            message = "Archive failed: \(error.localizedDescription)"
        }
    }
}

struct AboutSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    Image(systemName: "externaldrive.badge.timemachine")
                        .font(.system(size: 40, weight: .light))
                        .foregroundStyle(.tint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("HDWatcher").font(.title2.weight(.semibold))
                        Text(AppPaths.bundleIdentifier)
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
            .card()

            VStack(alignment: .leading, spacing: 8) {
                SectionHeader(title: "What this app can and cannot see")
                Text("""
                HDWatcher observes the filesystem through FSEvents, the same mechanism Spotlight and \
                Time Machine use. That gives it every create, modify, delete, rename and clone across \
                the volumes you select, along with each file's inode.

                It does not see reads, and it cannot attribute a change to the process that made it. \
                Doing either requires an Endpoint Security entitlement, which Apple grants only to \
                approved developers with a provisioning profile.

                Copies are therefore inferred rather than observed. A rename is certain, because both \
                halves share an inode. A copy across volumes is matched by size, name and a content \
                digest, and every transfer is labelled with how strong that evidence is.
                """)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            .card()

            VStack(alignment: .leading, spacing: 8) {
                SectionHeader(title: "Session")
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                    GridRow {
                        Text("Events processed").font(.caption).foregroundStyle(.secondary)
                        Text(Format.count(Int(model.status.eventsProcessed)))
                    }
                    GridRow {
                        Text("Filtered as noise").font(.caption).foregroundStyle(.secondary)
                        Text(Format.count(Int(model.status.eventsFiltered)))
                    }
                    GridRow {
                        Text("Dropped (rate cap)").font(.caption).foregroundStyle(.secondary)
                        Text(Format.count(Int(model.status.eventsDropped)))
                    }
                    GridRow {
                        Text("FSEvents batches").font(.caption).foregroundStyle(.secondary)
                        Text(Format.count(Int(model.engine?.monitorStatistics.batchesReceived ?? 0)))
                    }
                    if let started = model.status.startedAt {
                        GridRow {
                            Text("Monitoring since").font(.caption).foregroundStyle(.secondary)
                            Text(Format.fullTimestamp(started))
                        }
                    }
                }
            }
            .card()
        }
    }
}


/// Install, inspect and control the always-on recording agent.
struct BackgroundServiceSettings: View {
    @Environment(AppModel.self) private var model
    @State private var message: String?
    @State private var messageIsError = false
    @State private var working = false

    private var status: AgentStatus? { model.agentStatus }
    private var isInstalled: Bool { model.backgroundServiceState == .enabled }
    private var wantsBackground: Bool { model.settings.backgroundRecordingEnabled }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            summaryCard
            if isInstalled { activityCard }
            explanationCard
        }
        .onAppear { model.refreshBackgroundService() }
    }

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(systemName: symbol)
                    .font(.system(size: 30))
                    .foregroundStyle(tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(headline).font(.title3.weight(.semibold))
                    Text(subheadline)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
            }

            // The durable installation: one password, then it is launchd's
            // job forever. Offered whenever it is not already in place, because
            // every other route depends on an approval macOS can withdraw.
            if !BackgroundService.Durable.isInstalled {
                HStack(alignment: .top, spacing: 9) {
                    Image(systemName: "lock.shield").foregroundStyle(.blue)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Install it permanently")
                            .font(.callout.weight(.medium))
                        Text("Registering through Login Items depends on an approval macOS drops when the app is rebuilt or the system is updated — which is why the daemon keeps needing repair. Installing it as a plain system service asks for your administrator password once and then starts it at every boot, whatever happens to the app.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        HStack(spacing: 10) {
                            Button {
                                if let failure = model.installDaemonPermanently() {
                                    message = failure
                                    messageIsError = failure != "Cancelled."
                                } else {
                                    message = "Installed. It starts at boot on its own now — one thing left: give /usr/local/libexec/hdwatcherd Full Disk Access."
                                    messageIsError = false
                                }
                            } label: {
                                Label("Install Permanently…", systemImage: "lock.shield")
                            }
                            .buttonStyle(.borderedProminent)
                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(BackgroundService.Durable.command,
                                                               forType: .string)
                                message = "Copied the command, if you would rather run it yourself."
                                messageIsError = false
                            } label: {
                                Label("Copy Command", systemImage: "terminal")
                            }
                            .controlSize(.small)
                        }
                    }
                }
                .padding(10)
                .background(.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            } else if BackgroundService.Durable.isInstalled {
                HStack(alignment: .top, spacing: 9) {
                    Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Installed permanently")
                            .font(.callout.weight(.medium))
                        Text("Running as \(BackgroundService.Durable.label) from /usr/local/libexec, started by launchd at boot. It does not depend on this app, on Login Items, or on the app's signature — rebuilding or updating will not disturb it.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        HStack(spacing: 10) {
                            Button {
                                BackgroundService.openFullDiskAccessSettings()
                            } label: {
                                Label("Full Disk Access for the daemon", systemImage: "externaldrive.badge.person.crop")
                            }
                            .help("Add /usr/local/libexec/hdwatcherd — the app's own grant does not cover it")
                            Button(role: .destructive) {
                                if let failure = model.installDaemonPermanently(uninstall: true) {
                                    message = failure
                                    messageIsError = failure != "Cancelled."
                                } else {
                                    message = "Removed the permanent installation. The audit log is untouched."
                                    messageIsError = false
                                }
                            } label: {
                                Label("Remove", systemImage: "trash")
                            }
                        }
                        .controlSize(.small)
                    }
                }
                .padding(10)
                .background(.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            }

            if BackgroundService.Durable.isOutOfDate {
                HStack(alignment: .top, spacing: 9) {
                    Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(.orange)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("A newer daemon is in this app than the one running")
                            .font(.callout.weight(.medium))
                        Text("The installed daemon keeps running the build it was installed from. Update it to match this app.")
                            .font(.caption).foregroundStyle(.secondary)
                        Button {
                            if let failure = model.installDaemonPermanently() {
                                message = failure
                                messageIsError = failure != "Cancelled."
                            } else {
                                message = "Updated the installed daemon."
                                messageIsError = false
                            }
                        } label: {
                            Label("Update Daemon…", systemImage: "arrow.triangle.2.circlepath")
                        }
                        .controlSize(.small)
                    }
                }
                .padding(10)
                .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            }

            // What to do about it, when there is something to do.
            switch model.daemonVerdict.repair {
            case .openLoginItems:
                Button {
                    BackgroundService.openLoginItemsSettings()
                } label: {
                    Label("Open Login Items", systemImage: "gearshape")
                }
                .buttonStyle(.borderedProminent)

            case .reregister, .askForHelp:
                HStack(spacing: 10) {
                    Button {
                        if let failure = model.repairBackgroundService() {
                            message = failure
                            messageIsError = true
                        } else {
                            message = "Re-registered the daemon with macOS."
                            messageIsError = false
                        }
                        model.refreshBackgroundService()
                    } label: {
                        Label("Repair Now", systemImage: "wrench.and.screwdriver")
                    }
                    .buttonStyle(.borderedProminent)

                    Button {
                        BackgroundService.openLoginItemsSettings()
                    } label: {
                        Label("Login Items", systemImage: "gearshape")
                    }
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(
                            "sudo launchctl enable system/\(AgentPaths.serviceLabel)", forType: .string)
                        message = "Copied the command an administrator can run."
                        messageIsError = false
                    } label: {
                        Label("Copy Admin Command", systemImage: "terminal")
                    }
                }
                .controlSize(.small)

            case .none, .wait:
                EmptyView()
            }

            if !BackgroundService.isInTrustedLocation, !isInstalled {
                HStack(alignment: .top, spacing: 9) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Move HDWatcher to /Applications first")
                            .font(.callout.weight(.medium))
                        Text("macOS will not run a root daemon from \(BackgroundService.bundleLocation), because anything able to edit the app could edit code running as root.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(10)
                .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
            }

            HStack {
                Toggle(isOn: Binding(
                    get: { model.settings.backgroundRecordingEnabled },
                    set: { wanted in perform { model.setBackgroundRecording(wanted) } }
                )) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Keep recording in the background")
                        Text("Stays on across restarts. The app re-arms it on launch, so this is the only place it can be switched off.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .toggleStyle(.switch)
                .disabled(!BackgroundService.isInTrustedLocation
                          && !model.settings.backgroundRecordingEnabled)
                Spacer()

            }

            HStack {
                if model.backgroundServiceState == .requiresApproval {
                    Button("Open Login Items…") { BackgroundService.openLoginItemsSettings() }
                }
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Refresh") { model.refreshBackgroundService() }
                    .controlSize(.small)
            }

            if let error = model.backgroundServiceError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if model.backgroundServiceState == .requiresApproval {
                Label("macOS is waiting for you to allow HDWatcher in Login Items.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
            }
            if let message {
                Text(message).font(.caption)
                    .foregroundStyle(messageIsError ? .red : .green)
            }
        }
        .card()
    }

    private var activityCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Agent activity")
            if let status, status.isAlive {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                    GridRow {
                        Text("State").font(.caption).foregroundStyle(.secondary)
                        Label(status.isMonitoring ? "Recording" : "Idle",
                              systemImage: status.isMonitoring ? "record.circle" : "pause.circle")
                            .foregroundStyle(status.isMonitoring ? .green : .orange)
                    }
                    GridRow {
                        Text("Process").font(.caption).foregroundStyle(.secondary)
                        Text("pid \(status.pid) · up \(Format.relativeTime(status.startedAt))")
                    }
                    GridRow {
                        Text("Privileges").font(.caption).foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 1) {
                            Label(status.isPrivileged ? "Running as root" : "Running as your user",
                                  systemImage: status.isPrivileged ? "lock.shield.fill" : "person")
                                .foregroundStyle(status.isPrivileged ? .green : .orange)
                            if !status.isPrivileged {
                                Text("Expected root. A per-user recorder cannot inspect system processes and its log is not protected from you.")
                                    .font(.caption2).foregroundStyle(.orange)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    if !status.logDirectory.isEmpty {
                        GridRow {
                            Text("Audit trail").font(.caption).foregroundStyle(.secondary)
                            Text(status.logDirectory)
                                .font(.caption.monospaced()).textSelection(.enabled)
                        }
                    }
                    GridRow {
                        Text("Events recorded").font(.caption).foregroundStyle(.secondary)
                        Text(Format.count(Int(status.eventsRecorded)))
                    }
                    GridRow {
                        Text("Filtered / dropped").font(.caption).foregroundStyle(.secondary)
                        Text("\(Format.count(Int(status.eventsFiltered))) / \(Format.count(Int(status.eventsDropped)))")
                    }
                    GridRow {
                        Text("Watch roots").font(.caption).foregroundStyle(.secondary)
                        Text("\(status.watchedPaths.count)")
                    }
                    GridRow {
                        Text("Your settings").font(.caption).foregroundStyle(.secondary)
                        // The app cannot write into /Library, so a daemon
                        // running on defaults while the app believed it had
                        // published everything is a real failure mode, not a
                        // theoretical one.
                        Label(model.agentConfigurationPublished ? "Published" : "Not published",
                              systemImage: model.agentConfigurationPublished
                                ? "checkmark.seal" : "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(model.agentConfigurationPublished ? Color.green : Color.orange)
                            .help(model.agentConfigurationPublished
                                  ? "The daemon is watching what these screens say it is."
                                  : "The daemon is recording with defaults: your filters, rules and capture settings have not reached it.")
                    }
                    GridRow {
                        Text("Last heartbeat").font(.caption).foregroundStyle(.secondary)
                        Text(Format.relativeTime(status.heartbeat))
                    }
                }
                if let error = status.lastError {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else if status != nil {
                Label("The agent is registered but not responding. macOS restarts it automatically; if this persists, turn it off and on again.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Waiting for the agent's first heartbeat…")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .card()
    }

    private var explanationCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionHeader(title: "How this works")
            Text("""
            The daemon starts at boot, before anyone logs in, and appends to the encrypted audit \
            log. It holds only the *public* half of the log's key: it can record events and cannot \
            read a single one back. Viewing history still needs your password.

            Running with privileges buys three things a per-user agent cannot have. It records \
            before login. Its log lives in /Library owned by root, so the logged-in user cannot \
            delete or rewrite their own audit trail. And it can inspect every process, including \
            root-owned daemons — which is what makes attribution work for things like securityd.

            macOS asks for an administrator to approve it, and will only run it from /Applications.

            Its configuration — what to watch and which rules to apply — is sealed to the \
            daemon's own Secure Enclave key and left in your home, where this app can write it and \
            root can read it. Nothing about what you monitor is on disk in the clear. The daemon \
            pins the first ingest key it sees, so nobody can swap in their own and have future \
            events sealed to them.

            While the daemon is recording, this app stops watching the filesystem itself and \
            becomes a viewer, so nothing is counted twice.
            """)
            .font(.caption).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            Text(AgentPaths.configuration.path)
                .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                .textSelection(.enabled)
        }
        .card()
    }

    // All four come from the supervisor's verdict rather than from
    // SMAppService's own bookkeeping, which reports a service as installed
    // long after launchd has dropped it.
    private var symbol: String {
        switch model.daemonVerdict.health {
        case .recording:        return "bolt.circle.fill"
        case .startingUp:       return "clock.arrow.circlepath"
        case .droppedByLaunchd,
             .needsApproval:    return "exclamationmark.triangle.fill"
        case .notInstalled,
             .disabledByUser,
             .unsupported:      return "bolt.slash.circle"
        }
    }

    private var tint: Color {
        switch model.daemonVerdict.health {
        case .recording:                       return .green
        case .startingUp:                      return .blue
        case .droppedByLaunchd, .needsApproval: return .orange
        default:                               return .secondary
        }
    }

    private var headline: String { model.daemonVerdict.summary }
    private var subheadline: String { model.daemonVerdict.detail }

    private func perform(_ action: () -> String?) {
        working = true
        defer { working = false }
        if let failure = action() {
            message = failure
            messageIsError = true
        } else {
            message = wantsBackground
                ? "Background recording is on and will stay on."
                : "Background recording is off."
            messageIsError = false
        }
    }
}

extension String {
    /// Capitalises only the first character, leaving the rest — "the background
    /// daemon" must not become "The Background Daemon".
    var capitalizedFirst: String {
        guard let first else { return self }
        return first.uppercased() + dropFirst()
    }
}
