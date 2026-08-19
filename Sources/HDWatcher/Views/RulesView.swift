import SwiftUI
import HDWatcherCore

struct RulesView: View {
    @Environment(AppModel.self) private var model
    @State private var editing: AlertRule?
    @State private var showingNew = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            List {
                Section("Built-in") {
                    ForEach(model.rules.filter(\.isBuiltIn)) { rule in
                        RuleRow(rule: rule,
                                onToggle: { toggle(rule) },
                                onEdit: { editing = rule },
                                onDelete: nil)
                    }
                }
                let custom = model.rules.filter { !$0.isBuiltIn }
                if !custom.isEmpty {
                    Section("Custom") {
                        ForEach(custom) { rule in
                            RuleRow(rule: rule,
                                    onToggle: { toggle(rule) },
                                    onEdit: { editing = rule },
                                    onDelete: { model.deleteRule(rule) })
                        }
                    }
                }
            }
            .listStyle(.inset)
        }
        .sheet(item: $editing) { rule in
            RuleEditorView(rule: rule) { updated in
                model.upsertRule(updated)
                editing = nil
            } onCancel: { editing = nil }
        }
        .sheet(isPresented: $showingNew) {
            RuleEditorView(rule: AlertRule(name: "New rule")) { created in
                model.upsertRule(created)
                showingNew = false
            } onCancel: { showingNew = false }
        }
    }

    private func toggle(_ rule: AlertRule) {
        var updated = rule
        updated.enabled.toggle()
        model.upsertRule(updated)
    }

    private var header: some View {
        HStack {
            Text("\(model.rules.filter(\.enabled).count) of \(model.rules.count) rules enabled")
                .font(.caption).foregroundStyle(.secondary)
            Spacer()
            Button("Restore Built-ins") { model.restoreBuiltInRules() }
            Button { showingNew = true } label: {
                Label("New Rule", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
    }
}

struct RuleRow: View {
    let rule: AlertRule
    var onToggle: () -> Void
    var onEdit: () -> Void
    var onDelete: (() -> Void)?

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Toggle("", isOn: Binding(get: { rule.enabled }, set: { _ in onToggle() }))
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(rule.name).font(.body.weight(.medium))
                    SeverityBadge(severity: rule.severity)
                    if rule.triggerCount > 0 {
                        Text("fired \(rule.triggerCount)×")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                if !rule.detail.isEmpty {
                    Text(rule.detail).font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(rule.summary)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .opacity(rule.enabled ? 1 : 0.55)

            Spacer(minLength: 8)

            HStack(spacing: 4) {
                if rule.actions.notify {
                    Image(systemName: "bell.fill").font(.caption2).foregroundStyle(.secondary)
                        .help("Sends a notification")
                }
                if rule.actions.auditProcesses {
                    Image(systemName: "person.crop.square").font(.caption2).foregroundStyle(.blue)
                        .help("Identifies the responsible process")
                }
                Button("Edit", action: onEdit).buttonStyle(.link).font(.caption)
                if let onDelete {
                    Button(role: .destructive, action: onDelete) {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

/// Full rule editor. Everything the engine can match on is exposed here.
struct RuleEditorView: View {
    @State var rule: AlertRule
    var onSave: (AlertRule) -> Void
    var onCancel: () -> Void

    @State private var extensionText = ""
    @State private var includeText = ""
    @State private var excludeText = ""
    @State private var useBurst = false
    @State private var useTimeWindow = false
    @State private var useMinSize = false
    @State private var minSizeMB = 1.0

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(rule.isBuiltIn ? "Edit Built-in Rule" : "Rule").font(.headline)
                Spacer()
            }
            .padding(14)
            Divider()

            Form {
                Section("Identity") {
                    TextField("Name", text: $rule.name)
                    TextField("Description", text: $rule.detail, axis: .vertical)
                        .lineLimit(2...4)
                    Picker("Severity", selection: $rule.severity) {
                        ForEach(Severity.allCases, id: \.self) { Text($0.displayName).tag($0) }
                    }
                    Toggle("Enabled", isOn: $rule.enabled)
                }

                Section {
                    ForEach(EventKind.allCases, id: \.self) { kind in
                        Toggle(kind.displayName, isOn: Binding(
                            get: { rule.conditions.eventKinds.contains(kind) },
                            set: { on in
                                if on { rule.conditions.eventKinds.insert(kind) }
                                else { rule.conditions.eventKinds.remove(kind) }
                            }
                        ))
                    }
                } header: {
                    Text("Event kinds")
                } footer: {
                    Text("Leave all off to match every kind of change.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section {
                    TextField("Include paths", text: $includeText, axis: .vertical)
                        .lineLimit(1...3)
                    TextField("Exclude paths", text: $excludeText, axis: .vertical)
                        .lineLimit(1...3)
                    TextField("File extensions", text: $extensionText)
                } header: {
                    Text("Matching")
                } footer: {
                    Text("One pattern per line. Globs are supported: `~/Documents/**`, `*.pem`. Extensions are comma-separated and written without the dot.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Volumes") {
                    volumeClassPicker("Destination is", binding: $rule.conditions.destinationVolumeClasses)
                    volumeClassPicker("Source is", binding: $rule.conditions.sourceVolumeClasses)
                    Picker("Minimum transfer confidence", selection: $rule.conditions.minConfidence) {
                        Text("Any").tag(Confidence.none)
                        Text("Low").tag(Confidence.low)
                        Text("Medium").tag(Confidence.medium)
                        Text("High").tag(Confidence.high)
                        Text("Certain").tag(Confidence.certain)
                    }
                }

                Section("Size") {
                    Toggle("Only files larger than", isOn: $useMinSize)
                    if useMinSize {
                        HStack {
                            Slider(value: $minSizeMB, in: 0.1...20_000)
                            Text(Format.bytes(Int64(minSizeMB * 1_048_576)))
                                .font(.caption.monospacedDigit())
                                .frame(width: 80, alignment: .trailing)
                        }
                    }
                }

                Section {
                    Toggle("Only fire on a burst", isOn: $useBurst)
                    if useBurst {
                        Stepper("Threshold: \(rule.conditions.burst?.threshold ?? 50) events",
                                value: Binding(
                                    get: { rule.conditions.burst?.threshold ?? 50 },
                                    set: { updateBurst { $0.threshold = max(2, $1) }($0) }
                                ), in: 2...5000, step: 10)
                        Stepper("Window: \(Int(rule.conditions.burst?.windowSeconds ?? 60))s",
                                value: Binding(
                                    get: { Int(rule.conditions.burst?.windowSeconds ?? 60) },
                                    set: { newValue in
                                        var burst = rule.conditions.burst ?? BurstCondition(threshold: 50, windowSeconds: 60)
                                        burst.windowSeconds = TimeInterval(newValue)
                                        rule.conditions.burst = burst
                                    }
                                ), in: 5...3600, step: 5)
                        Picker("Count separately", selection: Binding(
                            get: { rule.conditions.burst?.grouping ?? .global },
                            set: { newValue in
                                var burst = rule.conditions.burst ?? BurstCondition(threshold: 50, windowSeconds: 60)
                                burst.grouping = newValue
                                rule.conditions.burst = burst
                            }
                        )) {
                            ForEach(BurstCondition.Grouping.allCases, id: \.self) {
                                Text($0.displayName).tag($0)
                            }
                        }
                    }
                } header: {
                    Text("Burst detection")
                } footer: {
                    Text("Useful for mass deletion or bulk copying, where one event is normal but many at once is not.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("Schedule") {
                    Toggle("Restrict to certain hours", isOn: $useTimeWindow)
                    if useTimeWindow {
                        let window = rule.conditions.timeWindow ?? TimeWindowCondition()
                        Stepper("From \(window.startHour):00", value: Binding(
                            get: { window.startHour },
                            set: { setWindow { $0.startHour = $1 } ($0) }
                        ), in: 0...23)
                        Stepper("Until \(window.endHour):00", value: Binding(
                            get: { window.endHour },
                            set: { setWindow { $0.endHour = $1 } ($0) }
                        ), in: 0...23)
                        Toggle("Fire outside these hours instead", isOn: Binding(
                            get: { window.inverted },
                            set: { newValue in
                                var w = rule.conditions.timeWindow ?? TimeWindowCondition()
                                w.inverted = newValue
                                rule.conditions.timeWindow = w
                            }
                        ))
                    }
                }

                Section {
                    Toggle("Identify the responsible process", isOn: $rule.actions.auditProcesses)
                    Text("Scans every reachable process for one holding the file open, and records who it is. Costs a little CPU each time the rule matches, so it is worth enabling only where the answer matters.")
                        .font(.caption).foregroundStyle(.secondary)
                } header: {
                    Text("Auditing")
                }

                Section("Actions") {
                    Toggle("Send a notification", isOn: $rule.actions.notify)
                    Toggle("Play a sound", isOn: $rule.actions.playSound)
                    Toggle("Raise the event's severity", isOn: $rule.actions.elevateEventSeverity)
                    HStack {
                        Text("Cooldown")
                        Spacer()
                        Text("\(Int(rule.cooldownSeconds))s")
                            .foregroundStyle(.secondary).monospacedDigit()
                    }
                    Slider(value: $rule.cooldownSeconds, in: 0...600, step: 5)
                    TextField("Webhook URL (https, optional)",
                              text: Binding(get: { rule.actions.webhookURL ?? "" },
                                            set: { rule.actions.webhookURL = $0.isEmpty ? nil : $0 }))
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction)
                Spacer()
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(rule.name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(14)
        }
        .frame(width: 560, height: 640)
        .onAppear(perform: load)
    }

    private func volumeClassPicker(_ title: String, binding: Binding<Set<VolumeClass>>) -> some View {
        HStack {
            Text(title)
            Spacer()
            ForEach(VolumeClass.allCases.filter { $0 != .unknown }, id: \.self) { klass in
                Toggle(isOn: Binding(
                    get: { binding.wrappedValue.contains(klass) },
                    set: { on in
                        if on { binding.wrappedValue.insert(klass) }
                        else { binding.wrappedValue.remove(klass) }
                    }
                )) {
                    Image(systemName: klass.symbolName)
                }
                .toggleStyle(.button)
                .controlSize(.small)
                .help(klass.displayName)
            }
        }
    }

    private func updateBurst(_ mutate: @escaping (inout BurstCondition, Int) -> Void) -> (Int) -> Void {
        { newValue in
            var burst = rule.conditions.burst ?? BurstCondition(threshold: 50, windowSeconds: 60)
            mutate(&burst, newValue)
            rule.conditions.burst = burst
        }
    }

    private func setWindow(_ mutate: @escaping (inout TimeWindowCondition, Int) -> Void) -> (Int) -> Void {
        { newValue in
            var window = rule.conditions.timeWindow ?? TimeWindowCondition()
            mutate(&window, newValue)
            rule.conditions.timeWindow = window
        }
    }

    private func load() {
        extensionText = rule.conditions.fileExtensions.sorted().joined(separator: ", ")
        includeText = rule.conditions.pathIncludes.map(\.pattern).joined(separator: "\n")
        excludeText = rule.conditions.pathExcludes.map(\.pattern).joined(separator: "\n")
        useBurst = rule.conditions.burst != nil
        useTimeWindow = rule.conditions.timeWindow != nil
        useMinSize = rule.conditions.minSize != nil
        if let minSize = rule.conditions.minSize {
            minSizeMB = Double(minSize) / 1_048_576
        }
    }

    private func save() {
        var updated = rule
        updated.conditions.fileExtensions = Set(
            extensionText.split(whereSeparator: { $0 == "," || $0 == " " })
                .map { $0.trimmingCharacters(in: .whitespaces).lowercased()
                        .trimmingCharacters(in: CharacterSet(charactersIn: ".")) }
                .filter { !$0.isEmpty }
        )
        updated.conditions.pathIncludes = includeText.split(separator: "\n")
            .map { GlobPattern($0.trimmingCharacters(in: .whitespaces)) }
            .filter { !$0.pattern.isEmpty }
        updated.conditions.pathExcludes = excludeText.split(separator: "\n")
            .map { GlobPattern($0.trimmingCharacters(in: .whitespaces)) }
            .filter { !$0.pattern.isEmpty }
        if !useBurst { updated.conditions.burst = nil }
        if !useTimeWindow { updated.conditions.timeWindow = nil }
        updated.conditions.minSize = useMinSize ? Int64(minSizeMB * 1_048_576) : nil
        onSave(updated)
    }
}
