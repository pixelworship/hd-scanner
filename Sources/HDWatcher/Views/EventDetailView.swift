import SwiftUI
import HDWatcherCore

/// Everything known about one recorded event: what changed, where it came from
/// and went, which process is implicated, and — when contents were captured —
/// the actual diff.
///
/// Alerts and transfers are the same report with a different headline, so both
/// present this rather than each growing its own copy.
struct EventDetailView: View {
    let event: FileEvent?
    let alert: SecurityAlert?
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var versions: [FileSnapshot] = []
    @State private var diff: TextDiff.Result?
    @State private var loadedContents = false
    @State private var isLoadingContents = false

    init(alert: SecurityAlert) {
        self.alert = alert
        self.event = alert.event
    }

    init(event: FileEvent) {
        self.alert = nil
        self.event = event
    }

    private var sourceVolume: VolumeInfo? {
        event?.sourceVolumeID.flatMap { model.engine?.registry.volume(id: $0) }
    }
    private var destinationVolume: VolumeInfo? {
        event?.volumeID.flatMap { model.engine?.registry.volume(id: $0) }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    whatHappened
                    if event?.sourcePath != nil || destinationVolume != nil { movement }
                    processSection
                    if isLoadingContents {
                        DetailCard(title: "What changed", symbol: "plusminus") {
                            InlineLoadingView(message: "Decrypting captured versions…")
                        }
                    } else if !versions.isEmpty {
                        changesSection
                    }
                    technical
                }
                .padding(16)
            }
            Divider()
            footer
        }
        .frame(width: 720, height: 640)
        .task { await loadContents() }
    }

    // MARK: - Header

    private var headlineSeverity: Severity {
        alert?.severity ?? event?.severity ?? .info
    }

    private var headlineTime: Date {
        alert?.timestamp ?? event?.timestamp ?? Date()
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: alert?.severity.symbol ?? (event?.kind.symbolName ?? "doc"))
                .font(.largeTitle)
                .foregroundStyle(alert == nil ? (event?.kind.tint ?? .secondary) : headlineSeverity.color)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(alert?.title ?? (event?.fileName ?? "Event"))
                        .font(.title3.weight(.semibold))
                        .lineLimit(1).truncationMode(.middle)
                    if let alert, alert.matchCount > 1 {
                        Text("×\(alert.matchCount)")
                            .font(.caption.weight(.bold))
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(alert.severity.color.opacity(0.2), in: Capsule())
                    }
                }
                if let alert {
                    Text("Rule: \(alert.ruleName)")
                        .font(.caption).foregroundStyle(.secondary)
                } else if let event {
                    HStack(spacing: 6) {
                        KindBadge(kind: event.kind)
                        ConfidenceBadge(confidence: event.confidence)
                    }
                }
                Text(Format.fullTimestamp(headlineTime))
                    .font(.caption).foregroundStyle(.tertiary)
            }
            Spacer()
            SeverityBadge(severity: headlineSeverity)
        }
        .padding(16)
    }

    // MARK: - Sections

    private var whatHappened: some View {
        DetailCard(title: "What happened", symbol: "questionmark.circle") {
            if let event {
                LabeledRow("Action") { KindBadge(kind: event.kind) }
                LabeledRow("File") {
                    Text((event.path as NSString).lastPathComponent)
                        .font(.body.monospaced()).textSelection(.enabled)
                }
                LabeledRow("Full path") {
                    Text(event.path)
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                LabeledRow("Size") { Text(event.isDirectory ? "Directory" : Format.bytes(event.size)) }
                if event.confidence != .none {
                    LabeledRow("Evidence") {
                        HStack(spacing: 6) {
                            ConfidenceBadge(confidence: event.confidence)
                            Text(confidenceExplanation(event.confidence))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if !event.ruleHits.isEmpty {
                    LabeledRow("Rules matched") {
                        Text(event.ruleHits.joined(separator: ", ")).font(.callout)
                    }
                }
            } else if let alert {
                Text(alert.detail).font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private var movement: some View {
        DetailCard(title: "Source and destination", symbol: "arrow.left.arrow.right") {
            HStack(alignment: .top, spacing: 10) {
                endpointBox(title: "From",
                            volume: sourceVolume,
                            path: event?.sourcePath,
                            emptyMessage: "Not identified")
                Image(systemName: "arrow.right")
                    .foregroundStyle(.tertiary)
                    .padding(.top, 22)
                endpointBox(title: "To",
                            volume: destinationVolume,
                            path: event?.path,
                            emptyMessage: "Unknown volume")
            }
            if event?.sourcePath == nil, event?.kind.isTransfer == true {
                Text("No source could be identified. macOS does not report file reads, so a copy leaves no trace on the side it came from unless that file was already known to HDWatcher or findable via Spotlight.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func endpointBox(title: String, volume: VolumeInfo?, path: String?,
                             emptyMessage: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            HStack(spacing: 5) {
                Image(systemName: volume?.volumeClass.symbolName ?? "questionmark.circle")
                    .foregroundStyle(volume?.volumeClass.tint ?? .secondary)
                Text(volume?.name ?? emptyMessage)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(volume == nil ? .secondary : .primary)
            }
            if let volume {
                Text(volume.volumeClass.displayName)
                    .font(.caption2).foregroundStyle(.tertiary)
            }
            if let path {
                Text((path as NSString).deletingLastPathComponent)
                    .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                    .lineLimit(2).truncationMode(.head)
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(9)
        .background((volume?.volumeClass.tint ?? .secondary).opacity(0.10),
                    in: RoundedRectangle(cornerRadius: 8))
    }

    private var processSection: some View {
        DetailCard(title: "Who did it", symbol: "person.crop.square") {
            if let attribution = event?.attribution, !attribution.isEmpty {
                ForEach(attribution.actors) { actor in
                    ProcessActorRow(actor: actor)
                }
                Text("Scanned \(attribution.scannedProcesses) reachable processes at \(Format.timeOfDay(attribution.attemptedAt)).")
                    .font(.caption2).foregroundStyle(.tertiary)
            } else if event?.attribution?.blockedByPrivileges == true {
                unattributedNotice(
                    "The responsible process is almost certainly a system daemon running as root. macOS does not let an unprivileged app inspect those, so it cannot be named."
                )
            } else if event?.attribution != nil {
                unattributedNotice(
                    "Nothing held this file open by the time the change was reported, and no process started close enough to implicate."
                )
            } else {
                unattributedNotice(
                    "Process attribution was not run for this rule. Enable \"Identify the responsible process\" on the rule to audit it."
                )
            }
        }
    }

    private func unattributedNotice(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "person.fill.questionmark")
                .foregroundStyle(.secondary)
            Text(text)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var changesSection: some View {
        DetailCard(title: "What changed", symbol: "plusminus") {
            if let diff, diff.hasChanges {
                HStack(spacing: 10) {
                    Text("+\(diff.addedCount)").foregroundStyle(.green)
                    Text("−\(diff.removedCount)").foregroundStyle(.red)
                    Spacer()
                    Button("Open in Recovery") {
                        model.selection = .recovery
                        dismiss()
                    }
                    .buttonStyle(.link).font(.caption)
                }
                .font(.caption.monospacedDigit().weight(.medium))

                DiffScrollView(lines: TextDiff.condense(diff, context: 2))
                    .frame(height: 220)
            } else {
                HStack {
                    Text("\(versions.count) version\(versions.count == 1 ? "" : "s") captured, but no textual diff is available.")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Open in Recovery") {
                        model.selection = .recovery
                        dismiss()
                    }
                    .buttonStyle(.link).font(.caption)
                }
            }
        }
    }

    private var technical: some View {
        DetailCard(title: "Technical detail", symbol: "wrench.and.screwdriver") {
            if let event {
                LabeledRow("Recorded") { Text(Format.fullTimestamp(event.timestamp)).font(.callout) }
                if let inode = event.inode {
                    LabeledRow("Inode") { Text("\(inode)").font(.callout.monospaced()) }
                }
                if event.rawFlags != 0 {
                    LabeledRow("FSEvents flags") {
                        Text(FSEventStreamEventFlags(event.rawFlags).describedFlags.joined(separator: ", "))
                            .font(.caption.monospaced())
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                LabeledRow("Event ID") { Text("\(event.eventID)").font(.caption.monospaced()) }
            }
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            if let path = event?.path {
                Button("Reveal in Finder") {
                    NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                }
                .disabled(!FileManager.default.fileExists(atPath: path))
                Button("Copy Path") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(path, forType: .string)
                }
            }
            Spacer()
            if let alert, !alert.acknowledged {
                Button("Acknowledge") {
                    model.acknowledgeAlert(alert)
                    dismiss()
                }
            }
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(14)
    }

    // MARK: - Loading

    /// Decrypting two versions and diffing them is far too slow for the main
    /// thread — the sheet would appear frozen while it ran.
    private func loadContents() async {
        guard !loadedContents, let path = event?.path, let vault = model.contentVault else { return }
        loadedContents = true
        isLoadingContents = true
        defer { isLoadingContents = false }

        let result = await Task.detached(priority: .userInitiated) {
            () -> (versions: [FileSnapshot], diff: TextDiff.Result?) in
            let versions = vault.versions(of: path)
            guard versions.count >= 2,
                  let newer = vault.content(of: versions[0]),
                  let older = vault.content(of: versions[1]),
                  FileSnapshot.looksTextual(newer), FileSnapshot.looksTextual(older),
                  let newerText = String(data: newer, encoding: .utf8),
                  let olderText = String(data: older, encoding: .utf8)
            else { return (versions, nil) }
            return (versions, TextDiff.compare(olderText, newerText))
        }.value

        versions = result.versions
        diff = result.diff
    }

    private func confidenceExplanation(_ confidence: Confidence) -> String {
        switch confidence {
        case .certain: return "the same inode was seen on both paths"
        case .high:    return "file contents matched a known source"
        case .medium:  return "name and size matched a file on another volume"
        case .low:     return "inferred; the source could not be confirmed"
        case .none:    return ""
        }
    }
}

// MARK: - Building blocks

struct DetailCard<Content: View>: View {
    let title: String
    let symbol: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: symbol)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(padding: 13)
    }
}

struct LabeledRow<Content: View>: View {
    let label: String
    @ViewBuilder var content: Content

    init(_ label: String, @ViewBuilder content: () -> Content) {
        self.label = label
        self.content = content()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label)
                .font(.caption).foregroundStyle(.secondary)
                .frame(width: 96, alignment: .trailing)
            content
            Spacer(minLength: 0)
        }
    }
}

struct ProcessActorRow: View {
    let actor: ProcessActor

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: actor.isSystemProcess ? "gearshape.fill" : "app.dashed")
                .font(.title3)
                .foregroundStyle(actor.evidence.confidence.color)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(actor.name).font(.callout.weight(.semibold))
                    Text("pid \(actor.pid)")
                        .font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
                    Text(actor.evidence.displayName)
                        .font(.caption2.weight(.medium))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(actor.evidence.confidence.color.opacity(0.18), in: Capsule())
                        .foregroundStyle(actor.evidence.confidence.color)
                }

                Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 2) {
                    if let user = actor.userName {
                        GridRow {
                            Text("User").font(.caption2).foregroundStyle(.tertiary)
                            Text("\(user) (uid \(actor.userID))").font(.caption)
                        }
                    }
                    if let path = actor.executablePath {
                        GridRow {
                            Text("Binary").font(.caption2).foregroundStyle(.tertiary)
                            Text(path).font(.caption.monospaced())
                                .lineLimit(1).truncationMode(.middle)
                                .textSelection(.enabled)
                        }
                    }
                    if let bundle = actor.bundleIdentifier {
                        GridRow {
                            Text("Bundle").font(.caption2).foregroundStyle(.tertiary)
                            Text(bundle).font(.caption.monospaced())
                        }
                    }
                    GridRow {
                        Text("Signed").font(.caption2).foregroundStyle(.tertiary)
                        Text(signature).font(.caption)
                    }
                    if let started = actor.startedAt {
                        GridRow {
                            Text("Started").font(.caption2).foregroundStyle(.tertiary)
                            Text(Format.fullTimestamp(started)).font(.caption)
                        }
                    }
                    if let arguments = actor.arguments, !arguments.isEmpty {
                        GridRow {
                            Text("Arguments").font(.caption2).foregroundStyle(.tertiary)
                            Text(arguments).font(.caption.monospaced())
                                .lineLimit(2).truncationMode(.tail)
                                .textSelection(.enabled)
                        }
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(9)
        .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 8))
    }

    private var signature: String {
        if let team = actor.teamIdentifier {
            return "\(actor.signingIdentifier ?? "unknown") · team \(team)"
        }
        if actor.isAppleSigned {
            return "\(actor.signingIdentifier ?? "Apple") · Apple platform binary"
        }
        return actor.signingIdentifier ?? "unsigned or unverifiable"
    }
}
