import SwiftUI
import HDWatcherCore

struct LiveFeedView: View {
    @Environment(AppModel.self) private var model

    @State private var searchText = ""
    @State private var kindFilter: EventKind?
    @State private var minSeverity: Severity = .trace
    @State private var follow = true
    @State private var selectedEvent: FileEvent?

    /// Filtered off the main thread and cached.
    ///
    /// The feed holds tens of thousands of events; filtering them inside `body`
    /// re-ran the whole pass on every redraw, which is what made opening this
    /// tab stall.
    @State private var filtered: [FileEvent] = []
    @State private var hasFiltered = false
    @State private var isFiltering = false
    @State private var page = PageWindow(pageSize: 150)

    nonisolated private static func filter(_ events: [FileEvent], search: String,
                                           kind: EventKind?, minSeverity: Severity) -> [FileEvent] {
        events.reversed().filter { event in
            if event.severity < minSeverity { return false }
            if let kind, event.kind != kind { return false }
            if !search.isEmpty {
                let haystack = event.path + (event.sourcePath ?? "")
                if haystack.range(of: search, options: .caseInsensitive) == nil { return false }
            }
            return true
        }
    }

    private var refreshKey: String {
        "\(searchText)|\(kindFilter?.rawValue ?? "-")|\(minSeverity.rawValue)|\(model.liveEvents.count)"
    }

    private func refilter() async {
        // The previous pass is cancelled when the key changes, so this sleep
        // coalesces a burst of typing into a single filter.
        if !searchText.isEmpty {
            try? await Task.sleep(for: .milliseconds(180))
            guard !Task.isCancelled else { return }
        }
        isFiltering = true
        defer { isFiltering = false }
        let events = model.liveEvents
        let search = searchText
        let kind = kindFilter
        let severity = minSeverity
        filtered = await Task.detached(priority: .userInitiated) {
            Self.filter(events, search: search, kind: kind, minSeverity: severity)
        }.value
        hasFiltered = true
    }

    var body: some View {
        @Bindable var model = model

        VStack(spacing: 0) {
            filterBar
            Divider()

            if !hasFiltered {
                LoadingStateView(message: "Reading recent activity…",
                                 detail: "Filtering \(Format.count(model.liveEvents.count)) recorded events.")
            } else if filtered.isEmpty {
                EmptyStateView(
                    symbol: model.isMonitoring ? "waveform.path.ecg" : "pause.circle",
                    title: model.isMonitoring ? "Waiting for activity" : "Monitoring is paused",
                    message: model.isMonitoring
                        ? "Changes appear here as they happen. Try creating or editing a file."
                        : "Resume monitoring from the toolbar to start recording again."
                )
            } else {
                ScrollViewReader { proxy in
                    List(selection: $selectedEvent) {
                        ForEach(Array(page.window(filtered))) { event in
                            EventRow(event: event, volume: model.engine?.registry.volume(id: event.volumeID ?? ""))
                                .id(event.id)
                                .tag(event)
                        }
                        if page.hasMore(filtered) {
                            PageLoadMoreRow(shown: page.limit, total: filtered.count) {
                                page.advance()
                            }
                        }
                    }
                    .listStyle(.inset)
                    .safeAreaInset(edge: .bottom) {
                        VStack(spacing: 0) { Divider(); windowNotice }
                            .background(.bar)
                    }
                    .onChange(of: filtered.first?.id) { _, newValue in
                        guard follow, let newValue else { return }
                        withAnimation(.easeOut(duration: 0.2)) {
                            proxy.scrollTo(newValue, anchor: .top)
                        }
                    }
                }
            }
        }
        .task(id: refreshKey) { await refilter() }
        .onChange(of: searchText) { _, _ in page.reset() }
        .onChange(of: kindFilter) { _, _ in page.reset() }
        .onChange(of: minSeverity) { _, _ in page.reset() }
        .inspector(isPresented: .constant(selectedEvent != nil)) {
            if let selectedEvent {
                EventInspector(event: selectedEvent, volume: model.engine?.registry.volume(id: selectedEvent.volumeID ?? ""))
                    .inspectorColumnWidth(min: 280, ideal: 340, max: 460)
            }
        }
    }

    private var filterBar: some View {
        @Bindable var model = model

        return HStack(spacing: 10) {
            HStack(spacing: 5) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Filter by path", text: $searchText)
                    .textFieldStyle(.plain)
                if isFiltering {
                    ProgressView().controlSize(.small)
                }
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                    }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))
            .frame(maxWidth: 320)

            Picker("Kind", selection: $kindFilter) {
                Text("All kinds").tag(EventKind?.none)
                Divider()
                ForEach(EventKind.allCases, id: \.self) { kind in
                    Text(kind.displayName).tag(EventKind?.some(kind))
                }
            }
            .pickerStyle(.menu)
            .frame(width: 150)

            Picker("Severity", selection: $minSeverity) {
                ForEach(Severity.allCases, id: \.self) { severity in
                    Text(severity == .trace ? "All severities" : "\(severity.displayName)+")
                        .tag(severity)
                }
            }
            .pickerStyle(.menu)
            .frame(width: 150)

            Spacer()

            Toggle(isOn: $follow) {
                Label("Follow", systemImage: "arrow.down.to.line")
            }
            .toggleStyle(.button)
            .help("Keep the newest event in view")

            Toggle(isOn: $model.settings.liveFeedPaused) {
                Label(model.settings.liveFeedPaused ? "Feed paused" : "Feed live",
                      systemImage: model.settings.liveFeedPaused ? "pause.fill" : "play.fill")
            }
            .toggleStyle(.button)
            .help("Freeze the feed without stopping recording")

            Text("\(filtered.count)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
    }

    /// The feed holds a rolling window in memory; the encrypted log keeps
    /// everything. Saying so avoids the impression that older events were lost.
    private var windowNotice: some View {
        let recorded = model.store?.currentManifest.totalEvents ?? 0
        let shown = model.liveEvents.count
        return HStack(spacing: 5) {
            Image(systemName: "info.circle").font(.caption2)
            if recorded > shown {
                Text("Showing the most recent \(Format.count(shown)) of \(Format.count(recorded)) events recorded. The full history stays in the encrypted log — use Search to query it.")
            } else {
                Text("Showing all \(Format.count(shown)) events recorded so far.")
            }
            Spacer()
            Button("Search history") { model.selection = .forensics }
                .buttonStyle(.link)
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
    }
}

struct EventRow: View {
    let event: FileEvent
    let volume: VolumeInfo?

    var body: some View {
        HStack(spacing: 10) {
            Text(Format.timeOfDay(event.timestamp))
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .frame(width: 62, alignment: .leading)

            KindBadge(kind: event.kind)
                .frame(width: 116, alignment: .leading)

            VStack(alignment: .leading, spacing: 1) {
                PathLabel(path: event.path, showsDirectory: false)
                if let source = event.sourcePath {
                    HStack(spacing: 3) {
                        Image(systemName: "arrow.turn.up.right")
                            .font(.caption2).foregroundStyle(.tertiary)
                        Text("from \(Format.abbreviatePath(source))")
                            .font(.caption).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.head)
                    }
                } else {
                    Text(Format.abbreviatePath(event.directory))
                        .font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.head)
                }
            }

            Spacer(minLength: 8)

            if !event.ruleHits.isEmpty {
                Image(systemName: "bell.fill")
                    .font(.caption2).foregroundStyle(.orange)
                    .help(event.ruleHits.joined(separator: ", "))
            }
            ConfidenceBadge(confidence: event.confidence)

            Text(event.isDirectory ? "folder" : Format.bytes(event.size))
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 74, alignment: .trailing)

            VolumeChip(volume: volume)
                .frame(width: 96, alignment: .leading)

            SeverityBadge(severity: event.severity, compact: true)
        }
        .padding(.vertical, 2)
    }
}

/// Full detail for one event, including the raw FSEvents flags that produced it.
struct EventInspector: View {
    let event: FileEvent
    let volume: VolumeInfo?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 6) {
                    KindBadge(kind: event.kind)
                    Text((event.path as NSString).lastPathComponent)
                        .font(.title3.weight(.medium))
                        .textSelection(.enabled)
                    Text(event.path)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }

                field("When", Format.fullTimestamp(event.timestamp))
                if let source = event.sourcePath {
                    field("Source", source, mono: true)
                }
                field("Type", event.isDirectory ? "Directory" : "File")
                if let size = event.size { field("Size", Format.bytes(size)) }
                if let inode = event.inode { field("Inode", "\(inode)") }
                if let volume { field("Volume", "\(volume.name) · \(volume.volumeClass.displayName)") }
                field("Severity", event.severity.displayName)
                if event.confidence != .none {
                    field("Transfer confidence", event.confidence.displayName)
                }
                if !event.ruleHits.isEmpty {
                    field("Rules matched", event.ruleHits.joined(separator: "\n"))
                }

                if event.rawFlags != 0 {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("FSEvents flags").font(.caption.weight(.medium)).foregroundStyle(.secondary)
                        Text(FSEventStreamEventFlags(event.rawFlags).describedFlags.joined(separator: ", "))
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                        Text("raw 0x\(String(event.rawFlags, radix: 16)) · event id \(event.eventID)")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }

                HStack {
                    Button("Reveal in Finder") {
                        NSWorkspace.shared.selectFile(event.path, inFileViewerRootedAtPath: "")
                    }
                    .disabled(!FileManager.default.fileExists(atPath: event.path))
                    Button("Copy Path") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(event.path, forType: .string)
                    }
                }
                .controlSize(.small)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
        }
    }

    private func field(_ label: String, _ value: String, mono: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption.weight(.medium)).foregroundStyle(.secondary)
            Text(value)
                .font(mono ? .caption.monospaced() : .callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
