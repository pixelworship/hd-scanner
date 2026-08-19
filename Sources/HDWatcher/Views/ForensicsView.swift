import SwiftUI
import UniformTypeIdentifiers
import HDWatcherCore

/// Queries the encrypted log directly, rather than the in-memory live window —
/// this is how you search history from days ago.
struct ForensicsView: View {
    @Environment(AppModel.self) private var model

    @State private var pathText = ""
    @State private var selectedKinds: Set<EventKind> = []
    @State private var minSeverity: Severity = .trace
    @State private var range: TimeRange = .day
    @State private var transfersOnly = false
    @State private var limit = 1000
    @State private var results: [FileEvent] = []
    @State private var isSearching = false
    @State private var hasSearched = false
    @State private var exportMessage: String?
    @State private var page = PageWindow(pageSize: 150)

    enum TimeRange: String, CaseIterable, Identifiable {
        case hour = "Last hour"
        case day = "Last 24 hours"
        case week = "Last 7 days"
        case month = "Last 30 days"
        case all = "Everything"
        var id: String { rawValue }

        var start: Date? {
            switch self {
            case .hour:  return Date().addingTimeInterval(-3600)
            case .day:   return Date().addingTimeInterval(-86_400)
            case .week:  return Date().addingTimeInterval(-604_800)
            case .month: return Date().addingTimeInterval(-2_592_000)
            case .all:   return nil
            }
        }
    }

    private var manifest: LogManifest? { model.store?.currentManifest }

    var body: some View {
        VStack(spacing: 0) {
            searchForm
            Divider()

            if isSearching {
                LoadingStateView(message: "Searching the encrypted log…",
                                 detail: "Decrypting and scanning \(manifest?.segments.count ?? 0) segment(s).")
            } else if !hasSearched {
                EmptyStateView(symbol: "magnifyingglass",
                               title: "Search the encrypted log",
                               message: coverageDescription)
            } else if results.isEmpty {
                EmptyStateView(symbol: "questionmark.folder",
                               title: "No matching events",
                               message: "Try a wider time range or fewer filters.")
            } else {
                resultsList
            }
        }
    }

    private var coverageDescription: String {
        guard let manifest, manifest.totalEvents > 0 else {
            return "The log is empty so far. Events recorded while monitoring is running become searchable here."
        }
        let oldest = manifest.oldestEvent.map { Format.relativeTime($0) } ?? "—"
        return "\(Format.count(manifest.totalEvents)) events across \(manifest.segments.count) encrypted segments, going back \(oldest)."
    }

    private var searchForm: some View {
        VStack(spacing: 9) {
            HStack(spacing: 10) {
                HStack(spacing: 5) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Path contains…", text: $pathText)
                        .textFieldStyle(.plain)
                        .onSubmit(search)
                }
                .padding(.horizontal, 8).padding(.vertical, 6)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))

                Picker("", selection: $range) {
                    ForEach(TimeRange.allCases) { Text($0.rawValue).tag($0) }
                }
                .frame(width: 150)

                Picker("", selection: $minSeverity) {
                    ForEach(Severity.allCases, id: \.self) { severity in
                        Text(severity == .trace ? "All severities" : "\(severity.displayName)+").tag(severity)
                    }
                }
                .frame(width: 150)

                Toggle("Transfers only", isOn: $transfersOnly).toggleStyle(.checkbox)

                Button(action: search) {
                    Label("Search", systemImage: "magnifyingglass")
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.return, modifiers: .command)
            }

            HStack(spacing: 6) {
                Text("Kinds:").font(.caption).foregroundStyle(.secondary)
                ForEach(EventKind.allCases, id: \.self) { kind in
                    Toggle(isOn: Binding(
                        get: { selectedKinds.contains(kind) },
                        set: { on in
                            if on { selectedKinds.insert(kind) } else { selectedKinds.remove(kind) }
                        }
                    )) {
                        Text(kind.displayName).font(.caption)
                    }
                    .toggleStyle(.button)
                    .controlSize(.mini)
                }
                Spacer()
                if hasSearched {
                    Text("\(results.count) results").font(.caption).foregroundStyle(.secondary)
                    Menu {
                        Button("Export as CSV…") { export(.csv) }
                        Button("Export as JSON…") { export(.jsonPlain) }
                        Divider()
                        Button("Export encrypted…") { export(.jsonEncrypted) }
                    } label: {
                        Label("Export", systemImage: "square.and.arrow.up")
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                    .disabled(results.isEmpty)
                }
            }

            if let exportMessage {
                Text(exportMessage).font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
    }

    private var resultsList: some View {
        List {
            ForEach(Array(page.window(results))) { event in
                EventRow(event: event,
                         volume: model.engine?.registry.volume(id: event.volumeID ?? ""))
            }
            if page.hasMore(results) {
                PageLoadMoreRow(shown: page.limit, total: results.count) { page.advance() }
            }
        }
        .listStyle(.inset)
    }

    private func search() {
        isSearching = true
        hasSearched = true
        exportMessage = nil
        page.reset()

        var query = EventQuery()
        query.start = range.start
        query.pathContains = pathText.isEmpty ? nil : pathText
        query.kinds = selectedKinds.isEmpty ? nil : selectedKinds
        query.minSeverity = minSeverity == .trace ? nil : minSeverity
        query.transfersOnly = transfersOnly
        query.limit = limit

        Task {
            let found = await model.runQueryAsync(query)
            results = found
            isSearching = false
        }
    }

    private func export(_ format: EventStore.ExportFormat) {
        let panel = NSSavePanel()
        panel.title = "Export search results"
        switch format {
        case .csv:
            panel.nameFieldStringValue = "hdwatcher-export.csv"
            panel.allowedContentTypes = [.commaSeparatedText]
        case .jsonPlain:
            panel.nameFieldStringValue = "hdwatcher-export.json"
            panel.allowedContentTypes = [.json]
        case .jsonEncrypted:
            panel.nameFieldStringValue = "hdwatcher-export.hdwenc"
        }
        if format != .jsonEncrypted {
            panel.message = "This export will not be encrypted. It will contain full file paths."
        }

        guard panel.runModal() == .OK, let url = panel.url else { return }

        var query = EventQuery()
        query.start = range.start
        query.pathContains = pathText.isEmpty ? nil : pathText
        query.kinds = selectedKinds.isEmpty ? nil : selectedKinds
        query.minSeverity = minSeverity == .trace ? nil : minSeverity
        query.transfersOnly = transfersOnly
        query.limit = limit

        do {
            let count = try model.store?.export(query, to: url, format: format) ?? 0
            exportMessage = "Exported \(count) events to \(url.lastPathComponent)."
        } catch {
            exportMessage = "Export failed: \(error.localizedDescription)"
        }
    }
}
