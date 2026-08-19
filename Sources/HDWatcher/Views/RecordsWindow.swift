import SwiftUI
import AppKit
import HDWatcherCore

/// A whole parsed record file, prepared away from the main thread.
struct ParsedRecords: Sendable {
    let path: String
    let fileName: String
    let generation: Int
    let capturedAt: Date
    let document: SEGB.Document
    let records: [RenderedRecord]
    let fullText: String
    /// The stream this file belongs to, when it is one we have names for.
    let stream: BiomeSchema.Stream?

    struct RenderedRecord: Identifiable, Sendable {
        let id: Int
        let record: SEGB.Record
        let lines: [String]
        /// Lower-cased text of the whole record, so searching does not have to
        /// re-render thousands of records on every keystroke.
        let searchKey: String
    }

    /// Renders every record once. Everything the browser needs afterwards is a
    /// lookup rather than a parse.
    static func build(from data: Data, snapshot: FileSnapshot) -> ParsedRecords? {
        guard let document = SEGB.parse(data, maxRecords: 200_000) else { return nil }
        let stream = BiomeSchema.stream(forFilePath: snapshot.path)
        let rendered = document.records.map { record -> RenderedRecord in
            let lines: [String]
            if record.data.isEmpty {
                lines = ["(empty)"]
            } else if let fields = ProtobufSnoop.decode(record.data) {
                lines = ProtobufSnoop.describe(fields, stream: stream)
            } else {
                let runs = BinaryText.runs(in: record.data, limit: 500)
                lines = runs.isEmpty
                    ? ["<\(record.data.count) bytes, no readable content>"]
                    : runs.map(\.text)
            }
            return RenderedRecord(id: record.id, record: record, lines: lines,
                                  searchKey: lines.joined(separator: "\n").lowercased())
        }
        return ParsedRecords(path: snapshot.path,
                             fileName: snapshot.fileName,
                             generation: snapshot.generation,
                             capturedAt: snapshot.capturedAt,
                             document: document,
                             records: rendered,
                             fullText: SEGB.render(document, maxRecords: 200_000, stream: stream),
                             stream: stream)
    }
}

/// Opens the parsed file in its own window.
///
/// The preview pane is a column in a split view — fine for a glance, wrong for
/// reading a log of thousands of records. A separate window can be sized, put
/// on another display, and kept open next to the rest of the app.
@MainActor
enum RecordsWindow {
    private static var open: [NSWindow] = []

    static func present(_ parsed: ParsedRecords) {
        let controller = NSHostingController(rootView: SEGBBrowserView(parsed: parsed))
        let window = NSWindow(contentViewController: controller)
        window.title = "\(parsed.fileName) — v\(parsed.generation) parsed"
        window.subtitle = parsed.path
        window.setContentSize(NSSize(width: 1140, height: 740))
        window.styleMask.insert([.resizable, .miniaturizable, .closable, .titled])
        window.isReleasedWhenClosed = false
        window.center()
        window.makeKeyAndOrderFront(nil)
        open.append(window)

        NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification, object: window, queue: .main
        ) { _ in
            Task { @MainActor in open.removeAll { $0 === window } }
        }
    }
}

/// Browses every record in a parsed SEGB file.
struct SEGBBrowserView: View {
    let parsed: ParsedRecords

    enum Filter: String, CaseIterable, Identifiable {
        case all = "All"
        case written = "Written"
        case deleted = "Deleted"
        case failed = "CRC failed"
        var id: String { rawValue }
    }

    enum Detail: String, CaseIterable, Identifiable {
        case fields = "Fields"
        case hex = "Hex"
        case strings = "Strings"
        var id: String { rawValue }
    }

    @State private var searchText = ""
    @State private var filter: Filter = .all
    @State private var detail: Detail = .fields
    @State private var selected: Int?
    @State private var matches: [ParsedRecords.RenderedRecord] = []
    @State private var isFiltering = false
    @State private var page = PageWindow(pageSize: 200)
    @State private var message: String?

    private var selectedRecord: ParsedRecords.RenderedRecord? {
        guard let selected else { return nil }
        return parsed.records.first { $0.id == selected }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HSplitView {
                recordList.frame(minWidth: 280, idealWidth: 340)
                recordDetail.frame(minWidth: 420)
            }
            if let message {
                Divider()
                HStack {
                    Image(systemName: "checkmark.circle").foregroundStyle(.green)
                    Text(message).font(.caption)
                    Spacer()
                    Button("Dismiss") { self.message = nil }.buttonStyle(.link).font(.caption)
                }
                .padding(.horizontal, 14).padding(.vertical, 6)
            }
        }
        .task(id: "\(searchText)|\(filter.rawValue)") { await applyFilter() }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Label(parsed.document.version.rawValue, systemImage: "list.bullet.rectangle")
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(.blue.opacity(0.15), in: Capsule())

                if let stream = parsed.stream {
                    Text(stream.title)
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(.green.opacity(0.15), in: Capsule())
                        .help("\(stream.name) · \(stream.fieldCount) named fields, from iLEAPP's parsers")
                }

                Text("\(Format.count(parsed.document.records.count)) records")
                    .font(.caption).foregroundStyle(.secondary)
                if parsed.document.deletedCount > 0 {
                    Text("\(Format.count(parsed.document.deletedCount)) deleted")
                        .font(.caption).foregroundStyle(.orange)
                }
                if parsed.document.failedCRCCount > 0 {
                    Label("\(parsed.document.failedCRCCount) failed CRC", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.red)
                }
                if let created = parsed.document.created {
                    Text("created \(Format.fullTimestamp(created))")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
                Spacer()
                Button {
                    openAsText()
                } label: {
                    Label("Open as Text", systemImage: "arrow.up.forward.app")
                }
                .controlSize(.small)
                .help("Writes the parsed records to a temporary file and opens them")
                Button {
                    exportText()
                } label: {
                    Label("Save Parsed…", systemImage: "square.and.arrow.down")
                }
                .controlSize(.small)
            }

            if let problem = parsed.document.problem {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
            }

            HStack(spacing: 12) {
                Picker("", selection: $filter) {
                    ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .frame(width: 320)

                HStack(spacing: 5) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Search inside records", text: $searchText).textFieldStyle(.plain)
                    if isFiltering { ProgressView().controlSize(.small) }
                    if !searchText.isEmpty {
                        Button { searchText = "" } label: {
                            Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                        }.buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 8).padding(.vertical, 5)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))
                .frame(maxWidth: 300)

                Spacer()
                Text("\(Format.count(matches.count)) shown")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    // MARK: - List

    private var recordList: some View {
        List(selection: $selected) {
            ForEach(page.window(matches)) { entry in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text("#\(entry.id + 1)")
                            .font(.caption.weight(.bold).monospacedDigit())
                        Text(entry.record.state.displayName)
                            .font(.caption2)
                            .foregroundStyle(entry.record.state == .deleted ? .orange : .secondary)
                        if entry.record.state == .written && !entry.record.crcPassed {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.caption2).foregroundStyle(.red)
                        }
                        Spacer()
                        Text(Format.bytes(Int64(entry.record.data.count)))
                            .font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
                    }
                    if let timestamp = entry.record.timestamp {
                        Text(Format.fullTimestamp(timestamp))
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                    Text(entry.lines.first ?? "")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
                .padding(.vertical, 2)
                .tag(entry.id)
            }
            if page.hasMore(matches) {
                PageLoadMoreRow(shown: page.limit, total: matches.count) { page.advance() }
            }
        }
        .listStyle(.inset)
    }

    // MARK: - Detail

    @ViewBuilder
    private var recordDetail: some View {
        if let entry = selectedRecord {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    Text("Record #\(entry.id + 1)").font(.headline)
                    if let timestamp = entry.record.timestamp {
                        Text(Format.fullTimestamp(timestamp))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if entry.record.state == .written {
                        Label(entry.record.crcPassed ? "CRC ok" : "CRC mismatch",
                              systemImage: entry.record.crcPassed ? "checkmark.seal" : "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(entry.record.crcPassed ? Color.green : Color.red)
                    }
                }
                .padding(.horizontal, 14).padding(.top, 12).padding(.bottom, 6)

                HStack(spacing: 10) {
                    Picker("", selection: $detail) {
                        ForEach(Detail.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented).labelsHidden().frame(width: 210)

                    Text("\(entry.record.state.displayName) · \(Format.bytes(Int64(entry.record.data.count))) at offset 0x\(String(entry.record.offset, radix: 16))")
                        .font(.caption2).foregroundStyle(.tertiary)

                    Spacer()
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(entry.lines.joined(separator: "\n"), forType: .string)
                        message = "Copied record #\(entry.id + 1)."
                    } label: {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                    .controlSize(.small)
                }
                .padding(.horizontal, 14).padding(.bottom, 8)

                Divider()

                switch detail {
                case .fields:
                    PlainTextScrollView(text: entry.lines.joined(separator: "\n"))
                case .hex:
                    BinaryVersionPane(identity: "record-\(entry.id)",
                                      data: entry.record.data,
                                      byteCount: Int64(entry.record.data.count),
                                      streamPath: parsed.path)
                case .strings:
                    PlainTextScrollView(text: BinaryText.plainText(in: entry.record.data))
                }
            }
        } else {
            EmptyStateView(symbol: "list.bullet.rectangle",
                           title: "Select a record",
                           message: "Every record in this file is listed on the left, with its timestamp, state and decoded contents.")
        }
    }

    // MARK: - Actions

    private func applyFilter() async {
        let query = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        let current = filter
        let all = parsed.records

        if query.isEmpty && current == .all {
            matches = all
            page.reset()
            reconcileSelection()
            return
        }

        isFiltering = true
        defer { isFiltering = false }
        // Typing is faster than filtering thousands of records; let the
        // keystrokes settle first.
        try? await Task.sleep(for: .milliseconds(150))
        guard !Task.isCancelled else { return }

        let filtered = await Task.detached(priority: .userInitiated) {
            all.filter { entry in
                switch current {
                case .all:     break
                case .written: if entry.record.state != .written { return false }
                case .deleted: if entry.record.state != .deleted { return false }
                case .failed:  if entry.record.crcPassed { return false }
                }
                return query.isEmpty || entry.searchKey.contains(query)
            }
        }.value

        guard !Task.isCancelled else { return }
        matches = filtered
        page.reset()
        reconcileSelection()
    }

    private func reconcileSelection() {
        if selected == nil || !matches.contains(where: { $0.id == selected }) {
            selected = matches.first?.id
        }
    }

    private func openAsText() {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdwatcher-records", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let url = directory.appendingPathComponent("\(parsed.fileName)-v\(parsed.generation).txt")
        do {
            try parsed.fullText.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            NSWorkspace.shared.open(url)
        } catch {
            message = "Could not write the parsed file: \(error.localizedDescription)"
        }
    }

    private func exportText() {
        let panel = NSSavePanel()
        panel.title = "Save parsed records"
        panel.nameFieldStringValue = "\(parsed.fileName)-v\(parsed.generation).txt"
        panel.message = "Writes every parsed record as plain, unencrypted text."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try parsed.fullText.write(to: url, atomically: true, encoding: .utf8)
            message = "Saved \(url.lastPathComponent)."
        } catch {
            message = "Could not save: \(error.localizedDescription)"
        }
    }
}
