import SwiftUI
import AppKit
import HDWatcherCore

/// Renders a captured version according to what it actually is, and — when
/// there is another version to compare against — what changed between them.
///
/// Every format gets an answer to that second question. Images are shown side
/// by side, text is diffed line by line, and everything else is diffed at the
/// byte level or through whatever readable structure it has. A comparison that
/// only worked for source files would miss most of what a filesystem monitor
/// actually captures.
struct MediaPreviewPane: View {
    let version: FileSnapshot
    let data: Data
    let kind: PreviewKind
    /// The version being compared against, when there is one.
    var comparison: (version: FileSnapshot, data: Data)?
    var onPickComparison: (() -> Void)?
    var onOpenCopy: () -> Void

    @State private var summary: BinaryDiff.Summary?

    private var identity: String {
        "\(version.id.uuidString)|\(comparison?.version.id.uuidString ?? "-")"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if let summary, let comparison, showsSummaryBar {
                ComparisonSummaryBar(summary: summary,
                                     oldLabel: "v\(comparison.version.generation)",
                                     newLabel: "v\(version.generation)",
                                     onPickComparison: onPickComparison)
                Divider()
            }
            content
        }
        .task(id: identity) {
            guard let comparison else { summary = nil; return }
            let mine = data
            let theirs = comparison.data
            summary = await Task.detached(priority: .userInitiated) {
                BinaryDiff.summarize(theirs, mine)
            }.value
        }
    }

    /// The byte-level pane carries its own comparison controls, so the bar
    /// would be saying the same thing twice.
    private var showsSummaryBar: Bool {
        switch kind {
        case .image, .pdf, .audio, .video, .archive: return true
        case .text, .binary, .records: return false
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Label(kind.displayName, systemImage: kind.symbolName)
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
            if let dimensions {
                Text(dimensions).font(.caption2).foregroundStyle(.tertiary)
            }
            Spacer()
            Text("\(Format.bytes(version.byteSize)) · captured \(Format.fullTimestamp(version.capturedAt))")
                .font(.caption2).foregroundStyle(.tertiary)
            Button(action: onOpenCopy) {
                Label("Open a Copy", systemImage: "arrow.up.forward.app")
            }
            .controlSize(.small)
            .help("Writes a temporary decrypted copy and opens it in the usual app")
        }
        .padding(.horizontal, 14).padding(.vertical, 7)
    }

    private var image: NSImage? { NSImage(data: data) }

    private var dimensions: String? {
        guard kind == .image, let image, image.size.width > 0 else { return nil }
        return "\(Int(image.size.width)) × \(Int(image.size.height))"
    }

    @ViewBuilder
    private var content: some View {
        switch kind {
        case .image, .pdf:
            if let comparison, kind.supportsVisualDiff,
               let before = NSImage(data: comparison.data), let after = image {
                ImageComparisonView(before: before, beforeVersion: comparison.version,
                                    after: after, afterVersion: version)
            } else if let image {
                ScrollView([.horizontal, .vertical]) {
                    Image(nsImage: image)
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(maxWidth: .infinity)
                        .padding(14)
                }
                .scrollIndicators(.visible)
            } else {
                undecodable
            }

        case .audio, .video, .archive:
            // Nothing here can be drawn, but the bytes can still be compared —
            // and when there is nothing to compare against, offering the file
            // to the app that understands it beats a hex dump nobody wants.
            if comparison != nil {
                binaryPane
            } else {
                handoff
            }

        case .text:
            PlainTextScrollView(text: String(data: data, encoding: .utf8) ?? "")

        case .binary, .records:
            binaryPane
        }
    }

    private var binaryPane: some View {
        BinaryVersionPane(identity: identity,
                          data: data,
                          byteCount: version.byteSize,
                          comparison: comparison?.data,
                          comparisonLabel: comparison.map { "v\($0.version.generation)" },
                          onPickComparison: onPickComparison)
    }

    private var handoff: some View {
        VStack(spacing: 12) {
            Image(systemName: kind.symbolName)
                .font(.system(size: 40))
                .foregroundStyle(.tertiary)
            Text("\(kind.displayName) file")
                .font(.headline).foregroundStyle(.secondary)
            Text("HDWatcher does not render this format. The captured bytes are intact — open a copy to view it in the app that normally handles it.")
                .font(.subheadline).foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 380)
            Button(action: onOpenCopy) {
                Label("Open a Copy", systemImage: "arrow.up.forward.app")
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(30)
    }

    private var undecodable: some View {
        EmptyStateView(symbol: "photo.badge.exclamationmark",
                       title: "Could not draw this image",
                       message: "The bytes were recovered but macOS could not decode them. Open a copy to try another application.")
    }
}

/// Two versions of an image, side by side.
struct ImageComparisonView: View {
    let before: NSImage
    let beforeVersion: FileSnapshot
    let after: NSImage
    let afterVersion: FileSnapshot

    var body: some View {
        HSplitView {
            pane(title: "v\(beforeVersion.generation)", subtitle: caption(beforeVersion),
                 image: before, tint: .red)
            pane(title: "v\(afterVersion.generation)", subtitle: caption(afterVersion),
                 image: after, tint: .green)
        }
    }

    private func caption(_ version: FileSnapshot) -> String {
        "\(Format.bytes(version.byteSize)) · \(Format.relativeTime(version.capturedAt))"
    }

    private func pane(title: String, subtitle: String, image: NSImage, tint: Color) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Circle().fill(tint).frame(width: 7, height: 7)
                Text(title).font(.caption.weight(.bold))
                Text(subtitle).font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Text("\(Int(image.size.width))×\(Int(image.size.height))")
                    .font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            Divider()
            ScrollView([.horizontal, .vertical]) {
                Image(nsImage: image)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .padding(10)
            }
        }
        .frame(minWidth: 200)
    }
}

/// Content with no dedicated viewer, read four ways.
///
/// Records is the structured reading of a format the app understands. Strings
/// pulls out the readable fragments, which is how you find an address or a
/// bundle identifier in a database. Full Text shows every byte the way a text
/// editor would, so nothing is hidden by the extraction. Hex is the ground
/// truth underneath all three. Each of them can be diffed against another
/// version.
struct BinaryVersionPane: View {
    let identity: String
    let data: Data
    let byteCount: Int64
    var comparison: Data?
    var comparisonLabel: String?
    var onPickComparison: (() -> Void)?

    enum Mode: String, CaseIterable, Identifiable {
        case records = "Records"
        case strings = "Strings"
        case raw = "Full Text"
        case hex = "Hex"
        var id: String { rawValue }
    }

    struct HexRow: Identifiable, Sendable {
        var id: Int { offset }
        let offset: Int
        let hex: String
        let ascii: String
    }

    /// Everything that can be prepared without knowing which mode the reader
    /// will pick. All of it is linear in the size of the file.
    struct Base: Sendable {
        var recordText: String?
        var strings: [BinaryText.Run]
        var rawLines: [BinaryText.RawLine]
        var rawTruncated: Bool
        var hexRows: [HexRow]
        var hexBytesShown: Int
        var readableFraction: Double
    }

    enum DiffPayload: Sendable {
        case lines(TextDiff.Result)
        case bytes(BinaryDiff.Result)
    }

    @State private var mode: Mode?
    @State private var base: Base?
    @State private var diff: DiffPayload?
    @State private var isDiffing = false
    @State private var showDiff = true
    @State private var showOffsets = false

    /// Hex is capped: past this, the rows stop telling you anything the other
    /// modes do not, and building millions of them helps nobody.
    private static let hexByteLimit = 131_072

    private var availableModes: [Mode] {
        guard let base else { return [] }
        return Mode.allCases.filter { $0 != .records || base.recordText != nil }
    }

    private var diffKey: String { "\(identity)|\(mode?.rawValue ?? "-")|\(showDiff)" }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if let base, let mode {
                if isDiffing {
                    InlineLoadingView(message: "Comparing versions…")
                } else {
                    content(base: base, mode: mode)
                }
            } else {
                InlineLoadingView(message: "Reading contents…")
            }
        }
        .task(id: identity) { await buildBase() }
        .task(id: diffKey) { await buildDiff() }
    }

    // MARK: - Header

    @ViewBuilder
    private var header: some View {
        HStack(spacing: 10) {
            if let mode, availableModes.count > 1 {
                Picker("", selection: Binding(get: { mode }, set: { self.mode = $0 })) {
                    ForEach(availableModes) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: CGFloat(availableModes.count) * 68)
            }

            if comparison != nil {
                Toggle(isOn: $showDiff) {
                    Label("Show changes", systemImage: "plusminus")
                }
                .toggleStyle(.button)
                .controlSize(.small)
                .help("Compare this version against \(comparisonLabel ?? "another version")")

                if let onPickComparison {
                    Button(action: onPickComparison) {
                        Label("vs \(comparisonLabel ?? "…")", systemImage: "arrow.left.arrow.right")
                    }
                    .buttonStyle(.link).font(.caption)
                }
            }

            diffStats

            if mode == .strings || mode == .raw {
                Toggle(isOn: $showOffsets) {
                    Label("Offsets", systemImage: "number")
                }
                .toggleStyle(.button)
                .controlSize(.small)
                .help("Show where each line sits in the file")
            }

            Spacer()
            Text(scopeNote).font(.caption2).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 14).padding(.vertical, 7)
    }

    @ViewBuilder
    private var diffStats: some View {
        switch diff {
        case .lines(let result):
            HStack(spacing: 8) {
                Text("+\(result.addedCount)").foregroundStyle(.green)
                Text("−\(result.removedCount)").foregroundStyle(.red)
                if result.truncated { Text("(clipped)").foregroundStyle(.tertiary) }
            }
            .font(.caption.monospacedDigit().weight(.medium))
        case .bytes(let result):
            HStack(spacing: 8) {
                if result.summary.identical {
                    Text("identical").foregroundStyle(.secondary)
                } else {
                    if result.changedRowCount > 0 { Text("~\(result.changedRowCount)").foregroundStyle(.orange) }
                    if result.addedRowCount > 0 { Text("+\(result.addedRowCount)").foregroundStyle(.green) }
                    if result.removedRowCount > 0 { Text("−\(result.removedRowCount)").foregroundStyle(.red) }
                    if result.truncated { Text("(clipped)").foregroundStyle(.tertiary) }
                }
            }
            .font(.caption.monospacedDigit().weight(.medium))
        case nil:
            EmptyView()
        }
    }

    private var scopeNote: String {
        guard let base, let mode else { return Format.bytes(byteCount) }
        switch mode {
        case .records:
            return Format.bytes(byteCount)
        case .strings:
            return "\(Format.count(base.strings.count)) readable strings · \(Format.bytes(byteCount))"
        case .raw:
            return base.rawTruncated
                ? "first \(Format.count(base.rawLines.count)) lines of \(Format.bytes(byteCount))"
                : "\(Format.count(base.rawLines.count)) lines · \(Format.bytes(byteCount))"
        case .hex:
            return base.hexBytesShown < Int(byteCount)
                ? "first \(Format.bytes(Int64(base.hexBytesShown))) of \(Format.bytes(byteCount))"
                : Format.bytes(byteCount)
        }
    }

    // MARK: - Content

    @ViewBuilder
    private func content(base: Base, mode: Mode) -> some View {
        switch (mode, diff) {
        case (.hex, .bytes(let result)):
            if result.summary.identical {
                identicalNotice
            } else {
                HexDiffScrollView(rows: result.rows, showsOffsets: true)
            }

        case (_, .lines(let result)):
            if result.hasChanges {
                DiffScrollView(lines: TextDiff.condense(result, context: 3),
                               showsLineNumbers: false)
            } else {
                identicalNotice
            }

        case (.records, _):
            PlainTextScrollView(text: base.recordText ?? "")

        case (.strings, _):
            stringsView(base)

        case (.raw, _):
            rawView(base)

        case (.hex, _):
            hexView(base)
        }
    }

    private var identicalNotice: some View {
        EmptyStateView(symbol: "equal.circle",
                       title: "No differences",
                       message: "These two versions are identical in this view. Turn off Show changes to read the contents.")
    }

    @ViewBuilder
    private func stringsView(_ base: Base) -> some View {
        if base.strings.isEmpty {
            EmptyStateView(symbol: "textformat.abc.dottedunderline",
                           title: "No readable text",
                           message: "This file contains no runs of printable characters long enough to show. Full Text has every byte, and Hex has the raw values.")
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(base.strings) { run in
                        HStack(alignment: .top, spacing: 10) {
                            if showOffsets {
                                Text(String(format: "%08x", run.offset))
                                    .foregroundStyle(.tertiary)
                                    .frame(width: 70, alignment: .trailing)
                            }
                            Text(run.text)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .font(.system(size: 11, design: .monospaced))
                        .padding(.horizontal, 10)
                    }
                }
                .padding(.vertical, 6)
            }
        }
    }

    private func rawView(_ base: Base) -> some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(base.rawLines) { line in
                    HStack(alignment: .top, spacing: 10) {
                        if showOffsets {
                            Text(String(format: "%08x", line.offset))
                                .foregroundStyle(.tertiary)
                                .frame(width: 70, alignment: .trailing)
                        }
                        Text(line.text.isEmpty ? " " : line.text)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .font(.system(size: 11, design: .monospaced))
                    .padding(.horizontal, 10)
                }
            }
            .padding(.vertical, 6)
        }
    }

    private func hexView(_ base: Base) -> some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(base.hexRows) { row in
                    HStack(spacing: 12) {
                        Text(String(format: "%08x", row.offset))
                            .foregroundStyle(.tertiary)
                        Text(row.hex)
                        Text(row.ascii).foregroundStyle(.secondary)
                    }
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                }
            }
            .padding(10)
        }
    }

    // MARK: - Building

    private func buildBase() async {
        base = nil
        diff = nil
        let bytes = data
        let built = await Task.detached(priority: .userInitiated) { Self.build(bytes) }.value
        base = built
        mode = Self.defaultMode(for: built)
    }

    private func buildDiff() async {
        guard let mode, let other = comparison, showDiff else { diff = nil; return }
        isDiffing = true
        defer { isDiffing = false }
        let mine = data
        diff = await Task.detached(priority: .userInitiated) { () -> DiffPayload in
            switch mode {
            case .hex:
                return .bytes(BinaryDiff.compare(other, mine))
            case .records:
                return .lines(TextDiff.compare(Self.renderRecords(of: other) ?? "",
                                               Self.renderRecords(of: mine) ?? ""))
            case .strings:
                return .lines(TextDiff.compare(BinaryText.plainText(in: other),
                                               BinaryText.plainText(in: mine)))
            case .raw:
                return .lines(TextDiff.compare(Self.rawText(of: other), Self.rawText(of: mine)))
            }
        }.value
    }

    nonisolated private static func build(_ data: Data) -> Base {
        let hexSlice = data.prefix(hexByteLimit)
        let rows = stride(from: 0, to: hexSlice.count, by: 16).map { start -> HexRow in
            let chunk = [UInt8](hexSlice[hexSlice.startIndex + start..<hexSlice.startIndex + min(start + 16, hexSlice.count)])
            let hex = chunk.enumerated()
                .map { $0.offset == 7 ? String(format: "%02x ", $0.element)
                                      : String(format: "%02x", $0.element) }
                .joined(separator: " ")
            let ascii = String(chunk.map { byte in
                (byte >= 32 && byte < 127) ? Character(UnicodeScalar(byte)) : "."
            })
            return HexRow(offset: start, hex: hex, ascii: ascii)
        }
        let raw = BinaryText.rawLines(of: data)
        return Base(recordText: renderRecords(of: data),
                    strings: BinaryText.runs(in: data),
                    rawLines: raw.lines,
                    rawTruncated: raw.truncated,
                    hexRows: rows,
                    hexBytesShown: hexSlice.count,
                    readableFraction: BinaryText.readableFraction(of: data))
    }

    nonisolated private static func renderRecords(of data: Data) -> String? {
        guard let document = SEGB.parse(data) else { return nil }
        return SEGB.render(document)
    }

    nonisolated private static func rawText(of data: Data) -> String {
        BinaryText.rawLines(of: data).lines.map(\.text).joined(separator: "\n")
    }

    /// Opens on the reading that will actually tell the user something.
    private static func defaultMode(for base: Base) -> Mode {
        if base.recordText != nil { return .records }
        if base.strings.count >= 8 { return .strings }
        if base.readableFraction > 0.05 { return .raw }
        return .hex
    }
}
