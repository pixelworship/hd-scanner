import SwiftUI
import HDWatcherCore

/// A hex comparison of two versions.
///
/// The text diff answers "what changed" for a source file; this answers the
/// same question for everything else. Changed rows are shown as a before and
/// after pair with the differing columns picked out, because in a binary the
/// interesting part is usually four bytes inside an otherwise identical row.
struct HexDiffScrollView: View {
    let rows: [BinaryDiff.Row]
    var showsOffsets = true

    var body: some View {
        ScrollView([.horizontal, .vertical]) {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(rows) { row in
                    HexDiffRow(row: row, showsOffsets: showsOffsets)
                }
            }
            .padding(.vertical, 6)
        }
        .scrollIndicators(.visible)
    }
}

private struct HexDiffRow: View {
    let row: BinaryDiff.Row
    let showsOffsets: Bool

    var body: some View {
        switch row.kind {
        case .gap:
            HStack(spacing: 8) {
                Rectangle().fill(.quaternary).frame(height: 1)
                Text("\(Format.count(row.skipped)) identical rows")
                    .font(.caption2).foregroundStyle(.tertiary).fixedSize()
                Rectangle().fill(.quaternary).frame(height: 1)
            }
            .padding(.horizontal, 10).padding(.vertical, 5)

        case .unchanged:
            line(offset: row.oldOffset, marker: " ", bytes: row.oldBytes,
                 highlighted: [], tint: .clear, textColor: .secondary)

        case .added:
            line(offset: row.newOffset, marker: "+", bytes: row.newBytes,
                 highlighted: [], tint: .green.opacity(0.18), textColor: .primary)

        case .removed:
            line(offset: row.oldOffset, marker: "−", bytes: row.oldBytes,
                 highlighted: [], tint: .red.opacity(0.18), textColor: .primary)

        case .changed:
            VStack(alignment: .leading, spacing: 0) {
                line(offset: row.oldOffset, marker: "−", bytes: row.oldBytes,
                     highlighted: row.differingColumns, tint: .red.opacity(0.18),
                     textColor: .primary, accent: .red)
                line(offset: row.newOffset, marker: "+", bytes: row.newBytes,
                     highlighted: row.differingColumns, tint: .green.opacity(0.18),
                     textColor: .primary, accent: .green)
            }
        }
    }

    private func line(offset: Int?, marker: String, bytes: [UInt8],
                      highlighted: Set<Int>, tint: Color, textColor: Color,
                      accent: Color = .primary) -> some View {
        HStack(spacing: 12) {
            if showsOffsets {
                Text(offset.map { String(format: "%08x", $0) } ?? "        ")
                    .foregroundStyle(.tertiary)
            }
            Text(marker).foregroundStyle(accent).frame(width: 8)
            hexColumns(bytes, highlighted: highlighted, accent: accent)
            asciiColumns(bytes, highlighted: highlighted, accent: accent)
                .foregroundStyle(.secondary)
        }
        .font(.system(size: 11, design: .monospaced))
        .foregroundStyle(textColor)
        .textSelection(.enabled)
        .padding(.horizontal, 10).padding(.vertical, 1)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint)
    }

    /// Built by concatenation so the differing bytes can be coloured
    /// individually while the row stays one selectable run of text.
    private func hexColumns(_ bytes: [UInt8], highlighted: Set<Int>, accent: Color) -> Text {
        var result = Text("")
        for column in 0..<16 {
            let piece: Text
            if column < bytes.count {
                piece = Text(String(format: "%02x", bytes[column]))
                    .foregroundColor(highlighted.contains(column) ? accent : nil)
                    .fontWeight(highlighted.contains(column) ? .bold : .regular)
            } else {
                piece = Text("  ")
            }
            result = result + piece + Text(column == 7 ? "  " : " ")
        }
        return result
    }

    private func asciiColumns(_ bytes: [UInt8], highlighted: Set<Int>, accent: Color) -> Text {
        var result = Text("")
        for column in 0..<bytes.count {
            let byte = bytes[column]
            let character = (byte >= 32 && byte < 127)
                ? String(UnicodeScalar(byte)) : "."
            result = result + Text(character)
                .foregroundColor(highlighted.contains(column) ? accent : nil)
        }
        return result
    }
}

/// One line saying how two versions differ, for formats where a byte-level
/// view is not the point — an image, a video, an archive.
struct ComparisonSummaryBar: View {
    let summary: BinaryDiff.Summary
    let oldLabel: String
    let newLabel: String
    var onPickComparison: (() -> Void)?

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: summary.identical ? "equal.circle" : "plusminus.circle")
                .foregroundStyle(summary.identical ? Color.secondary : Color.orange)
            Text("\(oldLabel) → \(newLabel)")
                .font(.caption.weight(.semibold))
            Text(detail)
                .font(.caption).foregroundStyle(.secondary)
            Spacer()
            if let onPickComparison {
                Button(action: onPickComparison) {
                    Label("Change", systemImage: "arrow.left.arrow.right")
                }
                .buttonStyle(.link).font(.caption)
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 6)
        .background(.quaternary.opacity(0.25))
    }

    private var detail: String {
        guard !summary.identical else { return "byte-for-byte identical" }
        var parts: [String] = []
        if summary.oldByteCount != summary.newByteCount {
            parts.append("\(Format.bytes(Int64(summary.oldByteCount))) → \(Format.bytes(Int64(summary.newByteCount)))")
            let delta = summary.sizeDelta
            parts.append("\(delta > 0 ? "+" : "")\(Format.bytes(Int64(delta)))")
        } else if let differing = summary.differingByteCount {
            parts.append("\(Format.count(differing)) of \(Format.count(summary.newByteCount)) bytes differ")
        }
        if let first = summary.firstDifferenceOffset {
            parts.append("first change at 0x\(String(first, radix: 16))")
        }
        return parts.joined(separator: " · ")
    }
}
