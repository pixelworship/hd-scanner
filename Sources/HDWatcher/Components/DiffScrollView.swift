import SwiftUI
import AppKit
import HDWatcherCore

/// Renders diff lines with real horizontal scrolling.
///
/// The obvious construction — an `HStack` per line ending in a `Spacer` — can
/// never scroll horizontally: the spacer absorbs the slack, so the content is
/// always exactly the viewport width and long lines wrap or truncate instead.
/// Here every row is laid out at the width of the widest line, measured once,
/// which both enables the scrollbar and lets a row's highlight span the full
/// width rather than stopping at the end of its text.
struct DiffScrollView: View {
    let lines: [TextDiff.Line]
    var showsLineNumbers = true
    /// Wrapped to the window by default: long lines are far more readable
    /// wrapped than scrolled sideways one screen at a time. Turning it off
    /// restores the fixed-width layout with a horizontal scrollbar.
    var wraps = true

    private static let font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
    private var gutterWidth: CGFloat { showsLineNumbers ? 96 : 18 }

    private var contentWidth: CGFloat {
        let longest = lines.map(\.text).max(by: { $0.count < $1.count }) ?? ""
        let measured = (longest as NSString).size(withAttributes: [.font: Self.font]).width
        return gutterWidth + max(measured, 120) + 24
    }

    var body: some View {
        GeometryReader { geo in
            ScrollView(wraps ? [.vertical] : [.horizontal, .vertical]) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(lines) { line in
                        DiffRow(line: line,
                                width: wraps ? geo.size.width : max(contentWidth, geo.size.width),
                                gutterWidth: gutterWidth,
                                showsLineNumbers: showsLineNumbers,
                                wraps: wraps)
                    }
                }
                .padding(.vertical, 6)
            }
            .scrollIndicators(.visible)
        }
    }
}

private struct DiffRow: View {
    let line: TextDiff.Line
    let width: CGFloat
    let gutterWidth: CGFloat
    let showsLineNumbers: Bool
    let wraps: Bool

    private var background: Color {
        switch line.kind {
        case .added:     return .green.opacity(0.18)
        case .removed:   return .red.opacity(0.18)
        case .unchanged: return .clear
        }
    }

    private var marker: String {
        switch line.kind {
        case .added:     return "+"
        case .removed:   return "−"
        case .unchanged: return " "
        }
    }

    private var markerColor: Color {
        switch line.kind {
        case .added:     return .green
        case .removed:   return .red
        case .unchanged: return .secondary
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            if showsLineNumbers {
                Text(line.oldNumber.map(String.init) ?? "")
                    .frame(width: 34, alignment: .trailing)
                    .foregroundStyle(.tertiary)
                Text(line.newNumber.map(String.init) ?? "")
                    .frame(width: 34, alignment: .trailing)
                    .foregroundStyle(.tertiary)
            }
            Text(marker)
                .foregroundStyle(markerColor)
                .frame(width: 10)
            Text(line.text.isEmpty ? " " : line.text)
                // Wrapping and horizontal scrolling are mutually exclusive:
                // a wrapped line never exceeds the viewport, so there is
                // nothing to scroll to.
                .fixedSize(horizontal: !wraps, vertical: false)
                .frame(maxWidth: wraps ? .infinity : nil, alignment: .leading)
                .textSelection(.enabled)
        }
        .font(.system(size: 11, design: .monospaced))
        .foregroundStyle(line.kind == .unchanged ? Color.secondary : Color.primary)
        .padding(.horizontal, 8)
        .padding(.vertical, 1)
        // Wrapped rows stretch to the viewport; unwrapped rows are pinned to the
        // measured content width so the highlight spans the full scrollable row.
        .frame(width: wraps ? nil : width, alignment: .leading)
        .frame(maxWidth: wraps ? .infinity : nil, alignment: .leading)
        .background(background)
    }
}

/// Plain (non-diff) file contents, with the same scrolling behaviour.
struct PlainTextScrollView: View {
    let text: String
    var lineLimit = 6_000
    var wraps = true

    private static let font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)

    private var lines: [String] {
        Array(text.components(separatedBy: .newlines).prefix(lineLimit))
    }

    private var contentWidth: CGFloat {
        let longest = lines.max(by: { $0.count < $1.count }) ?? ""
        let measured = (longest as NSString).size(withAttributes: [.font: Self.font]).width
        return 54 + max(measured, 120) + 24
    }

    var body: some View {
        GeometryReader { geo in
            ScrollView(wraps ? [.vertical] : [.horizontal, .vertical]) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { index, line in
                        HStack(alignment: .top, spacing: 8) {
                            Text("\(index + 1)")
                                .frame(width: 44, alignment: .trailing)
                                .foregroundStyle(.tertiary)
                            Text(line.isEmpty ? " " : line)
                                .fixedSize(horizontal: !wraps, vertical: false)
                                .frame(maxWidth: wraps ? .infinity : nil, alignment: .leading)
                                .textSelection(.enabled)
                        }
                        .font(.system(size: 11, design: .monospaced))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 1)
                        .frame(width: wraps ? nil : max(contentWidth, geo.size.width),
                               alignment: .leading)
                        .frame(maxWidth: wraps ? .infinity : nil, alignment: .leading)
                    }
                }
                .padding(.vertical, 6)
            }
            .scrollIndicators(.visible)
        }
    }
}
