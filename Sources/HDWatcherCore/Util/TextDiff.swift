import Foundation

/// Line-level diff used to review what changed between two captured versions.
public enum TextDiff {

    public enum LineKind: String, Sendable {
        case unchanged, added, removed
    }

    public struct Line: Identifiable, Sendable {
        public let id: Int
        public let kind: LineKind
        public let text: String
        /// 1-based line numbers, nil where the line does not exist on that side.
        public let oldNumber: Int?
        public let newNumber: Int?
    }

    public struct Result: Sendable {
        public var lines: [Line]
        public var addedCount: Int
        public var removedCount: Int
        /// True when either side exceeded the line budget and was clipped.
        public var truncated: Bool

        public var hasChanges: Bool { addedCount > 0 || removedCount > 0 }
    }

    /// Classic LCS diff. The line budget keeps the O(n·m) table from blowing up
    /// on large files — beyond it, the comparison is clipped rather than hanging.
    public static func compare(_ oldText: String, _ newText: String, maxLines: Int = 4_000) -> Result {
        var oldLines = oldText.components(separatedBy: .newlines)
        var newLines = newText.components(separatedBy: .newlines)

        var truncated = false
        if oldLines.count > maxLines { oldLines = Array(oldLines.prefix(maxLines)); truncated = true }
        if newLines.count > maxLines { newLines = Array(newLines.prefix(maxLines)); truncated = true }

        let width = newLines.count + 1
        let table = lcsTable(oldLines, newLines)
        func score(_ i: Int, _ j: Int) -> Int32 { table[i * width + j] }

        var lines: [Line] = []
        var added = 0
        var removed = 0
        var i = 0
        var j = 0
        var id = 0

        while i < oldLines.count && j < newLines.count {
            if oldLines[i] == newLines[j] {
                lines.append(Line(id: id, kind: .unchanged, text: oldLines[i],
                                  oldNumber: i + 1, newNumber: j + 1))
                i += 1; j += 1
            } else if score(i + 1, j) >= score(i, j + 1) {
                lines.append(Line(id: id, kind: .removed, text: oldLines[i],
                                  oldNumber: i + 1, newNumber: nil))
                removed += 1
                i += 1
            } else {
                lines.append(Line(id: id, kind: .added, text: newLines[j],
                                  oldNumber: nil, newNumber: j + 1))
                added += 1
                j += 1
            }
            id += 1
        }
        while i < oldLines.count {
            lines.append(Line(id: id, kind: .removed, text: oldLines[i], oldNumber: i + 1, newNumber: nil))
            removed += 1; i += 1; id += 1
        }
        while j < newLines.count {
            lines.append(Line(id: id, kind: .added, text: newLines[j], oldNumber: nil, newNumber: j + 1))
            added += 1; j += 1; id += 1
        }

        return Result(lines: lines, addedCount: added, removedCount: removed, truncated: truncated)
    }

    /// A flat buffer rather than an array of arrays: at the maximum line
    /// budget the nested form costs 128 MB for the same numbers.
    private static func lcsTable(_ a: [String], _ b: [String]) -> ContiguousArray<Int32> {
        let width = b.count + 1
        var table = ContiguousArray<Int32>(repeating: 0, count: (a.count + 1) * width)
        guard !a.isEmpty, !b.isEmpty else { return table }
        for i in stride(from: a.count - 1, through: 0, by: -1) {
            for j in stride(from: b.count - 1, through: 0, by: -1) {
                table[i * width + j] = a[i] == b[j]
                    ? table[(i + 1) * width + (j + 1)] + 1
                    : max(table[(i + 1) * width + j], table[i * width + (j + 1)])
            }
        }
        return table
    }

    /// Collapses long runs of unchanged lines, keeping `context` lines either
    /// side of each change.
    public static func condense(_ result: Result, context: Int = 3) -> [Line] {
        let lines = result.lines
        guard result.hasChanges else { return Array(lines.prefix(context * 2)) }

        var keep = Set<Int>()
        for (index, line) in lines.enumerated() where line.kind != .unchanged {
            for offset in max(0, index - context)...min(lines.count - 1, index + context) {
                keep.insert(offset)
            }
        }
        return lines.enumerated().filter { keep.contains($0.offset) }.map(\.element)
    }
}
