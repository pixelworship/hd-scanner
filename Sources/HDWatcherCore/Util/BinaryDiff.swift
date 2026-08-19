import Foundation

/// Byte-level comparison of two captured versions.
///
/// Recovery has to answer the same question for every file — what changed
/// between these two versions — and only text ever had an answer. A photo, a
/// database, a signed binary, a stream of protobuf: the question is identical,
/// only the rendering differs. This produces the row-aligned comparison the hex
/// view draws, plus a cheap whole-file summary for formats where a hex dump is
/// beside the point.
public enum BinaryDiff {

    public enum RowKind: String, Sendable {
        case unchanged, added, removed, changed
        /// A run of identical rows left out of the comparison.
        case gap
    }

    public struct Row: Identifiable, Sendable {
        public let id: Int
        public let kind: RowKind
        public let oldOffset: Int?
        public let newOffset: Int?
        public let oldBytes: [UInt8]
        public let newBytes: [UInt8]
        /// Columns whose byte differs, so a `.changed` row can point at the
        /// bytes rather than just being flagged.
        public let differingColumns: Set<Int>
        /// For `.gap`, how many identical rows were skipped.
        public let skipped: Int

        init(id: Int = 0, kind: RowKind, oldOffset: Int?, newOffset: Int?,
             oldBytes: [UInt8] = [], newBytes: [UInt8] = [],
             differingColumns: Set<Int> = [], skipped: Int = 0) {
            self.id = id
            self.kind = kind
            self.oldOffset = oldOffset
            self.newOffset = newOffset
            self.oldBytes = oldBytes
            self.newBytes = newBytes
            self.differingColumns = differingColumns
            self.skipped = skipped
        }

        func withID(_ id: Int) -> Row {
            Row(id: id, kind: kind, oldOffset: oldOffset, newOffset: newOffset,
                oldBytes: oldBytes, newBytes: newBytes,
                differingColumns: differingColumns, skipped: skipped)
        }
    }

    /// Whole-file answer, computed in a single linear pass. Cheap enough to run
    /// on a video file, where building rows would be pointless.
    public struct Summary: Sendable {
        public let oldByteCount: Int
        public let newByteCount: Int
        public let identical: Bool
        /// Where the two first disagree, which is often the only locator needed.
        public let firstDifferenceOffset: Int?
        public let commonPrefix: Int
        public let commonSuffix: Int
        /// Only meaningful when the two are the same length; otherwise the
        /// bytes do not line up and counting them would be misleading.
        public let differingByteCount: Int?

        public var sizeDelta: Int { newByteCount - oldByteCount }
        /// The span containing every difference.
        public var changedSpan: Int {
            max(0, max(oldByteCount, newByteCount) - commonPrefix - commonSuffix)
        }
    }

    public struct Result: Sendable {
        public var rows: [Row]
        public var summary: Summary
        public var addedRowCount: Int
        public var removedRowCount: Int
        public var changedRowCount: Int
        /// True when the changed region was larger than the row budget.
        public var truncated: Bool

        public var hasChanges: Bool { !summary.identical }
    }

    // MARK: - Summary

    public static func summarize(_ old: Data, _ new: Data) -> Summary {
        old.withUnsafeBytes { oldRaw in
            new.withUnsafeBytes { newRaw in
                let o = oldRaw.bindMemory(to: UInt8.self)
                let n = newRaw.bindMemory(to: UInt8.self)
                let shortest = min(o.count, n.count)

                var prefix = 0
                while prefix < shortest && o[prefix] == n[prefix] { prefix += 1 }

                var suffix = 0
                while suffix < shortest - prefix
                        && o[o.count - 1 - suffix] == n[n.count - 1 - suffix] {
                    suffix += 1
                }

                let identical = o.count == n.count && prefix == o.count
                var differing: Int?
                if o.count == n.count {
                    var count = 0
                    for index in prefix..<(o.count - suffix) where o[index] != n[index] { count += 1 }
                    differing = count
                }

                return Summary(oldByteCount: o.count,
                               newByteCount: n.count,
                               identical: identical,
                               firstDifferenceOffset: identical ? nil : prefix,
                               commonPrefix: prefix,
                               commonSuffix: suffix,
                               differingByteCount: differing)
            }
        }
    }

    // MARK: - Row comparison

    /// Row-aligned comparison.
    ///
    /// The identical head and tail are trimmed before the quadratic part runs,
    /// which is what makes this usable on real files: a change is almost always
    /// confined to one region, however large the file around it.
    public static func compare(_ old: Data, _ new: Data,
                               bytesPerRow: Int = 16,
                               maxRows: Int = 2_048,
                               context: Int = 4) -> Result {
        let summary = summarize(old, new)
        let oldRows = split(old, width: bytesPerRow)
        let newRows = split(new, width: bytesPerRow)

        var prefix = 0
        while prefix < oldRows.count && prefix < newRows.count && oldRows[prefix] == newRows[prefix] {
            prefix += 1
        }
        var suffix = 0
        while suffix < oldRows.count - prefix && suffix < newRows.count - prefix
                && oldRows[oldRows.count - 1 - suffix] == newRows[newRows.count - 1 - suffix] {
            suffix += 1
        }

        var middleOld = Array(oldRows[prefix..<(oldRows.count - suffix)])
        var middleNew = Array(newRows[prefix..<(newRows.count - suffix)])
        var truncated = false
        if middleOld.count > maxRows {
            middleOld = Array(middleOld.prefix(maxRows)); truncated = true
        }
        if middleNew.count > maxRows {
            middleNew = Array(middleNew.prefix(maxRows)); truncated = true
        }

        let middle = collapse(
            pairEdits(align(middleOld, middleNew),
                      oldRows: middleOld, newRows: middleNew,
                      base: prefix * bytesPerRow, width: bytesPerRow),
            context: context)

        var rows: [Row] = []

        // Leading context, with a marker for whatever was skipped to reach it.
        if prefix > context {
            rows.append(Row(kind: .gap, oldOffset: 0, newOffset: 0, skipped: prefix - context))
        }
        for index in max(0, prefix - context)..<prefix {
            rows.append(unchangedRow(oldRows[index], offset: index * bytesPerRow))
        }

        rows.append(contentsOf: middle)

        let suffixStartOld = oldRows.count - suffix
        let suffixStartNew = newRows.count - suffix
        for offset in 0..<min(context, suffix) {
            rows.append(Row(kind: .unchanged,
                            oldOffset: (suffixStartOld + offset) * bytesPerRow,
                            newOffset: (suffixStartNew + offset) * bytesPerRow,
                            oldBytes: oldRows[suffixStartOld + offset],
                            newBytes: newRows[suffixStartNew + offset]))
        }
        if suffix > context {
            rows.append(Row(kind: .gap,
                            oldOffset: (suffixStartOld + context) * bytesPerRow,
                            newOffset: (suffixStartNew + context) * bytesPerRow,
                            skipped: suffix - context))
        }

        rows = rows.enumerated().map { $0.element.withID($0.offset) }

        return Result(rows: rows,
                      summary: summary,
                      addedRowCount: rows.filter { $0.kind == .added }.count,
                      removedRowCount: rows.filter { $0.kind == .removed }.count,
                      changedRowCount: rows.filter { $0.kind == .changed }.count,
                      truncated: truncated)
    }

    private static func unchangedRow(_ bytes: [UInt8], offset: Int) -> Row {
        Row(kind: .unchanged, oldOffset: offset, newOffset: offset,
            oldBytes: bytes, newBytes: bytes)
    }

    private static func split(_ data: Data, width: Int) -> [[UInt8]] {
        data.withUnsafeBytes { raw -> [[UInt8]] in
            let bytes = raw.bindMemory(to: UInt8.self)
            return stride(from: 0, to: bytes.count, by: width).map { start in
                Array(bytes[start..<min(start + width, bytes.count)])
            }
        }
    }

    // MARK: - Alignment

    private struct Op {
        let old: Int?
        let new: Int?
    }

    /// Longest common subsequence over rows, so an inserted or removed run
    /// shifts the alignment instead of reporting every row after it as changed.
    ///
    /// The table is a flat `Int32` buffer: a row-of-rows `[[Int]]` at this size
    /// costs eight times the memory for no benefit.
    private static func align(_ a: [[UInt8]], _ b: [[UInt8]]) -> [Op] {
        guard !a.isEmpty else { return b.indices.map { Op(old: nil, new: $0) } }
        guard !b.isEmpty else { return a.indices.map { Op(old: $0, new: nil) } }

        let width = b.count + 1
        var table = ContiguousArray<Int32>(repeating: 0, count: (a.count + 1) * width)
        for i in stride(from: a.count - 1, through: 0, by: -1) {
            for j in stride(from: b.count - 1, through: 0, by: -1) {
                table[i * width + j] = a[i] == b[j]
                    ? table[(i + 1) * width + (j + 1)] + 1
                    : max(table[(i + 1) * width + j], table[i * width + (j + 1)])
            }
        }

        var ops: [Op] = []
        var i = 0
        var j = 0
        while i < a.count && j < b.count {
            if a[i] == b[j] {
                ops.append(Op(old: i, new: j)); i += 1; j += 1
            } else if table[(i + 1) * width + j] >= table[i * width + (j + 1)] {
                ops.append(Op(old: i, new: nil)); i += 1
            } else {
                ops.append(Op(old: nil, new: j)); j += 1
            }
        }
        while i < a.count { ops.append(Op(old: i, new: nil)); i += 1 }
        while j < b.count { ops.append(Op(old: nil, new: j)); j += 1 }
        return ops
    }

    /// Turns a removed run immediately followed by an added run into paired
    /// `.changed` rows. An edit in place is the common case, and reading it as
    /// before-and-after beats reading it as a deletion next to an insertion.
    private static func pairEdits(_ ops: [Op],
                                  oldRows: [[UInt8]], newRows: [[UInt8]],
                                  base: Int, width: Int) -> [Row] {
        func offset(_ index: Int) -> Int { base + index * width }

        var rows: [Row] = []
        var index = 0

        while index < ops.count {
            let op = ops[index]
            if let old = op.old, let new = op.new {
                rows.append(Row(kind: .unchanged,
                                oldOffset: offset(old), newOffset: offset(new),
                                oldBytes: oldRows[old], newBytes: newRows[new]))
                index += 1
                continue
            }

            var removed: [Int] = []
            while index < ops.count, let old = ops[index].old, ops[index].new == nil {
                removed.append(old); index += 1
            }
            var added: [Int] = []
            while index < ops.count, let new = ops[index].new, ops[index].old == nil {
                added.append(new); index += 1
            }

            let paired = min(removed.count, added.count)
            for index2 in 0..<paired {
                let oldRow = oldRows[removed[index2]]
                let newRow = newRows[added[index2]]
                var differing = Set<Int>()
                for column in 0..<max(oldRow.count, newRow.count) {
                    let lhs = column < oldRow.count ? oldRow[column] : nil
                    let rhs = column < newRow.count ? newRow[column] : nil
                    if lhs != rhs { differing.insert(column) }
                }
                rows.append(Row(kind: .changed,
                                oldOffset: offset(removed[index2]), newOffset: offset(added[index2]),
                                oldBytes: oldRow, newBytes: newRow,
                                differingColumns: differing))
            }
            for index2 in paired..<removed.count {
                rows.append(Row(kind: .removed,
                                oldOffset: offset(removed[index2]), newOffset: nil,
                                oldBytes: oldRows[removed[index2]]))
            }
            for index2 in paired..<added.count {
                rows.append(Row(kind: .added,
                                oldOffset: nil, newOffset: offset(added[index2]),
                                newBytes: newRows[added[index2]]))
            }
        }
        return rows
    }

    /// Replaces long runs of identical rows with a single gap marker.
    private static func collapse(_ rows: [Row], context: Int) -> [Row] {
        guard rows.contains(where: { $0.kind != .unchanged }) else {
            return Array(rows.prefix(context * 2))
        }

        var keep = [Bool](repeating: false, count: rows.count)
        for (index, row) in rows.enumerated() where row.kind != .unchanged {
            for offset in max(0, index - context)...min(rows.count - 1, index + context) {
                keep[offset] = true
            }
        }

        var result: [Row] = []
        var skipped = 0
        for (index, row) in rows.enumerated() {
            if keep[index] {
                if skipped > 0 {
                    result.append(Row(kind: .gap,
                                      oldOffset: row.oldOffset, newOffset: row.newOffset,
                                      skipped: skipped))
                    skipped = 0
                }
                result.append(row)
            } else {
                skipped += 1
            }
        }
        if skipped > 0 {
            result.append(Row(kind: .gap, oldOffset: nil, newOffset: nil, skipped: skipped))
        }
        return result
    }
}
