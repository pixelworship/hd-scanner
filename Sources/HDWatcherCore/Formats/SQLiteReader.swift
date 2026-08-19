import Foundation
import SQLite3

/// Reads SQLite databases out of captured bytes.
///
/// Databases are what most of the interesting data on a Mac actually lives in —
/// messages, history, call logs, photo metadata — and they are the largest
/// single category of artifact any forensics tool handles. In a hex or strings
/// view a database shows its text and nothing about which row or column it
/// belonged to, which is most of the meaning.
///
/// The captured bytes are written to a private temporary file and opened
/// read-only and immutable. Immutable matters for two reasons: the vault holds
/// the main database file without its write-ahead log, and SQLite would
/// otherwise try to recover the "missing" journal by writing to the file.
public enum SQLiteReader {

    public struct Table: Sendable {
        public let name: String
        public let columns: [String]
        public let rowCount: Int
        public let rows: [[String]]
        /// True when only the first rows were read.
        public let clipped: Bool
    }

    public struct Document: Sendable {
        public let tables: [Table]
        public let pageSize: Int
        public let problem: String?

        public var totalRows: Int { tables.reduce(0) { $0 + $1.rowCount } }
    }

    private static let magic = Data("SQLite format 3\0".utf8)

    public static func detect(_ data: Data) -> Bool {
        data.count >= 100 && data.prefix(16) == magic
    }

    /// Opens the database and reads a bounded amount of every table.
    public static func read(_ data: Data, rowsPerTable: Int = 200) -> Document? {
        guard detect(data) else { return nil }

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdwatcher-sqlite-\(UUID().uuidString)", isDirectory: true)
        guard (try? FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])) != nil else { return nil }
        defer { try? FileManager.default.removeItem(at: directory) }

        let file = directory.appendingPathComponent("captured.db")
        guard (try? data.write(to: file, options: [.atomic])) != nil,
              (try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                      ofItemAtPath: file.path)) != nil
        else { return nil }

        var handle: OpaquePointer?
        let uri = "file:\(file.path)?immutable=1"
        guard sqlite3_open_v2(uri, &handle,
                              SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nil) == SQLITE_OK,
              let database = handle else {
            sqlite3_close(handle)
            return Document(tables: [], pageSize: 0,
                            problem: "The file starts like a database but SQLite would not open it.")
        }
        defer { sqlite3_close(database) }

        var pageSize = 0
        if let row = query(database, "PRAGMA page_size").first, let value = Int(row.first ?? "") {
            pageSize = value
        }

        var tables: [Table] = []
        var problem: String?
        let names = query(database,
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .compactMap(\.first)

        for name in names {
            let quoted = "\"\(name.replacingOccurrences(of: "\"", with: "\"\""))\""
            let count = Int(query(database, "SELECT COUNT(*) FROM \(quoted)").first?.first ?? "") ?? 0
            var columns: [String] = []
            var rows: [[String]] = []
            var statement: OpaquePointer?
            let sql = "SELECT * FROM \(quoted) LIMIT \(rowsPerTable)"
            if sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement {
                for index in 0..<sqlite3_column_count(statement) {
                    columns.append(String(cString: sqlite3_column_name(statement, index)))
                }
                while sqlite3_step(statement) == SQLITE_ROW {
                    rows.append((0..<sqlite3_column_count(statement)).map { value(statement, $0) })
                }
            } else {
                problem = problem ?? "Some tables could not be read: \(String(cString: sqlite3_errmsg(database)))"
            }
            sqlite3_finalize(statement)
            tables.append(Table(name: name, columns: columns, rowCount: count,
                                rows: rows, clipped: count > rows.count))
        }

        return Document(tables: tables, pageSize: pageSize, problem: problem)
    }

    private static func query(_ database: OpaquePointer, _ sql: String) -> [[String]] {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else { return [] }
        var rows: [[String]] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            rows.append((0..<sqlite3_column_count(statement)).map { value(statement, $0) })
        }
        return rows
    }

    private static func value(_ statement: OpaquePointer, _ index: Int32) -> String {
        switch sqlite3_column_type(statement, index) {
        case SQLITE_NULL:
            return ""
        case SQLITE_INTEGER:
            return String(sqlite3_column_int64(statement, index))
        case SQLITE_FLOAT:
            let number = sqlite3_column_double(statement, index)
            return number == number.rounded() && abs(number) < 1e15
                ? String(format: "%.0f", number) : String(number)
        case SQLITE_BLOB:
            let bytes = sqlite3_column_bytes(statement, index)
            guard let pointer = sqlite3_column_blob(statement, index), bytes > 0 else { return "<empty>" }
            let blob = Data(bytes: pointer, count: Int(bytes))
            // Blob columns routinely hold whole plists — a message's attributed
            // body, a settings payload — and reading them is usually the point.
            if PlistReader.detect(blob), let plist = PlistReader.read(blob) {
                return "<\(bytes) bytes: \(plist.format)>\n" + plist.text
            }
            if let fields = ProtobufSnoop.decode(blob) {
                return "<\(bytes) bytes: protobuf>\n" + ProtobufSnoop.describe(fields).joined(separator: "\n")
            }
            return "<\(bytes) bytes> " + blob.prefix(16).map { String(format: "%02x", $0) }.joined()
        default:
            guard let text = sqlite3_column_text(statement, index) else { return "" }
            return String(cString: text)
        }
    }

    /// Renders the database as readable text.
    public static func render(_ document: Document, rowsPerTable: Int = 200) -> String {
        var lines: [String] = []
        var summary = "SQLite database · \(document.tables.count) table"
            + (document.tables.count == 1 ? "" : "s")
            + " · \(Format.count(document.totalRows)) rows"
        if document.pageSize > 0 { summary += " · \(document.pageSize)-byte pages" }
        lines.append(summary)
        if let problem = document.problem { lines.append("⚠︎ \(problem)") }
        lines.append("")

        for table in document.tables {
            lines.append("── \(table.name) · \(Format.count(table.rowCount)) rows · \(table.columns.count) columns")
            guard !table.rows.isEmpty else {
                lines.append("  (empty)")
                lines.append("")
                continue
            }
            for (index, row) in table.rows.prefix(rowsPerTable).enumerated() {
                lines.append("  [\(index + 1)]")
                for (column, cell) in zip(table.columns, row) where !cell.isEmpty {
                    // Multi-line cells — an unpacked plist, say — stay indented
                    // under their column rather than breaking the layout.
                    let pieces = cell.split(separator: "\n", omittingEmptySubsequences: false)
                    lines.append("    \(column): \(pieces[0])")
                    lines.append(contentsOf: pieces.dropFirst().map { "      \($0)" })
                }
            }
            if table.clipped {
                lines.append("  … \(Format.count(table.rowCount - table.rows.count)) further rows not shown")
            }
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }
}
