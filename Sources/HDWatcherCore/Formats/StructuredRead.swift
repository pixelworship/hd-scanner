import Foundation

/// One entry point for "read this file properly".
///
/// Recovery holds whatever the disk held, and the formats that matter are the
/// ones everything else stores data in: SQLite databases, property lists and
/// keyed archives, JSON, gzipped logs, protobuf payloads, Apple's SEGB record
/// streams. Each of those is unreadable as bytes and obvious once parsed.
///
/// Every part of the app that looks inside a file goes through here — the
/// preview, the parsed window, content search, and the question sent to an
/// outside model — so a format learned once is understood everywhere.
public enum StructuredRead {

    public enum Format: String, Sendable {
        case records = "Records"
        case database = "Database"
        case plist = "Property list"
        case keyedArchive = "Keyed archive"
        case json = "JSON"
        case protobuf = "Protobuf"

        public var symbolName: String {
            switch self {
            case .records:      return "list.bullet.rectangle"
            case .database:     return "tablecells"
            case .plist:        return "list.bullet.indent"
            case .keyedArchive: return "shippingbox"
            case .json:         return "curlybraces"
            case .protobuf:     return "chevron.left.forwardslash.chevron.right"
            }
        }
    }

    public struct Reading: Sendable {
        public let format: Format
        /// What this particular file is, e.g. "SQLite database · 14 tables".
        public let title: String
        public let text: String
        /// Set when the content had to be decompressed first.
        public let decompressed: Bool
    }

    /// Reads the content, or returns nil when nothing here understands it.
    ///
    /// The path is only used to name Biome streams, whose files are named by
    /// number and say nothing about themselves.
    public static func read(_ data: Data, path: String = "",
                            decompressed: Bool = false) -> Reading? {
        guard !data.isEmpty else { return nil }

        if let document = SEGB.parse(data) {
            let stream = BiomeSchema.stream(forFilePath: path)
            return Reading(format: .records,
                           title: stream.map { "\(document.version.rawValue) · \($0.title)" }
                                ?? "\(document.version.rawValue) · \(document.records.count) records",
                           text: SEGB.render(document, stream: stream),
                           decompressed: decompressed)
        }

        if SQLiteReader.detect(data) {
            guard let database = SQLiteReader.read(data) else { return nil }
            return Reading(format: .database,
                           title: "SQLite · \(database.tables.count) tables · \(HDWatcherCore.Format.count(database.totalRows)) rows",
                           text: SQLiteReader.render(database),
                           decompressed: decompressed)
        }

        if PlistReader.detect(data), let plist = PlistReader.read(data) {
            return Reading(format: plist.isKeyedArchive ? .keyedArchive : .plist,
                           title: plist.format,
                           text: plist.text,
                           decompressed: decompressed)
        }

        if JSONReader.detect(data), let json = JSONReader.read(data) {
            return Reading(format: .json, title: "JSON", text: json, decompressed: decompressed)
        }

        // Compressed content is opaque to every other reading, and what is
        // inside is usually one of the formats above.
        if !decompressed, Gunzip.detect(data), let expanded = Gunzip.inflate(data) {
            if let inner = read(expanded, path: path, decompressed: true) {
                return Reading(format: inner.format,
                               title: "gzip → \(inner.title)",
                               text: inner.text,
                               decompressed: true)
            }
            if let text = String(data: expanded, encoding: .utf8) {
                return Reading(format: .json, title: "gzip → text",
                               text: text, decompressed: true)
            }
        }

        // A bare protobuf payload, which is what a great many Apple caches and
        // preference blobs are. Small buffers decode as protobuf by accident,
        // so this needs enough substance to be believable.
        if data.count >= 32, let fields = ProtobufSnoop.decode(data), fields.count >= 2 {
            return Reading(format: .protobuf,
                           title: "Protobuf · \(fields.count) fields",
                           text: ProtobufSnoop.describe(fields).joined(separator: "\n"),
                           decompressed: decompressed)
        }

        return nil
    }

    /// Cheap check for whether a structured reading exists, without doing the
    /// work of producing one.
    public static func canRead(_ data: Data) -> Bool {
        SEGB.detect(data) != nil || SQLiteReader.detect(data) || PlistReader.detect(data)
            || JSONReader.detect(data) || Gunzip.detect(data)
    }
}
