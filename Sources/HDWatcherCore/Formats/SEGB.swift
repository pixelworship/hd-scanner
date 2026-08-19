import Foundation

/// Reader for Apple's SEGB record files.
///
/// Everything under `~/Library/Biome/streams` is stored this way: a segmented
/// log of timestamped records, each holding a protobuf payload. Recovery kept
/// showing these as an unreadable 131 KB blob even though they are among the
/// most interesting files on the disk — they record which apps ran, what was
/// played, which devices connected.
///
/// Two layouts exist, and they are back to front from each other. In v1 the
/// magic sits at the *end* of the file header and each record carries its own
/// header; in v2 the magic leads, and the record metadata lives in a trailer at
/// the end of the file. The structure follows CCL Forensics' `ccl_segb`, which
/// documents the format from the file bytes rather than from any Apple source.
public enum SEGB {

    public enum Version: String, Sendable {
        case v1 = "SEGB v1"
        case v2 = "SEGB v2"
    }

    public enum EntryState: Int, Sendable {
        case written = 1
        case deleted = 3
        case unused = 4
        case unknown = 0

        public var displayName: String {
            switch self {
            case .written: return "Written"
            case .deleted: return "Deleted"
            case .unused:  return "Empty"
            case .unknown: return "Unknown"
            }
        }
    }

    public struct Record: Identifiable, Sendable {
        public let id: Int
        public let offset: Int
        public let timestamp: Date?
        /// v1 records carry a second timestamp; v2 records do not.
        public let secondaryTimestamp: Date?
        public let state: EntryState
        public let storedCRC: UInt32
        public let computedCRC: UInt32
        public let data: Data

        public var crcPassed: Bool { storedCRC == computedCRC }
    }

    public struct Document: Sendable {
        public let version: Version
        public let created: Date?
        public let records: [Record]
        /// True when the record budget stopped the parse early.
        public let truncated: Bool
        /// Set when the file is SEGB but something in it did not add up. The
        /// records read before that point are still returned: a partially
        /// readable log beats none at all.
        public let problem: String?

        public var writtenCount: Int { records.filter { $0.state == .written }.count }
        public var deletedCount: Int { records.filter { $0.state == .deleted }.count }
        public var failedCRCCount: Int { records.filter { !$0.crcPassed && $0.state == .written }.count }
    }

    private static let magic = Data("SEGB".utf8)
    private static let v1HeaderLength = 56
    private static let v1RecordHeaderLength = 32
    private static let v2HeaderLength = 32
    private static let v2EntryHeaderLength = 8
    private static let v2TrailerEntryLength = 16

    // MARK: - Detection

    public static func detect(_ data: Data) -> Version? {
        if data.count >= v2HeaderLength, data.prefix(4) == magic { return .v2 }
        if data.count >= v1HeaderLength,
           data.subdata(in: (v1HeaderLength - 4)..<v1HeaderLength) == magic { return .v1 }
        return nil
    }

    // MARK: - Parsing

    public static func parse(_ data: Data, maxRecords: Int = 20_000) -> Document? {
        switch detect(data) {
        case .v1: return parseV1(data, maxRecords: maxRecords)
        case .v2: return parseV2(data, maxRecords: maxRecords)
        case nil: return nil
        }
    }

    private static func parseV1(_ data: Data, maxRecords: Int) -> Document {
        let bytes = [UInt8](data)
        let endOfData = Int(read32(bytes, 0))
        var cursor = v1HeaderLength
        var records: [Record] = []
        var problem: String?
        var truncated = false

        // The header's end-of-data offset is the only thing bounding the record
        // walk, and it comes from the file itself, so it is clamped.
        let limit = min(endOfData, bytes.count)

        while cursor + v1RecordHeaderLength <= limit {
            if records.count >= maxRecords { truncated = true; break }

            let length = Int(Int32(bitPattern: read32(bytes, cursor)))
            let stateRaw = Int(Int32(bitPattern: read32(bytes, cursor + 4)))
            let first = readDouble(bytes, cursor + 8)
            let second = readDouble(bytes, cursor + 16)
            let crc = read32(bytes, cursor + 24)
            let dataStart = cursor + v1RecordHeaderLength

            guard length >= 0, dataStart + length <= bytes.count else {
                problem = "Record \(records.count + 1) claims \(length) bytes, which runs past the end of the file."
                break
            }

            let payload = Data(bytes[dataStart..<(dataStart + length)])
            records.append(Record(id: records.count,
                                  offset: dataStart,
                                  timestamp: cocoaDate(first),
                                  secondaryTimestamp: cocoaDate(second),
                                  state: EntryState(rawValue: stateRaw) ?? .unknown,
                                  storedCRC: crc,
                                  computedCRC: CRC32.checksum(payload),
                                  data: payload))

            cursor = dataStart + length
            // Records are padded out to an eight-byte boundary.
            if cursor % 8 != 0 { cursor += 8 - (cursor % 8) }
        }

        return Document(version: .v1, created: nil, records: records,
                        truncated: truncated, problem: problem)
    }

    private static func parseV2(_ data: Data, maxRecords: Int) -> Document {
        let bytes = [UInt8](data)
        let entryCount = Int(Int32(bitPattern: read32(bytes, 4)))
        let created = cocoaDate(readDouble(bytes, 8))

        guard entryCount > 0 else {
            return Document(version: .v2, created: created, records: [],
                            truncated: false, problem: nil)
        }

        let trailerLength = entryCount * v2TrailerEntryLength
        guard trailerLength > 0, trailerLength <= bytes.count - v2HeaderLength else {
            return Document(version: .v2, created: created, records: [], truncated: false,
                            problem: "The trailer claims \(entryCount) records, which does not fit in \(bytes.count) bytes.")
        }

        struct Meta {
            let endOffset: Int
            let state: EntryState
            let timestamp: Date?
        }

        var metas: [Meta] = []
        let trailerStart = bytes.count - trailerLength
        for index in 0..<entryCount {
            let base = trailerStart + index * v2TrailerEntryLength
            let endOffset = Int(Int32(bitPattern: read32(bytes, base)))
            let stateRaw = Int(Int32(bitPattern: read32(bytes, base + 4)))
            let timestamp = cocoaDate(readDouble(bytes, base + 8))
            guard let state = EntryState(rawValue: stateRaw), state != .unknown else { continue }
            metas.append(Meta(endOffset: endOffset, state: state, timestamp: timestamp))
        }
        metas.sort { $0.endOffset < $1.endOffset }

        var records: [Record] = []
        var cursor = v2HeaderLength
        var problem: String?
        var truncated = false
        var previousEnd = -1

        for meta in metas {
            if records.count >= maxRecords { truncated = true; break }
            // State 4 slots are reserved space that was never written.
            if meta.state == .unused { continue }

            // Two trailer slots can point at one region — a record written and
            // later marked deleted. The bytes have already been read.
            if meta.endOffset == previousEnd, var last = records.last {
                last = Record(id: records.count, offset: last.offset,
                              timestamp: meta.timestamp, secondaryTimestamp: nil,
                              state: meta.state, storedCRC: last.storedCRC,
                              computedCRC: last.computedCRC, data: last.data)
                records.append(last)
                continue
            }

            let entryLength = meta.endOffset - cursor + v2HeaderLength
            // A stale slot can point inside a region a newer record has already
            // claimed; its own bytes are gone.
            guard entryLength >= v2EntryHeaderLength else { continue }
            guard cursor + entryLength <= trailerStart else {
                problem = "Record \(records.count + 1) ends at \(meta.endOffset), past the start of the trailer."
                break
            }

            let payloadStart = cursor + v2EntryHeaderLength
            let payload = Data(bytes[payloadStart..<(cursor + entryLength)])
            records.append(Record(id: records.count,
                                  offset: payloadStart,
                                  timestamp: meta.timestamp,
                                  secondaryTimestamp: nil,
                                  state: meta.state,
                                  storedCRC: read32(bytes, cursor),
                                  computedCRC: CRC32.checksum(payload),
                                  data: payload))

            previousEnd = meta.endOffset
            cursor += entryLength
            // Four-byte alignment, measured from the record's end offset.
            if meta.endOffset % 4 != 0 { cursor += 4 - (meta.endOffset % 4) }
        }

        return Document(version: .v2, created: created, records: records,
                        truncated: truncated, problem: problem)
    }

    // MARK: - Rendering

    /// Renders a document as readable text: one block per record, with the
    /// protobuf payload decoded where it can be.
    public static func render(_ document: Document, maxRecords: Int = 4_000) -> String {
        var lines: [String] = []
        var summary = "\(document.version.rawValue) · \(document.records.count) record"
            + (document.records.count == 1 ? "" : "s")
        if let created = document.created {
            summary += " · created \(timestampFormatter.string(from: created))"
        }
        if document.deletedCount > 0 { summary += " · \(document.deletedCount) deleted" }
        if document.failedCRCCount > 0 { summary += " · \(document.failedCRCCount) failed CRC" }
        lines.append(summary)
        if let problem = document.problem { lines.append("⚠︎ \(problem)") }
        lines.append("")

        for record in document.records.prefix(maxRecords) {
            var heading = "── #\(record.id + 1)"
            if let timestamp = record.timestamp {
                heading += " · \(timestampFormatter.string(from: timestamp))"
            }
            heading += " · \(record.state.displayName) · \(record.data.count) bytes"
            if record.state == .written && !record.crcPassed { heading += " · CRC MISMATCH" }
            lines.append(heading)

            if record.data.isEmpty {
                lines.append("  (empty)")
            } else if let fields = ProtobufSnoop.decode(record.data) {
                lines.append(contentsOf: ProtobufSnoop.describe(fields, indent: 1))
            } else {
                // Not protobuf: fall back to whatever text is in there.
                let runs = BinaryText.runs(in: record.data, limit: 200)
                if runs.isEmpty {
                    lines.append("  <\(record.data.count) bytes, no readable content>")
                } else {
                    lines.append(contentsOf: runs.map { "  \($0.text)" })
                }
            }
            lines.append("")
        }

        if document.records.count > maxRecords {
            lines.append("… \(document.records.count - maxRecords) further records not shown")
        }
        if document.truncated {
            lines.append("… the file holds more records than the reader will walk in one pass")
        }
        return lines.joined(separator: "\n")
    }

    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return formatter
    }()

    // MARK: - Byte helpers

    private static func read32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= bytes.count else { return 0 }
        return UInt32(bytes[offset])
            | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16
            | UInt32(bytes[offset + 3]) << 24
    }

    private static func readDouble(_ bytes: [UInt8], _ offset: Int) -> Double {
        guard offset >= 0, offset + 8 <= bytes.count else { return 0 }
        var raw: UInt64 = 0
        for index in 0..<8 { raw |= UInt64(bytes[offset + index]) << (8 * UInt64(index)) }
        return Double(bitPattern: raw)
    }

    /// Seconds since 2001-01-01, Apple's reference date.
    private static func cocoaDate(_ seconds: Double) -> Date? {
        guard seconds.isFinite, seconds > 0, seconds < 4_000_000_000 else { return nil }
        return Date(timeIntervalSinceReferenceDate: seconds)
    }
}

/// CRC-32 as zlib computes it, which is what SEGB records store.
public enum CRC32 {
    private static let table: [UInt32] = (0..<256).map { index -> UInt32 in
        var value = UInt32(index)
        for _ in 0..<8 {
            value = (value & 1) == 1 ? (value >> 1) ^ 0xEDB8_8320 : value >> 1
        }
        return value
    }

    public static func checksum(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc = (crc >> 8) ^ table[Int((crc ^ UInt32(byte)) & 0xFF)]
        }
        return crc ^ 0xFFFF_FFFF
    }
}
