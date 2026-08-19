import Foundation

/// Schema-less protobuf reader.
///
/// The payload inside a Biome record — and inside a great many other Apple
/// files — is protobuf, and the `.proto` that describes it is not published.
/// The wire format is self-describing enough to walk without one: every field
/// carries its number and a wire type, so the structure and all the leaf values
/// can be recovered even though the field *names* cannot.
public enum ProtobufSnoop {

    public indirect enum Value: Sendable {
        case varint(UInt64)
        case fixed64(UInt64)
        case fixed32(UInt32)
        case text(String)
        case bytes(Data)
        case message([Field])
    }

    public struct Field: Sendable {
        public let number: Int
        public let value: Value
    }

    /// Decodes a buffer, returning nil when it is not valid protobuf.
    ///
    /// "Valid" is strict on purpose: the decode has to consume the whole buffer
    /// with every length prefix in bounds. Loose parsing would turn arbitrary
    /// binary into a plausible-looking tree of nonsense.
    public static func decode(_ data: Data, depth: Int = 0) -> [Field]? {
        guard !data.isEmpty, depth < 8 else { return nil }
        var fields: [Field] = []
        var cursor = data.startIndex

        while cursor < data.endIndex {
            guard let (tag, afterTag) = varint(data, from: cursor) else { return nil }
            let number = Int(tag >> 3)
            let wire = Int(tag & 0x07)
            guard number > 0 else { return nil }
            cursor = afterTag

            switch wire {
            case 0:
                guard let (value, next) = varint(data, from: cursor) else { return nil }
                fields.append(Field(number: number, value: .varint(value)))
                cursor = next

            case 1:
                guard cursor + 8 <= data.endIndex else { return nil }
                fields.append(Field(number: number, value: .fixed64(integer(data, at: cursor, bytes: 8))))
                cursor += 8

            case 2:
                guard let (length, afterLength) = varint(data, from: cursor),
                      length <= UInt64(Int.max) else { return nil }
                let size = Int(length)
                guard afterLength + size <= data.endIndex else { return nil }
                let payload = data[afterLength..<(afterLength + size)]
                fields.append(Field(number: number, value: classify(Data(payload), depth: depth)))
                cursor = afterLength + size

            case 5:
                guard cursor + 4 <= data.endIndex else { return nil }
                fields.append(Field(number: number, value: .fixed32(UInt32(integer(data, at: cursor, bytes: 4)))))
                cursor += 4

            // Groups (3, 4) were deprecated long before any of this was written,
            // and 6/7 are not wire types at all — either means this is not
            // protobuf.
            default:
                return nil
            }
        }
        return fields.isEmpty ? nil : fields
    }

    /// A length-delimited field is a nested message, a string, or opaque bytes,
    /// and the wire format does not say which. Nesting is tried first because a
    /// buffer that decodes cleanly as a message almost always is one.
    private static func classify(_ payload: Data, depth: Int) -> Value {
        if let nested = decode(payload, depth: depth + 1) { return .message(nested) }
        if let text = readableString(payload) { return .text(text) }
        return .bytes(payload)
    }

    private static func readableString(_ data: Data) -> String? {
        guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return nil }
        // A string of control characters decodes fine but is not text.
        let printable = text.unicodeScalars.filter { $0.value >= 0x20 || $0 == "\n" || $0 == "\t" }.count
        return printable == text.unicodeScalars.count ? text : nil
    }

    private static func varint(_ data: Data, from start: Data.Index) -> (UInt64, Data.Index)? {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        var cursor = start
        while cursor < data.endIndex {
            let byte = data[cursor]
            cursor += 1
            value |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return (value, cursor) }
            shift += 7
            if shift > 63 { return nil }
        }
        return nil
    }

    private static func integer(_ data: Data, at start: Data.Index, bytes count: Int) -> UInt64 {
        var value: UInt64 = 0
        for offset in 0..<count {
            value |= UInt64(data[start + offset]) << (8 * UInt64(offset))
        }
        return value
    }

    // MARK: - Rendering

    /// Renders the decoded tree as indented text.
    ///
    /// With a schema the field numbers gain names and the values gain meaning:
    /// `Action (3): 1 · Foreground` rather than `3: 1`. Without one the
    /// structure is still complete, just anonymous.
    public static func describe(_ fields: [Field], indent: Int = 0,
                                stream: BiomeSchema.Stream? = nil,
                                prefix: String = "") -> [String] {
        let pad = String(repeating: "  ", count: indent)
        var lines: [String] = []
        for field in fields {
            let path = prefix.isEmpty ? "\(field.number)" : "\(prefix).\(field.number)"
            let spec = stream?.field(at: path)
            let name = spec.map { "\($0.label) (\(field.number))" } ?? "\(field.number)"

            switch field.value {
            case .varint(let value):
                let meaning = BiomeSchema.describe(Double(value), field: spec)
                    .map { " · \($0)" } ?? timestampHint(seconds: Double(value), known: spec != nil)
                lines.append("\(pad)\(name): \(value)\(meaning)")
            case .fixed64(let raw):
                let double = Double(bitPattern: raw)
                let meaning = BiomeSchema.describe(double, field: spec)
                    .map { " · \($0)" } ?? timestampHint(seconds: double, known: spec != nil)
                lines.append("\(pad)\(name): \(formatted(double))\(meaning) (0x\(String(raw, radix: 16)))")
            case .fixed32(let raw):
                lines.append("\(pad)\(name): \(raw) (0x\(String(raw, radix: 16)))")
            case .text(let text):
                lines.append("\(pad)\(name): \"\(text)\"")
            case .bytes(let data):
                lines.append("\(pad)\(name): <\(data.count) bytes> \(data.prefix(24).map { String(format: "%02x", $0) }.joined())")
            case .message(let nested):
                lines.append("\(pad)\(name): {")
                lines.append(contentsOf: describe(nested, indent: indent + 1,
                                                  stream: stream, prefix: path))
                lines.append("\(pad)}")
            }
        }
        return lines
    }

    private static func formatted(_ value: Double) -> String {
        value == value.rounded() && abs(value) < 1e15
            ? String(format: "%.0f", value)
            : String(value)
    }

    /// Apple stores dates as seconds since 2001. Values in that range are
    /// almost always timestamps, and reading one as a date rather than a large
    /// number is usually the difference between a useful record and a blob.
    private static func timestampHint(seconds: Double, known: Bool = false) -> String {
        // A schema that says this field is not a date is better evidence than
        // the value happening to fall in the plausible range.
        guard !known else { return "" }
        guard seconds > 100_000_000, seconds < 4_000_000_000 else { return "" }
        let date = Date(timeIntervalSinceReferenceDate: seconds)
        return "  · \(Self.formatter.string(from: date))"
    }

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()
}
