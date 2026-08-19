import Foundation

/// What the numbered fields inside a Biome record actually mean.
///
/// Protobuf's wire format carries field *numbers*, never names, and Apple does
/// not publish the `.proto` files for any of this. So a decoded record reads
/// `6: "com.apple.mobilesafari"` — structurally correct and nearly useless.
///
/// The names below come from the Biome parsers in
/// [iLEAPP](https://github.com/abrignoni/iLEAPP) (MIT, Alexis Brignoni and
/// contributors), where the forensics community has worked them out stream by
/// stream by comparing many devices against known activity. That work is what
/// turns field 6 into "Bundle ID" and value 1 in field 3 into "Foreground".
public enum BiomeSchema {

    public enum FieldKind: String, Sendable {
        case text, integer, real, bytes
        /// Seconds since 2001-01-01, which is how Apple writes dates here.
        case appleTime
        case unknown
    }

    public struct Field: Sendable {
        /// Dotted field path, so a field inside a nested message can be named:
        /// "4.3" is field 3 of the message in field 4.
        public let path: String
        public let label: String
        public let kind: FieldKind
        /// What particular values mean, where that is known.
        public let values: [Int: String]

        public init(path: String, label: String, kind: FieldKind = .unknown,
                    values: [Int: String] = [:]) {
            self.path = path
            self.label = label
            self.kind = kind
            self.values = values
        }
    }

    public struct Stream: Sendable {
        public let name: String
        /// Readable name for the stream as a whole, e.g. "In Focus".
        public let title: String
        private let byPath: [String: Field]

        public init(name: String, title: String, fields: [Field]) {
            self.name = name
            self.title = title
            self.byPath = Dictionary(fields.map { ($0.path, $0) },
                                     uniquingKeysWith: { first, _ in first })
        }

        public func field(at path: String) -> Field? { byPath[path] }
        public var fieldCount: Int { byPath.count }
    }

    private static let byName: [String: Stream] =
        Dictionary(table.map { ($0.name, $0) }, uniquingKeysWith: { first, _ in first })

    public static var streamCount: Int { byName.count }

    public static func stream(named name: String) -> Stream? { byName[name] }

    /// Identifies the stream from where the file sits.
    ///
    /// Biome files are named by a numeric id, so the path is the only thing
    /// that says what they hold: `…/Biome/streams/restricted/App.InFocus/local/797…`
    public static func stream(forFilePath path: String) -> Stream? {
        let parts = path.split(separator: "/").map(String.init)
        guard let index = parts.lastIndex(of: "streams"), index + 2 < parts.count else { return nil }
        // The component after the zone (restricted/public) is the stream name.
        return byName[parts[index + 2]]
    }

    /// Renders a value the way its field means it, rather than as a number.
    public static func describe(_ value: Double, field: Field?) -> String? {
        guard let field else { return nil }
        if !field.values.isEmpty, value == value.rounded(),
           let meaning = field.values[Int(value)] {
            return meaning
        }
        if field.kind == .appleTime, value > 0, value < 4_000_000_000 {
            return timestamp.string(from: Date(timeIntervalSinceReferenceDate: value))
        }
        return nil
    }

    private static let timestamp: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()
}
