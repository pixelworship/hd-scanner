import Foundation

/// Reads property lists, including the keyed archives inside them.
///
/// Plists are the second most common thing on a Mac worth reading — after
/// databases — and the binary ones are unreadable in a hex or strings view:
/// the keys and values are there, but the structure that relates them is not.
///
/// Keyed archives get particular attention. `NSKeyedArchiver` flattens an
/// object graph into a table of objects plus integer references, so a decoded
/// archive shows a list of fragments and a lot of `CF$UID`s rather than the
/// thing that was archived. Following those references back is the difference
/// between a wall of numbers and a readable record.
public enum PlistReader {

    public struct Document: Sendable {
        public let format: String
        public let isKeyedArchive: Bool
        public let text: String
    }

    public static func detect(_ data: Data) -> Bool {
        if data.starts(with: Array("bplist00".utf8)) { return true }
        guard data.count > 40 else { return false }
        let head = String(decoding: data.prefix(512), as: UTF8.self)
        return head.contains("<!DOCTYPE plist") || head.contains("<plist")
    }

    public static func read(_ data: Data) -> Document? {
        // Without this guard the parser accepts almost anything as an OpenStep
        // text plist — 200 identical bytes come back as a valid "string".
        guard detect(data) else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.binary
        guard let object = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format) else { return nil }

        let name = format == .binary ? "Binary property list"
                 : format == .xml ? "XML property list" : "Property list"

        if let dictionary = object as? [String: Any],
           dictionary["$archiver"] != nil, let objects = dictionary["$objects"] as? [Any] {
            let top = dictionary["$top"] as? [String: Any] ?? [:]
            var lines: [String] = ["\(name) · NSKeyedArchiver · \(objects.count) objects"]
            for key in top.keys.sorted() {
                lines.append("\(key):")
                lines.append(contentsOf: describe(resolve(top[key], in: objects, depth: 0),
                                                  indent: 1))
            }
            return Document(format: name, isKeyedArchive: true,
                            text: lines.joined(separator: "\n"))
        }

        return Document(format: name, isKeyedArchive: false,
                        text: ([name, ""] + describe(object, indent: 0)).joined(separator: "\n"))
    }

    /// Replaces `CF$UID` references with the objects they point at.
    ///
    /// The graph can be cyclic — that is the point of a reference — so the
    /// depth limit is load-bearing, not a nicety.
    private static func resolve(_ value: Any?, in objects: [Any], depth: Int) -> Any? {
        guard depth < 12 else { return "…" }
        if let reference = uidValue(value) {
            guard reference >= 0, reference < objects.count else { return "<bad reference \(reference)>" }
            // $null is how the archiver spells "nothing here".
            if let text = objects[reference] as? String, text == "$null" { return nil }
            return resolve(objects[reference], in: objects, depth: depth + 1)
        }
        if let dictionary = value as? [String: Any] {
            var result: [String: Any] = [:]
            for (key, item) in dictionary where key != "$class" {
                if let resolved = resolve(item, in: objects, depth: depth + 1) { result[key] = resolved }
            }
            return result
        }
        if let array = value as? [Any] {
            return array.compactMap { resolve($0, in: objects, depth: depth + 1) }
        }
        return value
    }

    /// Reads the integer out of a `CFKeyedArchiverUID`.
    ///
    /// The type is private to CoreFoundation and unavailable to Swift, so its
    /// description — `<CFKeyedArchiverUID 0x…>{value = 3}` — is the only handle
    /// on it. Ugly, but the alternative is not reading keyed archives at all.
    private static func uidValue(_ value: Any?) -> Int? {
        guard let value else { return nil }
        let object = value as AnyObject
        // The type reports itself as __NSCFType, so the description is the
        // only handle: "<CFKeyedArchiverUID 0x…>{value = 3}".
        //
        // It has to be the whole description, not a substring of it: a
        // dictionary that *contains* a reference describes itself with the
        // reference's text inside, and matching that resolved every object to
        // its own class descriptor.
        let described = String(describing: object)
        guard described.hasPrefix("<CFKeyedArchiverUID"),
              let marker = described.range(of: "value = ") else { return nil }
        let digits = described[marker.upperBound...].prefix { $0.isNumber }
        return Int(digits)
    }

    /// Renders a plist value as indented text.
    private static func describe(_ value: Any?, indent: Int, key: String? = nil) -> [String] {
        let pad = String(repeating: "  ", count: indent)
        let prefix = key.map { "\($0): " } ?? ""

        switch value {
        case nil:
            return ["\(pad)\(prefix)(null)"]
        case let dictionary as [String: Any]:
            guard !dictionary.isEmpty else { return ["\(pad)\(prefix){}"] }
            var lines = ["\(pad)\(prefix){"]
            for innerKey in dictionary.keys.sorted() {
                lines.append(contentsOf: describe(dictionary[innerKey], indent: indent + 1, key: innerKey))
            }
            lines.append("\(pad)}")
            return lines
        case let array as [Any]:
            guard !array.isEmpty else { return ["\(pad)\(prefix)[]"] }
            var lines = ["\(pad)\(prefix)["]
            for (index, item) in array.prefix(500).enumerated() {
                lines.append(contentsOf: describe(item, indent: indent + 1, key: "\(index)"))
            }
            if array.count > 500 { lines.append("\(pad)  … \(array.count - 500) more") }
            lines.append("\(pad)]")
            return lines
        case let date as Date:
            return ["\(pad)\(prefix)\(Self.stamp.string(from: date))"]
        case let data as Data:
            // Nested plists inside plists are routine — a data blob that is
            // itself a plist is worth opening rather than showing as bytes.
            if detect(data), let nested = read(data) {
                var lines = ["\(pad)\(prefix)<\(data.count) bytes: \(nested.format)>"]
                lines.append(contentsOf: nested.text.split(separator: "\n", omittingEmptySubsequences: false)
                    .map { "\(pad)  \($0)" })
                return lines
            }
            let preview = data.prefix(24).map { String(format: "%02x", $0) }.joined()
            return ["\(pad)\(prefix)<\(data.count) bytes> \(preview)"]
        case let number as NSNumber:
            return ["\(pad)\(prefix)\(number)"]
        case let text as String:
            return ["\(pad)\(prefix)\(text)"]
        default:
            return ["\(pad)\(prefix)\(String(describing: value ?? ""))"]
        }
    }

    private static let stamp: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()
}
