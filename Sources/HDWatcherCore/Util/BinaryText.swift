import Foundation

/// Pulls the readable text out of binary content.
///
/// A hex dump shows the same bytes but chops every string into 16-character
/// fragments spread down the right-hand column, which makes an address, a phone
/// number or a filename almost impossible to read. Databases, plists and
/// protobuf payloads are mostly structure wrapped around exactly that sort of
/// readable field, and reading it is usually the whole reason for opening the
/// file.
///
/// This is the same idea as `strings(1)`: runs of printable characters, long
/// enough not to be noise.
public enum BinaryText {

    public struct Run: Identifiable, Sendable, Hashable {
        public var id: Int { offset }
        /// Byte offset in the file, so a finding can still be located exactly.
        public let offset: Int
        public let text: String
    }

    /// Default minimum length. Shorter runs are mostly coincidental byte
    /// sequences rather than real text.
    public static let defaultMinimumLength = 4

    /// Extracts printable runs, in file order.
    ///
    /// Both ASCII and UTF-16 are scanned: macOS binary plists and Core Data
    /// stores frequently hold UTF-16, which an ASCII-only pass renders as text
    /// separated by NUL bytes and therefore misses entirely.
    public static func runs(in data: Data,
                            minimumLength: Int = defaultMinimumLength,
                            limit: Int = 20_000) -> [Run] {
        var result: [Run] = []
        var current: [UInt8] = []
        var start = 0

        func flush(end: Int) {
            if current.count >= minimumLength,
               let text = String(bytes: current, encoding: .utf8) {
                result.append(Run(offset: start, text: text))
            }
            current.removeAll(keepingCapacity: true)
        }

        for (index, byte) in data.enumerated() {
            if result.count >= limit { break }
            if isPrintable(byte) {
                if current.isEmpty { start = index }
                current.append(byte)
            } else {
                flush(end: index)
            }
        }
        flush(end: data.count)

        // A second pass for UTF-16: printable bytes separated by single NULs.
        if result.count < limit {
            result.append(contentsOf: wideRuns(in: data,
                                               minimumLength: minimumLength,
                                               limit: limit - result.count))
            result.sort { $0.offset < $1.offset }
        }
        return result
    }

    /// UTF-16 text stored little-endian shows up as `T\0e\0x\0t\0`.
    private static func wideRuns(in data: Data, minimumLength: Int, limit: Int) -> [Run] {
        var result: [Run] = []
        var current: [UInt8] = []
        var start = 0
        let bytes = [UInt8](data)
        var index = 0

        while index + 1 < bytes.count {
            if result.count >= limit { break }
            let low = bytes[index]
            let high = bytes[index + 1]
            if isPrintable(low), high == 0 {
                if current.isEmpty { start = index }
                current.append(low)
                index += 2
                continue
            }
            if current.count >= minimumLength,
               let text = String(bytes: current, encoding: .utf8) {
                result.append(Run(offset: start, text: text))
            }
            current.removeAll(keepingCapacity: true)
            index += 1
        }
        if current.count >= minimumLength,
           let text = String(bytes: current, encoding: .utf8) {
            result.append(Run(offset: start, text: text))
        }
        return result
    }

    private static func isPrintable(_ byte: UInt8) -> Bool {
        // Printable ASCII, plus tab. Newlines end a run so each line stands alone.
        (byte >= 0x20 && byte < 0x7F) || byte == 0x09
    }

    // MARK: - Whole-file view

    public struct RawLine: Identifiable, Sendable, Hashable {
        public var id: Int { offset }
        public let offset: Int
        public let text: String
    }

    /// Every byte, decoded as text.
    ///
    /// Extracting runs answers "what strings are in here"; it deliberately
    /// throws away everything between them. Sometimes the question is instead
    /// "show me the file the way a text editor would", and the answer has to
    /// include the parts that are not really text — which is what opening a
    /// copy in TextEdit shows, and what this reproduces without writing the
    /// contents to disk.
    ///
    /// Latin-1 is used because it is the one encoding where every byte maps to
    /// a character, so nothing is silently dropped. Control bytes would
    /// otherwise be invisible, so they are shown as `·`.
    public static func rawLines(of data: Data,
                                width: Int = 128,
                                limit: Int = 40_000) -> (lines: [RawLine], truncated: Bool) {
        var lines: [RawLine] = []
        var current = ""
        current.reserveCapacity(width)
        var start = 0
        var index = 0
        var truncated = false

        for byte in data {
            if lines.count >= limit { truncated = true; break }
            if byte == 0x0A {
                lines.append(RawLine(offset: start, text: current))
                current.removeAll(keepingCapacity: true)
                start = index + 1
            } else if byte == 0x0D {
                // Part of a CRLF pair, or a lone classic-Mac line ending.
                if current.isEmpty && start == index { start = index + 1 } else {
                    lines.append(RawLine(offset: start, text: current))
                    current.removeAll(keepingCapacity: true)
                    start = index + 1
                }
            } else {
                current.append(displayCharacter(byte))
                if current.count >= width {
                    lines.append(RawLine(offset: start, text: current))
                    current.removeAll(keepingCapacity: true)
                    start = index + 1
                }
            }
            index += 1
        }
        if !current.isEmpty { lines.append(RawLine(offset: start, text: current)) }
        return (lines, truncated)
    }

    private static func displayCharacter(_ byte: UInt8) -> Character {
        if byte == 0x09 { return "\t" }
        if byte < 0x20 || byte == 0x7F { return "·" }
        return Character(UnicodeScalar(byte))
    }

    /// The readable runs as one block of text, for diffing.
    public static func plainText(in data: Data, minimumLength: Int = defaultMinimumLength) -> String {
        runs(in: data, minimumLength: minimumLength).map(\.text).joined(separator: "\n")
    }

    /// Proportion of the content that is readable text, for deciding whether to
    /// open in text or hex.
    public static func readableFraction(of data: Data, minimumLength: Int = defaultMinimumLength) -> Double {
        guard !data.isEmpty else { return 0 }
        let extracted = runs(in: data, minimumLength: minimumLength)
            .reduce(0) { $0 + $1.text.utf8.count }
        return Double(extracted) / Double(data.count)
    }
}
