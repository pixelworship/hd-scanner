import Foundation

/// Builds the question to ask an outside model about a captured file.
///
/// Recovery can say what a file is made of but not what it *means*: a Biome
/// stream full of bundle identifiers and reference dates is readable and still
/// opaque. Handing the evidence to a general model closes that gap.
///
/// Everything here is assembled locally and shown to the user before it goes
/// anywhere. The budget is not only about URL limits — the less of a captured
/// file that leaves the machine, the better, and the head of a file plus its
/// readable strings is nearly always enough to identify it.
public enum AnalysisPrompt {

    public struct Payload: Sendable {
        public let text: String
        /// True when the contents were cut to fit the budget.
        public let truncated: Bool
        /// What the user is about to disclose, in bytes of the original file.
        public let includedBytes: Int
    }

    public static let defaultBudget = 12_000

    public static func describe(snapshot: FileSnapshot,
                                data: Data,
                                kind: PreviewKind,
                                budget: Int = defaultBudget) -> Payload {
        var lines: [String] = [
            "I am looking at a file captured by a filesystem monitor and I want to know what it is and what is stored inside it.",
            "",
            "Path: \(snapshot.path)",
            "Name: \(snapshot.fileName)",
            "Size: \(snapshot.byteSize) bytes",
            "Captured: \(ISO8601DateFormatter().string(from: snapshot.capturedAt)) (\(snapshot.reason.displayName), version \(snapshot.generation))",
        ]
        if snapshot.isDeleted { lines.append("This version was captured because the file was deleted.") }
        lines.append("Detected type: \(typeDescription(data: data, kind: kind))")
        lines.append("")

        let (body, truncated, used) = contents(data: data, kind: kind, budget: budget)
        lines.append("Contents:")
        lines.append("```")
        lines.append(body)
        if truncated { lines.append("… truncated; the file is larger than what is shown here.") }
        lines.append("```")
        lines.append("")
        lines.append("Please explain: what this file is and which program writes it, what the records or fields mean, and anything notable in the values above. If the format is documented or has known parsers, say which.")

        return Payload(text: lines.joined(separator: "\n"), truncated: truncated, includedBytes: used)
    }

    private static func typeDescription(data: Data, kind: PreviewKind) -> String {
        if let version = SEGB.detect(data) {
            return "Apple \(version.rawValue) record file (as found under ~/Library/Biome)"
        }
        return kind.displayName
    }

    /// Picks the most informative representation the format allows, rather than
    /// sending raw bytes for everything.
    private static func contents(data: Data, kind: PreviewKind, budget: Int) -> (String, Bool, Int) {
        if let document = SEGB.parse(data) {
            let rendered = SEGB.render(document, maxRecords: 60)
            return clip(rendered, budget: budget, source: data.count)
        }
        if kind == .text, let text = String(data: data, encoding: .utf8) {
            return clip(text, budget: budget, source: data.count)
        }
        let strings = BinaryText.runs(in: data, limit: 2_000)
        if !strings.isEmpty {
            let rendered = strings.map { "\(String(format: "%08x", $0.offset))  \($0.text)" }
                .joined(separator: "\n")
            return clip("Readable strings extracted from the binary:\n" + rendered,
                        budget: budget, source: data.count)
        }
        let hex = data.prefix(1_024).map { String(format: "%02x", $0) }.joined()
        return ("First \(min(1_024, data.count)) bytes, hex:\n" + hex,
                data.count > 1_024, min(1_024, data.count))
    }

    private static func clip(_ text: String, budget: Int, source: Int) -> (String, Bool, Int) {
        guard text.count > budget else { return (text, false, source) }
        let clipped = String(text.prefix(budget))
        // Rough, but honest about the order of magnitude being disclosed.
        return (clipped, true, min(source, budget))
    }

    /// A ChatGPT URL that arrives with the question already in the box.
    ///
    /// The prompt travels in the query string, so this only works while it is
    /// short; past that the caller should put it on the clipboard instead. The
    /// cutoff is deliberately conservative — a URL that silently loses its tail
    /// would send a truncated file with no sign that anything was missing.
    public static let urlLengthLimit = 6_000

    public static func chatGPTURL(for prompt: String) -> URL? {
        guard prompt.count <= urlLengthLimit else { return nil }
        var components = URLComponents(string: "https://chatgpt.com/")
        components?.queryItems = [URLQueryItem(name: "q", value: prompt)]
        return components?.url
    }
}
