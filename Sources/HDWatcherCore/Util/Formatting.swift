import Foundation

public enum Format {
    private static let byteFormatter: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .file
        f.allowedUnits = [.useBytes, .useKB, .useMB, .useGB, .useTB]
        return f
    }()

    public static func bytes(_ value: Int64?) -> String {
        guard let value else { return "—" }
        return byteFormatter.string(fromByteCount: value)
    }

    private static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f
    }()

    public static func relativeTime(_ date: Date, now: Date = Date()) -> String {
        let delta = now.timeIntervalSince(date)
        if delta < 2 { return "now" }
        return relative.localizedString(for: date, relativeTo: now)
    }

    private static let clock: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    public static func timeOfDay(_ date: Date) -> String { clock.string(from: date) }

    private static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return f
    }()

    public static func fullTimestamp(_ date: Date) -> String { stamp.string(from: date) }

    /// Shortens a long path for display: /Users/me/Very/Deep/Tree/file.txt
    /// becomes /Users/me/…/Tree/file.txt
    public static func abbreviatePath(_ path: String, maxComponents: Int = 5) -> String {
        let parts = (path as NSString).pathComponents.filter { $0 != "/" }
        guard parts.count > maxComponents else { return path }
        let head = parts.prefix(2).joined(separator: "/")
        let tail = parts.suffix(maxComponents - 3).joined(separator: "/")
        return "/\(head)/…/\(tail)"
    }

    public static func count(_ n: Int) -> String {
        if n < 1000 { return "\(n)" }
        if n < 1_000_000 { return String(format: "%.1fK", Double(n) / 1000) }
        return String(format: "%.1fM", Double(n) / 1_000_000)
    }
}
