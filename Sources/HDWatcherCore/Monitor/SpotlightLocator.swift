import Foundation
import CoreServices

/// Finds a probable source file for content that appeared on another volume.
///
/// The in-memory correlation index only knows about files HDWatcher has seen an
/// event for. Copying a file *reads* the source, and FSEvents never reports
/// reads — so a copy from the internal disk to a USB stick leaves no trace of
/// where it came from. Spotlight already indexes the internal disk by name, so
/// asking it is both accurate and fast, and it closes exactly that gap.
public final class SpotlightLocator: @unchecked Sendable {

    public struct Candidate: Sendable {
        public let path: String
        public let size: Int64
        public let modified: Date?
    }

    private let mutex = NSLock()
    /// Basenames that returned nothing recently, so a burst of unmatched files
    /// does not re-query for each one.
    private var negativeCache: [String: Date] = [:]
    private let negativeTTL: TimeInterval = 120

    public init() {}

    public var isAvailable: Bool {
        // Spotlight is present unless indexing has been disabled entirely.
        MDQueryCreate(kCFAllocatorDefault, "kMDItemFSName == \"*\"" as CFString, nil, nil) != nil
    }

    /// Looks for files with this name, ignoring anything under `excludingPaths`.
    public func findByName(_ name: String, limit: Int = 25) -> [Candidate] {
        guard !name.isEmpty else { return [] }

        mutex.lock()
        if let missed = negativeCache[name], Date().timeIntervalSince(missed) < negativeTTL {
            mutex.unlock()
            return []
        }
        mutex.unlock()

        // Spotlight query syntax is its own language; quotes and backslashes in
        // a filename would otherwise break out of the string literal.
        let escaped = name
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let expression = "kMDItemFSName == \"\(escaped)\"" as CFString

        guard let query = MDQueryCreate(kCFAllocatorDefault, expression, nil, nil) else { return [] }
        MDQuerySetMaxCount(query, limit)
        guard MDQueryExecute(query, CFOptionFlags(kMDQuerySynchronous.rawValue)) else {
            return []
        }

        var results: [Candidate] = []
        let count = MDQueryGetResultCount(query)
        for index in 0..<count {
            guard let raw = MDQueryGetResultAtIndex(query, index) else { continue }
            let item = unsafeBitCast(raw, to: MDItem.self)
            guard let path = MDItemCopyAttribute(item, kMDItemPath) as? String else { continue }

            // Trust the filesystem over the index: Spotlight metadata can lag
            // behind a file that was just written.
            var info = stat()
            guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { continue }
            let modified = MDItemCopyAttribute(item, kMDItemContentModificationDate) as? Date
            results.append(Candidate(path: path, size: Int64(info.st_size), modified: modified))
        }

        if results.isEmpty {
            mutex.lock()
            negativeCache[name] = Date()
            if negativeCache.count > 4_000 {
                let cutoff = Date().addingTimeInterval(-negativeTTL)
                negativeCache = negativeCache.filter { $0.value > cutoff }
            }
            mutex.unlock()
        }
        return results
    }

    public func clearCache() {
        mutex.lock(); defer { mutex.unlock() }
        negativeCache.removeAll()
    }
}
