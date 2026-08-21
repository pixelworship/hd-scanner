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
    /// How long to wait for Spotlight before giving up on it.
    ///
    /// `MDQueryExecute` with `kMDQuerySynchronous` blocks with no deadline of
    /// its own, and Spotlight is not always answering: it reindexes after a
    /// system update, it can be disabled, and it can simply be busy. A wait
    /// with no limit meant the transfer that triggered the lookup was never
    /// reported at all — the copy to the USB stick just silently did not
    /// appear. Late attribution is worth having; a lost event is not.
    public var timeout: TimeInterval = 2.0
    /// Counts lookups abandoned on the deadline, so this is visible rather than
    /// merely quiet.
    public private(set) var timeouts = 0
    /// After a timeout, how long to stop asking. A stuck index answers no
    /// faster for the hundredth file than it did for the first, and a burst of
    /// copies would otherwise wait out the deadline once per file.
    public var backoff: TimeInterval = 15
    private var unavailableUntil: Date?

    private let queryQueue = DispatchQueue(label: "co.pixelworship.hdwatcher.spotlight",
                                           qos: .utility, attributes: .concurrent)

    public init() {}

    public var isAvailable: Bool {
        // Spotlight is present unless indexing has been disabled entirely.
        MDQueryCreate(kCFAllocatorDefault, "kMDItemFSName == \"*\"" as CFString, nil, nil) != nil
    }

    /// Looks for files with this name, giving up if Spotlight does not answer.
    public func findByName(_ name: String, limit: Int = 25) -> [Candidate] {
        guard !name.isEmpty else { return [] }

        mutex.lock()
        if let missed = negativeCache[name], Date().timeIntervalSince(missed) < negativeTTL {
            mutex.unlock()
            return []
        }
        if let until = unavailableUntil, until > Date() {
            mutex.unlock()
            return []
        }
        mutex.unlock()

        // The query runs where it can be abandoned. Anything still running when
        // the deadline passes finishes into a result nobody reads.
        let box = ResultBox()
        let done = DispatchSemaphore(value: 0)
        queryQueue.async { [weak self] in
            guard let self else { done.signal(); return }
            box.store(self.query(name: name, limit: limit))
            done.signal()
        }
        guard done.wait(timeout: .now() + timeout) == .success else {
            mutex.lock()
            timeouts += 1
            unavailableUntil = Date().addingTimeInterval(backoff)
            mutex.unlock()
            return []
        }
        let found = box.take()
        if found.isEmpty {
            mutex.lock(); negativeCache[name] = Date(); mutex.unlock()
        }
        return found
    }

    private func query(name: String, limit: Int) -> [Candidate] {

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

        mutex.lock()
        if negativeCache.count > 4_000 {
            let cutoff = Date().addingTimeInterval(-negativeTTL)
            negativeCache = negativeCache.filter { $0.value > cutoff }
        }
        mutex.unlock()
        return results
    }

    /// Carries a result between the query's thread and the caller waiting on
    /// the deadline.
    private final class ResultBox: @unchecked Sendable {
        private let lock = NSLock()
        private var value: [Candidate] = []
        func store(_ candidates: [Candidate]) { lock.lock(); value = candidates; lock.unlock() }
        func take() -> [Candidate] { lock.lock(); defer { lock.unlock() }; return value }
    }

    public func clearCache() {
        mutex.lock(); defer { mutex.unlock() }
        negativeCache.removeAll()
        unavailableUntil = nil
    }

    /// True while lookups are being skipped because Spotlight stopped
    /// answering. Attribution is degraded; transfers are still reported.
    public var isBackedOff: Bool {
        mutex.lock(); defer { mutex.unlock() }
        return (unavailableUntil ?? .distantPast) > Date()
    }
}
