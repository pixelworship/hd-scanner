import Foundation

/// Bookkeeping for one segment file. Stored encrypted so that the shape of the
/// log (when it was written, how much) is not visible without the vault key.
public struct SegmentRecord: Codable, Sendable, Identifiable, Hashable {
    public var id: UInt32 { segmentIndex }
    public var segmentIndex: UInt32
    public var fileName: String

    public var createdAt: Date
    public var blockCount: Int
    public var eventCount: Int
    public var firstEventAt: Date?
    public var lastEventAt: Date?
    /// Chain MAC after the last block. Verification recomputes this and
    /// compares, which catches truncation as well as rewriting.
    public var finalMAC: Data
    public var byteSize: Int64
    /// False while the segment is still the active write target.
    public var sealed: Bool

    /// Which writer produced this segment. Segment files are named
    /// `<lineage>-<index>-<epoch>.hdwseg`, and each writer keeps its own hash
    /// chain and its own index sequence — so verification has to follow one
    /// lineage at a time rather than treating every segment as one chain.
    public var lineage: String {
        fileName.split(separator: "-").first.map(String.init) ?? "seg"
    }

    public init(segmentIndex: UInt32, fileName: String, createdAt: Date = Date(),
                blockCount: Int = 0, eventCount: Int = 0,
                firstEventAt: Date? = nil, lastEventAt: Date? = nil,
                finalMAC: Data = Data(), byteSize: Int64 = 0, sealed: Bool = false) {
        self.segmentIndex = segmentIndex
        self.fileName = fileName
        self.createdAt = createdAt
        self.blockCount = blockCount
        self.eventCount = eventCount
        self.firstEventAt = firstEventAt
        self.lastEventAt = lastEventAt
        self.finalMAC = finalMAC
        self.byteSize = byteSize
        self.sealed = sealed
    }
}

public struct LogManifest: Codable, Sendable {
    public var segments: [SegmentRecord] = []
    public var totalEvents: Int = 0
    public var updatedAt: Date = Date()

    public init() {}

    /// Drops records that do not name a real segment file.
    ///
    /// An earlier build inserted a placeholder record so a write-only recorder
    /// could resume numbering. It was never a file, so verification reported it
    /// as missing history — an alarming and entirely false result. Manifests
    /// written by that build are cleaned up on load.
    public mutating func removingPhantomRecords() {
        segments.removeAll { !$0.fileName.hasSuffix(".hdwseg") }
    }

    public var totalBytes: Int64 { segments.reduce(0) { $0 + $1.byteSize } }
    public var oldestEvent: Date? { segments.compactMap(\.firstEventAt).min() }
    public var newestEvent: Date? { segments.compactMap(\.lastEventAt).max() }
}
