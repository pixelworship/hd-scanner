import Foundation

/// Decides when the Recovery list needs rebuilding, and when the reader should
/// be told it is happening.
///
/// The list polls once a second so it stays live as captures arrive. Without a
/// gate, every tick re-filtered thousands of groups and flashed the progress
/// spinner in the search box — constant activity for a list that had not
/// changed. Both halves matter and they are not the same question:
///
/// - *Does work need doing?* Only when the vault has moved or the filter has
///   changed.
/// - *Should the reader see a spinner?* Only when the work is theirs — a
///   refresh caused by new data arriving should update silently, because
///   nobody asked for it and nobody is waiting on it.
public struct RecoveryRefreshGate: Sendable, Equatable {

    private var completedPass: String?
    private var completedSearch: String?

    public init() {}

    /// True when the list would come back different from what is on screen.
    public func needsPass(revision: Int, deletedOnly: Bool, search: String?,
                          force: Bool = false) -> Bool {
        force || completedPass != Self.signature(revision, deletedOnly, search)
    }

    /// True when the reader is waiting on this particular pass.
    public func showsProgress(for search: String?) -> Bool {
        guard let search, !search.isEmpty else { return false }
        return search != completedSearch
    }

    /// Records a pass that finished. A pass cancelled part-way is deliberately
    /// not recorded, so the next tick repeats it.
    public mutating func finished(revision: Int, deletedOnly: Bool, search: String?) {
        completedPass = Self.signature(revision, deletedOnly, search)
        completedSearch = search
    }

    /// Forgets everything, for when the vault is locked or replaced.
    public mutating func reset() {
        completedPass = nil
        completedSearch = nil
    }

    private static func signature(_ revision: Int, _ deletedOnly: Bool, _ search: String?) -> String {
        "\(revision)|\(deletedOnly)|\(search ?? "")"
    }
}
