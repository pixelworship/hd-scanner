import SwiftUI
import HDWatcherCore

/// Feeds a long collection into a list a page at a time.
///
/// SwiftUI's `List` is lazy about *drawing* rows, but handing it thousands of
/// elements still costs: every update diffs the whole collection, and with a
/// selection binding attached that work lands on the main thread. Clearing a
/// search box and going from a handful of rows back to several thousand was
/// enough to stall the window.
///
/// This keeps a window over the data and grows it when the reader reaches the
/// end — the same arrangement a table view uses.
@MainActor
@Observable
final class PageWindow {
    /// Rows shown initially, and added each time the end comes into view.
    let pageSize: Int
    private(set) var limit: Int

    init(pageSize: Int = 100) {
        self.pageSize = pageSize
        self.limit = pageSize
    }

    /// The slice to render.
    func window<T>(_ items: [T]) -> ArraySlice<T> {
        items.prefix(limit)
    }

    func hasMore<T>(_ items: [T]) -> Bool { items.count > limit }

    func advance() { limit += pageSize }

    /// Back to the first page — call whenever the underlying set changes, or a
    /// filtered-down list would keep an enormous window from before.
    func reset() { limit = pageSize }
}

/// Row placed at the end of a paged list; loads the next page when reached.
struct PageLoadMoreRow: View {
    let shown: Int
    let total: Int
    let onAppear: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text("Showing \(Format.count(shown)) of \(Format.count(total))…")
                .font(.caption).foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.vertical, 6)
        .onAppear(perform: onAppear)
    }
}
