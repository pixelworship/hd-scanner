import SwiftUI
import HDWatcherCore

/// Cross-volume copies and moves, framed as "what left this Mac and what
/// arrived on it".
struct TransfersView: View {
    @Environment(AppModel.self) private var model

    @State private var directionFilter: Direction = .all
    @State private var minConfidence: Confidence = .low
    @State private var historical: [FileEvent] = []
    @State private var loadedHistory = false
    @State private var selected: FileEvent?
    @State private var hasLoaded = false
    @State private var page = PageWindow(pageSize: 100)

    enum Direction: String, CaseIterable, Identifiable {
        case all = "All"
        case outbound = "Leaving this Mac"
        case inbound = "Arriving"
        var id: String { rawValue }
    }

    /// Merged, filtered and sorted off the main thread. Doing it in `body`
    /// meant redoing the whole thing on every redraw.
    @State private var combined: [FileEvent] = []

    nonisolated private static func merge(live: [FileEvent], historical: [FileEvent],
                              direction: Direction, minConfidence: Confidence) -> [FileEvent] {
        var seen = Set<UUID>()
        return (live + historical)
            .filter { seen.insert($0.id).inserted }
            .filter { event in
                guard event.confidence >= minConfidence else { return false }
                switch direction {
                case .all:      return true
                case .outbound: return event.kind == .copiedOut || event.kind == .movedOut
                case .inbound:  return event.kind == .copiedIn || event.kind == .movedIn
                }
            }
            .sorted { $0.timestamp > $1.timestamp }
    }

    /// Anything that changes what the list should show.
    private var recomputeKey: String {
        "\(directionFilter.rawValue)|\(minConfidence.rawValue)|\(model.transfers.count)|\(historical.count)"
    }

    private func recompute() async {
        let live = model.transfers
        let history = historical
        let direction = directionFilter
        let floor = minConfidence
        combined = await Task.detached(priority: .userInitiated) {
            Self.merge(live: live, historical: history,
                       direction: direction, minConfidence: floor)
        }.value
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if !hasLoaded {
                LoadingStateView(message: "Decrypting transfer history…",
                                 detail: "Reading the encrypted log for copies and moves between volumes.")
            } else if combined.isEmpty {
                EmptyStateView(
                    symbol: "arrow.left.arrow.right",
                    title: "No transfers detected",
                    message: "Copy a file between your disk and an external drive and it will show up here, along with how confident the match is."
                )
            } else {
                List {
                    Section {
                        ForEach(Array(page.window(combined))) { event in
                            TransferRow(event: event,
                                        sourceVolume: model.engine?.registry.volume(id: event.sourceVolumeID ?? ""),
                                        destVolume: model.engine?.registry.volume(id: event.volumeID ?? ""))
                                .contentShape(Rectangle())
                                .onTapGesture { selected = event }
                                .contextMenu {
                                    Button("Show Details") { selected = event }
                                    Button("Copy Destination Path") {
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general.setString(event.path, forType: .string)
                                    }
                                    if let source = event.sourcePath {
                                        Button("Copy Source Path") {
                                            NSPasteboard.general.clearContents()
                                            NSPasteboard.general.setString(source, forType: .string)
                                        }
                                    }
                                }
                        }
                        if page.hasMore(combined) {
                            PageLoadMoreRow(shown: page.limit, total: combined.count) {
                                page.advance()
                            }
                        }
                    } footer: {
                        Text("Transfers are inferred from filesystem events. macOS does not report which process performed a copy without an Endpoint Security entitlement, so each row shows how strong the evidence is.")
                            .font(.caption).foregroundStyle(.secondary)
                            .padding(.top, 8)
                    }
                }
                .listStyle(.inset)
            }
        }
        .sheet(item: $selected) { event in
            EventDetailView(event: event).environment(model)
        }
        .task {
            guard !loadedHistory else { return }
            loadedHistory = true
            // Usually already fetched during unlock, so this tab opens instantly.
            if !model.preloadedTransfers.isEmpty {
                historical = model.preloadedTransfers
            } else {
                var query = EventQuery()
                query.transfersOnly = true
                query.limit = 500
                historical = await model.runQueryAsync(query)
            }
            await recompute()
            hasLoaded = true
        }
        .task(id: recomputeKey) { await recompute() }
        .onChange(of: directionFilter) { _, _ in page.reset() }
        .onChange(of: minConfidence) { _, _ in page.reset() }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Picker("Direction", selection: $directionFilter) {
                ForEach(Direction.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .frame(width: 340)

            Picker("Confidence", selection: $minConfidence) {
                Text("Any confidence").tag(Confidence.none)
                Text("Low+").tag(Confidence.low)
                Text("Medium+").tag(Confidence.medium)
                Text("High+").tag(Confidence.high)
            }
            .pickerStyle(.menu)
            .frame(width: 160)

            Spacer()
            Text("\(combined.count) transfers").font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
    }
}

struct TransferRow: View {
    let event: FileEvent
    let sourceVolume: VolumeInfo?
    let destVolume: VolumeInfo?

    private var isEgress: Bool { event.kind.isEgress }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: isEgress ? "arrow.up.right.circle.fill" : "arrow.down.left.circle.fill")
                    .foregroundStyle(isEgress ? .orange : .indigo)
                Text((event.path as NSString).lastPathComponent)
                    .font(.body.weight(.medium))
                    .lineLimit(1).truncationMode(.middle)
                KindBadge(kind: event.kind)
                ConfidenceBadge(confidence: event.confidence)
                Spacer(minLength: 6)
                Text(Format.bytes(event.size))
                    .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                Text(Format.relativeTime(event.timestamp))
                    .font(.caption).foregroundStyle(.tertiary)
                    .frame(width: 58, alignment: .trailing)
                Image(systemName: "chevron.right")
                    .font(.caption2).foregroundStyle(.tertiary)
            }

            if let actor = event.attribution?.best {
                HStack(spacing: 4) {
                    Image(systemName: actor.isSystemProcess ? "gearshape.fill" : "app.dashed")
                    Text(actor.summary)
                    Text("·").foregroundStyle(.tertiary)
                    Text(actor.evidence.displayName).foregroundStyle(.tertiary)
                }
                .font(.caption2)
                .foregroundStyle(actor.evidence.confidence.color)
                .padding(.leading, 24)
            }

            HStack(spacing: 8) {
                endpoint(volume: sourceVolume,
                         path: event.sourcePath,
                         fallback: "Unidentified source")
                Image(systemName: "arrow.right")
                    .font(.caption).foregroundStyle(.tertiary)
                endpoint(volume: destVolume, path: event.path, fallback: "Unknown volume")
                Spacer(minLength: 0)
            }
            .padding(.leading, 24)
        }
        .padding(.vertical, 4)
    }

    private func endpoint(volume: VolumeInfo?, path: String?, fallback: String) -> some View {
        HStack(spacing: 5) {
            Image(systemName: volume?.volumeClass.symbolName ?? "questionmark.circle")
                .font(.caption)
                .foregroundStyle(volume?.volumeClass.tint ?? .secondary)
            VStack(alignment: .leading, spacing: 0) {
                Text(volume?.name ?? fallback)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(volume == nil ? .secondary : .primary)
                if let path {
                    Text(Format.abbreviatePath((path as NSString).deletingLastPathComponent, maxComponents: 4))
                        .font(.caption2).foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.head)
                }
            }
        }
        .padding(.horizontal, 7).padding(.vertical, 4)
        .background((volume?.volumeClass.tint ?? .secondary).opacity(0.10),
                    in: RoundedRectangle(cornerRadius: 6))
    }
}
