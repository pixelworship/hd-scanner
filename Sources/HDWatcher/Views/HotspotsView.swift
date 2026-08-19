import SwiftUI
import HDWatcherCore

struct HotspotsView: View {
    @Environment(AppModel.self) private var model

    @State private var ranking: HotspotTracker.Ranking = .heat
    @State private var drillPath: [String] = []
    @State private var selected: DirectoryHeat?

    private var currentRoot: String? { drillPath.last }

    /// Ranked off the main thread and cached. Decaying and sorting the whole
    /// directory table inside `body` re-ran on every redraw.
    @State private var rows: [DirectoryHeat] = []
    @State private var hasRanked = false

    private var refreshKey: String {
        "\(ranking.rawValue)|\(currentRoot ?? "-")|\(model.hotspotRows.count)"
    }

    private func rank() async {
        guard let engine = model.engine else { rows = []; return }
        let root = currentRoot
        let by = ranking
        rows = await Task.detached(priority: .userInitiated) {
            if let root { return engine.hotspots.children(of: root, limit: 60) }
            return engine.hotspots.topDirectories(60, by: by)
        }.value
        hasRanked = true
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if !hasRanked {
                LoadingStateView(message: "Ranking directories…",
                                 detail: "Scoring recent activity across \(model.engine?.hotspots.trackedDirectoryCount ?? 0) tracked directories.")
            } else if rows.isEmpty {
                EmptyStateView(symbol: "flame",
                               title: "No hotspots yet",
                               message: "Directories heat up as files are read, written and deleted inside them.")
            } else {
                HSplitView {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 14) {
                            Treemap(rows: rows, selection: $selected) { row in
                                drillPath.append(row.path)
                                selected = nil
                            }
                            .frame(height: 320)

                            rankedList
                        }
                        .padding(16)
                    }
                    .frame(minWidth: 460)

                    if let selected {
                        HotspotDetail(row: selected) {
                            drillPath.append(selected.path)
                            self.selected = nil
                        }
                        .frame(minWidth: 260, idealWidth: 300)
                    }
                }
            }
        }
        .task(id: refreshKey) { await rank() }
    }

    private var header: some View {
        HStack(spacing: 12) {
            if drillPath.isEmpty {
                Picker("Rank by", selection: $ranking) {
                    ForEach(HotspotTracker.Ranking.allCases, id: \.self) { option in
                        Text(option.rawValue).tag(option)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 190)
                .help(ranking.explanation)
            }

            breadcrumbs

            Spacer()

            Text("\(model.engine?.hotspots.trackedDirectoryCount ?? 0) directories tracked")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
    }

    private var breadcrumbs: some View {
        HStack(spacing: 4) {
            if !drillPath.isEmpty {
                Button {
                    drillPath.removeAll(); selected = nil
                } label: {
                    Label("All", systemImage: "chevron.left")
                }
                .buttonStyle(.link)

                ForEach(Array(drillPath.enumerated()), id: \.offset) { index, path in
                    Text("/").foregroundStyle(.tertiary)
                    Button((path as NSString).lastPathComponent) {
                        drillPath = Array(drillPath.prefix(index + 1))
                        selected = nil
                    }
                    .buttonStyle(.link)
                    .lineLimit(1)
                }
            }
        }
        .font(.caption)
    }

    private var rankedList: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: currentRoot.map { "Inside \(($0 as NSString).lastPathComponent)" } ?? "Ranked directories",
                          subtitle: ranking.explanation)

            let peak = max(rows.map(\.heat).max() ?? 1, 0.001)
            ForEach(rows.prefix(40)) { row in
                Button {
                    selected = row
                } label: {
                    HStack(spacing: 10) {
                        RoundedRectangle(cornerRadius: 3)
                            .fill(heatColor(row.heat / peak))
                            .frame(width: 4, height: 26)

                        VStack(alignment: .leading, spacing: 1) {
                            Text(row.name).font(.callout.weight(.medium)).lineLimit(1)
                            Text(Format.abbreviatePath(row.path))
                                .font(.caption).foregroundStyle(.secondary)
                                .lineLimit(1).truncationMode(.head)
                        }
                        Spacer(minLength: 8)

                        metric("\(row.creates)", "new", .green)
                        metric("\(row.modifies)", "chg", .blue)
                        metric("\(row.deletes)", "del", .red)
                        // Atomic saves (plists, documents) land as renames, so a
                        // directory can be busy with none of the counters above.
                        metric("\(row.renames)", "ren", .purple)
                        metric("\(row.transfers)", "xfer", .indigo)
                        Text(Format.bytes(row.bytesTouched))
                            .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            .frame(width: 74, alignment: .trailing)
                    }
                    .padding(.vertical, 4)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .background(selected?.id == row.id ? Color.accentColor.opacity(0.12) : .clear,
                            in: RoundedRectangle(cornerRadius: 6))
            }
        }
    }

    private func metric(_ value: String, _ label: String, _ color: Color) -> some View {
        VStack(spacing: 0) {
            Text(value).font(.caption.monospacedDigit().weight(.medium)).foregroundStyle(color)
            Text(label).font(.system(size: 8)).foregroundStyle(.tertiary)
        }
        .frame(width: 34)
    }
}

func heatColor(_ fraction: Double) -> Color {
    // Cool blue through amber to red as a directory gets hotter.
    let clamped = max(0, min(1, fraction))
    return Color(hue: 0.62 - 0.62 * clamped, saturation: 0.75, brightness: 0.92)
}

/// Squarified treemap: each directory's rectangle is proportional to its share
/// of subtree activity, so where the traffic goes is visible at a glance.
struct Treemap: View {
    let rows: [DirectoryHeat]
    @Binding var selection: DirectoryHeat?
    var onDrill: (DirectoryHeat) -> Void

    var body: some View {
        GeometryReader { geo in
            let items = Array(rows.prefix(40)).filter { $0.subtreeEvents > 0 }
            let total = max(items.reduce(0.0) { $0 + Double($1.subtreeEvents) }, 1)
            let tiles = squarify(items: items, total: total,
                                 rect: CGRect(origin: .zero, size: geo.size))
            let peak = max(items.map(\.heat).max() ?? 1, 0.001)

            ZStack(alignment: .topLeading) {
                ForEach(tiles, id: \.row.id) { tile in
                    let isSelected = selection?.id == tile.row.id
                    RoundedRectangle(cornerRadius: 5)
                        .fill(heatColor(tile.row.heat / peak).opacity(0.75))
                        .overlay(
                            RoundedRectangle(cornerRadius: 5)
                                .strokeBorder(isSelected ? Color.primary : Color.black.opacity(0.18),
                                              lineWidth: isSelected ? 2 : 0.5)
                        )
                        .overlay(alignment: .topLeading) {
                            if tile.rect.width > 58 && tile.rect.height > 26 {
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(tile.row.name)
                                        .font(.caption.weight(.semibold))
                                        .lineLimit(1)
                                    Text("\(tile.row.subtreeEvents)")
                                        .font(.caption2.monospacedDigit())
                                        .opacity(0.85)
                                }
                                .foregroundStyle(.white)
                                .shadow(radius: 1)
                                .padding(5)
                            }
                        }
                        .frame(width: max(0, tile.rect.width - 2), height: max(0, tile.rect.height - 2))
                        .offset(x: tile.rect.minX + 1, y: tile.rect.minY + 1)
                        .help("\(tile.row.path)\n\(tile.row.subtreeEvents) events in subtree")
                        .onTapGesture(count: 2) { onDrill(tile.row) }
                        .onTapGesture { selection = tile.row }
                }
            }
        }
    }

    struct Tile {
        let row: DirectoryHeat
        let rect: CGRect
    }

    /// Standard squarified treemap layout: fill a strip along the shorter edge
    /// until adding another tile would make the aspect ratios worse.
    private func squarify(items: [DirectoryHeat], total: Double, rect: CGRect) -> [Tile] {
        var tiles: [Tile] = []
        var remaining = rect
        var queue = items.sorted { $0.subtreeEvents > $1.subtreeEvents }
        let area = Double(rect.width * rect.height)
        guard area > 0 else { return [] }

        while !queue.isEmpty {
            let horizontal = remaining.width >= remaining.height
            let shortSide = Double(horizontal ? remaining.height : remaining.width)
            guard shortSide > 1 else { break }

            var strip: [DirectoryHeat] = []
            var stripValue = 0.0
            var bestRatio = Double.greatestFiniteMagnitude

            while let next = queue.first {
                let candidateValue = stripValue + Double(next.subtreeEvents) / total * area
                let candidate = strip + [next]
                let ratio = worstRatio(candidate, value: candidateValue, side: shortSide, total: total, area: area)
                if ratio > bestRatio { break }
                bestRatio = ratio
                stripValue = candidateValue
                strip.append(next)
                queue.removeFirst()
            }
            if strip.isEmpty, !queue.isEmpty {
                strip = [queue.removeFirst()]
                stripValue = Double(strip[0].subtreeEvents) / total * area
            }

            let stripThickness = stripValue / max(shortSide, 1)
            var offset = 0.0
            for item in strip {
                let itemArea = Double(item.subtreeEvents) / total * area
                let length = itemArea / max(stripThickness, 0.001)
                let tileRect: CGRect = horizontal
                    ? CGRect(x: remaining.minX, y: remaining.minY + offset,
                             width: stripThickness, height: length)
                    : CGRect(x: remaining.minX + offset, y: remaining.minY,
                             width: length, height: stripThickness)
                tiles.append(Tile(row: item, rect: tileRect))
                offset += length
            }

            if horizontal {
                remaining = CGRect(x: remaining.minX + stripThickness, y: remaining.minY,
                                   width: remaining.width - stripThickness, height: remaining.height)
            } else {
                remaining = CGRect(x: remaining.minX, y: remaining.minY + stripThickness,
                                   width: remaining.width, height: remaining.height - stripThickness)
            }
            if remaining.width < 1 || remaining.height < 1 { break }
        }
        return tiles
    }

    private func worstRatio(_ strip: [DirectoryHeat], value: Double, side: Double,
                            total: Double, area: Double) -> Double {
        guard value > 0, !strip.isEmpty else { return .greatestFiniteMagnitude }
        let areas = strip.map { Double($0.subtreeEvents) / total * area }
        let maxArea = areas.max() ?? 0
        let minArea = areas.min() ?? 0
        guard minArea > 0 else { return .greatestFiniteMagnitude }
        let side2 = side * side
        let value2 = value * value
        return max(side2 * maxArea / value2, value2 / (side2 * minArea))
    }
}

struct HotspotDetail: View {
    let row: DirectoryHeat
    var onDrill: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(row.name).font(.title3.weight(.medium))
                    Text(row.path)
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }

                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 7) {
                    statRow("Events here", "\(row.directEvents)")
                    statRow("Events in subtree", "\(row.subtreeEvents)")
                    statRow("Created", "\(row.creates)")
                    statRow("Modified", "\(row.modifies)")
                    statRow("Deleted", "\(row.deletes)")
                    statRow("Renamed", "\(row.renames)")
                    statRow("Transfers", "\(row.transfers)")
                    statRow("Bytes touched", Format.bytes(row.bytesTouched))
                    statRow("Heat score", String(format: "%.1f", row.heat))
                    statRow("Last activity", Format.relativeTime(row.lastActivity))
                }

                if row.deleteRatio > 0.5 && row.directEvents > 10 {
                    Label("Most activity here is deletion", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                }

                HStack {
                    Button("Drill In", action: onDrill)
                    Button("Reveal") {
                        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: row.path)
                    }
                    .disabled(!FileManager.default.fileExists(atPath: row.path))
                }
                .controlSize(.small)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
        }
    }

    private func statRow(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout.monospacedDigit())
                .gridColumnAlignment(.trailing)
        }
    }
}
