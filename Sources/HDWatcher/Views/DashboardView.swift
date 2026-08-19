import SwiftUI
import HDWatcherCore

struct DashboardView: View {
    @Environment(AppModel.self) private var model

    private var columns: [GridItem] {
        [GridItem(.adaptive(minimum: 210), spacing: 12)]
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if model.fullDiskAccess != .granted { permissionBanner }

                LazyVGrid(columns: columns, spacing: 12) {
                    StatTile(title: "Events recorded",
                             value: Format.count(Int(model.status.eventsProcessed)),
                             caption: "\(Int(model.eventsPerMinute))/min now",
                             symbol: "waveform.path.ecg", tint: .blue)

                    StatTile(title: "Transfers detected",
                             value: "\(model.status.transfersDetected)",
                             caption: "cross-volume copies and moves",
                             symbol: "arrow.left.arrow.right", tint: .indigo)

                    StatTile(title: "Alerts",
                             value: "\(model.alerts.count)",
                             caption: "\(model.unacknowledgedAlertCount) unacknowledged",
                             symbol: "bell", tint: model.unacknowledgedAlertCount > 0 ? .red : .green)

                    StatTile(title: "Volumes watched",
                             value: "\(model.status.watchedPaths.count)",
                             caption: "\(model.volumes.count) mounted",
                             symbol: "externaldrive", tint: .orange)

                    StatTile(title: "Filtered as noise",
                             value: Format.count(Int(model.status.eventsFiltered)),
                             caption: "excluded by filters",
                             symbol: "line.3.horizontal.decrease.circle", tint: .secondary)

                    StatTile(title: "Recoverable files",
                             value: "\(model.contentStats.uniqueFileCount)",
                             caption: "\(model.contentStats.deletedFileCount) deleted · \(Format.bytes(model.contentStats.liveBytes))",
                             symbol: "clock.arrow.circlepath", tint: .teal)

                    StatTile(title: "Log size",
                             value: Format.bytes(model.store?.currentManifest.totalBytes ?? 0),
                             caption: "\(model.store?.currentManifest.segments.count ?? 0) encrypted segments",
                             symbol: "lock.doc", tint: .purple)
                }

                activityCard

                HStack(alignment: .top, spacing: 12) {
                    hotspotsCard
                    VStack(spacing: 12) {
                        alertsCard
                        typesCard
                    }
                }
            }
            .padding(18)
        }
    }

    private var permissionBanner: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.title2).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("Full Disk Access is not granted").font(.subheadline.weight(.semibold))
                Text("HDWatcher can only see folders macOS already permits. Grant Full Disk Access to watch the whole drive, then relaunch.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            VStack(spacing: 6) {
                Button("Open Settings") { Permissions.openFullDiskAccessSettings() }
                Button("Re-check") { model.refreshPermissions() }.buttonStyle(.link)
            }
        }
        .card(padding: 14)
        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }

    private var activityCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                SectionHeader(title: "Activity", subtitle: "Events per minute over the last hour")
                Spacer()
                legend
            }
            if model.hasLoadedDerivedState {
                Sparkline(values: model.activitySeries.map { Double($0.total) }, tint: .blue)
                    .frame(height: 110)
            } else {
                InlineLoadingView(message: "Building the activity chart…")
                    .frame(height: 110)
            }
            HStack {
                Text("60 min ago").font(.caption2).foregroundStyle(.tertiary)
                Spacer()
                Text("now").font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .card()
    }

    private var legend: some View {
        HStack(spacing: 14) {
            legendItem("Writes", model.activitySeries.reduce(0) { $0 + $1.creates + $1.modifies }, .green)
            legendItem("Deletes", model.activitySeries.reduce(0) { $0 + $1.deletes }, .red)
            legendItem("Transfers", model.activitySeries.reduce(0) { $0 + $1.transfers }, .indigo)
        }
    }

    private func legendItem(_ title: String, _ value: Int, _ color: Color) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(Format.count(value)).font(.caption.weight(.medium)).monospacedDigit()
        }
    }

    private var hotspotsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Hotspots", subtitle: "Busiest directories right now")
            if !model.hasLoadedDerivedState {
                InlineLoadingView(message: "Ranking directories…")
            } else if model.hotspotRows.isEmpty {
                Text("No activity recorded yet.")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 20)
            } else {
                let peak = model.hotspotRows.first?.heat ?? 1
                ForEach(model.hotspotRows.prefix(8)) { row in
                    HotspotBar(row: row, peak: peak)
                }
                Button("See all hotspots") { model.selection = .hotspots }
                    .buttonStyle(.link).font(.caption)
            }
        }
        .card()
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var alertsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Recent alerts")
            if model.alerts.isEmpty {
                Text("Nothing has tripped a rule.")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 12)
            } else {
                ForEach(model.alerts.prefix(4)) { alert in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: alert.severity.symbol)
                            .foregroundStyle(alert.severity.color)
                            .font(.caption)
                            .padding(.top, 2)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(alert.title).font(.caption.weight(.medium)).lineLimit(1)
                            Text(alert.detail).font(.caption2).foregroundStyle(.secondary).lineLimit(2)
                        }
                        Spacer(minLength: 0)
                        Text(Format.relativeTime(alert.timestamp))
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                Button("See all alerts") { model.selection = .alerts }
                    .buttonStyle(.link).font(.caption)
            }
        }
        .card()
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var typesCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Busiest file types")
            if !model.hasLoadedDerivedState {
                InlineLoadingView(message: "Counting file types…")
            } else if model.topExtensions.isEmpty {
                Text("No file activity yet.")
                    .font(.caption).foregroundStyle(.secondary)
                    .padding(.vertical, 12)
            } else {
                let peak = model.topExtensions.first?.count ?? 1
                ForEach(model.topExtensions.prefix(6)) { stat in
                    HStack(spacing: 8) {
                        Text(".\(stat.ext)")
                            .font(.caption.monospaced())
                            .frame(width: 62, alignment: .leading)
                            .lineLimit(1)
                        GeometryReader { geo in
                            RoundedRectangle(cornerRadius: 3)
                                .fill(Color.accentColor.opacity(0.7))
                                .frame(width: geo.size.width * CGFloat(stat.count) / CGFloat(peak))
                        }
                        .frame(height: 8)
                        Text(Format.count(stat.count))
                            .font(.caption2).monospacedDigit()
                            .foregroundStyle(.secondary)
                            .frame(width: 42, alignment: .trailing)
                    }
                }
            }
        }
        .card()
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct HotspotBar: View {
    let row: DirectoryHeat
    let peak: Double

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Text(row.name)
                    .font(.caption.weight(.medium))
                    .lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 4)
                Text("\(row.directEvents)")
                    .font(.caption2).monospacedDigit().foregroundStyle(.secondary)
            }
            GeometryReader { geo in
                let fraction = peak > 0 ? CGFloat(row.heat / peak) : 0
                RoundedRectangle(cornerRadius: 3)
                    .fill(LinearGradient(colors: [.orange, .red],
                                         startPoint: .leading, endPoint: .trailing))
                    .frame(width: max(2, geo.size.width * fraction))
            }
            .frame(height: 6)
        }
        .help(row.path)
    }
}
