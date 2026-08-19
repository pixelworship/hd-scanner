import SwiftUI
import HDWatcherCore

struct AlertsView: View {
    @Environment(AppModel.self) private var model

    @State private var severityFilter: Severity = .trace
    @State private var showAcknowledged = true
    @State private var searchText = ""
    @State private var selectedAlert: SecurityAlert?

    /// Filtered off the main thread and cached, like every other list. Doing it
    /// in `body` re-ran the whole pass on every redraw and every keystroke.
    @State private var filtered: [SecurityAlert] = []
    @State private var hasFiltered = false
    @State private var isFiltering = false
    @State private var page = PageWindow(pageSize: 100)

    nonisolated private static func filter(_ alerts: [SecurityAlert], search: String,
                                           minSeverity: Severity,
                                           showAcknowledged: Bool) -> [SecurityAlert] {
        alerts.filter { alert in
            if alert.severity < minSeverity { return false }
            if !showAcknowledged && alert.acknowledged { return false }
            if !search.isEmpty {
                let haystack = alert.title + alert.detail + alert.ruleName
                if haystack.range(of: search, options: .caseInsensitive) == nil { return false }
            }
            return true
        }
    }

    private var refreshKey: String {
        "\(searchText)|\(severityFilter.rawValue)|\(showAcknowledged)|\(model.alerts.count)"
    }

    private func refilter() async {
        if !searchText.isEmpty {
            try? await Task.sleep(for: .milliseconds(180))
            guard !Task.isCancelled else { return }
        }
        isFiltering = true
        let alerts = model.alerts
        let search = searchText
        let severity = severityFilter
        let acknowledged = showAcknowledged
        filtered = await Task.detached(priority: .userInitiated) {
            Self.filter(alerts, search: search, minSeverity: severity,
                        showAcknowledged: acknowledged)
        }.value
        hasFiltered = true
        isFiltering = false
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if model.phase != .unlocked {
                LoadingStateView(message: "Opening the vault…")
            } else if !hasFiltered {
                LoadingStateView(message: "Reading alerts…")
            } else if filtered.isEmpty {
                EmptyStateView(symbol: "bell.slash",
                               title: model.alerts.isEmpty ? "No alerts" : "Nothing matches these filters",
                               message: model.alerts.isEmpty
                                ? "Alerts appear when activity matches one of your rules. Review them under Rules."
                                : nil)
            } else {
                List {
                    ForEach(Array(page.window(filtered))) { alert in
                        AlertRowView(alert: alert) {
                            model.acknowledgeAlert(alert)
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { selectedAlert = alert }
                        .contextMenu {
                            Button("Show Details") { selectedAlert = alert }
                            if !alert.acknowledged {
                                Button("Acknowledge") { model.acknowledgeAlert(alert) }
                            }
                            if let path = alert.event?.path {
                                Button("Copy Path") {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(path, forType: .string)
                                }
                            }
                        }
                    }
                    if page.hasMore(filtered) {
                        PageLoadMoreRow(shown: page.limit, total: filtered.count) { page.advance() }
                    }
                }
                .listStyle(.inset)
            }
        }
        .task(id: refreshKey) { await refilter() }
        .onChange(of: searchText) { _, _ in page.reset() }
        .sheet(item: $selectedAlert) { alert in
            EventDetailView(alert: alert).environment(model)
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            HStack(spacing: 5) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search alerts", text: $searchText).textFieldStyle(.plain)
                if isFiltering { ProgressView().controlSize(.small) }
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))
            .frame(maxWidth: 260)

            Picker("Severity", selection: $severityFilter) {
                ForEach(Severity.allCases, id: \.self) { severity in
                    Text(severity == .trace ? "All severities" : "\(severity.displayName)+").tag(severity)
                }
            }
            .pickerStyle(.menu).frame(width: 160)

            Toggle("Show acknowledged", isOn: $showAcknowledged)
                .toggleStyle(.checkbox)

            Spacer()

            Button("Acknowledge All") { model.acknowledgeAllAlerts() }
                .disabled(model.unacknowledgedAlertCount == 0)
            Button("Clear") { model.clearAlerts() }
                .disabled(model.alerts.isEmpty)
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
    }
}

struct AlertRowView: View {
    let alert: SecurityAlert
    var onAcknowledge: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: alert.severity.symbol)
                .font(.title3)
                .foregroundStyle(alert.severity.color)
                .frame(width: 26)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(alert.title)
                        .font(.body.weight(.medium))
                        .foregroundStyle(alert.acknowledged ? .secondary : .primary)
                    if alert.matchCount > 1 {
                        Text("×\(alert.matchCount)")
                            .font(.caption.weight(.bold))
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(alert.severity.color.opacity(0.2), in: Capsule())
                    }
                    if alert.acknowledged {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.caption).foregroundStyle(.green)
                    }
                }
                Text(alert.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if let path = alert.event?.path {
                    Text(path)
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.middle)
                }

                if let actor = alert.event?.attribution?.best {
                    HStack(spacing: 4) {
                        Image(systemName: actor.isSystemProcess ? "gearshape.fill" : "app.dashed")
                        Text(actor.summary)
                        Text("·").foregroundStyle(.tertiary)
                        Text(actor.evidence.displayName).foregroundStyle(.tertiary)
                    }
                    .font(.caption2)
                    .foregroundStyle(actor.evidence.confidence.color)
                }
            }

            Spacer(minLength: 8)

            VStack(alignment: .trailing, spacing: 4) {
                Text(Format.relativeTime(alert.timestamp))
                    .font(.caption).foregroundStyle(.tertiary)
                if !alert.acknowledged {
                    Button("Acknowledge", action: onAcknowledge)
                        .buttonStyle(.link).font(.caption)
                }
            }

            Image(systemName: "chevron.right")
                .font(.caption2).foregroundStyle(.tertiary)
                .padding(.top, 3)
        }
        .padding(.vertical, 5)
        .opacity(alert.acknowledged ? 0.65 : 1)
    }
}
