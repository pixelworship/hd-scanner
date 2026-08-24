import SwiftUI
import HDWatcherCore

struct MainView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model

        NavigationSplitView {
            List(selection: $model.selection) {
                Section("Monitor") {
                    row(.dashboard); row(.live); row(.hotspots); row(.transfers)
                    row(.reads); row(.recovery)
                }
                Section("Security") {
                    row(.alerts); row(.rules); row(.integrity)
                }
                Section("Data") {
                    row(.volumes); row(.forensics)
                }
                Section {
                    row(.settings)
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 260)
            .safeAreaInset(edge: .bottom) { sidebarFooter }
        } detail: {
            detailView
                .navigationTitle(model.selection.title)
                .toolbar { toolbarContent }
        }
    }

    private func row(_ section: SidebarSection) -> some View {
        Label {
            HStack {
                Text(section.title)
                if section == .alerts, model.unacknowledgedAlertCount > 0 {
                    Spacer()
                    Text("\(model.unacknowledgedAlertCount)")
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.red, in: Capsule())
                        .foregroundStyle(.white)
                }
            }
        } icon: {
            Image(systemName: section.symbol)
        }
        .tag(section)
    }

    @ViewBuilder
    private var detailView: some View {
        switch model.selection {
        case .dashboard: DashboardView()
        case .live:      LiveFeedView()
        case .hotspots:  HotspotsView()
        case .transfers: TransfersView()
        case .reads:     ReadsView()
        case .recovery:  RecoveryView()
        case .alerts:    AlertsView()
        case .rules:     RulesView()
        case .volumes:   VolumesView()
        case .forensics: ForensicsView()
        case .integrity: IntegrityView()
        case .settings:  SettingsView()
        }
    }

    private var sidebarFooter: some View {
        VStack(alignment: .leading, spacing: 6) {
            Divider()
            HStack(spacing: 6) {
                Circle()
                    .fill(model.isMonitoring ? Color.green : Color.orange)
                    .frame(width: 7, height: 7)
                Text(model.isViewerMode ? "Recording in background"
                                        : (model.isMonitoring ? "Monitoring" : "Paused"))
                    .font(.caption.weight(.medium))
                Spacer()
            }
            Text(model.recordingSummary)
                .font(.caption2).foregroundStyle(.secondary)
            HStack(spacing: 4) {
                Image(systemName: model.protectionTier.isHardwareBacked ? "lock.shield.fill" : "lock.shield")
                Text(model.protectionTier.isHardwareBacked ? "Enclave-bound" : "Password only")
            }
            .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 14)
        .padding(.bottom, 10)
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItemGroup {
            Button {
                model.toggleMonitoring()
            } label: {
                Label(model.status.isMonitoring ? "Pause" : "Resume",
                      systemImage: model.status.isMonitoring ? "pause.circle" : "play.circle")
            }
            .disabled(model.isViewerMode)
            .help(model.isViewerMode
                  ? "The background daemon is recording; turn it off in Settings → Background to stop."
                  : (model.status.isMonitoring ? "Pause monitoring" : "Resume monitoring"))

            Button {
                model.lock()
            } label: {
                Label("Lock", systemImage: "lock")
            }
            .help("Lock the vault and clear decrypted data from memory")
        }
    }
}
