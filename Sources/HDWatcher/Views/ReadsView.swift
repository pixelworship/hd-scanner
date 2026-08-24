import SwiftUI
import HDWatcherCore

/// Which files were **read**, and by what.
///
/// Recovery answers "what changed". This answers the question a change log
/// cannot: who opened this, and when. Reading is how data leaves — a document
/// copied to a USB stick, mailed, or uploaded is read first, and nothing about
/// that touches the filesystem for FSEvents to report.
struct ReadsView: View {
    @Environment(AppModel.self) private var model

    @State private var searchText = ""
    @State private var selectedPath: String?
    @State private var isPaused = false
    @State private var page = PageWindow(pageSize: 100)

    private var groups: [AppModel.ReadGroup] { model.readGroups }

    private var selectedGroup: AppModel.ReadGroup? {
        groups.first { $0.path == selectedPath }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if !model.settings.trackFileReads {
                EmptyStateView(
                    symbol: "eye.slash",
                    title: "Read tracking is off",
                    message: "Turn on \"Record which files are read\" in Settings → Monitoring. Reads are found by sampling open files, which is the only way to see them at all: nothing changes on disk when a file is read.")
            } else if model.isLoadingReads && groups.isEmpty {
                LoadingStateView(message: "Reading the log…",
                                 detail: "Scanning the last day of the encrypted log — the first pass on a large log can take a while. New reads stream in live once it lands.")
            } else if groups.isEmpty {
                EmptyStateView(
                    symbol: "eye",
                    title: searchText.isEmpty ? "Nothing read yet" : "No matches",
                    message: searchText.isEmpty
                        ? "As files are opened, the process holding them is recorded here. Files opened and closed between two samples are missed — the sampling interval is in Settings → Monitoring."
                        : nil)
            } else {
                coverageBanner
                HSplitView {
                    fileList.frame(minWidth: 300, idealWidth: 380)
                    detail.frame(minWidth: 420)
                }
            }
        }
        .onAppear { reload(force: true) }
        .onChange(of: searchText) { _, _ in page.reset(); reload() }
        .task(id: pollKey) {
            while !Task.isCancelled && !isPaused {
                try? await Task.sleep(for: .seconds(2))
                guard !Task.isCancelled, !isPaused else { break }
                reload()
            }
        }
    }

    /// States plainly which mechanism is catching reads — the difference
    /// between "every open, including a Terminal cat" and "only files held open
    /// long enough to be sampled" is not a detail to hide.
    @ViewBuilder
    private var coverageBanner: some View {
        switch model.readCoverage {
        case .kernel:
            EmptyView()   // complete coverage; nothing to caveat
        case .sampling:
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text("Sampling open files every few seconds — a file opened and closed quickly (a Terminal `cat`, a Quick Look) can be missed. Kernel-level capture that catches every read needs the background daemon, which runs as root.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14).padding(.vertical, 7)
            .background(.orange.opacity(0.08))
        case .off:
            EmptyView()
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            HStack(spacing: 5) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search files that were read", text: $searchText).textFieldStyle(.plain)
                if model.isLoadingReads { ProgressView().controlSize(.small) }
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                    }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))
            .frame(minWidth: 160, maxWidth: 320)

            Spacer()

            if model.readCoverage == .kernel {
                Label("Kernel capture", systemImage: "bolt.shield")
                    .font(.caption2.weight(.medium))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(.green.opacity(0.15), in: Capsule())
                    .help("Every open() is caught from the audit trail, including reads too brief to sample")
            }
            Text("\(Format.count(groups.count)) file\(groups.count == 1 ? "" : "s") · \(Format.count(groups.reduce(0) { $0 + $1.events.count })) reads")
                .font(.caption).foregroundStyle(.secondary)
                .lineLimit(1).fixedSize()

            Toggle(isOn: Binding(get: { !isPaused }, set: { isPaused = !$0 })) {
                Label(isPaused ? "Paused" : "Live",
                      systemImage: isPaused ? "pause.fill" : "dot.radiowaves.left.and.right")
            }
            .toggleStyle(.button)

            Button { reload(force: true) } label: { Image(systemName: "arrow.clockwise") }
                .help("Refresh now")
                .disabled(!isPaused)
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
        // The header owns its height. Without this a long list could compress
        // it until the search field and title collided, which is exactly what a
        // build's worth of reads did to it.
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity)
        .background(.bar)
        .zIndex(1)
    }

    private var fileList: some View {
        List(selection: $selectedPath) {
            ForEach(Array(page.window(groups))) { group in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Image(systemName: "eye.circle").foregroundStyle(.cyan)
                        Text(group.fileName)
                            .font(.callout.weight(.medium))
                            .lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 4)
                        Text("\(group.events.count)×")
                            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    Text(Format.abbreviatePath(group.directory, maxComponents: 4))
                        .font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.head)
                    HStack(spacing: 6) {
                        Text(group.readers.prefix(2).joined(separator: ", "))
                            .font(.caption2).foregroundStyle(.tertiary)
                            .lineLimit(1)
                        Spacer(minLength: 4)
                        Text(Format.relativeTime(group.lastRead))
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                .padding(.vertical, 2)
                .frame(height: 52)
                .tag(group.path)
                .help(group.path)
            }
            if page.hasMore(groups) {
                PageLoadMoreRow(shown: page.limit, total: groups.count) { page.advance() }
            }
        }
        .listStyle(.inset)
    }

    @ViewBuilder
    private var detail: some View {
        if let group = selectedGroup {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(group.fileName)
                        .font(.title3.weight(.medium))
                        .lineLimit(1).truncationMode(.middle)
                    Text(group.directory)
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(1).truncationMode(.head)
                    HStack(spacing: 10) {
                        if FileManager.default.fileExists(atPath: group.path) {
                            Button {
                                NSWorkspace.shared.selectFile(group.path, inFileViewerRootedAtPath: "")
                            } label: {
                                Label("Reveal", systemImage: "folder")
                            }
                        }
                        Text("\(group.events.count) read\(group.events.count == 1 ? "" : "s") · \(group.readers.count) process\(group.readers.count == 1 ? "" : "es")")
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                    }
                    .controlSize(.small)
                }
                .padding(14)

                Divider()

                List {
                    ForEach(group.events) { event in
                        ReadRow(event: event)
                    }
                }
                .listStyle(.inset)
            }
        } else {
            EmptyStateView(symbol: "eye.trianglebadge.exclamationmark",
                           title: "Select a file",
                           message: "Pick a file on the left to see every time it was opened, and by what.")
        }
    }

    private var pollKey: String { "\(isPaused)|\(searchText)" }

    private func reload(force: Bool = false) {
        model.refreshReads(search: searchText.isEmpty ? nil : searchText, force: force)
    }
}

/// One occasion on which something held the file open.
private struct ReadRow: View {
    let event: FileEvent

    private var actor: ProcessActor? { event.attribution?.best }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "eye")
                .font(.caption)
                .foregroundStyle(.cyan)
                .frame(width: 16)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(actor?.name ?? "unidentified process")
                        .font(.callout.weight(.medium))
                    if let pid = actor?.pid {
                        Text("pid \(pid)")
                            .font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
                    }
                    if actor?.isAppleSigned == true {
                        Image(systemName: "apple.logo").font(.caption2).foregroundStyle(.tertiary)
                    }
                    Spacer(minLength: 4)
                    Text(Format.fullTimestamp(event.timestamp))
                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                }
                if let identifier = actor?.bundleIdentifier ?? actor?.signingIdentifier {
                    Text(identifier)
                        .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.middle)
                }
                if event.attribution?.blockedByPrivileges == true {
                    Text("The process was invisible to the recorder — almost always a root-owned daemon.")
                        .font(.caption2).foregroundStyle(.orange)
                }
            }
        }
        .padding(.vertical, 3)
    }
}
