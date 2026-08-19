import SwiftUI
import UniformTypeIdentifiers
import HDWatcherCore

/// Review and recover the contents of files that were changed or deleted.
struct RecoveryView: View {
    @Environment(AppModel.self) private var model

    @State private var scope: Scope = .all
    @State private var searchText = ""
    @State private var selectedPath: String?
    @State private var selectedVersion: FileSnapshot?
    @State private var compareAgainst: FileSnapshot?
    @State private var message: String?
    @State private var messageIsError = false
    @State private var confirmingRestore: FileSnapshot?
    @State private var isPaused = false
    @State private var page = PageWindow(pageSize: 100)

    enum Scope: String, CaseIterable, Identifiable {
        case all = "All captured"
        case deleted = "Deleted only"
        var id: String { rawValue }
    }

    /// Where the search box looks. Names is instant because the paths are
    /// already in memory; Contents decrypts and reads the stored bytes, so it
    /// is a scan with progress rather than a filter.
    enum SearchTarget: String, CaseIterable, Identifiable {
        case names = "Names"
        case contents = "Contents"
        var id: String { rawValue }
    }

    @State private var searchIn: SearchTarget = .names
    @State private var selectedHit: UUID?

    private var groups: [SnapshotGroup] { model.recoveryGroups }

    private var selectedGroup: SnapshotGroup? {
        groups.first { $0.path == selectedPath }
            ?? model.allRecoveryGroups.first { $0.path == selectedPath }
    }

    private var isSearchingContents: Bool {
        searchIn == .contents && !searchText.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if model.contentVault == nil {
                EmptyStateView(
                    symbol: "clock.badge.xmark",
                    title: "Content capture is off",
                    message: "Turn on \"Keep contents of changed and deleted files\" in Settings → Storage to be able to review and recover file contents."
                )
            } else if model.isLoadingRecovery && groups.isEmpty {
                LoadingStateView(message: "Reading captured versions…",
                                 detail: "Opening the encrypted container and grouping every stored version.")
            } else if model.isFilteringRecovery && groups.isEmpty {
                LoadingStateView(message: "Searching \(Format.count(model.allRecoveryGroups.count)) files…")
            } else if let problem = model.daemonCaptureProblem, groups.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "lock.slash")
                        .font(.system(size: 34)).foregroundStyle(.orange)
                    Text("Captures are being made but cannot be read")
                        .font(.headline)
                    Text(problem)
                        .font(.callout).foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .textSelection(.enabled)
                        .frame(maxWidth: 520)
                    Button("Copy Command") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(
                            "sudo launchctl kickstart -k system/co.pixelworship.hdwatcher.daemon",
                            forType: .string)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(40)
            } else if groups.isEmpty && !isSearchingContents {
                EmptyStateView(
                    symbol: "clock.arrow.circlepath",
                    title: searchText.isEmpty ? "Nothing captured yet" : "No matches",
                    message: searchText.isEmpty
                        ? "As files are written, HDWatcher stores a copy of their contents here so you can review changes or recover a file after it is deleted."
                        : nil
                )
            } else {
                HSplitView {
                    Group {
                        if isSearchingContents {
                            contentResults
                        } else {
                            fileList
                        }
                    }
                    .frame(minWidth: 320, idealWidth: 400)
                    versionDetail.frame(minWidth: 420)
                }
            }

            if let message {
                Divider()
                HStack {
                    Image(systemName: messageIsError ? "exclamationmark.triangle" : "checkmark.circle")
                        .foregroundStyle(messageIsError ? .red : .green)
                    Text(message).font(.caption)
                    Spacer()
                    Button("Dismiss") { self.message = nil }.buttonStyle(.link).font(.caption)
                }
                .padding(.horizontal, 14).padding(.vertical, 7)
            }
        }
        .onAppear { reload(force: true) }
        .onChange(of: scope) { _, _ in page.reset(); reload(); runContentSearch() }
        .onChange(of: searchText) { _, _ in page.reset(); reload(); runContentSearch() }
        .onChange(of: searchIn) { _, _ in
            page.reset()
            reload()
            runContentSearch()
        }
        .onDisappear { model.cancelContentSearch() }
        .task(id: pollKey) {
            // A second is frequent enough to feel live, and the refresh itself
            // is a no-op unless the vault revision moved.
            while !Task.isCancelled && !isPaused {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled, !isPaused else { break }
                reload()
            }
        }
        .onChange(of: model.recoveryGroups.count) { _, _ in reconcileSelection() }
        .sheet(item: $pendingAnalysis) { analysis in
            AnalysisSheet(
                fileName: analysis.fileName,
                payload: analysis.payload,
                onSend: { send(analysis) },
                onCopy: {
                    copy(analysis.payload.text)
                    pendingAnalysis = nil
                    message = "Copied the description of \(analysis.fileName) to the clipboard."
                    messageIsError = false
                },
                onCancel: { pendingAnalysis = nil }
            )
        }
        .confirmationDialog(
            "Restore this version?",
            isPresented: Binding(get: { confirmingRestore != nil },
                                 set: { if !$0 { confirmingRestore = nil } }),
            titleVisibility: .visible
        ) {
            if let snapshot = confirmingRestore {
                Button("Restore to Original Location") { restore(snapshot, overwrite: true) }
                Button("Save a Copy…") { exportCopy(snapshot) }
                Button("Cancel", role: .cancel) { confirmingRestore = nil }
            }
        } message: {
            if let snapshot = confirmingRestore {
                Text("\(snapshot.fileName) captured \(Format.fullTimestamp(snapshot.capturedAt)) will be written to \(snapshot.path), replacing anything there now.")
            }
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            Picker("", selection: $scope) {
                ForEach(Scope.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .frame(width: 240)

            Picker("", selection: $searchIn) {
                ForEach(SearchTarget.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .frame(width: 150)
            .help("Search file names, or read the contents of every captured version")

            HStack(spacing: 5) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField(searchIn == .contents ? "Search inside file contents" : "Search captured files",
                          text: $searchText).textFieldStyle(.plain)
                if model.isFilteringRecovery {
                    ProgressView().controlSize(.small)
                }
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                    }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))
            .frame(maxWidth: 280)

            Spacer()

            let stats = model.contentStats
            Text(counterText(stats))
                .font(.caption).foregroundStyle(.secondary)

            Toggle(isOn: Binding(get: { !isPaused }, set: { isPaused = !$0 })) {
                Label(isPaused ? "Paused" : "Live",
                      systemImage: isPaused ? "pause.fill" : "dot.radiowaves.left.and.right")
            }
            .toggleStyle(.button)
            .help(isPaused
                  ? "Updates are paused; the list will not change while you work"
                  : "The list updates itself as files are captured")

            Button {
                reload(force: true)
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Refresh now")
            .disabled(!isPaused)
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
    }

    // MARK: - File list

    private var fileList: some View {
        List(selection: $selectedPath) {
            // Only a window of the results is handed to the list; the rest
            // arrives as the reader scrolls.
            ForEach(Array(page.window(groups))) { group in
                RecoveryGroupRow(group: group)
                    .tag(group.path)
                    .onTapGesture(count: 2) {
                        selectedPath = group.path
                        if let latest = group.latest {
                            select(latest, in: group)
                            openCopy(latest)
                        }
                    }
                    .contextMenu {
                        Button("Open Newest a Copy") {
                            if let latest = group.latest { openCopy(latest) }
                        }
                        Button("Forget This File's History", role: .destructive) {
                            model.contentVault?.deleteGroup(path: group.path)
                            reload()
                        }
                    }
            }
            if page.hasMore(groups) {
                PageLoadMoreRow(shown: page.limit, total: groups.count) { page.advance() }
            }
        }
        .listStyle(.inset)
        .onChange(of: groups.count) { _, _ in
            // A different result set means the old window is meaningless.
            if page.limit > page.pageSize, groups.count <= page.pageSize { page.reset() }
        }
        .onChange(of: selectedPath) { _, _ in
            selectedVersion = selectedGroup?.latest
            compareAgainst = selectedGroup?.versions.dropFirst().first
        }
    }

    // MARK: - Content search results

    private var contentResults: some View {
        VStack(spacing: 0) {
            searchProgress
            Divider()
            if model.contentHits.isEmpty {
                if model.isSearchingContents {
                    LoadingStateView(message: "Reading captured contents…",
                                     detail: "Every stored version is decrypted and searched, newest first.")
                } else {
                    EmptyStateView(
                        symbol: "text.magnifyingglass",
                        title: "No matches inside any file",
                        message: "Nothing captured contains \"\(searchText)\". Record files are searched as parsed records, so timestamps and decoded fields count as contents too.")
                }
            } else {
                List(selection: $selectedHit) {
                    ForEach(model.contentHits) { hit in
                        ContentHitRow(hit: hit, query: searchText)
                            .tag(hit.id)
                            .contentShape(Rectangle())
                            .onTapGesture { select(hit) }
                            .onTapGesture(count: 2) {
                                select(hit)
                                openCopy(hit.snapshot)
                            }
                    }
                }
                .listStyle(.inset)
            }
        }
    }

    private var searchProgress: some View {
        HStack(spacing: 10) {
            if model.isSearchingContents {
                ProgressView(value: Double(model.contentSearchScanned),
                             total: Double(max(model.contentSearchTotal, 1)))
                    .progressViewStyle(.linear)
                    .frame(width: 130)
                Text("\(Format.count(model.contentSearchScanned)) of \(Format.count(model.contentSearchTotal)) versions")
                    .font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Button("Stop") { model.cancelContentSearch() }
                    .buttonStyle(.link).font(.caption)
            } else {
                Image(systemName: "checkmark.circle").font(.caption).foregroundStyle(.secondary)
                Text("\(Format.count(model.contentSearchScanned)) versions searched · \(Format.count(model.contentHits.count)) matched")
                    .font(.caption2).foregroundStyle(.secondary)
                Spacer()
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    /// Jumps the detail pane to the version a match was found in — not just the
    /// file, the exact version, since that is where the text actually is.
    private func select(_ hit: ContentSearchEngine.Hit) {
        selectedHit = hit.id
        selectedPath = hit.snapshot.path
        selectedVersion = hit.snapshot
        let versions = model.allRecoveryGroups.first { $0.path == hit.snapshot.path }?.versions ?? []
        let index = versions.firstIndex(of: hit.snapshot) ?? 0
        compareAgainst = versions.indices.contains(index + 1) ? versions[index + 1] : nil
    }

    // MARK: - Detail

    @ViewBuilder
    private var versionDetail: some View {
        if let group = selectedGroup {
            VStack(alignment: .leading, spacing: 0) {
                detailHeader(group)
                Divider()
                versionPicker(group)
                Divider()
                contentPane(group)
            }
        } else {
            EmptyStateView(symbol: "doc.text.magnifyingglass",
                           title: "Select a file",
                           message: "Pick a file on the left to see its captured versions.")
        }
    }

    private func detailHeader(_ group: SnapshotGroup) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(group.fileName)
                    .font(.title3.weight(.medium))
                    .lineLimit(1).truncationMode(.middle)
                if group.isDeleted {
                    Label("Deleted", systemImage: "trash")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.red)
                        .padding(.horizontal, 7).padding(.vertical, 3)
                        .background(.red.opacity(0.15), in: Capsule())
                }
                Spacer()
            }
            Text(group.directory)
                .font(.caption.monospaced()).foregroundStyle(.secondary)
                .textSelection(.enabled)
                .lineLimit(1).truncationMode(.head)

            HStack(spacing: 10) {
                if let snapshot = selectedVersion {
                    Button {
                        confirmingRestore = snapshot
                    } label: {
                        Label("Restore…", systemImage: "arrow.uturn.backward")
                    }
                    Button {
                        exportCopy(snapshot)
                    } label: {
                        Label("Save a Copy…", systemImage: "square.and.arrow.down")
                    }
                    if !group.isDeleted, FileManager.default.fileExists(atPath: group.path) {
                        Button {
                            NSWorkspace.shared.selectFile(group.path, inFileViewerRootedAtPath: "")
                        } label: {
                            Label("Reveal", systemImage: "folder")
                        }
                    }
                    if previewKind == .records {
                        Button {
                            openRecords(of: snapshot)
                        } label: {
                            if isParsingRecords {
                                ProgressView().controlSize(.small)
                            } else {
                                Label("Open Records", systemImage: "list.bullet.rectangle")
                            }
                        }
                        .disabled(previewData == nil || isParsingRecords)
                        .help("Opens every record in this file in its own window, parsed")
                    }
                    Button {
                        prepareAnalysis(of: snapshot)
                    } label: {
                        if isPreparingPrompt {
                            ProgressView().controlSize(.small)
                        } else {
                            Label("Send to ChatGPT", systemImage: "sparkles")
                        }
                    }
                    .disabled(previewData == nil || isPreparingPrompt)
                    .help(previewData == nil
                          ? "Available once the contents have been decrypted"
                          : "Builds a description of this file to ask about. Nothing is sent until you confirm.")
                }
                Spacer()
            }
            .controlSize(.small)
        }
        .padding(14)
    }

    private func versionPicker(_ group: SnapshotGroup) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            // With dozens of versions the strip is far wider than the pane, so
            // it needs both a visible scrollbar and a way to jump to either end.
            HStack(spacing: 8) {
                Text("\(group.versions.count) version\(group.versions.count == 1 ? "" : "s")")
                    .font(.caption.weight(.medium)).foregroundStyle(.secondary)
                if let selected = selectedVersion,
                   let index = group.versions.firstIndex(of: selected) {
                    Text("· showing v\(selected.generation), \(index + 1) of \(group.versions.count)")
                        .font(.caption).foregroundStyle(.tertiary)
                }
                Spacer()
                if group.versions.count > 4 {
                    Button {
                        select(group.versions.first, in: group)
                    } label: {
                        Label("Newest", systemImage: "chevron.left.to.line")
                    }
                    .disabled(selectedVersion?.id == group.versions.first?.id)
                    Button {
                        select(group.versions.last, in: group)
                    } label: {
                        Label("Oldest", systemImage: "chevron.right.to.line")
                    }
                    .disabled(selectedVersion?.id == group.versions.last?.id)
                }
            }
            .labelStyle(.titleAndIcon)
            .controlSize(.small)
            .buttonStyle(.borderless)
            .padding(.horizontal, 14)
            .padding(.top, 8)

            ScrollViewReader { proxy in
                ScrollView(.horizontal) {
                    HStack(spacing: 8) {
                        ForEach(group.versions) { version in
                            versionChip(version)
                                .contentShape(Rectangle())
                                .onTapGesture(count: 2) {
                                    select(version, in: group)
                                    openCopy(version)
                                }
                                .onTapGesture { select(version, in: group) }
                                .contextMenu {
                                    Button("Open a Copy") { openCopy(version) }
                                    Button("Compare With This") { compareAgainst = version }
                                    Divider()
                                    Button("Save a Copy…") { exportCopy(version) }
                                }
                                .help("\(version.reason.displayName) · \(Format.fullTimestamp(version.capturedAt))\nDouble-click to open a copy")
                                .id(version.id)
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.top, 8)
                    // Room beneath the chips so the scrollbar never sits on top
                    // of the expiry line.
                    .padding(.bottom, 12)
                }
                .scrollIndicators(.visible)
                .onChange(of: selectedVersion?.id) { _, newValue in
                    guard let newValue else { return }
                    withAnimation(.easeOut(duration: 0.2)) {
                        proxy.scrollTo(newValue, anchor: .center)
                    }
                }
            }
        }
    }

    /// Selects a version and points the comparison at the one before it.
    private func select(_ version: FileSnapshot?, in group: SnapshotGroup) {
        guard let version else { return }
        selectedVersion = version
        let index = group.versions.firstIndex(of: version) ?? 0
        compareAgainst = group.versions.indices.contains(index + 1)
            ? group.versions[index + 1] : nil
    }

    private func versionChip(_ version: FileSnapshot) -> some View {
        let isSelected = selectedVersion?.id == version.id
        return VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 4) {
                Text("v\(version.generation)")
                    .font(.caption.weight(.bold))
                Text(version.reason.displayName)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Text(Format.relativeTime(version.capturedAt))
                .font(.caption2).foregroundStyle(.secondary)
            Text(Format.bytes(version.byteSize))
                .font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
            if let remaining = version.timeRemaining {
                Text("expires in \(shortDuration(remaining))")
                    .font(.system(size: 9))
                    .foregroundStyle(remaining < 3600 ? Color.orange : Color.secondary)
            } else {
                Text("kept indefinitely")
                    .font(.system(size: 9)).foregroundStyle(.tertiary)
            }
        }
        .padding(8)
        .frame(width: 132, alignment: .leading)
        .background(isSelected ? Color.accentColor.opacity(0.2) : Color.secondary.opacity(0.08),
                    in: RoundedRectangle(cornerRadius: 8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(isSelected ? Color.accentColor : .clear, lineWidth: 1.5)
        )
        .help("\(version.reason.displayName) · \(Format.fullTimestamp(version.capturedAt))")
    }

    /// A prompt that has been prepared but not yet sent anywhere.
    private struct PendingAnalysis: Identifiable {
        let id = UUID()
        let payload: AnalysisPrompt.Payload
        let fileName: String
    }

    @State private var pendingAnalysis: PendingAnalysis?
    @State private var isPreparingPrompt = false
    @State private var isParsingRecords = false

    @State private var previewOutcome: ContentVault.ContentOutcome?
    /// Which version the outcome belongs to. Nil means the decrypt for the
    /// current selection has not finished yet.
    @State private var previewLoadedForID: UUID?
    @State private var previewKind: PreviewKind = .binary
    @State private var previewComparisonData: Data?
    @State private var previewComparisonID: UUID?

    private var previewData: Data? {
        if case .data(let data) = previewOutcome { return data }
        return nil
    }

    /// Precomputed alongside the selected version, rather than decrypted during
    /// layout the way it used to be.
    private var comparisonText: String? {
        guard let previewComparisonData,
              FileSnapshot.looksTextual(previewComparisonData) else { return nil }
        return String(data: previewComparisonData, encoding: .utf8)
    }

    @ViewBuilder
    private func contentPane(_ group: SnapshotGroup) -> some View {
        Group {
            if let version = selectedVersion {
                if previewLoadedForID != version.id {
                    LoadingStateView(message: "Decrypting \(version.fileName)…",
                                     detail: "Version \(version.generation), \(Format.bytes(version.byteSize)).")
                } else {
                    switch previewOutcome {
                    case .data(let data):
                        loadedPane(version: version, data: data, group: group)
                    case .purged:
                        EmptyStateView(
                            symbol: "clock.badge.xmark",
                            title: "No longer stored",
                            message: "This version has passed its retention window or was removed to stay within the space limit. The record that the change happened is still in the audit log.")
                    case .unreadable, .none:
                        EmptyStateView(
                            symbol: "exclamationmark.triangle",
                            title: "Contents could not be read",
                            message: "The stored bytes are present but did not decrypt. This is worth investigating — use Integrity to check the rest of the vault.")
                    }
                }
            } else {
                EmptyStateView(symbol: "doc", title: "Select a version")
            }
        }
        .task(id: previewKey) { await loadPreview() }
    }

    @ViewBuilder
    private func loadedPane(version: FileSnapshot, data: Data, group: SnapshotGroup) -> some View {
        if previewKind.supportsTextDiff {
            TextVersionPane(
                version: version,
                text: String(data: data, encoding: .utf8) ?? "",
                comparison: comparisonText,
                comparisonLabel: compareAgainst.map { "v\($0.generation)" },
                onPickComparison: { pickComparison(group) },
                onOpenCopy: { openCopy(version) }
            )
        } else {
            MediaPreviewPane(
                version: version,
                data: data,
                kind: previewKind,
                comparison: comparisonPair,
                onPickComparison: group.versions.count > 1 ? { pickComparison(group) } : nil,
                onOpenCopy: { openCopy(version) }
            )
        }
    }

    /// The pair needed for a side-by-side image comparison, when both halves
    /// are available.
    private var comparisonPair: (version: FileSnapshot, data: Data)? {
        guard let other = compareAgainst, let data = previewComparisonData else { return nil }
        return (other, data)
    }

    /// Writes a decrypted copy to a private temporary file and opens it.
    private func openCopy(_ version: FileSnapshot) {
        guard let vault = model.contentVault else { return }
        Task {
            let url = await Task.detached(priority: .userInitiated) {
                vault.temporaryCopy(of: version)
            }.value
            guard let url else {
                message = "Could not write a copy of \(version.fileName)."
                messageIsError = true
                return
            }
            NSWorkspace.shared.open(url)
            message = "Opened a temporary copy of \(version.fileName). It is removed when HDWatcher quits."
            messageIsError = false
        }
    }

    private var previewKey: String {
        "\(selectedVersion?.id.uuidString ?? "-")|\(compareAgainst?.id.uuidString ?? "-")"
    }

    /// Decrypts the selected version and its comparison together, off the main
    /// thread. Both are real work: decrypt, decompress, and for text a diff.
    private func loadPreview() async {
        guard let version = selectedVersion, let vault = model.contentVault else {
            previewOutcome = nil
            previewComparisonData = nil
            previewLoadedForID = nil
            return
        }
        if previewLoadedForID == version.id && previewComparisonID == compareAgainst?.id { return }

        let other = compareAgainst
        let daemonVault = model.daemonContentVault
        let result = await Task.detached(priority: .userInitiated) {
            () -> (outcome: ContentVault.ContentOutcome, kind: PreviewKind, comparison: Data?) in
            // A version may live in either container depending on whether the
            // app or the daemon was running when it was captured.
            var outcome = vault.contentResult(of: version)
            if case .purged = outcome, let daemonVault {
                outcome = daemonVault.contentResult(of: version)
            }
            var kind = PreviewKind.binary
            if case .data(let data) = outcome {
                kind = PreviewKind.detect(data: data, fileName: version.fileName)
            }
            let comparison = other.flatMap { vault.content(of: $0) ?? daemonVault?.content(of: $0) }
            return (outcome, kind, comparison)
        }.value

        // Ignore a result that arrived after the user moved on.
        guard selectedVersion?.id == version.id else { return }
        previewOutcome = result.outcome
        previewKind = result.kind
        previewComparisonData = result.comparison
        previewLoadedForID = version.id
        previewComparisonID = other?.id
    }

    /// Parses the whole file and opens it in a window of its own. The preview
    /// pane is a column in a split view; a log of thousands of records needs
    /// more room than that.
    private func openRecords(of version: FileSnapshot) {
        guard let data = previewData else { return }
        isParsingRecords = true
        Task {
            let parsed = await Task.detached(priority: .userInitiated) {
                ParsedRecords.build(from: data, snapshot: version)
            }.value
            isParsingRecords = false
            guard let parsed else {
                message = "\(version.fileName) is not a record file."
                messageIsError = true
                return
            }
            RecordsWindow.present(parsed)
        }
    }

    /// Assembles the question about this file. Building it is local; the sheet
    /// that follows is where the user decides whether any of it leaves the
    /// machine.
    private func prepareAnalysis(of version: FileSnapshot) {
        guard let data = previewData else { return }
        isPreparingPrompt = true
        let kind = previewKind
        Task {
            let payload = await Task.detached(priority: .userInitiated) {
                AnalysisPrompt.describe(snapshot: version, data: data, kind: kind)
            }.value
            pendingAnalysis = PendingAnalysis(payload: payload, fileName: version.fileName)
            isPreparingPrompt = false
        }
    }

    private func send(_ analysis: PendingAnalysis) {
        pendingAnalysis = nil
        if let url = AnalysisPrompt.chatGPTURL(for: analysis.payload.text) {
            NSWorkspace.shared.open(url)
            message = "Opened ChatGPT with a description of \(analysis.fileName)."
        } else {
            // Too long for a URL. Copying keeps the whole prompt intact rather
            // than sending a silently truncated one.
            copy(analysis.payload.text)
            NSWorkspace.shared.open(URL(string: "https://chatgpt.com/")!)
            message = "The description of \(analysis.fileName) was too long for a link, so it is on the clipboard — paste it into ChatGPT."
        }
        messageIsError = false
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    /// Steps the comparison to the next other version.
    private func pickComparison(_ group: SnapshotGroup) {
        guard let current = selectedVersion else { return }
        let others = group.versions.filter { $0.id != current.id }
        guard !others.isEmpty else { return }
        if let index = others.firstIndex(where: { $0.id == compareAgainst?.id }) {
            compareAgainst = others.indices.contains(index + 1) ? others[index + 1] : others.first
        } else {
            compareAgainst = others.first
        }
    }

    // MARK: - Actions

    private var pollKey: String { "\(isPaused)|\(scope.rawValue)|\(searchText)" }

    private func reload(force: Bool = false) {
        let nameFilter = (searchIn == .names && !searchText.isEmpty) ? searchText : nil
        model.refreshRecovery(deletedOnly: scope == .deleted,
                              search: nameFilter,
                              force: force)
    }

    private func runContentSearch() {
        guard searchIn == .contents else {
            model.cancelContentSearch()
            return
        }
        model.searchContents(searchText, deletedOnly: scope == .deleted)
    }

    private func counterText(_ stats: ContentVaultStats) -> String {
        if isSearchingContents {
            let matched = Set(model.contentHits.map(\.snapshot.path)).count
            return "\(Format.count(matched)) files · \(Format.count(model.contentHits.count)) versions matched"
        }
        if searchText.isEmpty {
            return "\(stats.uniqueFileCount) files · \(stats.snapshotCount) versions · \(Format.bytes(stats.liveBytes))"
        }
        return "\(groups.count) of \(model.allRecoveryGroups.count) files"
    }

    /// Keeps the user's place across a background refresh. A live-updating list
    /// that moves the selection out from under you is worse than a static one.
    private func reconcileSelection() {
        guard !isSearchingContents else { return }
        if let selectedPath, !groups.contains(where: { $0.path == selectedPath }) {
            self.selectedPath = nil
            selectedVersion = nil
            compareAgainst = nil
            return
        }
        if selectedVersion == nil { selectedVersion = selectedGroup?.latest }
    }

    private func restore(_ snapshot: FileSnapshot, overwrite: Bool) {
        confirmingRestore = nil
        guard let vault = model.contentVault else { return }
        do {
            try vault.restore(snapshot, to: URL(fileURLWithPath: snapshot.path), overwrite: overwrite)
            message = "Restored \(snapshot.fileName) to \(snapshot.directory)."
            messageIsError = false
        } catch {
            message = "Could not restore: \(error.localizedDescription)"
            messageIsError = true
        }
    }

    private func exportCopy(_ snapshot: FileSnapshot) {
        confirmingRestore = nil
        guard let vault = model.contentVault else { return }
        let panel = NSSavePanel()
        panel.title = "Save a copy of \(snapshot.fileName)"
        panel.nameFieldStringValue = snapshot.fileName
        panel.message = "This writes the captured contents as an ordinary, unencrypted file."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try vault.restore(snapshot, to: url, overwrite: true)
            message = "Saved a copy to \(url.lastPathComponent)."
            messageIsError = false
        } catch {
            message = "Could not save: \(error.localizedDescription)"
            messageIsError = true
        }
    }

    private func shortDuration(_ interval: TimeInterval) -> String {
        if interval < 60 { return "\(Int(interval))s" }
        if interval < 3600 { return "\(Int(interval / 60))m" }
        if interval < 86_400 { return "\(Int(interval / 3600))h" }
        return "\(Int(interval / 86_400))d"
    }
}

/// One version whose contents matched, with the text around the match.
struct ContentHitRow: View {
    let hit: ContentSearchEngine.Hit
    let query: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Image(systemName: hit.snapshot.isDeleted ? "trash.circle.fill" : "doc.circle")
                    .foregroundStyle(hit.snapshot.isDeleted ? .red : .blue)
                Text(hit.snapshot.fileName)
                    .font(.callout.weight(.medium))
                    .lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 4)
                Text("\(hit.matchCount) match\(hit.matchCount == 1 ? "" : "es")")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            Text(Format.abbreviatePath(hit.snapshot.directory, maxComponents: 4))
                .font(.caption).foregroundStyle(.secondary)
                .lineLimit(1).truncationMode(.head)

            ForEach(Array(hit.snippets.prefix(2).enumerated()), id: \.offset) { _, snippet in
                highlighted(snippet)
                    .font(.system(size: 10, design: .monospaced))
                    .lineLimit(2)
                    .padding(.horizontal, 6).padding(.vertical, 3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 4))
            }

            HStack(spacing: 6) {
                Text("v\(hit.snapshot.generation)")
                    .font(.caption2.weight(.bold))
                Text(hit.source.rawValue)
                    .font(.caption2).foregroundStyle(.tertiary)
                Text(Format.relativeTime(hit.snapshot.capturedAt))
                    .font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 3)
        .help(hit.snapshot.path)
    }

    /// Picks the query out of the surrounding text, so the eye lands on the
    /// reason this row is here.
    private func highlighted(_ snippet: String) -> Text {
        guard !query.isEmpty,
              let range = snippet.range(of: query, options: .caseInsensitive) else {
            return Text(snippet).foregroundColor(.secondary)
        }
        return Text(snippet[snippet.startIndex..<range.lowerBound]).foregroundColor(.secondary)
            + Text(snippet[range]).foregroundColor(.primary).bold()
            + Text(snippet[range.upperBound...]).foregroundColor(.secondary)
    }
}

struct RecoveryGroupRow: View {
    let group: SnapshotGroup

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: group.isDeleted ? "trash.circle.fill" : "doc.circle")
                .font(.title3)
                .foregroundStyle(group.isDeleted ? .red : .blue)

            VStack(alignment: .leading, spacing: 1) {
                Text(group.fileName)
                    .font(.callout.weight(.medium))
                    .lineLimit(1).truncationMode(.middle)
                Text(Format.abbreviatePath(group.directory, maxComponents: 4))
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.head)
            }

            Spacer(minLength: 6)

            VStack(alignment: .trailing, spacing: 1) {
                Text("\(group.versions.count) version\(group.versions.count == 1 ? "" : "s")")
                    .font(.caption2).foregroundStyle(.secondary)
                if let deletedAt = group.deletedAt {
                    Text("deleted \(Format.relativeTime(deletedAt))")
                        .font(.caption2).foregroundStyle(.red)
                } else if let latest = group.latest {
                    Text(Format.relativeTime(latest.capturedAt))
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.vertical, 3)
        .help(group.path)
    }
}

/// Text preview with an optional diff against another version.
struct TextVersionPane: View {
    let version: FileSnapshot
    let text: String
    let comparison: String?
    let comparisonLabel: String?
    var onPickComparison: () -> Void
    var onOpenCopy: () -> Void

    @State private var showDiff = true
    @State private var diff: TextDiff.Result?
    @State private var isDiffing = false

    private var key: String {
        "\(version.id.uuidString)|\(comparison?.count ?? -1)|\(showDiff)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                if comparison != nil {
                    Toggle(isOn: $showDiff) {
                        Label(showDiff ? "Show changes" : "Whole file", systemImage: "plusminus")
                    }
                    .toggleStyle(.button)
                    .controlSize(.small)
                    .help("Switch between the differences and the complete contents")

                    Button(action: onPickComparison) {
                        Label("Compare with \(comparisonLabel ?? "…")", systemImage: "arrow.left.arrow.right")
                    }
                    .buttonStyle(.link).font(.caption)
                }

                if let diff, showDiff {
                    HStack(spacing: 8) {
                        Text("+\(diff.addedCount)").foregroundStyle(.green)
                        Text("−\(diff.removedCount)").foregroundStyle(.red)
                        if diff.truncated {
                            Text("(clipped)").foregroundStyle(.tertiary)
                        }
                    }
                    .font(.caption.monospacedDigit().weight(.medium))
                }

                Spacer()
                Text("\(Format.bytes(version.byteSize)) · captured \(Format.fullTimestamp(version.capturedAt))")
                    .font(.caption2).foregroundStyle(.tertiary)
                Button(action: onOpenCopy) {
                    Label("Open a Copy", systemImage: "arrow.up.forward.app")
                }
                .controlSize(.small)
            }
            .padding(.horizontal, 14).padding(.vertical, 7)

            Divider()

            if isDiffing {
                InlineLoadingView(message: "Comparing versions…")
            } else if let diff, diff.hasChanges {
                DiffScrollView(lines: TextDiff.condense(diff, context: 3))
            } else {
                PlainTextScrollView(text: text)
            }
        }
        // A diff over two large files is real work, so it never runs on the
        // main thread — the pane shows the file until the comparison lands.
        .task(id: key) {
            guard showDiff, let comparison else { diff = nil; return }
            isDiffing = true
            defer { isDiffing = false }
            let mine = text
            diff = await Task.detached(priority: .userInitiated) {
                TextDiff.compare(comparison, mine)
            }.value
        }
    }
}

/// Confirms what is about to be sent to ChatGPT, and shows all of it.
///
/// This is the one place in the app where captured contents leave the machine.
/// Everything else here is encrypted at rest and never transmitted, so the
/// exact text is shown in full, in advance, with an option to take it to the
/// clipboard instead and decide later.
struct AnalysisSheet: View {
    let fileName: String
    let payload: AnalysisPrompt.Payload
    var onSend: () -> Void
    var onCopy: () -> Void
    var onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: "sparkles").foregroundStyle(.purple)
                    Text("Ask ChatGPT about \(fileName)")
                        .font(.headline)
                    Spacer()
                }
                Label {
                    Text("This sends the text below — including part of the file's contents — to OpenAI. Nothing has left this Mac yet.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                Text(payload.truncated
                     ? "About \(Format.bytes(Int64(payload.includedBytes))) of the file is included; the rest is left out."
                     : "The whole file is included (\(Format.bytes(Int64(payload.includedBytes)))).")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
            .padding(16)

            Divider()

            ScrollView {
                Text(payload.text)
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(14)
            }
            .background(.quaternary.opacity(0.2))

            Divider()

            HStack {
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.escape)
                Spacer()
                Button("Copy Instead", action: onCopy)
                Button("Open ChatGPT", action: onSend)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 680, height: 560)
    }
}
