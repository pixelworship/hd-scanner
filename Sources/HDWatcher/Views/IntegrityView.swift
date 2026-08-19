import SwiftUI
import HDWatcherCore

/// Verifies the hash chain over every segment. This is the screen that answers
/// "has anyone edited my audit log?".
struct IntegrityView: View {
    @Environment(AppModel.self) private var model

    @State private var report: IntegrityReport?
    @State private var isVerifying = false

    private var manifest: LogManifest? { model.store?.currentManifest }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                summaryCard

                if isVerifying {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionHeader(title: "Segment results")
                        InlineLoadingView(message: "Re-reading and re-checking every segment…")
                    }
                    .card()
                } else if let report {
                    resultsCard(report)
                }

                storageCard
                explanationCard
            }
            .padding(18)
        }
    }

    private var summaryCard: some View {
        HStack(spacing: 14) {
            Image(systemName: statusSymbol)
                .font(.system(size: 34))
                .foregroundStyle(statusColor)

            VStack(alignment: .leading, spacing: 3) {
                Text(statusTitle).font(.title3.weight(.semibold))
                Text(statusDetail)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 8)

            Button {
                verify()
            } label: {
                HStack {
                    if isVerifying { ProgressView().controlSize(.small) }
                    Text(isVerifying ? "Verifying…" : "Verify Now")
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(isVerifying)
        }
        .card()
    }

    private var statusSymbol: String {
        guard let report else { return "shield.lefthalf.filled" }
        return report.isIntact ? "checkmark.seal.fill" : "exclamationmark.triangle.fill"
    }

    private var statusColor: Color {
        guard let report else { return .secondary }
        return report.isIntact ? .green : .red
    }

    private var statusTitle: String {
        guard let report else { return "Not yet verified" }
        return report.isIntact ? "Log is intact" : "Tampering detected"
    }

    private var statusDetail: String {
        guard let report else {
            return "Run a verification to recompute the hash chain across every encrypted segment."
        }
        if report.isIntact {
            return "Verified \(report.totalBlocks) blocks across \(report.results.count) segments at \(Format.timeOfDay(report.checkedAt)). Every block's MAC matches, and the chain is unbroken."
        }
        var problems: [String] = []
        let broken = report.results.filter { !$0.ok }.count
        if broken > 0 { problems.append("\(broken) segment(s) failed verification") }
        if !report.missingSegments.isEmpty { problems.append("\(report.missingSegments.count) segment file(s) missing") }
        if !report.unexpectedFiles.isEmpty { problems.append("\(report.unexpectedFiles.count) unrecognised file(s) present") }
        return problems.joined(separator: " · ")
    }

    private func resultsCard(_ report: IntegrityReport) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Segment results")

            ForEach(report.results) { result in
                HStack(alignment: .top, spacing: 9) {
                    Image(systemName: result.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                        .foregroundStyle(result.ok ? .green : .red)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(result.fileName).font(.callout.monospaced())
                        Text("\(result.blocksVerified) of \(result.expectedBlocks) blocks verified")
                            .font(.caption).foregroundStyle(.secondary)
                        if let problem = result.problem {
                            Text(problem).font(.caption).foregroundStyle(.red)
                        }
                    }
                    Spacer()
                }
                .padding(.vertical, 3)
            }

            if !report.missingSegments.isEmpty {
                Divider()
                Text("Missing segment files").font(.caption.weight(.medium)).foregroundStyle(.red)
                ForEach(report.missingSegments, id: \.self) { name in
                    Text(name).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
            if !report.unexpectedFiles.isEmpty {
                Divider()
                Text("Files not listed in the manifest")
                    .font(.caption.weight(.medium)).foregroundStyle(.orange)
                ForEach(report.unexpectedFiles, id: \.self) { name in
                    Text(name).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
        }
        .card()
    }

    private var storageCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Encrypted storage")
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                row("Events on disk", Format.count(manifest?.totalEvents ?? 0))
                row("Segments", "\(manifest?.segments.count ?? 0)")
                row("Total size", Format.bytes(manifest?.totalBytes ?? 0))
                if let oldest = manifest?.oldestEvent {
                    row("Oldest event", Format.fullTimestamp(oldest))
                }
                if let newest = manifest?.newestEvent {
                    row("Newest event", Format.fullTimestamp(newest))
                }
                row("Protection", model.protectionTier.displayName)
                row("Location", AppPaths.logDirectory.path)
            }
        }
        .card()
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout).textSelection(.enabled)
        }
    }

    private var explanationCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionHeader(title: "How verification works")
            Text("""
            Events are written in compressed blocks, each sealed with AES-256-GCM. \
            Every block carries an HMAC computed over the previous block's MAC, its own position \
            and a digest of its ciphertext — so the segments form a hash chain.

            Editing a block breaks its MAC. Reordering blocks breaks the position binding. \
            Deleting blocks from the end is caught by comparing against the recorded block count, \
            and deleting a whole segment is caught because the manifest still lists it and the next \
            segment's chain no longer lines up.

            All of this depends on the integrity key, which is derived from your master key. Someone \
            without the password cannot forge a valid chain.
            """)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        .card()
    }

    private func verify() {
        isVerifying = true
        Task {
            // Reads and re-MACs the whole log; would freeze the window if it ran
            // on the main thread.
            let result = await model.verifyIntegrityAsync()
            report = result
            isVerifying = false
        }
    }
}
