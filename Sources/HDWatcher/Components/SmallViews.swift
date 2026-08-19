import SwiftUI
import HDWatcherCore

struct SeverityBadge: View {
    let severity: Severity
    var compact = false

    var body: some View {
        Label {
            if !compact { Text(severity.displayName) }
        } icon: {
            Image(systemName: severity.symbol)
        }
        .labelStyle(.titleAndIcon)
        .font(.caption.weight(.medium))
        .foregroundStyle(severity.color)
        .padding(.horizontal, compact ? 4 : 7)
        .padding(.vertical, 3)
        .background(severity.color.opacity(0.15), in: Capsule())
    }
}

struct KindBadge: View {
    let kind: EventKind

    var body: some View {
        Label(kind.displayName, systemImage: kind.symbolName)
            .font(.caption.weight(.medium))
            .foregroundStyle(kind.tint)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(kind.tint.opacity(0.15), in: Capsule())
            .fixedSize()
    }
}

struct ConfidenceBadge: View {
    let confidence: Confidence

    var body: some View {
        if confidence != .none {
            Text(confidence.displayName)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(confidence.color)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .overlay(Capsule().strokeBorder(confidence.color.opacity(0.5), lineWidth: 1))
        }
    }
}

struct StatTile: View {
    let title: String
    let value: String
    var caption: String?
    var symbol: String
    var tint: Color = .accentColor

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(tint)
                .frame(width: 34, height: 34)
                .background(tint.opacity(0.15), in: RoundedRectangle(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 1) {
                Text(value)
                    .font(.title3.weight(.semibold))
                    .monospacedDigit()
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let caption {
                    Text(caption).font(.caption2).foregroundStyle(.tertiary)
                }
            }
            Spacer(minLength: 0)
        }
        .card(padding: 12)
    }
}

/// Compact activity chart. Bars are drawn directly rather than through Charts so
/// the dashboard stays light even when it redraws every couple of seconds.
struct Sparkline: View {
    let values: [Double]
    var tint: Color = .accentColor
    var showsBaseline = true

    var body: some View {
        GeometryReader { geo in
            let peak = max(values.max() ?? 1, 1)
            let count = max(values.count, 1)
            let barWidth = geo.size.width / CGFloat(count)

            ZStack(alignment: .bottom) {
                if showsBaseline {
                    Rectangle()
                        .fill(.quaternary)
                        .frame(height: 1)
                        .frame(maxHeight: .infinity, alignment: .bottom)
                }
                HStack(alignment: .bottom, spacing: max(0, barWidth * 0.15)) {
                    ForEach(Array(values.enumerated()), id: \.offset) { _, value in
                        let fraction = value / peak
                        RoundedRectangle(cornerRadius: 1)
                            .fill(tint.opacity(value > 0 ? 0.85 : 0.15))
                            .frame(height: max(1, geo.size.height * fraction))
                    }
                }
            }
        }
    }
}

/// Shown while data is still being fetched.
///
/// The distinction from `EmptyStateView` matters: "no transfers detected" and
/// "still decrypting the log" look identical to a user but mean opposite
/// things, and claiming the former while the latter is true is a lie the
/// interface tells about its own data.
struct LoadingStateView: View {
    var message: String
    var detail: String?

    var body: some View {
        VStack(spacing: 10) {
            ProgressView()
                .controlSize(.large)
            Text(message)
                .font(.headline)
                .foregroundStyle(.secondary)
            if let detail {
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

/// Compact form, for a card that is part of a larger screen.
struct InlineLoadingView: View {
    var message: String

    var body: some View {
        HStack(spacing: 7) {
            ProgressView().controlSize(.small)
            Text(message).font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 12)
    }
}

struct EmptyStateView: View {
    let symbol: String
    let title: String
    var message: String?

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 34))
                .foregroundStyle(.tertiary)
            Text(title).font(.headline).foregroundStyle(.secondary)
            if let message {
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(40)
    }
}

/// A path rendered so the filename stays readable even when the row is narrow.
struct PathLabel: View {
    let path: String
    var showsDirectory = true

    private var directory: String { (path as NSString).deletingLastPathComponent }
    private var name: String { (path as NSString).lastPathComponent }

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(name)
                .font(.system(.body, design: .monospaced))
                .lineLimit(1)
                .truncationMode(.middle)
            if showsDirectory, !directory.isEmpty {
                Text(directory)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.head)
            }
        }
        .help(path)
    }
}

struct VolumeChip: View {
    let volume: VolumeInfo?
    var fallback: String = "—"

    var body: some View {
        if let volume {
            Label(volume.name, systemImage: volume.volumeClass.symbolName)
                .font(.caption)
                .foregroundStyle(volume.volumeClass.tint)
                .lineLimit(1)
        } else {
            Text(fallback).font(.caption).foregroundStyle(.tertiary)
        }
    }
}
