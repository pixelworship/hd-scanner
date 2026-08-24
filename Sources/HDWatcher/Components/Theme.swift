import SwiftUI
import HDWatcherCore

extension Severity {
    var color: Color {
        switch self {
        case .trace:    return .secondary
        case .info:     return .blue
        case .notice:   return .yellow
        case .warning:  return .orange
        case .critical: return .red
        }
    }

    var symbol: String {
        switch self {
        case .trace:    return "circle.dotted"
        case .info:     return "info.circle"
        case .notice:   return "exclamationmark.circle"
        case .warning:  return "exclamationmark.triangle"
        case .critical: return "exclamationmark.octagon"
        }
    }
}

extension EventKind {
    var tint: Color {
        switch self {
        case .created, .cloned:      return .green
        case .modified:              return .blue
        case .removed:               return .red
        case .renamed:               return .purple
        case .metadata:              return .secondary
        case .read:                  return .cyan
        case .mounted:               return .teal
        case .unmounted:             return .brown
        case .copiedOut, .movedOut:  return .orange
        case .copiedIn, .movedIn:    return .indigo
        case .rescan:                return .yellow
        case .monitoringStarted:     return .mint
        case .monitoringStopped:     return .gray
        case .tamperDetected:        return .red
        }
    }
}

extension VolumeClass {
    var tint: Color {
        switch self {
        case .internalDisk: return .blue
        case .externalDisk: return .orange
        case .removable:    return .pink
        case .network:      return .teal
        case .diskImage:    return .purple
        case .unknown:      return .secondary
        }
    }
}

extension Confidence {
    var color: Color {
        switch self {
        case .none:    return .secondary
        case .low:     return .yellow
        case .medium:  return .orange
        case .high:    return .green
        case .certain: return .mint
        }
    }
}

/// A soft, rounded container used for every card on the dashboard.
struct CardBackground: ViewModifier {
    var padding: CGFloat = 16
    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .strokeBorder(.quaternary.opacity(0.5), lineWidth: 0.5)
            )
    }
}

extension View {
    func card(padding: CGFloat = 16) -> some View {
        modifier(CardBackground(padding: padding))
    }
}

struct SectionHeader: View {
    let title: String
    var subtitle: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.headline)
            if let subtitle {
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
