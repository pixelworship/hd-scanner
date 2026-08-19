import SwiftUI
import HDWatcherCore

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            switch model.phase {
            case .loading:
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            case .setup:
                SetupView()
            case .locked:
                LockView()
            case .unlocked:
                MainView()
            }
        }
        .animation(.easeInOut(duration: 0.25), value: model.phase)
    }
}

/// Shared visual treatment for the two pre-unlock screens.
struct VaultBackdrop<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(nsColor: .windowBackgroundColor),
                         Color.accentColor.opacity(0.10)],
                startPoint: .top, endPoint: .bottom
            )
            .ignoresSafeArea()

            content
                .frame(maxWidth: 460)
                .padding(40)
        }
    }
}

struct AppMark: View {
    var subtitle: String

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "externaldrive.badge.timemachine")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(.tint)
            Text("HDWatcher")
                .font(.largeTitle.weight(.semibold))
            Text(subtitle)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
    }
}
