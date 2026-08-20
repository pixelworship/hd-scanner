import SwiftUI
import AppKit
import HDWatcherCore

@main
struct HDWatcherApp: App {
    @State private var model = AppModel()
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        Window("HDWatcher", id: "main") {
            RootView()
                .environment(model)
                .frame(minWidth: 1040, minHeight: 660)
                .onAppear { appDelegate.model = model }
        }
        .defaultSize(width: 1280, height: 820)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Monitor") {
                Button(model.isMonitoring ? "Pause Monitoring" : "Resume Monitoring") {
                    model.toggleMonitoring()
                }
                .keyboardShortcut("m", modifiers: [.command, .shift])
                .disabled(model.phase != .unlocked)

                Divider()

                Button("Lock Vault") { model.lock() }
                    .keyboardShortcut("l", modifiers: [.command, .control])
                    .disabled(model.phase != .unlocked)
            }
        }

        MenuBarExtra("HDWatcher", systemImage: menuBarSymbol, isInserted: .constant(true)) {
            MenuBarContent().environment(model)
        }
        .menuBarExtraStyle(.menu)
    }

    private var menuBarSymbol: String {
        switch model.phase {
        case .unlocked: return model.isMonitoring ? "eye.fill" : "eye.slash"
        default:        return "lock.fill"
        }
    }
}

/// Handles termination so buffered events are flushed and keys are dropped.
final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated {
            model?.shutdown()
        }
    }
}

struct MenuBarContent: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if model.phase == .unlocked {
            Text(model.isViewerMode
                 ? "Recording in the background"
                 : (model.isMonitoring ? "Monitoring \(model.coverage.watchedPaths.count) path(s)" : "Paused"))
            Text("\(model.recordingSummary) · \(model.unacknowledgedAlertCount) new alerts")
            Divider()
            if !model.isViewerMode {
                Button(model.status.isMonitoring ? "Pause Monitoring" : "Resume Monitoring") {
                    model.toggleMonitoring()
                }
            }
            Button("Lock Vault") { model.lock() }
        } else {
            Text("Vault locked")
        }
        Divider()
        Button("Open HDWatcher") {
            NSApp.activate(ignoringOtherApps: true)
            openWindow(id: "main")
        }
        Button("Quit HDWatcher") { NSApp.terminate(nil) }
    }
}
