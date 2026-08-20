import Foundation

/// Who is actually recording, and what they are watching.
///
/// Two things can record: this app's own engine, and the privileged daemon.
/// Normally it is the daemon — that is the point of it — and the app is a
/// viewer. Reporting coverage from the app's engine in that state produces the
/// worst possible answer: "Not watching anything" on a Mac that is being
/// watched continuously, from boot, by a root process the same screen shows as
/// healthy two panels further down.
///
/// So coverage is asked of whoever holds the FSEvents stream.
public struct CoverageReport: Sendable, Equatable {

    public enum Recorder: String, Sendable {
        case daemon
        case app
        case none

        public var displayName: String {
            switch self {
            case .daemon: return "the background daemon"
            case .app:    return "this app"
            case .none:   return "nothing"
            }
        }
    }

    public let recorder: Recorder
    public let watchedPaths: [String]
    public let startedAt: Date?

    public var isRecording: Bool { recorder != .none }

    /// True when the recording survives this app being closed.
    public var survivesQuitting: Bool { recorder == .daemon }

    public static func resolve(agent: AgentStatus?, engine: WatcherEngine.Status) -> CoverageReport {
        // The daemon is authoritative whenever it is alive and recording: the
        // app's own engine deliberately stands down in that case rather than
        // watching the same tree twice.
        if let agent, agent.isAlive, agent.isMonitoring {
            return CoverageReport(recorder: .daemon,
                                  watchedPaths: agent.watchedPaths,
                                  startedAt: agent.startedAt)
        }
        if engine.isMonitoring {
            return CoverageReport(recorder: .app,
                                  watchedPaths: engine.watchedPaths,
                                  startedAt: engine.startedAt)
        }
        // A daemon that is alive but paused still says more than nothing: its
        // roots are what would be watched the moment it resumes.
        if let agent, agent.isAlive {
            return CoverageReport(recorder: .none,
                                  watchedPaths: agent.watchedPaths,
                                  startedAt: nil)
        }
        return CoverageReport(recorder: .none, watchedPaths: [], startedAt: nil)
    }

    /// Whether a volume is covered by these roots.
    public func covers(mountPath: String) -> Bool {
        watchedPaths.contains { root in
            root == "/" || mountPath == root || mountPath.hasPrefix(root + "/")
        }
    }
}
