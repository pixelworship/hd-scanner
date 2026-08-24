import Foundation

/// Decides whether the Reads list should start a query, wait for the one
/// already running, or do nothing.
///
/// This exists because the same bug shipped twice. The list polls every couple
/// of seconds; the query over a large log takes longer than that; and both
/// attempts at an inline guard compared against state that is only written when
/// a pass *completes* — so from a cold start every poll cancelled the running
/// query and the list never appeared. The rule that matters is written here
/// once, where it can be tested: **an identical pass already in flight is never
/// cancelled.**
public struct ReadsRefreshGate: Sendable, Equatable {

    public enum Decision: Equatable, Sendable {
        /// Begin a pass (cancelling any in-flight pass for a *different* query).
        case start
        /// The same query is already being computed; let it finish.
        case waitForRunning
        /// The results on screen are already current.
        case skip
    }

    private var runningSignature: String?
    private var completedSignature: String?

    public init() {}

    /// Note what is deliberately absent: any notion of "new data has arrived".
    /// A full pass over a real log was measured at three minutes; re-running it
    /// because the event count moved would mean permanent background scanning.
    /// New reads reach the list incrementally from the live event stream — a
    /// completed pass is rescanned only when the query itself changes.
    public mutating func decide(signature: String, force: Bool = false) -> Decision {
        if let running = runningSignature {
            if running == signature && !force { return .waitForRunning }
            runningSignature = signature
            return .start
        }
        if !force, signature == completedSignature { return .skip }
        runningSignature = signature
        return .start
    }

    /// Records a pass that delivered results to the screen.
    public mutating func finished(signature: String) {
        completedSignature = signature
        if runningSignature == signature { runningSignature = nil }
    }

    /// Records a pass that was abandoned; the work is still outstanding.
    public mutating func cancelled(signature: String) {
        if runningSignature == signature { runningSignature = nil }
    }

    public var isRunning: Bool { runningSignature != nil }
}
