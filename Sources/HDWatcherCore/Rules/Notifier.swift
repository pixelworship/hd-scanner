import Foundation
import UserNotifications
import AppKit

/// Delivers alerts to Notification Center, degrading gracefully when the app is
/// not in a state where the system will accept notifications (which is common
/// for ad-hoc signed builds run outside /Applications).
public final class Notifier: @unchecked Sendable {

    public enum Availability: String, Sendable {
        case unknown = "Not yet requested"
        case authorized = "Enabled"
        case denied = "Denied in System Settings"
        case unavailable = "Unavailable for this build"
    }

    private let mutex = NSLock()
    private var availability: Availability = .unknown
    private var center: UNUserNotificationCenter?

    /// Mirrors every delivered alert so the in-app feed still works when system
    /// notifications are unavailable.
    public var onAlertPosted: (@Sendable (SecurityAlert) -> Void)?

    public init() {
        // UNUserNotificationCenter.current() raises an uncatchable exception
        // unless the process is a real .app bundle — having a bundle identifier
        // is not enough, as a test runner or CLI invocation shows.
        let bundle = Bundle.main
        let isApplicationBundle = bundle.bundleURL.pathExtension == "app"
            && bundle.bundleIdentifier != nil
            && bundle.infoDictionary?["CFBundleExecutable"] != nil

        if isApplicationBundle {
            center = UNUserNotificationCenter.current()
        } else {
            availability = .unavailable
        }
    }

    public var status: Availability {
        mutex.lock(); defer { mutex.unlock() }
        return availability
    }

    public func requestAuthorization() {
        guard let center else { return }
        center.requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, _ in
            guard let self else { return }
            self.mutex.lock()
            self.availability = granted ? .authorized : .denied
            self.mutex.unlock()
        }
    }

    public func refreshStatus(_ completion: (@Sendable (Availability) -> Void)? = nil) {
        guard let center else { completion?(.unavailable); return }
        center.getNotificationSettings { [weak self] settings in
            guard let self else { return }
            let value: Availability
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral: value = .authorized
            case .denied:                               value = .denied
            case .notDetermined:                        value = .unknown
            @unknown default:                           value = .unknown
            }
            self.mutex.lock(); self.availability = value; self.mutex.unlock()
            completion?(value)
        }
    }

    public func post(_ alert: SecurityAlert) {
        onAlertPosted?(alert)

        if alert.severity >= .warning {
            NSSound(named: alert.severity == .critical ? "Basso" : "Funk")?.play()
        }

        guard let center, status != .denied else { return }

        let content = UNMutableNotificationContent()
        content.title = alert.title
        content.body = alert.detail
        content.sound = alert.severity >= .warning ? .defaultCritical : .default
        content.threadIdentifier = alert.ruleID.uuidString
        if alert.severity == .critical {
            content.interruptionLevel = .timeSensitive
        }

        let request = UNNotificationRequest(
            identifier: alert.id.uuidString,
            content: content,
            trigger: nil
        )
        center.add(request, withCompletionHandler: nil)
    }

    /// Fires the rule's optional webhook. Opt-in per rule and never enabled by
    /// default, since it sends path names off the machine.
    public func deliverWebhook(_ alert: SecurityAlert, urlString: String) {
        guard let url = URL(string: urlString), url.scheme == "https" else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 10

        let payload: [String: Any] = [
            "rule": alert.ruleName,
            "severity": alert.severity.displayName,
            "title": alert.title,
            "detail": alert.detail,
            "timestamp": ISO8601DateFormatter().string(from: alert.timestamp),
            "path": alert.event?.path ?? "",
            "sourcePath": alert.event?.sourcePath ?? "",
            "matchCount": alert.matchCount
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        URLSession.shared.dataTask(with: request).resume()
    }
}
