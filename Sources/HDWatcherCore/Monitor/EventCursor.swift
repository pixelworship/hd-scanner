import Foundation
import CryptoKit

/// Remembers how far through the FSEvents stream we have read.
///
/// Without this, every start passes `kFSEventStreamEventIdSinceNow` and anything
/// that happened while the watcher was down is lost for good — a silent hole in
/// an audit trail. fseventsd keeps a journal per volume, so handing it the last
/// ID we saw makes it replay the intervening changes instead.
///
/// The file holds a single opaque counter and a timestamp. There is nothing
/// sensitive in it, which is deliberate: it has to be readable at startup,
/// before any vault is unlocked.
public struct EventCursor: Codable, Sendable {
    public var lastEventID: UInt64
    public var savedAt: Date
    /// When the watcher last stopped cleanly, so a gap can be described.
    public var stoppedAt: Date?

    public init(lastEventID: UInt64 = 0, savedAt: Date = Date(), stoppedAt: Date? = nil) {
        self.lastEventID = lastEventID
        self.savedAt = savedAt
        self.stoppedAt = stoppedAt
    }

    public static var fileURL: URL {
        AppPaths.supportDirectory.appendingPathComponent("cursor.enc")
    }

    /// Sealed like everything else. A bare event id and timestamp would still
    /// disclose when the machine was active and for how long it was not being
    /// watched, which is exactly the sort of thing an intruder would like to
    /// know.
    public static func load(settingsKey: SymmetricKey? = nil) -> EventCursor? {
        guard let sealed = try? Data(contentsOf: fileURL) else { return nil }
        let plaintext: Data?
        if let settingsKey {
            plaintext = try? CryptoPrimitives.open(sealed, key: settingsKey,
                                                   aad: Data("hdwatcher.cursor".utf8))
        } else {
            plaintext = DaemonIdentity.open(sealed, context: "hdwatcher.cursor")
        }
        guard let plaintext else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(EventCursor.self, from: plaintext)
    }

    public func save(settingsKey: SymmetricKey? = nil) {
        AppPaths.ensureDirectories()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        guard let plaintext = try? encoder.encode(self) else { return }

        let sealed: Data?
        if let settingsKey {
            sealed = try? CryptoPrimitives.seal(plaintext, key: settingsKey,
                                                aad: Data("hdwatcher.cursor".utf8))
        } else {
            sealed = DaemonIdentity.seal(plaintext, context: "hdwatcher.cursor")
        }
        guard let sealed else { return }
        try? sealed.write(to: Self.fileURL, options: [.atomic])
        try? FileManager.default.setAttributes(
            [.posixPermissions: AppPaths.filePermissions],
            ofItemAtPath: Self.fileURL.path)
    }

    /// How long the watcher was not running, if it can be determined.
    public var gapDuration: TimeInterval? {
        guard let stoppedAt else { return nil }
        return max(0, Date().timeIntervalSince(stoppedAt))
    }
}
