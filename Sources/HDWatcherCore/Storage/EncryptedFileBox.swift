import Foundation
import CryptoKit

/// Reads and writes a single `Codable` value as an AES-GCM sealed file.
/// Used for settings, rules, alert history, the segment manifest and stats —
/// everything the app persists outside the event log itself.
public enum EncryptedFileBox {

    private static func makeEncoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .secondsSince1970
        return e
    }

    private static func makeDecoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .secondsSince1970
        return d
    }

    public static func write<T: Encodable>(_ value: T, to url: URL, key: SymmetricKey, context: String) throws {
        let plaintext = try makeEncoder().encode(value)
        let compressed = LogFormat.compress(plaintext) ?? plaintext
        var payload = Data()
        payload.appendLE(UInt32(plaintext.count))
        payload.appendLE(UInt8(compressed.count < plaintext.count ? 1 : 0))
        payload.append(compressed.count < plaintext.count ? compressed : plaintext)

        let sealed = try CryptoPrimitives.seal(payload, key: key, aad: Data(context.utf8))
        // Write via a temporary file so a crash mid-write cannot corrupt the
        // existing copy.
        let tmp = url.appendingPathExtension("tmp")
        try sealed.write(to: tmp, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: AppPaths.filePermissions],
                                               ofItemAtPath: tmp.path)
        if FileManager.default.fileExists(atPath: url.path) {
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
        } else {
            try FileManager.default.moveItem(at: tmp, to: url)
        }
        try? FileManager.default.setAttributes([.posixPermissions: AppPaths.filePermissions],
                                               ofItemAtPath: url.path)
    }

    public static func read<T: Decodable>(_ type: T.Type, from url: URL, key: SymmetricKey, context: String) throws -> T? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let sealed = try Data(contentsOf: url)
        let payload = try CryptoPrimitives.open(sealed, key: key, aad: Data(context.utf8))
        guard let originalSize: UInt32 = payload.readLE(at: 0),
              payload.count > 5 else {
            throw CryptoError.vaultCorrupt("short payload in \(url.lastPathComponent)")
        }
        let isCompressed = payload[payload.startIndex + 4] == 1
        let body = payload.subdata(in: (payload.startIndex + 5)..<payload.endIndex)
        let plaintext: Data
        if isCompressed {
            guard let out = LogFormat.decompress(body, expectedSize: Int(originalSize)) else {
                throw CryptoError.vaultCorrupt("decompression failed in \(url.lastPathComponent)")
            }
            plaintext = out
        } else {
            plaintext = body
        }
        return try makeDecoder().decode(T.self, from: plaintext)
    }
}
