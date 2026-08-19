import Foundation
import Compression

/// Decompresses gzip streams.
///
/// Logs and exported data are routinely stored gzipped, and a compressed file
/// is opaque to every other reading — no strings, no structure, nothing. What
/// is inside is usually text or JSON that reads perfectly well once expanded.
///
/// The system compression library speaks raw DEFLATE rather than gzip, so the
/// header and its optional fields are parsed off the front here.
public enum Gunzip {

    public static func detect(_ data: Data) -> Bool {
        data.count > 18 && data[data.startIndex] == 0x1F && data[data.startIndex + 1] == 0x8B
    }

    public static func inflate(_ data: Data, limit: Int = 64 * 1024 * 1024) -> Data? {
        guard detect(data), data[data.startIndex + 2] == 8 else { return nil }

        let flags = data[data.startIndex + 3]
        var cursor = data.startIndex + 10

        func skipZeroTerminated() {
            while cursor < data.endIndex, data[cursor] != 0 { cursor += 1 }
            cursor += 1
        }
        if flags & 0x04 != 0 {                       // extra field
            guard cursor + 2 <= data.endIndex else { return nil }
            let length = Int(data[cursor]) | Int(data[cursor + 1]) << 8
            cursor += 2 + length
        }
        if flags & 0x08 != 0 { skipZeroTerminated() }   // original file name
        if flags & 0x10 != 0 { skipZeroTerminated() }   // comment
        if flags & 0x02 != 0 { cursor += 2 }            // header CRC
        guard cursor < data.endIndex - 8 else { return nil }

        let payload = data[cursor..<(data.endIndex - 8)]
        // The gzip trailer records the uncompressed size modulo 2^32, which is
        // a hint for sizing the buffer rather than something to trust.
        let trailer = data.suffix(4)
        var expected = 0
        for (index, byte) in trailer.enumerated() { expected |= Int(byte) << (8 * index) }
        let capacity = min(max(expected, payload.count * 4, 64 * 1024), limit)

        var output = Data()
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        defer { buffer.deallocate() }

        let written = payload.withUnsafeBytes { raw -> Int in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return compression_decode_buffer(buffer, capacity, base, payload.count,
                                             nil, COMPRESSION_ZLIB)
        }
        guard written > 0 else { return nil }
        output.append(buffer, count: written)
        return output
    }
}

/// Pretty-prints JSON.
public enum JSONReader {

    public static func detect(_ data: Data) -> Bool {
        guard let first = data.first(where: { !($0 == 0x20 || $0 == 0x09 || $0 == 0x0A || $0 == 0x0D) })
        else { return false }
        return first == 0x7B || first == 0x5B      // { or [
    }

    public static func read(_ data: Data) -> String? {
        guard detect(data),
              let object = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]),
              let pretty = try? JSONSerialization.data(withJSONObject: object,
                                                       options: [.prettyPrinted, .sortedKeys,
                                                                 .withoutEscapingSlashes])
        else { return nil }
        return String(data: pretty, encoding: .utf8)
    }
}
