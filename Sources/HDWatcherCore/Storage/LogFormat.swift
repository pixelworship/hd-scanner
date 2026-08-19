import Foundation
import Compression

/// On-disk layout for encrypted log segments.
///
/// A segment file is:
///
///     [ 56-byte header ][ block ][ block ] ...
///
/// and each block is:
///
///     u32 payloadLength | u32 blockIndex | AES-GCM payload | 32-byte chain MAC
///
/// The payload is LZFSE-compressed JSON sealed with the log subkey, using the
/// segment ID and block index as additional authenticated data — so a block
/// cannot be silently reordered or transplanted into another segment. The chain
/// MAC links each block to its predecessor, which makes deletion or rewriting of
/// history detectable during verification.
public enum LogFormat {
    public static let magic: [UInt8] = Array("HDWSEG".utf8) + [0x01, 0x00]
    /// v1: sealed with keys derived from the master key (written by the app).
    /// v2: sealed to the ingest public key (written by the background agent,
    ///     which cannot read back what it writes).
    public static let version: UInt16 = 1
    public static let agentVersion: UInt16 = 2
    public static let headerSize = 56
    /// v2 carries the segment's ephemeral public key after the common prefix.
    public static let agentHeaderSize = 128
    public static let macSize = 32
    public static let flagCompressed: UInt16 = 1 << 0

    /// Header length for a given version — the reader must branch on this
    /// before it can locate the first block.
    public static func headerSize(forVersion version: UInt16) -> Int {
        version >= agentVersion ? agentHeaderSize : headerSize
    }

    public struct SegmentHeader {
        public var version: UInt16
        public var flags: UInt16
        public var segmentIndex: UInt32
        public var createdAt: Date
        public var segmentID: Data   // 16 random bytes, used as AAD
        /// Present only in v2: the ephemeral public key whose ECDH with the
        /// ingest key yields this segment's keys.
        public var ephemeralPublicKey: Data?

        public var isAgentWritten: Bool { version >= LogFormat.agentVersion }

        public init(version: UInt16 = LogFormat.version,
                    flags: UInt16 = LogFormat.flagCompressed,
                    segmentIndex: UInt32,
                    createdAt: Date = Date(),
                    segmentID: Data = CryptoPrimitives.randomBytes(16),
                    ephemeralPublicKey: Data? = nil) {
            self.version = version
            self.flags = flags
            self.segmentIndex = segmentIndex
            self.createdAt = createdAt
            self.segmentID = segmentID
            self.ephemeralPublicKey = ephemeralPublicKey
        }

        public func encoded() -> Data {
            var out = Data(LogFormat.magic)
            out.appendLE(version)
            out.appendLE(flags)
            out.appendLE(segmentIndex)
            out.appendLE(createdAt.timeIntervalSince1970.bitPattern)
            out.append(segmentID)
            // Pad the fields out to the full v1 header first: v1 and v2 share
            // this 56-byte prefix exactly, so any reader can reach the version
            // field before deciding how much more of the header to expect.
            out.append(Data(repeating: 0, count: max(0, LogFormat.headerSize - out.count)))

            if let ephemeralPublicKey {
                out.appendLE(UInt16(ephemeralPublicKey.count))
                out.append(ephemeralPublicKey)
            }
            let target = LogFormat.headerSize(forVersion: version)
            out.append(Data(repeating: 0, count: max(0, target - out.count)))
            return out
        }

        public static func decode(_ data: Data) -> SegmentHeader? {
            guard data.count >= LogFormat.headerSize else { return nil }
            let prefix = [UInt8](data.prefix(LogFormat.headerSize))
            guard Array(prefix[0..<8]) == LogFormat.magic else { return nil }
            var cursor = 8
            let version: UInt16 = readLE(prefix, &cursor)
            let flags: UInt16 = readLE(prefix, &cursor)
            let segmentIndex: UInt32 = readLE(prefix, &cursor)
            let tsBits: UInt64 = readLE(prefix, &cursor)
            let segmentID = Data(prefix[cursor..<(cursor + 16)])

            var ephemeral: Data?
            if version >= LogFormat.agentVersion {
                guard data.count >= LogFormat.agentHeaderSize,
                      let length: UInt16 = data.readLE(at: LogFormat.headerSize),
                      length > 0,
                      LogFormat.headerSize + 2 + Int(length) <= LogFormat.agentHeaderSize
                else { return nil }
                let start = data.startIndex + LogFormat.headerSize + 2
                ephemeral = data.subdata(in: start..<(start + Int(length)))
            }

            return SegmentHeader(
                version: version, flags: flags, segmentIndex: segmentIndex,
                createdAt: Date(timeIntervalSince1970: Double(bitPattern: tsBits)),
                segmentID: segmentID, ephemeralPublicKey: ephemeral
            )
        }
    }

    private static func readLE<T: FixedWidthInteger>(_ bytes: [UInt8], _ cursor: inout Int) -> T {
        var value: T = 0
        let size = MemoryLayout<T>.size
        for i in 0..<size {
            value |= T(bytes[cursor + i]) << (8 * i)
        }
        cursor += size
        return value
    }

    // MARK: - Compression

    public static func compress(_ data: Data) -> Data? {
        guard !data.isEmpty else { return Data() }
        let capacity = data.count + 1024
        var destination = Data(count: capacity)
        let written = destination.withUnsafeMutableBytes { dst -> Int in
            data.withUnsafeBytes { src -> Int in
                guard let d = dst.bindMemory(to: UInt8.self).baseAddress,
                      let s = src.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_encode_buffer(d, capacity, s, data.count, nil, COMPRESSION_LZFSE)
            }
        }
        guard written > 0 else { return nil }
        return destination.prefix(written)
    }

    public static func decompress(_ data: Data, expectedSize: Int) -> Data? {
        guard expectedSize > 0 else { return Data() }
        var destination = Data(count: expectedSize)
        let written = destination.withUnsafeMutableBytes { dst -> Int in
            data.withUnsafeBytes { src -> Int in
                guard let d = dst.bindMemory(to: UInt8.self).baseAddress,
                      let s = src.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_decode_buffer(d, expectedSize, s, data.count, nil, COMPRESSION_LZFSE)
            }
        }
        guard written == expectedSize else { return nil }
        return destination
    }
}

extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }

    func readLE<T: FixedWidthInteger>(at offset: Int, as type: T.Type = T.self) -> T? {
        let size = MemoryLayout<T>.size
        guard offset >= 0, offset + size <= count else { return nil }
        var value: T = 0
        for i in 0..<size {
            value |= T(self[startIndex + offset + i]) << (8 * i)
        }
        return value
    }
}
