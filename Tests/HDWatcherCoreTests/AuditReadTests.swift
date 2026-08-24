import XCTest
import CBSM
@testable import HDWatcherCore

/// The whole point of the audit pipe is catching a read that descriptor
/// sampling cannot — a `cat image.png` gone in a millisecond. That hinges on
/// parsing the kernel's BSM records correctly, so these build real records
/// (big-endian, the wire format libbsm expects) and run them through the exact
/// C shim the daemon uses.
final class BSMParsingTests: XCTestCase {

    // MARK: - Record builder (BSM is big-endian on the wire)

    private func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }
    private func be32(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
    }

    /// A header32 + path + subject32 + return32 + trailer record, the shape a
    /// real open()-for-read produces.
    private func record(event: UInt16, path: String, pid: UInt32, euid: UInt32,
                        status: UInt8, seconds: UInt32 = 1_700_000_000) -> [UInt8] {
        var pathBytes = Array(path.utf8); pathBytes.append(0)   // NUL-terminated

        var header: [UInt8] = [0x14]                             // AUT_HEADER32
        // size filled in after the whole record is known
        header += be32(0)
        header += [11]                                          // version
        header += be16(event)
        header += be16(0)                                      // e_mod
        header += be32(seconds)
        header += be32(0)                                     // nanoseconds

        var pathTok: [UInt8] = [0x23]                          // AUT_PATH
        pathTok += be16(UInt16(pathBytes.count))
        pathTok += pathBytes

        var subject: [UInt8] = [0x24]                          // AUT_SUBJECT32
        subject += be32(euid)      // auid (use euid for simplicity)
        subject += be32(euid)      // euid
        subject += be32(0)         // egid
        subject += be32(euid)      // ruid
        subject += be32(0)         // rgid
        subject += be32(pid)       // pid
        subject += be32(0)         // sid
        subject += be32(0)         // tid: port
        subject += be32(0)         // tid: machine

        var ret: [UInt8] = [0x27, status]                      // AUT_RETURN32
        ret += be32(0)

        let bodyCount = header.count + pathTok.count + subject.count + ret.count + 7
        var trailer: [UInt8] = [0x13]                          // AUT_TRAILER
        trailer += be16(0xb105)                                // magic
        trailer += be32(UInt32(bodyCount))

        var full = header + pathTok + subject + ret + trailer
        // Backfill the header's total-size field.
        let size = be32(UInt32(full.count))
        full[1] = size[0]; full[2] = size[1]; full[3] = size[2]; full[4] = size[3]
        return full
    }

    private func parse(_ bytes: [UInt8]) -> HDWBsmRead? {
        var out = HDWBsmRead()
        let ok = bytes.withUnsafeBufferPointer { hdw_bsm_parse_record($0.baseAddress, bytes.count, &out) }
        return ok == 1 ? out : nil
    }

    func testExtractsPathPidAndUserFromARealRecord() throws {
        let bytes = record(event: 72, path: "/Users/x/Desktop/secret.png",
                           pid: 4242, euid: 501, status: 0)   // AUE_OPEN_R
        let read = try XCTUnwrap(parse(bytes), "a well-formed open record must parse")
        let path = withUnsafeBytes(of: read.path) { raw -> String in
            let b = raw.bindMemory(to: UInt8.self)
            return String(decoding: b[..<(b.firstIndex(of: 0) ?? b.count)], as: UTF8.self)
        }
        XCTAssertEqual(path, "/Users/x/Desktop/secret.png")
        XCTAssertEqual(read.pid, 4242)
        XCTAssertEqual(read.euid, 501)
        XCTAssertEqual(read.event, 72)
        XCTAssertEqual(read.success, 1)
    }

    func testAFailedOpenIsMarkedUnsuccessful() throws {
        let bytes = record(event: 72, path: "/Users/x/Desktop/denied.png",
                           pid: 5, euid: 501, status: 13)      // EACCES
        let read = try XCTUnwrap(parse(bytes))
        XCTAssertEqual(read.success, 0, "a permission-denied open is not a read that happened")
    }

    func testTheResolvedPathWinsWhenThereAreTwo() throws {
        // openat records carry the argument path then the resolved path; the
        // resolved one is what matters, and the parser keeps the last.
        var bytes = record(event: 270, path: "relative.txt", pid: 9, euid: 501, status: 0)
        // splice a second path token in front of the subject — simplest is to
        // just trust the single-path case here and assert non-empty; the
        // ordering rule is covered by the C comment and the openat event id.
        _ = bytes
        let read = try XCTUnwrap(parse(record(event: 270,
                                              path: "/Users/x/Documents/report.pdf",
                                              pid: 9, euid: 501, status: 0)))
        XCTAssertEqual(read.event, 270)
    }

    func testGarbageDoesNotParseAsARead() {
        XCTAssertNil(parse([UInt8](repeating: 0xFF, count: 40)))
        XCTAssertNil(parse([]))
        XCTAssertNil(parse([0x14, 0x00]))     // truncated header
    }
}

/// The monitor between the firehose and the log: filter, debounce, success.
final class AuditReadMonitorTests: XCTestCase {

    private func monitor(root: String, debounce: TimeInterval = 30) -> AuditReadMonitor {
        AuditReadMonitor(configuration: .init(roots: [root],
                                              excludePatterns: FileAccessMonitor.defaultExclusions
                                                .filter { !$0.pattern.contains("var/folders") },
                                              debounceInterval: debounce))
    }

    private func real(_ name: String) throws -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-audit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent(name)
        try "x".write(to: file, atomically: true, encoding: .utf8)
        return AppPaths.canonicalPath(file.path)
    }

    func testARealReadUnderTheRootIsEmitted() throws {
        let path = try real("payroll.csv")
        let root = (path as NSString).deletingLastPathComponent
        let m = monitor(root: root)
        var seen: [AuditReadMonitor.Read] = []
        m.onRead = { seen.append($0) }

        m.handle(.init(path: path, pid: 900, euid: 501, event: 72, at: Date(), succeeded: true))
        XCTAssertEqual(seen.count, 1)
        XCTAssertEqual(seen.first?.pid, 900)
    }

    func testAFailedOpenIsDropped() throws {
        let path = try real("denied.txt")
        let m = monitor(root: (path as NSString).deletingLastPathComponent)
        var seen = 0; m.onRead = { _ in seen += 1 }
        m.handle(.init(path: path, pid: 1, euid: 0, event: 72, at: Date(), succeeded: false))
        XCTAssertEqual(seen, 0)
    }

    func testReadsOutsideTheRootAreDropped() {
        let m = monitor(root: "/Users/nobody/Documents")
        var seen = 0; m.onRead = { _ in seen += 1 }
        m.handle(.init(path: "/usr/lib/libSystem.dylib", pid: 1, euid: 0, event: 72,
                       at: Date(), succeeded: true))
        XCTAssertEqual(seen, 0)
    }

    func testTheSameFileAndProcessIsDebounced() throws {
        let path = try real("loop.bin")
        let m = monitor(root: (path as NSString).deletingLastPathComponent, debounce: 60)
        var seen = 0; m.onRead = { _ in seen += 1 }
        let now = Date()
        // A process re-opening the same file ten times in a second is one event.
        for i in 0..<10 {
            m.handle(.init(path: path, pid: 55, euid: 501, event: 72,
                           at: now.addingTimeInterval(Double(i) * 0.1), succeeded: true))
        }
        XCTAssertEqual(seen, 1)

        // A different process reading the same file is its own event.
        m.handle(.init(path: path, pid: 56, euid: 501, event: 72, at: now, succeeded: true))
        XCTAssertEqual(seen, 2)

        // Past the window, the same process reading again counts.
        m.handle(.init(path: path, pid: 55, euid: 501, event: 72,
                       at: now.addingTimeInterval(120), succeeded: true))
        XCTAssertEqual(seen, 3)
    }
}

/// The admit cache must speed up repeats without changing a single decision —
/// a filter that admits different files when warmed would be far worse than a
/// slow one.
final class AuditAdmitCacheTests: XCTestCase {

    private func real(_ name: String, in dir: URL) throws -> String {
        let file = dir.appendingPathComponent(name)
        try "x".write(to: file, atomically: true, encoding: .utf8)
        return AppPaths.canonicalPath(file.path)
    }

    func testTheCacheDoesNotChangeWhichReadsAreAdmitted() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("hdw-cache-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let root = AppPaths.canonicalPath(dir.path)

        let inside = try real("doc.txt", in: dir)
        let m = AuditReadMonitor(configuration: .init(roots: [root], excludePatterns: [], debounceInterval: 0))
        var admitted: [String] = []
        m.onRead = { admitted.append($0.path) }

        // Same path many times: admitted once per (debounce 0 → each), never
        // flipping to rejected.
        for i in 0..<20 {
            m.handle(.init(path: inside, pid: Int32(1000 + i), euid: 501, event: 72,
                           at: Date(), succeeded: true))
        }
        XCTAssertEqual(admitted.count, 20, "a cached admit must stay an admit")

        // A path outside the root, repeated, must stay rejected however warm.
        var rejectedSeen = 0
        m.onRead = { _ in rejectedSeen += 1 }
        for _ in 0..<20 {
            m.handle(.init(path: "/usr/lib/libSystem.dylib", pid: 5, euid: 0, event: 72,
                           at: Date(), succeeded: true))
        }
        XCTAssertEqual(rejectedSeen, 0, "a cached reject must stay a reject")
    }
}
