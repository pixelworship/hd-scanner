import Foundation
import CBSM

/// Reads file-read events from the kernel audit pipe.
///
/// This is the mechanism that catches everything the descriptor sampler cannot:
/// a `cat image.png` in Terminal opens, reads and closes in well under a
/// sampling interval, but the kernel still records the `open()` in the audit
/// trail, and this taps that trail as it happens. It needs root (the pipe is
/// `crw------- root`), which the daemon has; the app, running unprivileged,
/// falls back to sampling.
///
/// The heavy lifting — walking BSM tokens — is done by Apple's own libbsm
/// through the CBSM shim, so this class is just the pipe lifecycle plus a read
/// loop on its own thread.
public final class AuditPipeReader: @unchecked Sendable {

    public struct Read: Sendable {
        public let path: String
        public let pid: Int32
        public let euid: UInt32
        public let event: UInt16
        public let at: Date
        public let succeeded: Bool
    }

    public enum StartResult: Equatable, Sendable {
        case started
        /// The pipe could not be opened — almost always because the process is
        /// not root.
        case needsRoot
        /// Opened, but the audit subsystem rejected the configuration.
        case unavailable(String)
    }

    private let path: String
    private var fd: Int32 = -1
    private let stateLock = NSLock()
    private var running = false
    private var thread: Thread?

    public var onRead: (@Sendable (Read) -> Void)?
    /// Raw records seen, before any filtering — a sign the tap is live.
    public private(set) var recordsSeen = 0

    public init(path: String = "/dev/auditpipe") {
        self.path = path
    }

    deinit { stop() }

    public var isRunning: Bool {
        stateLock.lock(); defer { stateLock.unlock() }
        return running
    }

    public func start() -> StartResult {
        stop()
        let descriptor = path.withCString { open($0, O_RDONLY) }
        guard descriptor >= 0 else {
            return errno == EPERM || errno == EACCES ? .needsRoot
                 : .unavailable("open(\(path)) failed: errno \(errno)")
        }
        let configured = hdw_auditpipe_configure(descriptor)
        guard configured == 0 else {
            close(descriptor)
            return .unavailable("could not select the file-read audit class: errno \(-configured)")
        }

        stateLock.lock()
        fd = descriptor
        running = true
        stateLock.unlock()

        let worker = Thread { [weak self] in self?.loop(descriptor) }
        worker.name = "co.pixelworship.hdwatcher.auditpipe"
        worker.stackSize = 512 * 1024
        worker.start()
        thread = worker
        return .started
    }

    public func stop() {
        stateLock.lock()
        let descriptor = fd
        running = false
        fd = -1
        stateLock.unlock()
        // Closing the descriptor unblocks the read() the worker is parked on.
        if descriptor >= 0 { close(descriptor) }
        thread = nil
    }

    private func loop(_ descriptor: Int32) {
        // The pipe returns at most one complete record per read; a record is
        // bounded by the kernel's max audit data size, comfortably under this.
        let capacity = 128 * 1024
        var buffer = [UInt8](repeating: 0, count: capacity)

        while true {
            stateLock.lock(); let keepGoing = running; stateLock.unlock()
            guard keepGoing else { break }

            let count = read(descriptor, &buffer, capacity)
            if count <= 0 {
                if count < 0 && errno == EINTR { continue }
                break                      // closed, or an unrecoverable error
            }

            var parsed = HDWBsmRead()
            let isFile = buffer.withUnsafeBufferPointer {
                hdw_bsm_parse_record($0.baseAddress, count, &parsed)
            }
            recordsSeen += 1
            guard isFile == 1 else { continue }

            let filePath = withUnsafeBytes(of: parsed.path) { raw -> String in
                let bytes = raw.bindMemory(to: UInt8.self)
                let length = bytes.firstIndex(of: 0) ?? bytes.count
                return String(decoding: bytes[..<length], as: UTF8.self)
            }
            guard !filePath.isEmpty else { continue }

            onRead?(Read(path: filePath,
                         pid: parsed.pid,
                         euid: parsed.euid,
                         event: parsed.event,
                         at: parsed.seconds > 0 ? Date(timeIntervalSince1970: TimeInterval(parsed.seconds)) : Date(),
                         succeeded: parsed.success == 1))
        }
    }
}
