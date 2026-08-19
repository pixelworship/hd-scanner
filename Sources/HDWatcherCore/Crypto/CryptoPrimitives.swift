import Foundation
import CryptoKit
import CommonCrypto

public enum CryptoError: LocalizedError {
    case kdfFailed(Int32)
    case secureEnclaveUnavailable
    case secureEnclaveFailed(String)
    case badPassword
    case vaultCorrupt(String)
    case vaultLocked
    case vaultNotInitialized
    case lockedOut(until: Date)

    public var errorDescription: String? {
        switch self {
        case .kdfFailed(let s):          return "Key derivation failed (status \(s))."
        case .secureEnclaveUnavailable:  return "This Mac has no Secure Enclave."
        case .secureEnclaveFailed(let m):return "Secure Enclave error: \(m)"
        case .badPassword:               return "Incorrect password."
        case .vaultCorrupt(let m):       return "Vault is corrupt: \(m)"
        case .vaultLocked:               return "The vault is locked."
        case .vaultNotInitialized:       return "No vault has been created yet."
        case .lockedOut(let until):
            let secs = max(0, Int(until.timeIntervalSinceNow))
            return "Too many failed attempts. Try again in \(secs)s."
        }
    }
}

public enum CryptoPrimitives {

    // MARK: - Random

    public static func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        let ok = data.withUnsafeMutableBytes { buf -> Bool in
            guard let base = buf.baseAddress else { return false }
            return SecRandomCopyBytes(kSecRandomDefault, count, base) == errSecSuccess
        }
        precondition(ok, "SecRandomCopyBytes failed")
        return data
    }

    // MARK: - Password KDF

    public static let defaultPBKDF2Rounds: UInt32 = 600_000

    /// PBKDF2-HMAC-SHA512. Deliberately slow; run this off the main thread.
    public static func deriveKey(
        password: String,
        salt: Data,
        rounds: UInt32 = defaultPBKDF2Rounds,
        outputBytes: Int = 32
    ) throws -> SymmetricKey {
        let passwordBytes = Array(password.utf8)
        var out = [UInt8](repeating: 0, count: outputBytes)

        let status: Int32 = salt.withUnsafeBytes { saltBuf in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                passwordBytes.map { Int8(bitPattern: $0) }, passwordBytes.count,
                saltBuf.bindMemory(to: UInt8.self).baseAddress, salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                rounds,
                &out, outputBytes
            )
        }
        guard status == kCCSuccess else { throw CryptoError.kdfFailed(status) }
        defer { out.resetBytes(in: 0..<out.count) }
        return SymmetricKey(data: Data(out))
    }

    /// Number of rounds that costs roughly `targetSeconds` on this machine.
    /// Used at vault creation so the work factor tracks the hardware.
    public static func calibrateRounds(targetSeconds: Double = 0.45) -> UInt32 {
        let probe: UInt32 = 50_000
        let salt = randomBytes(16)
        let start = Date()
        _ = try? deriveKey(password: "calibration-probe", salt: salt, rounds: probe)
        let elapsed = Date().timeIntervalSince(start)
        guard elapsed > 0.001 else { return defaultPBKDF2Rounds }
        let scaled = Double(probe) * (targetSeconds / elapsed)
        // Clamp to a sane band and round to the nearest 10k.
        let clamped = min(max(scaled, 200_000), 2_000_000)
        return UInt32((clamped / 10_000).rounded() * 10_000)
    }

    // MARK: - Subkey derivation

    /// Derives a purpose-bound subkey so that a compromise of one usage
    /// (say, the settings file) does not hand over the log key.
    public static func subkey(from master: SymmetricKey, info: String, outputBytes: Int = 32) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            info: Data(info.utf8),
            outputByteCount: outputBytes
        )
    }

    // MARK: - Sealing helpers

    public static func seal(_ plaintext: Data, key: SymmetricKey, aad: Data? = nil) throws -> Data {
        let box: AES.GCM.SealedBox
        if let aad {
            box = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
        } else {
            box = try AES.GCM.seal(plaintext, using: key)
        }
        guard let combined = box.combined else {
            throw CryptoError.vaultCorrupt("could not serialize sealed box")
        }
        return combined
    }

    public static func open(_ combined: Data, key: SymmetricKey, aad: Data? = nil) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: combined)
        if let aad {
            return try AES.GCM.open(box, using: key, authenticating: aad)
        }
        return try AES.GCM.open(box, using: key)
    }

    // MARK: - Digests

    public static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    public static func hmac(_ data: Data, key: SymmetricKey) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
    }
}

public extension SymmetricKey {
    var rawData: Data { withUnsafeBytes { Data($0) } }
}

public extension Data {
    /// Best-effort overwrite of key material held in a mutable buffer.
    mutating func zeroize() {
        withUnsafeMutableBytes { buf in
            guard let base = buf.baseAddress else { return }
            memset_s(base, buf.count, 0, buf.count)
        }
    }
}
