import Foundation
import CryptoKit
import LocalAuthentication

/// Keys available while the vault is unlocked. Each usage gets its own
/// HKDF-derived subkey.
public struct VaultKeys: Sendable {
    public let master: SymmetricKey
    public let log: SymmetricKey
    public let integrity: SymmetricKey
    public let settings: SymmetricKey
    /// Encrypts captured file contents in the content vault.
    public let content: SymmetricKey
    /// Private half of the ingest key pair.
    ///
    /// The background agent has to record events without the user present, so
    /// it cannot hold a key that decrypts anything. Instead it gets only the
    /// public half and seals each segment to it; recovering the contents needs
    /// this private key, which exists solely while the vault is unlocked.
    public let ingest: P256.KeyAgreement.PrivateKey

    init(master: SymmetricKey) {
        self.master = master
        self.log = CryptoPrimitives.subkey(from: master, info: "hdwatcher.log.v1")
        self.integrity = CryptoPrimitives.subkey(from: master, info: "hdwatcher.integrity.v1")
        self.settings = CryptoPrimitives.subkey(from: master, info: "hdwatcher.settings.v1")
        self.content = CryptoPrimitives.subkey(from: master, info: "hdwatcher.content.v1")
        self.ingest = VaultKeys.deriveIngestKey(from: master)
    }

    /// Derives the ingest key deterministically, so nothing extra has to be
    /// stored in the vault file and existing vaults gain the capability for free.
    /// The counter covers the vanishingly unlikely case of HKDF output landing
    /// outside the curve order.
    static func deriveIngestKey(from master: SymmetricKey) -> P256.KeyAgreement.PrivateKey {
        for counter in 0..<16 {
            let material = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: master,
                info: Data("hdwatcher.ingest.v1.\(counter)".utf8),
                outputByteCount: 32
            ).withUnsafeBytes { Data($0) }
            if let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: material) {
                return key
            }
        }
        // Unreachable in practice; a fresh random key would make old segments
        // unreadable, so failing loudly is better than failing silently.
        preconditionFailure("could not derive an ingest key from the master key")
    }

    public var ingestPublicKey: P256.KeyAgreement.PublicKey { ingest.publicKey }
}

struct QuickUnlockRecord: Codable, Sendable {
    var binding: SecureEnclaveBinding
    var sealed: Data
}

struct VaultMetadata: Codable, Sendable {
    var version: Int = 1
    var createdAt: Date = Date()
    var tier: KeyProtectionTier
    var kdfSalt: Data
    var kdfRounds: UInt32
    /// Hardware-binding key. Present whenever tier == .secureEnclave.
    var seBinding: SecureEnclaveBinding?
    /// A random secret wrapped to the enclave. Required to rebuild the KEK.
    var seSecretSealed: Data?
    /// The master key, sealed under HKDF(passwordKEK || enclaveSecret).
    var masterSealed: Data
    /// Optional Touch ID / device-password unlock that bypasses the password.
    var quickUnlock: QuickUnlockRecord?
    var failedAttempts: Int = 0
    var lockoutUntil: Date?
    var passwordHint: String?
}

/// Owns the vault file and the in-memory key material. Thread-safe; unlocking
/// is intentionally slow, so call `unlock` off the main thread.
public final class VaultKeyManager: @unchecked Sendable {

    private let mutex = NSLock()
    private var metadata: VaultMetadata?
    private var keys: VaultKeys?
    private let vaultURL: URL

    private static let combinedInfo = "hdwatcher.combined.v1"
    private static let seInfo = "hdwatcher.se.binding.v1"
    private static let quickInfo = "hdwatcher.se.quick.v1"

    public init(vaultURL: URL = AppPaths.vaultFile) {
        self.vaultURL = vaultURL
        AppPaths.ensureDirectories()
        self.metadata = Self.loadMetadata(from: vaultURL)
    }

    // MARK: - State

    public var vaultExists: Bool {
        mutex.lock(); defer { mutex.unlock() }
        return metadata != nil
    }

    public var isUnlocked: Bool {
        mutex.lock(); defer { mutex.unlock() }
        return keys != nil
    }

    public var currentKeys: VaultKeys? {
        mutex.lock(); defer { mutex.unlock() }
        return keys
    }

    public var protectionTier: KeyProtectionTier {
        mutex.lock(); defer { mutex.unlock() }
        return metadata?.tier ?? (SecureEnclaveKeyStore.isAvailable ? .secureEnclave : .passwordOnly)
    }

    public var quickUnlockEnabled: Bool {
        mutex.lock(); defer { mutex.unlock() }
        return metadata?.quickUnlock != nil
    }

    public var passwordHint: String? {
        mutex.lock(); defer { mutex.unlock() }
        return metadata?.passwordHint
    }

    public var createdAt: Date? {
        mutex.lock(); defer { mutex.unlock() }
        return metadata?.createdAt
    }

    public var failedAttempts: Int {
        mutex.lock(); defer { mutex.unlock() }
        return metadata?.failedAttempts ?? 0
    }

    public var lockoutUntil: Date? {
        mutex.lock(); defer { mutex.unlock() }
        guard let until = metadata?.lockoutUntil, until > Date() else { return nil }
        return until
    }

    // MARK: - Creation

    /// Creates a new vault. When the Secure Enclave is available the master key
    /// is bound to this Mac's hardware in addition to the password, so the log
    /// cannot be decrypted by moving the files to another machine.
    public func createVault(
        password: String,
        hint: String? = nil,
        enableQuickUnlock: Bool
    ) throws {
        mutex.lock(); defer { mutex.unlock() }

        var master = CryptoPrimitives.randomBytes(32)
        defer { master.zeroize() }

        let salt = CryptoPrimitives.randomBytes(32)
        let rounds = CryptoPrimitives.calibrateRounds()
        let passwordKEK = try CryptoPrimitives.deriveKey(password: password, salt: salt, rounds: rounds)

        var tier: KeyProtectionTier = .passwordOnly
        var seBinding: SecureEnclaveBinding?
        var seSecretSealed: Data?
        var enclaveSecret = Data()

        if SecureEnclaveKeyStore.isAvailable {
            var secret = CryptoPrimitives.randomBytes(32)
            do {
                let result = try SecureEnclaveKeyStore.createBinding(
                    wrapping: secret,
                    requireUserPresence: false,
                    info: Self.seInfo
                )
                seBinding = result.binding
                seSecretSealed = result.sealed
                enclaveSecret = secret
                tier = .secureEnclave
            } catch {
                // Fall back to password-only rather than refusing to run.
                tier = .passwordOnly
            }
            secret.zeroize()
        }

        let combined = Self.combineKEK(passwordKEK: passwordKEK, enclaveSecret: enclaveSecret)
        let masterSealed = try CryptoPrimitives.seal(master, key: combined)

        var quick: QuickUnlockRecord?
        if enableQuickUnlock, tier == .secureEnclave, SecureEnclaveKeyStore.userPresenceAvailable() {
            if let result = try? SecureEnclaveKeyStore.createBinding(
                wrapping: master,
                requireUserPresence: true,
                info: Self.quickInfo
            ) {
                quick = QuickUnlockRecord(binding: result.binding, sealed: result.sealed)
            }
        }

        let meta = VaultMetadata(
            tier: tier,
            kdfSalt: salt,
            kdfRounds: rounds,
            seBinding: seBinding,
            seSecretSealed: seSecretSealed,
            masterSealed: masterSealed,
            quickUnlock: quick,
            passwordHint: hint
        )
        try Self.saveMetadata(meta, to: vaultURL)
        metadata = meta
        keys = VaultKeys(master: SymmetricKey(data: master))
    }

    // MARK: - Unlock

    public func unlock(password: String) throws {
        mutex.lock(); defer { mutex.unlock() }
        guard var meta = metadata else { throw CryptoError.vaultNotInitialized }

        if let until = meta.lockoutUntil, until > Date() {
            throw CryptoError.lockedOut(until: until)
        }

        let passwordKEK = try CryptoPrimitives.deriveKey(
            password: password, salt: meta.kdfSalt, rounds: meta.kdfRounds
        )

        var enclaveSecret = Data()
        if meta.tier == .secureEnclave, let binding = meta.seBinding, let sealed = meta.seSecretSealed {
            enclaveSecret = try SecureEnclaveKeyStore.unwrap(
                binding: binding, sealed: sealed,
                info: Self.seInfo,
                reason: "Unlock the HDWatcher vault"
            )
        }
        defer { enclaveSecret.zeroize() }

        let combined = Self.combineKEK(passwordKEK: passwordKEK, enclaveSecret: enclaveSecret)

        guard var master = try? CryptoPrimitives.open(meta.masterSealed, key: combined) else {
            meta.failedAttempts += 1
            meta.lockoutUntil = Self.lockoutDate(forFailures: meta.failedAttempts)
            metadata = meta
            try? Self.saveMetadata(meta, to: vaultURL)
            if let until = meta.lockoutUntil, until > Date() {
                throw CryptoError.lockedOut(until: until)
            }
            throw CryptoError.badPassword
        }

        meta.failedAttempts = 0
        meta.lockoutUntil = nil
        metadata = meta
        try? Self.saveMetadata(meta, to: vaultURL)

        keys = VaultKeys(master: SymmetricKey(data: master))
        master.zeroize()
    }

    /// Unlocks using Touch ID or the device password, if the user enrolled it.
    public func unlockWithBiometrics(reason: String = "Unlock HDWatcher") throws {
        mutex.lock(); defer { mutex.unlock() }
        guard let meta = metadata else { throw CryptoError.vaultNotInitialized }
        guard let quick = meta.quickUnlock else {
            throw CryptoError.secureEnclaveFailed("quick unlock is not enabled")
        }
        if let until = meta.lockoutUntil, until > Date() {
            throw CryptoError.lockedOut(until: until)
        }

        let context = LAContext()
        context.localizedReason = reason
        var master = try SecureEnclaveKeyStore.unwrap(
            binding: quick.binding, sealed: quick.sealed,
            info: Self.quickInfo, reason: reason, context: context
        )
        keys = VaultKeys(master: SymmetricKey(data: master))
        master.zeroize()
    }

    public func lock() {
        mutex.lock(); defer { mutex.unlock() }
        keys = nil
    }

    // MARK: - Maintenance

    public func changePassword(current: String, new: String, hint: String? = nil) throws {
        try unlock(password: current)
        mutex.lock(); defer { mutex.unlock() }
        guard var meta = metadata, let keys else { throw CryptoError.vaultLocked }

        let salt = CryptoPrimitives.randomBytes(32)
        let rounds = CryptoPrimitives.calibrateRounds()
        let passwordKEK = try CryptoPrimitives.deriveKey(password: new, salt: salt, rounds: rounds)

        var enclaveSecret = Data()
        if meta.tier == .secureEnclave, let binding = meta.seBinding, let sealed = meta.seSecretSealed {
            enclaveSecret = try SecureEnclaveKeyStore.unwrap(
                binding: binding, sealed: sealed,
                info: Self.seInfo, reason: "Re-key the HDWatcher vault"
            )
        }
        defer { enclaveSecret.zeroize() }

        let combined = Self.combineKEK(passwordKEK: passwordKEK, enclaveSecret: enclaveSecret)
        meta.masterSealed = try CryptoPrimitives.seal(keys.master.rawData, key: combined)
        meta.kdfSalt = salt
        meta.kdfRounds = rounds
        meta.passwordHint = hint
        try Self.saveMetadata(meta, to: vaultURL)
        metadata = meta
    }

    public func setQuickUnlock(_ enabled: Bool) throws {
        mutex.lock(); defer { mutex.unlock() }
        guard var meta = metadata else { throw CryptoError.vaultNotInitialized }
        guard let keys else { throw CryptoError.vaultLocked }

        if enabled {
            guard SecureEnclaveKeyStore.isAvailable, SecureEnclaveKeyStore.userPresenceAvailable() else {
                throw CryptoError.secureEnclaveFailed("no biometric or device password available")
            }
            let result = try SecureEnclaveKeyStore.createBinding(
                wrapping: keys.master.rawData,
                requireUserPresence: true,
                info: Self.quickInfo
            )
            meta.quickUnlock = QuickUnlockRecord(binding: result.binding, sealed: result.sealed)
        } else {
            meta.quickUnlock = nil
        }
        try Self.saveMetadata(meta, to: vaultURL)
        metadata = meta
    }

    /// Irreversibly discards the key material. Any existing log segments become
    /// permanently unreadable.
    public func destroyVault() throws {
        mutex.lock(); defer { mutex.unlock() }
        keys = nil
        metadata = nil
        try? FileManager.default.removeItem(at: vaultURL)
    }

    public func resetLockout() {
        mutex.lock(); defer { mutex.unlock() }
        guard var meta = metadata else { return }
        meta.failedAttempts = 0
        meta.lockoutUntil = nil
        metadata = meta
        try? Self.saveMetadata(meta, to: vaultURL)
    }

    // MARK: - Helpers

    /// Binds the password-derived key to the enclave secret. With no enclave the
    /// second input is empty and this degrades to a plain HKDF of the password key.
    private static func combineKEK(passwordKEK: SymmetricKey, enclaveSecret: Data) -> SymmetricKey {
        var material = passwordKEK.rawData
        material.append(enclaveSecret)
        defer { material.zeroize() }
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: material),
            info: Data(combinedInfo.utf8),
            outputByteCount: 32
        )
    }

    /// Throttles guessing: free for the first 3 tries, then backs off
    /// exponentially to a 5-minute ceiling.
    private static func lockoutDate(forFailures n: Int) -> Date? {
        guard n >= 3 else { return nil }
        let seconds = min(pow(2.0, Double(n - 2)), 300)
        return Date().addingTimeInterval(seconds)
    }

    private static func loadMetadata(from url: URL) -> VaultMetadata? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(VaultMetadata.self, from: data)
    }

    private static func saveMetadata(_ meta: VaultMetadata, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(meta)
        try data.write(to: url, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
