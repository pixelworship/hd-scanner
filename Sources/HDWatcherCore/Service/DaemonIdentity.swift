import Foundation
import CryptoKit

/// The daemon's own Secure Enclave key, used to protect its operational state.
///
/// The daemon starts before anyone logs in, so it cannot be handed the vault
/// key — that is why it records with a write-only ingest key it cannot read
/// back. But it also has state of its own: where it had reached in the event
/// stream, and what it has been told to watch. Leaving that in the clear
/// discloses which directories are monitored and when activity happened.
///
/// So the daemon generates a Secure Enclave key on first run and publishes only
/// the public half. The app seals configuration to it; the daemon seals its own
/// cursor to itself. The private half never leaves the enclave and the wrapped
/// blob is root-readable only, so nothing short of root running on this exact
/// machine can read either.
public enum DaemonIdentity {

    private static let info = "hdwatcher.daemon.identity.v1"

    /// Enclave-wrapped private key. Useless on other hardware, and readable
    /// only by root.
    public static var keyBlobURL: URL {
        AppPaths.systemSupportDirectory.appendingPathComponent("daemon.key")
    }

    /// Public half, published so the app can seal configuration to the daemon.
    public static var publicKeyURL: URL {
        AppPaths.systemSupportDirectory.appendingPathComponent("daemon.pub")
    }

    /// Loads the daemon's key, creating it on first run. Root only.
    @discardableResult
    public static func loadOrCreate() -> P256.KeyAgreement.PrivateKey? {
        AppPaths.ensureDirectories()

        if let blob = try? Data(contentsOf: keyBlobURL) {
            if SecureEnclaveKeyStore.isAvailable,
               let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob) {
                publish(key.publicKey)
                return nil   // enclave-backed: use `open`/`seal` below
            }
            // No enclave on this Mac: the blob is a raw key, protected by file
            // permissions alone.
            if let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: blob) {
                publish(key.publicKey)
                return key
            }
        }

        if SecureEnclaveKeyStore.isAvailable,
           let result = try? SecureEnclaveKeyStore.createBinding(
               wrapping: Data(), requireUserPresence: false, info: info) {
            write(result.binding.keyBlob, to: keyBlobURL, mode: 0o600)
            if let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: result.binding.keyBlob) {
                publish(key.publicKey)
            }
            return nil
        }

        let software = P256.KeyAgreement.PrivateKey()
        write(software.rawRepresentation, to: keyBlobURL, mode: 0o600)
        publish(software.publicKey)
        return software
    }

    public static var publicKey: P256.KeyAgreement.PublicKey? {
        guard let data = try? Data(contentsOf: publicKeyURL) else { return nil }
        return try? P256.KeyAgreement.PublicKey(rawRepresentation: data)
    }

    public static var exists: Bool {
        FileManager.default.fileExists(atPath: publicKeyURL.path)
    }

    /// Opens something sealed to this daemon. Root only.
    public static func open(_ data: Data, context: String) -> Data? {
        guard let blob = try? Data(contentsOf: keyBlobURL) else { return nil }
        if SecureEnclaveKeyStore.isAvailable,
           let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob) {
            return try? PublicKeyBoxEnclave.open(data, with: key, context: context)
        }
        guard let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: blob) else { return nil }
        return try? PublicKeyBox.open(data, with: key, context: context)
    }

    /// Seals something only this daemon can reopen.
    public static func seal(_ data: Data, context: String) -> Data? {
        guard let publicKey else { return nil }
        return try? PublicKeyBox.seal(data, to: publicKey, context: context)
    }

    private static func publish(_ key: P256.KeyAgreement.PublicKey) {
        write(key.rawRepresentation, to: publicKeyURL, mode: 0o644)
    }

    private static func write(_ data: Data, to url: URL, mode: Int) {
        try? data.write(to: url, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: mode],
                                               ofItemAtPath: url.path)
    }
}

/// ECIES against a Secure Enclave key. Mirrors `PublicKeyBox`, but the private
/// half lives in the enclave and cannot be extracted.
public enum PublicKeyBoxEnclave {
    public static func open(_ data: Data,
                            with key: SecureEnclave.P256.KeyAgreement.PrivateKey,
                            context: String) throws -> Data {
        let ephemeralBytes = 64
        let headerSize = ephemeralBytes + 32
        guard data.count > headerSize else {
            throw CryptoError.vaultCorrupt("sealed blob is too short")
        }
        let start = data.startIndex
        let ephemeralData = data.subdata(in: start..<(start + ephemeralBytes))
        let salt = data.subdata(in: (start + ephemeralBytes)..<(start + headerSize))
        let body = data.subdata(in: (start + headerSize)..<data.endIndex)

        let ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralData)
        let shared = try key.sharedSecretFromKeyAgreement(with: ephemeral)
        let derived = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt,
            sharedInfo: Data(context.utf8), outputByteCount: 32)
        return try CryptoPrimitives.open(body, key: derived)
    }
}
