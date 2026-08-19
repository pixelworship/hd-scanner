import Foundation
import CryptoKit

/// Seals data to a P-256 public key so that only the holder of the private key
/// can read it back.
///
/// This is what lets the background agent record an audit trail it cannot
/// itself decrypt: it holds the public key alone. Standard ECIES — a fresh
/// ephemeral key per message, ECDH against the recipient, HKDF to an AES-GCM
/// key, and the ephemeral public key carried alongside the ciphertext.
public enum PublicKeyBox {

    private static let ephemeralKeyBytes = 64   // P-256 raw representation

    public static func seal(_ plaintext: Data,
                            to recipient: P256.KeyAgreement.PublicKey,
                            context: String) throws -> Data {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let salt = CryptoPrimitives.randomBytes(32)
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt,
            sharedInfo: Data(context.utf8), outputByteCount: 32
        )
        let sealed = try CryptoPrimitives.seal(plaintext, key: key)

        var out = Data()
        out.append(ephemeral.publicKey.rawRepresentation)   // 64
        out.append(salt)                                     // 32
        out.append(sealed)
        return out
    }

    public static func open(_ data: Data,
                            with recipient: P256.KeyAgreement.PrivateKey,
                            context: String) throws -> Data {
        let headerSize = ephemeralKeyBytes + 32
        guard data.count > headerSize else {
            throw CryptoError.vaultCorrupt("sealed blob is too short")
        }
        let start = data.startIndex
        let ephemeralData = data.subdata(in: start..<(start + ephemeralKeyBytes))
        let salt = data.subdata(in: (start + ephemeralKeyBytes)..<(start + headerSize))
        let body = data.subdata(in: (start + headerSize)..<data.endIndex)

        let ephemeral = try P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralData)
        let shared = try recipient.sharedSecretFromKeyAgreement(with: ephemeral)
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt,
            sharedInfo: Data(context.utf8), outputByteCount: 32
        )
        return try CryptoPrimitives.open(body, key: key)
    }

    /// Per-segment keys for the log: one ECDH, then two purpose-bound subkeys.
    public static func segmentKeys(ephemeralPrivate: P256.KeyAgreement.PrivateKey,
                                   recipient: P256.KeyAgreement.PublicKey,
                                   segmentID: Data) throws -> (log: SymmetricKey, integrity: SymmetricKey) {
        let shared = try ephemeralPrivate.sharedSecretFromKeyAgreement(with: recipient)
        return derive(shared: shared, segmentID: segmentID)
    }

    public static func segmentKeys(privateKey: P256.KeyAgreement.PrivateKey,
                                   ephemeralPublic: P256.KeyAgreement.PublicKey,
                                   segmentID: Data) throws -> (log: SymmetricKey, integrity: SymmetricKey) {
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublic)
        return derive(shared: shared, segmentID: segmentID)
    }

    private static func derive(shared: SharedSecret, segmentID: Data)
        -> (log: SymmetricKey, integrity: SymmetricKey) {
        let log = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: segmentID,
            sharedInfo: Data("hdwatcher.segment.log.v2".utf8), outputByteCount: 32
        )
        let integrity = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: segmentID,
            sharedInfo: Data("hdwatcher.segment.integrity.v2".utf8), outputByteCount: 32
        )
        return (log, integrity)
    }
}
