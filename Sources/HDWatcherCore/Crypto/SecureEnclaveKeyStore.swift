import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// How strongly the master key is protected on this machine.
public enum KeyProtectionTier: String, Codable, Sendable {
    /// Master key requires the password AND a secret that only this Mac's
    /// Secure Enclave can produce. The vault cannot be opened on other hardware.
    case secureEnclave
    /// No usable Secure Enclave; the password alone protects the vault.
    case passwordOnly

    public var displayName: String {
        switch self {
        case .secureEnclave: return "Secure Enclave + Password"
        case .passwordOnly:  return "Password Only"
        }
    }

    public var isHardwareBacked: Bool { self == .secureEnclave }
}

/// A Secure Enclave key-agreement keypair, persisted as the enclave's own
/// wrapped blob rather than as a keychain item.
///
/// This matters: keychain-resident Secure Enclave keys require a
/// `keychain-access-groups` entitlement backed by a real team identifier, which
/// an ad-hoc signed build does not have (it fails with errSecMissingEntitlement).
/// CryptoKit's `dataRepresentation` is an enclave-encrypted blob that is inert
/// on any other machine, so storing it beside the vault is safe and keeps the
/// app buildable without a paid signing identity.
public struct SecureEnclaveBinding: Codable, Sendable {
    /// The enclave-wrapped private key. Useless on other hardware.
    public var keyBlob: Data
    /// Ephemeral P-256 public key used for the ECDH that wrapped the master key.
    public var ephemeralPublicKey: Data
    public var salt: Data
    /// True when unwrapping requires Touch ID or the login password.
    public var requiresUserPresence: Bool

    public init(keyBlob: Data, ephemeralPublicKey: Data, salt: Data, requiresUserPresence: Bool) {
        self.keyBlob = keyBlob
        self.ephemeralPublicKey = ephemeralPublicKey
        self.salt = salt
        self.requiresUserPresence = requiresUserPresence
    }
}

public enum SecureEnclaveKeyStore {

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Whether Touch ID (or a paired Watch) can be used on this Mac.
    public static func biometryAvailable() -> Bool {
        let ctx = LAContext()
        var err: NSError?
        return ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    }

    /// Whether any user-presence check is possible (biometry or device password).
    public static func userPresenceAvailable() -> Bool {
        let ctx = LAContext()
        var err: NSError?
        return ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err)
    }

    public static func biometryDescription() -> String {
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else {
            return userPresenceAvailable() ? "Device password" : "Unavailable"
        }
        switch ctx.biometryType {
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        case .faceID:  return "Face ID"
        default:       return "Biometrics"
        }
    }

    private static func accessControl(requireUserPresence: Bool) throws -> SecAccessControl {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireUserPresence { flags.insert(.userPresence) }
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &error
        ) else {
            let msg = (error?.takeRetainedValue()).map { String(describing: $0) } ?? "unknown"
            throw CryptoError.secureEnclaveFailed("access control: \(msg)")
        }
        return ac
    }

    /// Creates a fresh enclave key and wraps `secret` to it via ECDH.
    public static func createBinding(
        wrapping secret: Data,
        requireUserPresence: Bool,
        info: String
    ) throws -> (binding: SecureEnclaveBinding, sealed: Data) {
        guard SecureEnclave.isAvailable else { throw CryptoError.secureEnclaveUnavailable }
        let ac = try accessControl(requireUserPresence: requireUserPresence)

        let enclaveKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        } catch {
            throw CryptoError.secureEnclaveFailed(String(describing: error))
        }

        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
        let salt = CryptoPrimitives.randomBytes(32)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt,
            sharedInfo: Data(info.utf8), outputByteCount: 32
        )
        let sealed = try CryptoPrimitives.seal(secret, key: kek)

        return (
            SecureEnclaveBinding(
                keyBlob: enclaveKey.dataRepresentation,
                ephemeralPublicKey: ephemeral.publicKey.rawRepresentation,
                salt: salt,
                requiresUserPresence: requireUserPresence
            ),
            sealed
        )
    }

    /// Reconstructs the enclave key and recovers the wrapped secret. When the
    /// binding requires user presence this triggers the system auth prompt.
    public static func unwrap(
        binding: SecureEnclaveBinding,
        sealed: Data,
        info: String,
        reason: String,
        context: LAContext? = nil
    ) throws -> Data {
        guard SecureEnclave.isAvailable else { throw CryptoError.secureEnclaveUnavailable }

        let enclaveKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            if let context {
                context.localizedReason = reason
                enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: binding.keyBlob,
                    authenticationContext: context
                )
            } else {
                enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: binding.keyBlob
                )
            }
        } catch {
            throw CryptoError.secureEnclaveFailed(String(describing: error))
        }

        let ephemeralPub = try P256.KeyAgreement.PublicKey(
            rawRepresentation: binding.ephemeralPublicKey
        )
        let shared = try enclaveKey.sharedSecretFromKeyAgreement(with: ephemeralPub)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: binding.salt,
            sharedInfo: Data(info.utf8), outputByteCount: 32
        )
        return try CryptoPrimitives.open(sealed, key: kek)
    }

    /// Rewraps an existing secret to the *same* enclave key with a new ephemeral
    /// key. Used when the password changes but the hardware binding should stay.
    public static func rewrap(
        binding: SecureEnclaveBinding,
        secret: Data,
        info: String
    ) throws -> (binding: SecureEnclaveBinding, sealed: Data) {
        let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: binding.keyBlob
        )
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
        let salt = CryptoPrimitives.randomBytes(32)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt,
            sharedInfo: Data(info.utf8), outputByteCount: 32
        )
        let sealed = try CryptoPrimitives.seal(secret, key: kek)
        var updated = binding
        updated.ephemeralPublicKey = ephemeral.publicKey.rawRepresentation
        updated.salt = salt
        return (updated, sealed)
    }
}
