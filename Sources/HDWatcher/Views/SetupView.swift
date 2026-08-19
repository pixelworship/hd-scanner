import SwiftUI
import HDWatcherCore

/// First-run vault creation. The password chosen here is the only way back into
/// the log, so the screen is explicit about what happens if it is lost.
struct SetupView: View {
    @Environment(AppModel.self) private var model

    @State private var password = ""
    @State private var confirmation = ""
    @State private var hint = ""
    @State private var enableQuickUnlock = true
    @State private var acknowledgedNoRecovery = false

    private var strength: PasswordStrength { PasswordStrength.evaluate(password) }
    private var passwordsMatch: Bool { !password.isEmpty && password == confirmation }
    private var canCreate: Bool {
        passwordsMatch && strength.score >= 2 && acknowledgedNoRecovery && !model.isWorking
    }

    var body: some View {
        VaultBackdrop {
            ScrollView {
                VStack(spacing: 22) {
                    AppMark(subtitle: "Set up the encrypted vault that will hold your\nfilesystem activity log.")

                    protectionCard

                    VStack(alignment: .leading, spacing: 14) {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Vault password").font(.subheadline.weight(.medium))
                            SecureField("Choose a strong password", text: $password)
                                .textFieldStyle(.roundedBorder)
                            PasswordStrengthBar(strength: strength)
                        }

                        VStack(alignment: .leading, spacing: 6) {
                            SecureField("Confirm password", text: $confirmation)
                                .textFieldStyle(.roundedBorder)
                            if !confirmation.isEmpty && !passwordsMatch {
                                Label("Passwords do not match", systemImage: "exclamationmark.circle")
                                    .font(.caption).foregroundStyle(.red)
                            }
                        }

                        VStack(alignment: .leading, spacing: 6) {
                            TextField("Password hint (optional)", text: $hint)
                                .textFieldStyle(.roundedBorder)
                            Text("Shown on the lock screen. Do not put the password here.")
                                .font(.caption).foregroundStyle(.secondary)
                        }

                        if SecureEnclaveKeyStore.userPresenceAvailable() {
                            Toggle(isOn: $enableQuickUnlock) {
                                VStack(alignment: .leading, spacing: 1) {
                                    Text("Allow unlocking with \(model.biometryName)")
                                    Text("Stores a second copy of the key in the Secure Enclave, released only after you authenticate.")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }

                        Toggle(isOn: $acknowledgedNoRecovery) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text("I understand there is no password recovery")
                                Text("The log is encrypted with a key derived from this password. Losing it makes existing history permanently unreadable.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .card()

                    if let error = model.unlockError {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.callout).foregroundStyle(.red)
                    }

                    Button {
                        Task {
                            await model.createVault(password: password,
                                                    hint: hint.isEmpty ? nil : hint,
                                                    enableQuickUnlock: enableQuickUnlock)
                        }
                    } label: {
                        HStack {
                            if model.isWorking { ProgressView().controlSize(.small) }
                            Text(model.isWorking ? "Creating vault…" : "Create Vault")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .keyboardShortcut(.defaultAction)
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canCreate)
                }
            }
            .scrollIndicators(.never)
        }
    }

    private var protectionCard: some View {
        HStack(spacing: 12) {
            Image(systemName: SecureEnclaveKeyStore.isAvailable ? "lock.shield.fill" : "lock.shield")
                .font(.title2)
                .foregroundStyle(SecureEnclaveKeyStore.isAvailable ? .green : .orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(SecureEnclaveKeyStore.isAvailable
                     ? "Secure Enclave available"
                     : "Secure Enclave unavailable")
                    .font(.subheadline.weight(.medium))
                Text(SecureEnclaveKeyStore.isAvailable
                     ? "Your key will be bound to this Mac's hardware as well as your password. Copying the log to another machine will not make it readable."
                     : "The vault will be protected by your password alone.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .card(padding: 12)
    }
}

struct PasswordStrength {
    var score: Int        // 0...4
    var label: String
    var color: Color

    /// A deliberately simple estimator — length first, then variety. It guides
    /// the user without pretending to be a real cracking-time model.
    static func evaluate(_ password: String) -> PasswordStrength {
        guard !password.isEmpty else { return .init(score: 0, label: "Empty", color: .secondary) }

        var score = 0
        if password.count >= 8 { score += 1 }
        if password.count >= 14 { score += 1 }
        if password.count >= 20 { score += 1 }

        let classes = [
            password.rangeOfCharacter(from: .lowercaseLetters) != nil,
            password.rangeOfCharacter(from: .uppercaseLetters) != nil,
            password.rangeOfCharacter(from: .decimalDigits) != nil,
            password.rangeOfCharacter(from: .punctuationCharacters.union(.symbols)) != nil,
        ].filter { $0 }.count
        if classes >= 3 { score += 1 }
        score = min(score, 4)

        switch score {
        case 0, 1: return .init(score: score, label: "Too weak", color: .red)
        case 2:    return .init(score: score, label: "Fair", color: .orange)
        case 3:    return .init(score: score, label: "Good", color: .yellow)
        default:   return .init(score: score, label: "Strong", color: .green)
        }
    }
}

struct PasswordStrengthBar: View {
    let strength: PasswordStrength

    var body: some View {
        HStack(spacing: 6) {
            HStack(spacing: 3) {
                ForEach(0..<4, id: \.self) { index in
                    RoundedRectangle(cornerRadius: 2)
                        .fill(index < strength.score ? strength.color : Color.secondary.opacity(0.2))
                        .frame(height: 4)
                }
            }
            Text(strength.label)
                .font(.caption)
                .foregroundStyle(strength.color)
                .frame(width: 62, alignment: .trailing)
        }
    }
}
