import SwiftUI
import HDWatcherCore

struct LockView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @FocusState private var focused: Bool
    @State private var now = Date()

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var lockout: Date? { model.vault.lockoutUntil }
    private var lockedOut: Bool { (lockout ?? .distantPast) > now }

    var body: some View {
        VaultBackdrop {
            VStack(spacing: 22) {
                AppMark(subtitle: "Your activity log is encrypted.\nUnlock to resume monitoring.")

                VStack(spacing: 14) {
                    SecureField("Vault password", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .controlSize(.large)
                        .focused($focused)
                        .disabled(model.isWorking || lockedOut)
                        .onSubmit(submit)

                    if let hint = model.vault.passwordHint, !hint.isEmpty {
                        Label("Hint: \(hint)", systemImage: "lightbulb")
                            .font(.caption).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    Button(action: submit) {
                        HStack {
                            if model.isWorking { ProgressView().controlSize(.small) }
                            Text(model.isWorking ? "Unlocking…" : "Unlock")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .keyboardShortcut(.defaultAction)
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty || model.isWorking || lockedOut)

                    if model.quickUnlockAvailable {
                        Button {
                            Task { await model.unlockWithBiometrics() }
                        } label: {
                            Label("Unlock with \(model.biometryName)",
                                  systemImage: model.biometryName == "Touch ID" ? "touchid" : "person.badge.key")
                                .frame(maxWidth: .infinity)
                        }
                        .controlSize(.large)
                        .disabled(model.isWorking || lockedOut)
                    }
                }
                .card()

                if lockedOut, let lockout {
                    let remaining = max(0, Int(lockout.timeIntervalSince(now)))
                    Label("Too many attempts — locked for \(remaining)s",
                          systemImage: "hourglass")
                        .font(.callout).foregroundStyle(.orange)
                } else if let error = model.unlockError {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .font(.callout).foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                }

                HStack(spacing: 6) {
                    Image(systemName: model.protectionTier.isHardwareBacked ? "lock.shield.fill" : "lock.shield")
                    Text(model.protectionTier.displayName)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .onAppear { focused = true }
        .onReceive(ticker) { now = $0 }
    }

    private func submit() {
        guard !password.isEmpty, !lockedOut else { return }
        let value = password
        password = ""
        Task { await model.unlock(password: value) }
    }
}
