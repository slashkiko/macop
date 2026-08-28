// swiftlint:disable file_length
import AppKit
import Darwin
import LocalAuthentication
import MacopCore
import Security
import SwiftUI

@main
struct MacopAuthApplication: App {
    @StateObject private var coordinator = AuthApprovalCoordinator(socketPath: Self.socketPath())

    var body: some Scene {
        WindowGroup("Macop") {
            AuthApprovalView(coordinator: self.coordinator)
                .frame(minWidth: 480, idealWidth: 560, minHeight: 520, idealHeight: 620)
                .task { self.coordinator.start() }
        }
        .windowResizability(.contentSize)
    }

    private static func socketPath() -> String? {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let index = arguments.firstIndex(of: "--socket"), index + 1 < arguments.count else { return nil }
        return arguments[index + 1]
    }
}

@MainActor
private final class AuthApprovalCoordinator: ObservableObject {
    private enum PasswordPoCError: Error {
        case accessControlUnavailable
    }

    enum State {
        case starting
        case pending(PendingApproval)
        case processing
        case completed(String)
        case cancelled
        case failed(String)
    }

    struct PendingApproval {
        let request: AuthBrokerApprovalRequest
        let peer: AuthBrokerVerifiedPeer
        let context: LAContext
        let attemptID: UUID
    }

    struct ApprovalOutcome: @unchecked Sendable {
        let status: AuthBrokerApprovalStatus
        let context: LAContext?
        let credential: Data?
        let saveToKeychain: Bool
    }

    @Published private(set) var state: State = .starting
    private let socketPath: String?
    private var started = false
    private var continuation: CheckedContinuation<ApprovalOutcome, Never>?

    init(socketPath: String?) {
        self.socketPath = socketPath
    }

    func start() {
        guard !self.started else { return }
        self.started = true
        guard let socketPath = self.socketPath else {
            self.state = .failed("MacopAuthはmacopから起動してください。")
            return
        }
        Task.detached { [weak self] in
            guard let self else { return }
            do {
                try await AuthBrokerAppServer.run(socketPath: socketPath, coordinator: self)
            } catch {
                await self.fail("承認要求を安全に検証できませんでした。")
                await self.terminateSoon()
            }
        }
    }

    func requestApproval(
        _ request: AuthBrokerApprovalRequest,
        peer: AuthBrokerVerifiedPeer
    ) async -> ApprovalOutcome {
        await withCheckedContinuation { continuation in
            let context = LAContext()
            context.localizedCancelTitle = "キャンセル"
            context.localizedFallbackTitle = "パスワードを使用"
            self.continuation = continuation
            self.state = .pending(PendingApproval(
                request: request,
                peer: peer,
                context: context,
                attemptID: UUID()
            ))
            NSApplication.shared.activate(ignoringOtherApps: true)
            NSApplication.shared.windows.first?.makeKeyAndOrderFront(nil)
            NSRunningApplication.current.activate(options: [.activateAllWindows])
        }
    }

    func authenticate(_ pending: PendingApproval) {
        guard case let .pending(current) = self.state,
              current.request.requestID == pending.request.requestID else { return }
        Task {
            do {
                let success = try await pending.context.evaluatePolicy(
                    .deviceOwnerAuthentication,
                    localizedReason: self.localizedReason(for: pending.request)
                )
                self.finish(success ? .approved : .denied, pending: pending)
            } catch let error as LAError where error.code == .userCancel || error.code == .appCancel {
                self.finish(.cancelled, pending: pending)
            } catch {
                self.finish(.denied, pending: pending)
            }
        }
    }

    func authenticateWithPassword(_ pending: PendingApproval) {
        guard case let .pending(current) = self.state,
              current.attemptID == pending.attemptID else { return }
        let context = LAContext()
        context.localizedCancelTitle = "キャンセル"
        let replacement = PendingApproval(
            request: pending.request,
            peer: pending.peer,
            context: context,
            attemptID: UUID()
        )
        self.state = .pending(replacement)
        current.context.invalidate()
        Task {
            do {
                let success = try await self.evaluatePasswordOnly(replacement)
                self.finish(success ? .approved : .denied, pending: replacement)
            } catch let error as LAError where error.code == .userCancel || error.code == .appCancel {
                self.finish(.cancelled, pending: replacement)
            } catch {
                self.finish(.denied, pending: replacement)
            }
        }
    }

    func submitCredential(
        _ password: String,
        saveToKeychain: Bool,
        passwordOnly: Bool,
        pending: PendingApproval
    ) {
        guard case let .pending(current) = self.state,
              current.request.requestID == pending.request.requestID,
              !password.isEmpty,
              let credential = password.data(using: .utf8),
              credential.count <= ManagedKeychainStore.maximumSecretLength,
              !password.contains("\0")
        else { return }
        Task {
            do {
                let success = if passwordOnly {
                    try await self.evaluatePasswordOnly(pending)
                } else {
                    try await pending.context.evaluatePolicy(
                        .deviceOwnerAuthentication,
                        localizedReason: self.localizedReason(for: pending.request)
                    )
                }
                self.finish(
                    success ? .approved : .denied,
                    credential: success ? credential : nil,
                    saveToKeychain: success && saveToKeychain,
                    pending: pending
                )
            } catch let error as LAError where error.code == .userCancel || error.code == .appCancel {
                self.finish(.cancelled, pending: pending)
            } catch {
                self.finish(.denied, pending: pending)
            }
        }
    }

    func cancel() {
        if case let .pending(pending) = self.state {
            pending.context.invalidate()
            self.finish(.cancelled, pending: pending)
        }
    }

    func fail(_ message: String) {
        self.state = .failed(message)
        self.continuation?.resume(returning: ApprovalOutcome(
            status: .denied,
            context: nil,
            credential: nil,
            saveToKeychain: false
        ))
        self.continuation = nil
    }

    func complete(_ message: String) {
        self.state = .completed(message)
    }

    func terminateSoon(after delay: Duration = .milliseconds(250)) {
        Task {
            try? await Task.sleep(for: delay)
            NSApplication.shared.terminate(nil)
        }
    }

    private func finish(
        _ status: AuthBrokerApprovalStatus,
        credential: Data? = nil,
        saveToKeychain: Bool = false,
        pending: PendingApproval
    ) {
        guard let continuation = self.continuation,
              case let .pending(current) = self.state,
              current.attemptID == pending.attemptID
        else { return }
        let context: LAContext? = if status == .approved {
            current.context
        } else {
            nil
        }
        self.continuation = nil
        self.state = status == .approved ? .processing : .cancelled
        continuation.resume(returning: ApprovalOutcome(
            status: status,
            context: context,
            credential: credential,
            saveToKeychain: saveToKeychain
        ))
    }

    private func localizedReason(for request: AuthBrokerApprovalRequest) -> String {
        switch request.operation {
        case .sshSession:
            "Secure EnclaveのSSH鍵を使用します。"
        case .managedKeychainRead:
            "macop管理のKeychain項目を読み取ります。"
        case .sshSign:
            "Secure EnclaveのSSH鍵で署名します。"
        case .managedKeychainImport:
            "Touch IDで保護するKeychain項目を登録します。"
        case .passwordAutoFill:
            "Passwordsから選んだ資格情報をmacopで使用します。"
        case .managedKeychainDelete:
            "macop管理のKeychain項目を削除します。"
        case .gitSSHSign:
            "Secure EnclaveのSSH鍵でGit commitまたはtagへ署名します。"
        }
    }

    private func evaluatePasswordOnly(_ pending: PendingApproval) async throws -> Bool {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .devicePasscode,
            &error
        ) else {
            if let error {
                throw error.takeRetainedValue()
            }
            throw PasswordPoCError.accessControlUnavailable
        }
        return try await pending.context.evaluateAccessControl(
            accessControl,
            operation: .useItem,
            localizedReason: self.localizedReason(for: pending.request)
        )
    }
}

private enum AuthBrokerRuntimeCapabilities {
    static let value: UInt32 = {
        var capabilities = AuthBrokerCapability.approvalUI.rawValue
            | AuthBrokerCapability.sshSigning.rawValue
        if AuthBrokerRuntimeCapabilities.hasManagedKeychainEntitlements() {
            capabilities |= AuthBrokerCapability.managedKeychain.rawValue
                | AuthBrokerCapability.passwordAutoFill.rawValue
        }
        return capabilities
    }()

    private static func hasManagedKeychainEntitlements() -> Bool {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return false }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return false }
        var raw: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &raw
        ) == errSecSuccess,
            let information = raw as? [CFString: Any],
            let entitlements = information[kSecCodeInfoEntitlementsDict] as? [String: Any],
            let applicationIdentifier = entitlements["com.apple.application-identifier"] as? String,
            let accessGroups = entitlements["keychain-access-groups"] as? [String]
        else { return false }
        return !applicationIdentifier.isEmpty && accessGroups.contains(applicationIdentifier)
    }
}

private enum AuthBrokerAppServer {
    static func run(socketPath: String, coordinator: AuthApprovalCoordinator) async throws {
        try self.validateSocketParent(socketPath)
        let executable = try RunningExecutable.path()
        let serverIdentity = try LiveCodeIdentityInspector.inspect(pid: getpid(), expectedPath: executable).identity
        guard serverIdentity.identifier == AuthBrokerCompanionResolver.appIdentifier,
              serverIdentity.hasTrustedPublisher,
              let teamID = serverIdentity.teamID, !teamID.isEmpty else { throw AgentProtocolError.denied }

        let listener = try AuthBrokerSocketIO.openListener(path: socketPath)
        defer { close(listener); _ = unlink(socketPath) }
        let client = try AuthBrokerSocketIO.accept(listener: listener, timeout: 10)
        defer { close(client) }
        let peerEvidence = try SocketPeerEvidence.read(from: client)
        let peer = try AuthBrokerPeerVerifier(expectedTeamID: teamID).verify(peer: peerEvidence)

        guard case let .hello(hello) = try AuthBrokerSocketIO.readMessage(from: client, timeout: 5) else {
            throw AgentProtocolError.denied
        }
        let selected = try AuthBrokerWire.selectVersion(
            clientMinimum: hello.minimumVersion,
            clientMaximum: hello.maximumVersion
        )
        let capabilities = AuthBrokerRuntimeCapabilities.value
        try AuthBrokerSocketIO.writeMessage(.helloReply(AuthBrokerHelloReply(
            selectedVersion: selected,
            capabilities: capabilities,
            nonce: AuthBrokerSocketIO.randomNonce()
        )), to: client, timeout: 5)

        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        guard case let .approvalRequest(request) = try AuthBrokerSocketIO.readMessage(
            from: client,
            timeout: 10,
            nowMilliseconds: now
        ) else { throw AgentProtocolError.denied }
        guard request.operation != .sshSign else { throw AgentProtocolError.denied }
        let requiredCapability = switch request.operation {
        case .sshSession, .sshSign, .gitSSHSign:
            AuthBrokerCapability.sshSigning.rawValue
        case .managedKeychainRead, .managedKeychainImport, .passwordAutoFill, .managedKeychainDelete:
            AuthBrokerCapability.managedKeychain.rawValue
        }
        guard capabilities & requiredCapability == requiredCapability else {
            throw AgentProtocolError.denied
        }
        let isKeychainRequest = request.operation == .managedKeychainRead
            || request.operation == .managedKeychainImport
            || request.operation == .passwordAutoFill
            || request.operation == .managedKeychainDelete
        if isKeychainRequest {
            let isDeleteAll = request.operation == .managedKeychainDelete
                && request.keychainService.isEmpty
                && request.keychainAccount.isEmpty
            guard isDeleteAll || (!request.keychainService.isEmpty && !request.keychainAccount.isEmpty) else {
                throw AgentProtocolError.denied
            }
        }
        try self.validateRoot(request)
        let outcome = await coordinator.requestApproval(request, peer: peer)
        let signer: (any AgentKeySigning)?
        var resultStatus = outcome.status == .approved ? errSecSuccess : errSecAuthFailed
        var resultData = Data()
        var resultMessage = ""
        let isSigningRequest = request.operation == .sshSession || request.operation == .gitSSHSign
        if outcome.status == .approved, let context = outcome.context, isSigningRequest {
            try self.validateRoot(request)
            let candidate = try SSHCommand.makeVerifiedSessionSigner(
                label: request.credentialLabel,
                authenticationContext: context
            )
            guard constantTimeEqual(
                Data(candidate.fingerprint.utf8),
                Data(request.credentialFingerprint.utf8)
            ) else { throw AgentProtocolError.denied }
            signer = candidate
            resultData = candidate.publicKeyBlob
        } else if outcome.status == .approved,
                  let context = outcome.context,
                  request.operation == .managedKeychainRead
        // swiftlint:disable:next opening_brace
        {
            try self.validateRoot(request)
            switch ManagedKeychainStore.read(
                service: request.keychainService,
                account: request.keychainAccount,
                synchronizable: request.keychainSynchronizable,
                authenticationContext: context
            ) {
            case let .success(secret):
                resultData = secret
            case let .failure(failure):
                resultStatus = failure.status
            }
            signer = nil
        } else if outcome.status == .approved,
                  let context = outcome.context,
                  let credential = outcome.credential,
                  request.operation == .passwordAutoFill
        // swiftlint:disable:next opening_brace
        {
            try self.validateRoot(request)
            resultData = credential
            if outcome.saveToKeychain {
                resultStatus = ManagedKeychainStore.upsertSecret(
                    credential,
                    service: request.keychainService,
                    account: request.keychainAccount,
                    synchronizable: request.keychainSynchronizable,
                    authenticationContext: context
                )
                resultMessage = resultStatus == errSecSuccess ? "saved" : "save_failed"
            } else {
                resultMessage = "not_requested"
            }
            signer = nil
        } else if outcome.status == .approved,
                  let context = outcome.context,
                  request.operation == .managedKeychainDelete
        // swiftlint:disable:next opening_brace
        {
            try self.validateRoot(request)
            if request.keychainService.isEmpty, request.keychainAccount.isEmpty {
                resultStatus = ManagedKeychainStore.deleteAll(authenticationContext: context)
            } else {
                resultStatus = ManagedKeychainStore.delete(
                    service: request.keychainService,
                    account: request.keychainAccount,
                    synchronizable: request.keychainSynchronizable,
                    authenticationContext: context
                )
            }
            signer = nil
        } else {
            signer = nil
        }
        try AuthBrokerSocketIO.writeMessage(.approvalResponse(AuthBrokerApprovalResponse(
            requestID: request.requestID,
            status: outcome.status,
            message: resultMessage,
            resultStatus: resultStatus,
            resultData: resultData
        )), to: client, timeout: 5)
        let completionMessage = if request.operation == .passwordAutoFill {
            switch resultMessage {
            case "saved": "Keychainに保存しました"
            case "not_requested": "今回のみ使用しました"
            default: "資格情報を受け取りましたが、Keychainへの保存に失敗しました"
            }
        } else if request.operation == .managedKeychainDelete {
            resultStatus == errSecSuccess ? "Keychainから削除しました" : "Keychain項目の削除に失敗しました"
        } else if request.operation == .gitSSHSign {
            "Git SSH署名を許可しました"
        } else {
            "許可しました"
        }
        await coordinator.complete(completionMessage)
        if let signer {
            try self.serveSigning(
                client: client,
                request: request,
                signer: signer
            )
        } else if outcome.status == .approved,
                  let context = outcome.context,
                  request.operation == .managedKeychainImport
        // swiftlint:disable:next opening_brace
        {
            try self.serveManagedKeychainImport(client: client, request: request, context: context)
        }
        await coordinator.terminateSoon(
            after: request.operation == .passwordAutoFill ? .seconds(2) : .milliseconds(250)
        )
    }

    private static func serveManagedKeychainImport(
        client: Int32,
        request: AuthBrokerApprovalRequest,
        context: LAContext
    ) throws {
        guard case let .managedKeychainImportRequest(importRequest) = try AuthBrokerSocketIO.readMessage(
            from: client,
            timeout: 30
        ), importRequest.authorizationID == request.requestID else { throw AgentProtocolError.denied }
        try self.validateRoot(request)
        let status = ManagedKeychainStore.importSecret(
            importRequest.secret,
            service: request.keychainService,
            account: request.keychainAccount,
            synchronizable: request.keychainSynchronizable,
            authenticationContext: context
        )
        try AuthBrokerSocketIO.writeMessage(.managedKeychainImportResponse(
            AuthBrokerManagedKeychainImportResponse(
                authorizationID: request.requestID,
                status: status
            )
        ), to: client, timeout: 30)
    }

    private static func serveSigning(
        client: Int32,
        request: AuthBrokerApprovalRequest,
        signer: any AgentKeySigning
    ) throws {
        while true {
            let now = UInt64(Date().timeIntervalSince1970 * 1000)
            guard now < request.expiresAtMilliseconds else { return }
            let remaining = TimeInterval(request.expiresAtMilliseconds - now) / 1000
            let message: AuthBrokerMessage
            do {
                message = try AuthBrokerSocketIO.readMessage(
                    from: client,
                    timeout: min(remaining, 600),
                    nowMilliseconds: now
                )
            } catch {
                return
            }
            guard case let .sshSignRequest(signRequest) = message,
                  signRequest.authorizationID == request.requestID else { throw AgentProtocolError.denied }
            try self.validateRoot(request)
            let signature = try signer.sign(data: signRequest.data, flags: signRequest.flags)
            try AuthBrokerSocketIO.writeMessage(.sshSignResponse(AuthBrokerSSHSignResponse(
                authorizationID: request.requestID,
                signature: signature
            )), to: client, timeout: 30)
        }
    }

    private static func validateRoot(_ request: AuthBrokerApprovalRequest) throws {
        let inspector = SystemRequesterInspector()
        guard let before = inspector.snapshot(of: request.rootPID),
              before.startTime == request.rootStartTime,
              try inspector.validatedCodeIdentity(
                  pid: request.rootPID,
                  requirement: request.rootCodeRequirement
              ) == request.rootIdentifier
        else { throw AgentProtocolError.denied }
        let identity = try LiveCodeIdentityInspector.inspect(
            pid: request.rootPID,
            expectedPath: request.rootExecutablePath
        ).identity
        guard identity.identifier == request.rootIdentifier,
              inspector.snapshot(of: request.rootPID) == before else { throw AgentProtocolError.denied }
    }

    private static func validateSocketParent(_ socketPath: String) throws {
        let url = URL(fileURLWithPath: socketPath)
        guard url.lastPathComponent == "auth.sock",
              url.path.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path)
        else { throw AgentProtocolError.denied }
        var parent = stat()
        guard lstat(url.deletingLastPathComponent().path, &parent) == 0,
              parent.st_mode & S_IFMT == S_IFDIR,
              parent.st_uid == getuid(), parent.st_mode & 0o077 == 0
        else { throw AgentProtocolError.denied }
    }
}

private struct AuthApprovalView: View {
    @ObservedObject var coordinator: AuthApprovalCoordinator

    var body: some View {
        Group {
            switch self.coordinator.state {
            case .starting:
                ProgressView("承認要求を確認しています…")
            case let .pending(pending):
                if pending.request.operation == .passwordAutoFill {
                    PasswordAutoFillRequestView(
                        pending: pending,
                        submit: { password, save, passwordOnly in
                            self.coordinator.submitCredential(
                                password,
                                saveToKeychain: save,
                                passwordOnly: passwordOnly,
                                pending: pending
                            )
                        },
                        cancel: self.coordinator.cancel
                    )
                } else {
                    ApprovalRequestView(
                        pending: pending,
                        usePassword: { self.coordinator.authenticateWithPassword(pending) },
                        cancel: self.coordinator.cancel
                    )
                    .task(id: pending.request.requestID) { self.coordinator.authenticate(pending) }
                }
            case .processing:
                ProgressView("処理しています…")
            case let .completed(message):
                ResultView(symbol: "checkmark.circle.fill", title: message)
            case .cancelled:
                ResultView(symbol: "xmark.circle", title: "キャンセルしました")
            case let .failed(message):
                ResultView(symbol: "exclamationmark.triangle", title: message)
            }
        }
        .padding(28)
    }
}

private struct PasswordAutoFillRequestView: View {
    let pending: AuthApprovalCoordinator.PendingApproval
    let submit: (String, Bool, Bool) -> Void
    let cancel: () -> Void
    @State private var password = ""
    @State private var saveToKeychain = true

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 14) {
                Image(nsImage: self.requesterIcon)
                    .resizable()
                    .frame(width: 52, height: 52)
                VStack(alignment: .leading, spacing: 3) {
                    Text("\(self.requesterName) が資格情報を要求しています")
                        .font(.headline)
                    Label("検証済み", systemImage: "checkmark.seal.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                }
                Spacer()
            }
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                Text("Passwordsから選択")
                    .font(.title3.weight(.semibold))
                Text("パスワード欄をクリックし、システムのAutoFill候補から使用するログイン情報を選んでください。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 12) {
                AutoFillTextField(
                    text: self.$password,
                    placeholder: "パスワード",
                    contentType: .password,
                    secure: true
                )
            }
            Toggle("選んだパスワードをmacop管理のKeychainに保存・更新する", isOn: self.$saveToKeychain)
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                self.row("サービス", self.pending.request.keychainService)
                self.row("保存先", self.pending.request.keychainAccount)
                self.row("コマンド", self.pending.request.command)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
            VStack(alignment: .leading, spacing: 12) {
                Text("資格情報は画面に再表示せず、現在の要求にだけ返します")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    Button("キャンセル", action: self.cancel)
                        .keyboardShortcut(.cancelAction)
                    Spacer(minLength: 24)
                    HStack(spacing: 10) {
                        Button("Macのパスワードで使用") {
                            self.submit(self.password, self.saveToKeychain, true)
                            self.password = ""
                        }
                        Button("Touch IDで使用") {
                            self.submit(self.password, self.saveToKeychain, false)
                            self.password = ""
                        }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                    }
                    .fixedSize(horizontal: true, vertical: false)
                    .disabled(self.password.isEmpty)
                }
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).lineLimit(2).textSelection(.enabled)
        }
    }

    private var requesterIdentity: LiveCodeIdentity {
        self.pending.peer.requestingApplication ?? self.pending.peer.peerIdentity
    }

    private var requesterName: String {
        let path = self.requesterIdentity.canonicalPath
        if let range = path.range(of: ".app/Contents/MacOS/") {
            return URL(fileURLWithPath: String(path[..<range.lowerBound]) + ".app")
                .deletingPathExtension().lastPathComponent
        }
        return URL(fileURLWithPath: path).lastPathComponent
    }

    private var requesterIcon: NSImage {
        let path = self.requesterIdentity.canonicalPath
        if let range = path.range(of: ".app/Contents/MacOS/") {
            return NSWorkspace.shared.icon(forFile: String(path[..<range.lowerBound]) + ".app")
        }
        return NSWorkspace.shared.icon(forFile: path)
    }
}

private struct AutoFillTextField: NSViewRepresentable {
    @Binding var text: String
    let placeholder: String
    let contentType: NSTextContentType
    let secure: Bool

    func makeCoordinator() -> Coordinator {
        Coordinator(text: self.$text)
    }

    func makeNSView(context: Context) -> NSTextField {
        let field: NSTextField = self.secure ? NSSecureTextField() : NSTextField()
        field.placeholderString = self.placeholder
        field.contentType = self.contentType
        field.delegate = context.coordinator
        field.isEditable = true
        field.isSelectable = true
        field.bezelStyle = .roundedBezel
        field.controlSize = .large
        field.font = .systemFont(ofSize: NSFont.systemFontSize(for: .large))
        return field
    }

    func updateNSView(_ field: NSTextField, context _: Context) {
        if field.stringValue != self.text {
            field.stringValue = self.text
        }
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        @Binding private var text: String

        init(text: Binding<String>) {
            self._text = text
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSTextField else { return }
            self.text = field.stringValue
        }
    }
}

private struct ApprovalRequestView: View {
    let pending: AuthApprovalCoordinator.PendingApproval
    let usePassword: () -> Void
    let cancel: () -> Void

    var body: some View {
        VStack(spacing: 20) {
            HStack(spacing: 14) {
                Image(nsImage: self.requesterIcon)
                    .resizable()
                    .frame(width: 52, height: 52)
                VStack(alignment: .leading, spacing: 3) {
                    Text(self.requestTitle)
                        .font(.headline)
                    Label("検証済み", systemImage: "checkmark.seal.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                }
                Spacer()
            }
            Divider()
            LocalAuthenticationView("Touch IDで許可", context: self.pending.context)
                .controlSize(.large)
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                if self.isManagedKeychainRequest {
                    self.row("操作", self.managedKeychainAction)
                    if self.isDeleteAllRequest {
                        self.row("対象", "macop管理のKeychain項目すべて")
                    } else {
                        self.row("サービス", self.pending.request.keychainService)
                        self.row("アカウント", self.pending.request.keychainAccount)
                    }
                } else {
                    self.row("接続先", self.pending.request.host.isEmpty ? "SSHセッション" : self.pending.request.host)
                    self.row("使用する鍵", self.pending.request.credentialLabel)
                    self.row("フィンガープリント", self.pending.request.credentialFingerprint)
                }
                self.row("コマンド", self.pending.request.command)
            }
            .padding(14)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
            HStack {
                Text("現在のプロセスと要求内容にだけ有効")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Macのパスワードを使用", action: self.usePassword)
                Button("キャンセル", action: self.cancel)
                    .keyboardShortcut(.cancelAction)
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).lineLimit(2).textSelection(.enabled)
        }
    }

    private var requesterIdentity: LiveCodeIdentity {
        self.pending.peer.requestingApplication ?? self.pending.peer.peerIdentity
    }

    private var isManagedKeychainRequest: Bool {
        self.pending.request.operation == .managedKeychainRead
            || self.pending.request.operation == .managedKeychainImport
            || self.pending.request.operation == .managedKeychainDelete
    }

    private var isDeleteAllRequest: Bool {
        self.pending.request.operation == .managedKeychainDelete
            && self.pending.request.keychainService.isEmpty
            && self.pending.request.keychainAccount.isEmpty
    }

    private var managedKeychainAction: String {
        switch self.pending.request.operation {
        case .managedKeychainRead: "読み取り"
        case .managedKeychainDelete: "削除"
        default: "登録"
        }
    }

    private var requestTitle: String {
        if self.isManagedKeychainRequest {
            return "\(self.requesterName) がKeychain項目の\(self.managedKeychainAction)を要求しています"
        }
        if self.pending.request.operation == .gitSSHSign {
            return "\(self.requesterName) がGit SSH署名を要求しています"
        }
        return "\(self.requesterName) がSSH鍵を要求しています"
    }

    private var requesterName: String {
        let path = self.requesterIdentity.canonicalPath
        if let range = path.range(of: ".app/Contents/MacOS/") {
            return URL(fileURLWithPath: String(path[..<range.lowerBound]) + ".app")
                .deletingPathExtension().lastPathComponent
        }
        return URL(fileURLWithPath: path).lastPathComponent
    }

    private var requesterIcon: NSImage {
        let path = self.requesterIdentity.canonicalPath
        if let range = path.range(of: ".app/Contents/MacOS/") {
            return NSWorkspace.shared.icon(forFile: String(path[..<range.lowerBound]) + ".app")
        }
        return NSWorkspace.shared.icon(forFile: path)
    }
}

private struct ResultView: View {
    let symbol: String
    let title: String

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: self.symbol).font(.system(size: 42)).foregroundStyle(.secondary)
            Text(self.title).font(.headline).multilineTextAlignment(.center)
        }
    }
}
