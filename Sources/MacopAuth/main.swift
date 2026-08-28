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
    enum State {
        case starting
        case pending(PendingApproval)
        case approved
        case cancelled
        case failed(String)
    }

    struct PendingApproval {
        let request: AuthBrokerApprovalRequest
        let peer: AuthBrokerVerifiedPeer
        let context: LAContext
    }

    struct ApprovalOutcome: @unchecked Sendable {
        let status: AuthBrokerApprovalStatus
        let context: LAContext?
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
            self.continuation = continuation
            self.state = .pending(PendingApproval(request: request, peer: peer, context: context))
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
                self.finish(success ? .approved : .denied)
            } catch let error as LAError where error.code == .userCancel || error.code == .appCancel {
                self.finish(.cancelled)
            } catch {
                self.finish(.denied)
            }
        }
    }

    func cancel() {
        if case let .pending(pending) = self.state {
            pending.context.invalidate()
        }
        self.finish(.cancelled)
    }

    func fail(_ message: String) {
        self.state = .failed(message)
        self.continuation?.resume(returning: ApprovalOutcome(status: .denied, context: nil))
        self.continuation = nil
    }

    func terminateSoon() {
        Task {
            try? await Task.sleep(for: .milliseconds(250))
            NSApplication.shared.terminate(nil)
        }
    }

    private func finish(_ status: AuthBrokerApprovalStatus) {
        guard let continuation = self.continuation else { return }
        let context: LAContext? = if status == .approved, case let .pending(pending) = self.state {
            pending.context
        } else {
            nil
        }
        self.continuation = nil
        self.state = status == .approved ? .approved : .cancelled
        continuation.resume(returning: ApprovalOutcome(status: status, context: context))
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
        }
    }
}

private enum AuthBrokerRuntimeCapabilities {
    static let value: UInt32 = {
        var capabilities = AuthBrokerCapability.approvalUI.rawValue
            | AuthBrokerCapability.sshSigning.rawValue
        if AuthBrokerRuntimeCapabilities.hasManagedKeychainEntitlements() {
            capabilities |= AuthBrokerCapability.managedKeychain.rawValue
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
        case .sshSession, .sshSign:
            AuthBrokerCapability.sshSigning.rawValue
        case .managedKeychainRead, .managedKeychainImport:
            AuthBrokerCapability.managedKeychain.rawValue
        }
        guard capabilities & requiredCapability == requiredCapability else {
            throw AgentProtocolError.denied
        }
        if request.operation == .managedKeychainRead || request.operation == .managedKeychainImport {
            guard !request.keychainService.isEmpty, !request.keychainAccount.isEmpty else {
                throw AgentProtocolError.denied
            }
        }
        try self.validateRoot(request)
        let outcome = await coordinator.requestApproval(request, peer: peer)
        let signer: (any AgentKeySigning)?
        var resultStatus = outcome.status == .approved ? errSecSuccess : errSecAuthFailed
        var resultData = Data()
        if outcome.status == .approved, let context = outcome.context, request.operation == .sshSession {
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
                authenticationContext: context
            ) {
            case let .success(secret):
                resultData = secret
            case let .failure(failure):
                resultStatus = failure.status
            }
            signer = nil
        } else {
            signer = nil
        }
        try AuthBrokerSocketIO.writeMessage(.approvalResponse(AuthBrokerApprovalResponse(
            requestID: request.requestID,
            status: outcome.status,
            resultStatus: resultStatus,
            resultData: resultData
        )), to: client, timeout: 5)
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
        await coordinator.terminateSoon()
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
                ApprovalRequestView(pending: pending, cancel: self.coordinator.cancel)
                    .task(id: pending.request.requestID) { self.coordinator.authenticate(pending) }
            case .approved:
                ResultView(symbol: "checkmark.circle.fill", title: "許可しました")
            case .cancelled:
                ResultView(symbol: "xmark.circle", title: "キャンセルしました")
            case let .failed(message):
                ResultView(symbol: "exclamationmark.triangle", title: message)
            }
        }
        .padding(28)
    }
}

private struct ApprovalRequestView: View {
    let pending: AuthApprovalCoordinator.PendingApproval
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
                    self.row("操作", self.pending.request.operation == .managedKeychainRead ? "読み取り" : "登録")
                    self.row("サービス", self.pending.request.keychainService)
                    self.row("アカウント", self.pending.request.keychainAccount)
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
    }

    private var requestTitle: String {
        if self.isManagedKeychainRequest {
            let action = self.pending.request.operation == .managedKeychainRead ? "読み取り" : "登録"
            return "\(self.requesterName) がKeychain項目の\(action)を要求しています"
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
