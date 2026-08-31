// swiftlint:disable file_length
import AppKit
import Darwin
import LocalAuthentication
import MacopCore
import Security
import SwiftUI

@main
struct MacopAuthApplication: App {
    @StateObject private var coordinator: AuthApprovalCoordinator

    init() {
        // The companion has no installer verification command.  It therefore
        // never starts a socket/UI while its sibling generation is pending.
        if case let .blocked(reason) = InstallGenerationGuard.invocationDecision(argv: CommandLine.arguments) {
            fputs("MacopAuth: \(reason.diagnostic).\n", stderr)
            exit(ExitCode.providerUnavailable.rawValue)
        }
        _coordinator = StateObject(wrappedValue: AuthApprovalCoordinator(
            socketPath: Self.socketPath(), probe: Self.isProbe()
        ))
    }

    var body: some Scene {
        WindowGroup("Macop") {
            AuthApprovalView(coordinator: self.coordinator)
                .frame(minWidth: 400, idealWidth: 580, minHeight: 220, idealHeight: 440)
                .task { self.coordinator.start() }
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 440, height: 240)
    }

    private static func socketPath() -> String? {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let index = arguments.firstIndex(of: "--socket"), index + 1 < arguments.count else { return nil }
        return arguments[index + 1]
    }

    private static func isProbe() -> Bool {
        CommandLine.arguments.dropFirst().contains("--probe")
    }
}

@MainActor
// swiftlint:disable:next type_body_length
private final class AuthApprovalCoordinator: NSObject, ObservableObject {
    private enum PasswordPoCError: Error {
        case accessControlUnavailable
    }

    enum State {
        case starting
        case pending(PendingApproval)
        case processing
        case completed(Completion)
        case cancelled(String)
        case denied(String)
        case failed(String)
    }

    struct Completion {
        let message: String
        let isSuccess: Bool
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
        let username: String?
        let saveToKeychain: Bool
    }

    @Published private(set) var state: State = .starting {
        didSet { self.resizeWindow(for: self.state) }
    }

    private let socketPath: String?
    private let probe: Bool
    private var started = false
    private var continuation: CheckedContinuation<ApprovalOutcome, Never>?
    private weak var observedWindow: NSWindow?
    private var isTerminating = false

    init(socketPath: String?, probe: Bool = false) {
        self.socketPath = socketPath
        self.probe = probe
        super.init()
    }

    func start() {
        guard !self.started else { return }
        self.started = true
        self.resizeWindow(for: self.state)
        guard let socketPath = self.socketPath else {
            self.state = .failed("MacopAuthはmacopから起動してください。")
            return
        }
        Task.detached { [weak self] in
            guard let self else { return }
            do {
                try await AuthBrokerAppServer.run(socketPath: socketPath, coordinator: self, probe: self.probe)
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
            let attemptID = UUID()
            self.continuation = continuation
            self.state = .pending(PendingApproval(
                request: request,
                peer: peer,
                context: context,
                attemptID: attemptID
            ))
            NSApplication.shared.activate(ignoringOtherApps: true)
            NSApplication.shared.windows.first?.makeKeyAndOrderFront(nil)
            NSRunningApplication.current.activate(options: [.activateAllWindows])
            let now = UInt64(Date().timeIntervalSince1970 * 1000)
            let deadline = min(request.expiresAtMilliseconds, now + 110_000)
            let delay = deadline > now ? deadline - now : 0
            Task { [weak self] in
                try? await Task.sleep(for: .milliseconds(Int64(delay)))
                self?.expireApproval(attemptID: attemptID)
            }
        }
    }

    private func resizeWindow(for state: State) {
        let size = switch state {
        case let .pending(pending): self.approvalWindowSize(for: pending.request)
        case .starting, .processing, .completed, .cancelled, .denied, .failed:
            NSSize(width: 440, height: 240)
        }
        Task { @MainActor in
            await Task.yield()
            guard let window = NSApplication.shared.windows.first else { return }
            window.setContentSize(size)
            window.standardWindowButton(.miniaturizeButton)?.isEnabled = false
            window.standardWindowButton(.zoomButton)?.isEnabled = false
            window.standardWindowButton(.closeButton)?.isEnabled = self.state.allowsWindowClose
            self.observeWindowClose(window)
            window.center()
        }
    }

    private func observeWindowClose(_ window: NSWindow) {
        guard self.observedWindow !== window else { return }
        if let observedWindow {
            NotificationCenter.default.removeObserver(
                self,
                name: NSWindow.willCloseNotification,
                object: observedWindow
            )
        }
        self.observedWindow = window
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(self.windowWillClose(_:)),
            name: NSWindow.willCloseNotification,
            object: window
        )
    }

    @objc private func windowWillClose(_ notification: Notification) {
        guard !self.isTerminating, notification.object as? NSWindow === self.observedWindow else { return }
        switch self.state {
        case .pending:
            self.cancel()
        case .completed, .cancelled, .denied, .failed:
            self.dismissResult()
        case .starting, .processing:
            break
        }
    }

    private func approvalWindowSize(for request: AuthBrokerApprovalRequest) -> NSSize {
        switch request.operation {
        case .passwordAutoFill:
            NSSize(width: 620, height: 580)
        case .sshSession:
            NSSize(width: 640, height: 560)
        case .gitSSHSign:
            NSSize(width: 640, height: 440)
        case .directSSHKeyCreate, .directSSHKeyDelete, .sshMigrationTransition:
            NSSize(width: 580, height: 500)
        default:
            NSSize(width: 580, height: 460)
        }
    }

    /// A trust-set change is not represented by caller controlled text.  The
    /// sheet renders the exact canonical entries that MacopAuth will bind to
    /// protected state before invoking LocalAuthentication.
    func requestGitClientTrustMutation(
        _ document: GitClientTrustDocument,
        operation: GitClientTrustMutationOperation,
        peer: AuthBrokerVerifiedPeer
    ) async -> Bool {
        let entries = document.clients.enumerated().map { index, entry in
            "\(index + 1). 選択したパス: \(entry.selectorPath)\n"
                + "   実際の Git: \(entry.resolvedPath)\n"
                + "   バージョン: \(entry.version)\n"
                + "   署名: \(entry.signatureKind)\n"
                + "   識別子: \(entry.identifier)\n"
                + "   コードハッシュ: \(entry.cdHash)"
        }.joined(separator: "\n\n")
        let presentation = GitClientTrustMutationPresentation(
            operation: operation,
            trustedClientCount: document.clients.count
        )
        let alert = NSAlert()
        alert.messageText = presentation.title
        let requester = peer.requestingApplication ?? peer.peerIdentity
        alert.informativeText = "要求元: \(requester.identifier)\n\(requester.canonicalPath)\n\n"
            + "\(presentation.changeDescription)\n"
            + "\(presentation.resultDescription)\n"
            + "\(presentation.listIntroduction)"
            + (entries.isEmpty ? "" : "\n\n\(entries)")
        alert.icon = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "Macop")
        alert.accessoryView = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 1))
        alert.addButton(withTitle: presentation.confirmationTitle)
        alert.addButton(withTitle: "キャンセル")
        guard alert.runModal() == .alertFirstButtonReturn else { return false }
        let context = LAContext()
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: presentation.authenticationReason
            )
        } catch { return false }
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

    func continueToSystemSigningAuthentication(_ pending: PendingApproval) {
        guard pending.request.operation.phaseTwoKind == .signing else { return }
        self.finish(.approved, includeAuthenticationContext: false, pending: pending)
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
        username: String,
        _ password: String,
        saveToKeychain: Bool,
        passwordOnly: Bool,
        pending: PendingApproval
    ) {
        guard case let .pending(current) = self.state,
              current.request.requestID == pending.request.requestID,
              username == pending.request.keychainAccount,
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
                    username: success ? username : nil,
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
            username: nil,
            saveToKeychain: false
        ))
        self.continuation = nil
    }

    func complete(_ message: String, isSuccess: Bool = true) {
        self.state = .completed(Completion(message: message, isSuccess: isSuccess))
    }

    func beginProcessing() {
        self.state = .processing
    }

    func completeRejection(_ status: AuthBrokerApprovalStatus, message: String) {
        switch status {
        case .cancelled:
            self.state = .cancelled(message)
        case .denied:
            self.state = .denied(message)
        case .approved:
            self.state = .completed(Completion(message: message, isSuccess: false))
        }
    }

    func terminateSoon(after delay: Duration = .milliseconds(250)) {
        Task {
            try? await Task.sleep(for: delay)
            guard !self.retainsResultUntilDismissed else { return }
            self.isTerminating = true
            NSApplication.shared.terminate(nil)
        }
    }

    func dismissResult() {
        self.isTerminating = true
        NSApplication.shared.terminate(nil)
    }

    private var retainsResultUntilDismissed: Bool {
        switch self.state {
        case let .completed(completion): !completion.isSuccess
        case .denied, .failed: true
        case .starting, .pending, .processing, .cancelled: false
        }
    }

    private func expireApproval(attemptID: UUID) {
        guard case let .pending(pending) = self.state,
              pending.attemptID == attemptID
        else { return }
        pending.context.invalidate()
        self.finish(.denied, pending: pending)
    }

    private func finish(
        _ status: AuthBrokerApprovalStatus,
        credential: Data? = nil,
        username: String? = nil,
        saveToKeychain: Bool = false,
        includeAuthenticationContext: Bool = true,
        pending: PendingApproval
    ) {
        guard let continuation = self.continuation,
              case let .pending(current) = self.state,
              current.attemptID == pending.attemptID
        else { return }
        let context: LAContext? = if status == .approved, includeAuthenticationContext {
            current.context
        } else {
            nil
        }
        self.continuation = nil
        self.state = switch status {
        case .approved: .processing
        case .cancelled: .cancelled("キャンセルしました")
        case .denied: .denied("許可されませんでした")
        }
        continuation.resume(returning: ApprovalOutcome(
            status: status,
            context: context,
            credential: credential,
            username: username,
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
            request.purpose.concernsOTP
                ? "OTP seedをTouch ID、Apple Watch、またはMacのログインパスワードで保護して登録します。"
                : "Touch ID、Apple Watch、またはMacのログインパスワードで保護するKeychain項目を登録します。"
        case .managedKeychainUpdate:
            request.purpose.concernsOTP
                ? "OTP seedをTouch ID、Apple Watch、またはMacのログインパスワードで更新します。"
                : "macop管理のKeychain項目を更新します。"
        case .passwordAutoFill:
            "Passwordsから選んだ資格情報をmacopで使用します。"
        case .managedKeychainDelete:
            "macop管理のKeychain項目を削除します。"
        case .gitSSHSign:
            "Secure EnclaveのSSH鍵でGit commitまたはtagへ署名します。"
        case .directSSHKeyCreate:
            "Touch ID、Apple Watch、またはMacのログインパスワードで保護するSecure Enclave SSH鍵を作成します。"
        case .directSSHKeyDelete:
            "Secure Enclave SSH鍵を削除します。"
        case .sshMigrationTransition:
            "Secure Enclave SSH鍵の移行状態を変更します。"
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

private extension AuthApprovalCoordinator.State {
    var allowsWindowClose: Bool {
        switch self {
        case .pending, .completed, .cancelled, .denied, .failed: true
        case .starting, .processing: false
        }
    }
}

private enum AuthBrokerRuntimeCapabilities {
    static let value: UInt32 = {
        var capabilities = AuthBrokerCapability.approvalUI.rawValue
            | AuthBrokerCapability.sshSigning.rawValue
        if AuthBrokerRuntimeCapabilities.gitClientTrustAccessGroup != nil {
            capabilities |= AuthBrokerCapability.gitClientTrust.rawValue
        }
        if AuthBrokerRuntimeCapabilities.hasManagedKeychainEntitlements() {
            capabilities |= AuthBrokerCapability.managedKeychain.rawValue
                | AuthBrokerCapability.passwordAutoFill.rawValue
                | AuthBrokerCapability.passwordAutoFillUsername.rawValue
        }
        if AuthBrokerRuntimeCapabilities.sshKeyAccessGroup != nil {
            capabilities |= AuthBrokerCapability.directSSHKeyManagement.rawValue
        }
        return capabilities
    }()

    private static func hasManagedKeychainEntitlements() -> Bool {
        self.gitClientTrustAccessGroup != nil
    }

    private static let resolvedKeychainAccessGroups: MacopAuthEntitlementPolicy.Resolved? = {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
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
        else { return nil }
        return MacopAuthEntitlementPolicy.resolve(
            applicationIdentifier: applicationIdentifier,
            keychainAccessGroups: accessGroups
        )
    }()

    static let gitClientTrustAccessGroup = resolvedKeychainAccessGroups?.managedKeychainAccessGroup
    static let sshKeyAccessGroup = resolvedKeychainAccessGroups?.sshKeyAccessGroup
}

/// This item is deliberately owned by the MacopAuth app's private access
/// group.  macop and macop-agent have no Keychain entitlement and can only ask
/// this process for an equality verdict over the exact document they supplied.
private final class MacopAuthGitClientTrustStateStore: GitClientTrustStateStoring, @unchecked Sendable {
    private struct Stored: Codable { let generation: UInt64; let digest: Data }
    private let queries: GitClientTrustKeychainQueryBuilder

    init(accessGroup: String) {
        self.queries = GitClientTrustKeychainQueryBuilder(accessGroup: accessGroup)
    }

    func load() throws -> GitClientTrustProtectedState? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(self.queries.read() as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data,
              let stored = try? JSONDecoder().decode(Stored.self, from: data), stored.digest.count == 32
        else { throw AgentProtocolError.denied }
        return GitClientTrustProtectedState(generation: stored.generation, documentDigest: stored.digest)
    }

    func compareAndSwap(expectedGeneration: UInt64?, next: GitClientTrustProtectedState) throws -> Bool {
        guard next.documentDigest.count == 32,
              let data = try? JSONEncoder().encode(Stored(generation: next.generation, digest: next.documentDigest))
        else { throw AgentProtocolError.denied }
        if let expectedGeneration {
            let query = self.queries.update(generation: self.generationData(expectedGeneration))
            let status = SecItemUpdate(query as CFDictionary, [
                kSecValueData: data, kSecAttrGeneric: self.generationData(next.generation)
            ] as CFDictionary)
            if status == errSecItemNotFound {
                return false
            }
            guard status == errSecSuccess else { throw AgentProtocolError.denied }
            return true
        }
        let attributes = self.queries.add().merging([
            kSecAttrGeneric: self.generationData(next.generation),
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecUseDataProtectionKeychain: true
        ]) { _, new in new }
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            return false
        }
        guard status == errSecSuccess else { throw AgentProtocolError.denied }
        return true
    }

    private func generationData(_ value: UInt64) -> Data {
        withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }
}

private final class MacopAuthSSHKeyMigrationStateStore: SSHKeyMigrationStateStoring, @unchecked Sendable {
    private let queries: SSHKeyMigrationKeychainQueryBuilder

    init(accessGroup: String) throws {
        self.queries = try SSHKeyMigrationKeychainQueryBuilder(accessGroup: accessGroup)
    }

    func load() throws -> SSHKeyMigrationDocument? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(self.queries.read() as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw AgentProtocolError.denied
        }
        return try SSHKeyMigrationDocument.decode(data)
    }

    func compareAndSwap(expectedGeneration: UInt64?, next: SSHKeyMigrationDocument) throws -> Bool {
        guard (expectedGeneration ?? 0) < UInt64.max else { throw AgentProtocolError.denied }
        let expectedNext = (expectedGeneration ?? 0) + 1
        guard next.generation == expectedNext else { throw AgentProtocolError.denied }
        let data = try next.encoded()
        if let expectedGeneration {
            let status = SecItemUpdate(
                self.queries.update(generation: self.generationData(expectedGeneration)) as CFDictionary,
                [kSecValueData: data, kSecAttrGeneric: self.generationData(next.generation)] as CFDictionary
            )
            if status == errSecItemNotFound {
                return false
            }
            guard status == errSecSuccess else { throw AgentProtocolError.denied }
            return true
        }
        let attributes = self.queries.add().merging([
            kSecAttrGeneric: self.generationData(next.generation),
            kSecValueData: data
        ]) { _, new in new }
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            return false
        }
        guard status == errSecSuccess else { throw AgentProtocolError.denied }
        return true
    }

    private func generationData(_ value: UInt64) -> Data {
        withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }
}

private enum SSHKeyMigrationBrokerFailure: Error {
    case notFound
    case generationConflict(UInt64)
    case denied

    var status: AuthBrokerSSHMigrationStatus {
        switch self {
        case .notFound: .notFound
        case .generationConflict: .generationConflict
        case .denied: .denied
        }
    }

    var generation: UInt64 {
        if case let .generationConflict(value) = self {
            return value
        }
        return 0
    }
}

private enum DirectSSHKeyMutationFailure: Error {
    case generationConflict
    case protectedRecord
    case indeterminate
}

// swiftlint:disable:next type_body_length
private enum AuthBrokerAppServer {
    static func run(socketPath: String, coordinator: AuthApprovalCoordinator, probe: Bool = false) async throws {
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
        if probe {
            await coordinator.terminateSoon(after: .milliseconds(100))
            return
        }

        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        let firstMessage = try AuthBrokerSocketIO.readMessage(
            from: client,
            timeout: 10,
            nowMilliseconds: now
        )
        // Trust verification is deliberately the first post-handshake request:
        // a peer cannot use this connection for a different operation first.
        switch firstMessage {
        case let .gitClientTrustStateRequest(request):
            guard let accessGroup = AuthBrokerRuntimeCapabilities.gitClientTrustAccessGroup else {
                throw AgentProtocolError.denied
            }
            try self.serveGitClientTrustState(client: client, request: request, accessGroup: accessGroup)
            await coordinator.terminateSoon(after: .milliseconds(250))
            return
        case let .gitClientTrustVerifyRequest(request):
            guard let accessGroup = AuthBrokerRuntimeCapabilities.gitClientTrustAccessGroup else {
                throw AgentProtocolError.denied
            }
            try self.serveGitClientTrustVerify(client: client, request: request, accessGroup: accessGroup)
            await coordinator.terminateSoon(after: .milliseconds(250))
            return
        case let .gitClientTrustMutationRequest(request):
            guard let accessGroup = AuthBrokerRuntimeCapabilities.gitClientTrustAccessGroup else {
                throw AgentProtocolError.denied
            }
            try await self.serveGitClientTrustMutation(
                client: client, request: request, peer: peer, accessGroup: accessGroup,
                coordinator: coordinator
            )
            await coordinator.terminateSoon(after: .seconds(2))
            return
        case let .directSSHKeyRequest(request):
            guard request.operation == .list,
                  let accessGroup = AuthBrokerRuntimeCapabilities.sshKeyAccessGroup
            else { throw AgentProtocolError.denied }
            try self.serveDirectSSHKeyList(
                client: client,
                request: request,
                accessGroup: accessGroup
            )
            await coordinator.terminateSoon(after: .milliseconds(250))
            return
        case let .sshMigrationRequest(request):
            guard request.action == .list,
                  let accessGroup = AuthBrokerRuntimeCapabilities.sshKeyAccessGroup
            else { throw AgentProtocolError.denied }
            try self.serveSSHMigrationList(client: client, request: request, accessGroup: accessGroup)
            await coordinator.terminateSoon(after: .milliseconds(250))
            return
        case let .approvalRequest(request):
            try await self.serveApprovalRequest(
                client: client,
                request: request,
                peer: peer,
                capabilities: capabilities,
                coordinator: coordinator
            )
        default:
            throw AgentProtocolError.denied
        }
    }

    private static func serveApprovalRequest(
        client: Int32,
        request: AuthBrokerApprovalRequest,
        peer: AuthBrokerVerifiedPeer,
        capabilities: UInt32,
        coordinator: AuthApprovalCoordinator
    ) async throws {
        guard request.operation != .sshSign,
              request.purpose.isValid(for: request.operation),
              request.presentation.isValid(for: request.operation)
        else { throw AgentProtocolError.denied }
        let requiredCapability = request.operation.requiredCapability.rawValue
        guard capabilities & requiredCapability == requiredCapability else {
            throw AgentProtocolError.denied
        }
        let isKeychainRequest = request.operation.family == .managedKeychain
        if isKeychainRequest {
            let isDeleteAll = request.operation == .managedKeychainDelete
                && request.keychainService.isEmpty
                && request.keychainAccount.isEmpty
            guard isDeleteAll == (request.purpose == .managedKeychainDeleteAll) else {
                throw AgentProtocolError.denied
            }
            guard isDeleteAll || (!request.keychainService.isEmpty && !request.keychainAccount.isEmpty) else {
                throw AgentProtocolError.denied
            }
        }
        if request.operation.family == .directSSHKeyManagement {
            guard request.keychainService.isEmpty, request.keychainAccount.isEmpty,
                  request.host.isEmpty,
                  request.sshKeyBackend == .directSecureEnclaveV1,
                  (try? SSHIdentityLabelValidator.validate(request.credentialLabel)) != nil
            else { throw AgentProtocolError.denied }
            switch request.operation {
            case .directSSHKeyCreate:
                guard !request.credentialFingerprint.isEmpty else { throw AgentProtocolError.denied }
            case .directSSHKeyDelete, .sshMigrationTransition:
                guard !request.credentialFingerprint.isEmpty else { throw AgentProtocolError.denied }
            default:
                throw AgentProtocolError.denied
            }
        }
        try self.validateRoot(request)
        let outcome = await coordinator.requestApproval(request, peer: peer)
        let signer: (any AgentKeySigning)?
        var resultStatus = outcome.status == .approved ? errSecSuccess : errSecAuthFailed
        var resultData = Data()
        var resultMessage = ""
        let isSigningRequest = request.operation.phaseTwoKind == .signing
        if outcome.status == .approved, isSigningRequest {
            do {
                try self.validateRoot(request)
            } catch {
                await self.completeSigningFailure(
                    client: client,
                    request: request,
                    failure: .requesterInvalid,
                    coordinator: coordinator
                )
                await coordinator.terminateSoon(after: .seconds(2))
                return
            }
            let candidate: any AgentKeySigning
            do {
                candidate = try self.signer(
                    for: request,
                    authenticationContext: outcome.context
                )
            } catch {
                await self.completeSigningFailure(
                    client: client,
                    request: request,
                    failure: .signerUnavailable,
                    coordinator: coordinator
                )
                await coordinator.terminateSoon(after: .seconds(2))
                return
            }
            guard constantTimeEqual(
                Data(candidate.fingerprint.utf8),
                Data(request.credentialFingerprint.utf8)
            ) else {
                await self.completeSigningFailure(
                    client: client,
                    request: request,
                    failure: .identityMismatch,
                    coordinator: coordinator
                )
                await coordinator.terminateSoon(after: .seconds(2))
                return
            }
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
                let mutation = ManagedKeychainStore.upsertSecret(
                    credential,
                    service: request.keychainService,
                    account: request.keychainAccount,
                    synchronizable: request.keychainSynchronizable,
                    authenticationContext: context
                )
                resultStatus = mutation.status
                resultMessage = PasswordAutoFillSaveStatus(mutationOutcome: mutation).rawValue
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
        let completion = self.approvedCompletion(
            operation: request.operation,
            resultStatus: resultStatus
        )
        do {
            try AuthBrokerSocketIO.writeMessage(.approvalResponse(AuthBrokerApprovalResponse(
                requestID: request.requestID,
                status: outcome.status,
                message: resultMessage,
                resultStatus: resultStatus,
                resultData: resultData,
                verifiedUsername: request.operation == .passwordAutoFill ? (outcome.username ?? "") : ""
            )), to: client, timeout: 5)
        } catch {
            if request.operation == .passwordAutoFill {
                if outcome.status == .approved {
                    if let saveStatus = PasswordAutoFillSaveStatus(rawValue: resultMessage) {
                        let presentation = PasswordAutoFillCompletionPresentation(
                            saveStatus: saveStatus,
                            delivery: .unknown
                        )
                        await coordinator.complete(presentation.message, isSuccess: false)
                    } else {
                        await coordinator.complete(
                            "資格情報の承認結果と、要求元への結果通知を確認できません",
                            isSuccess: false
                        )
                    }
                } else {
                    let presentation = PasswordAutoFillRejectionPresentation(
                        status: outcome.status,
                        delivery: .unknown
                    )
                    await coordinator.completeRejection(
                        outcome.status,
                        message: presentation.message
                    )
                }
                await coordinator.terminateSoon(after: .seconds(2))
                return
            }
            if outcome.status == .approved {
                if request.operation == .managedKeychainImport || request.operation == .managedKeychainUpdate {
                    let presentation = ManagedKeychainEffectPresentation(
                        updating: request.operation == .managedKeychainUpdate,
                        outcome: .notStarted,
                        delivery: .notAttempted
                    )
                    await coordinator.complete(presentation.message, isSuccess: false)
                } else if isSigningRequest {
                    let presentation = SSHSigningEffectPresentation(
                        operation: request.operation,
                        outcome: .noSignatureRequested,
                        delivery: .notAttempted
                    )
                    await coordinator.complete(presentation.message, isSuccess: false)
                } else {
                    await coordinator.complete(
                        completion.message + "。要求元への結果通知は確認できません",
                        isSuccess: false
                    )
                }
            } else {
                let presentation = PasswordAutoFillRejectionPresentation(
                    status: outcome.status,
                    delivery: .unknown
                )
                await coordinator.completeRejection(
                    outcome.status,
                    message: presentation.message
                )
            }
            await coordinator.terminateSoon(after: .seconds(2))
            return
        }
        switch AuthApprovalOrchestration.deliveredRoute(
            operation: request.operation,
            status: outcome.status,
            hasSigner: signer != nil
        ) {
        case .passwordAutoFill:
            if let saveStatus = PasswordAutoFillSaveStatus(rawValue: resultMessage) {
                let presentation = PasswordAutoFillCompletionPresentation(
                    saveStatus: saveStatus,
                    delivery: .delivered
                )
                await coordinator.complete(presentation.message, isSuccess: presentation.isSuccess)
            } else {
                await coordinator.complete("資格情報の承認結果を確認できません", isSuccess: false)
            }
        case .approvedPhaseTwo:
            await coordinator.beginProcessing()
        case .approvedImmediate:
            await coordinator.complete(completion.message, isSuccess: completion.isSuccess)
        case let .rejected(status):
            let presentation = PasswordAutoFillRejectionPresentation(
                status: status,
                delivery: .delivered
            )
            await coordinator.completeRejection(
                status,
                message: presentation.message
            )
        }
        if let signer {
            await self.serveSigning(
                client: client,
                request: request,
                signer: signer,
                coordinator: coordinator
            )
            await coordinator.terminateSoon(after: .seconds(2))
            return
        } else if outcome.status == .approved,
                  let context = outcome.context,
                  request.operation == .managedKeychainImport || request.operation == .managedKeychainUpdate
        // swiftlint:disable:next opening_brace
        {
            await self.serveManagedKeychainImport(
                client: client,
                request: request,
                context: context,
                coordinator: coordinator
            )
            await coordinator.terminateSoon(after: .seconds(2))
            return
        } else if outcome.status == .approved,
                  request.operation == .directSSHKeyCreate || request.operation == .directSSHKeyDelete,
                  let accessGroup = AuthBrokerRuntimeCapabilities.sshKeyAccessGroup
        // swiftlint:disable:next opening_brace
        {
            await self.serveDirectSSHKeyMutation(
                client: client,
                approval: request,
                accessGroup: accessGroup,
                coordinator: coordinator
            )
            await coordinator.terminateSoon(after: .seconds(2))
            return
        } else if outcome.status == .approved,
                  request.operation == .sshMigrationTransition,
                  let accessGroup = AuthBrokerRuntimeCapabilities.sshKeyAccessGroup
        // swiftlint:disable:next opening_brace
        {
            await self.serveSSHMigrationTransition(
                client: client,
                approval: request,
                accessGroup: accessGroup,
                coordinator: coordinator
            )
            await coordinator.terminateSoon(after: .seconds(2))
            return
        }
        await coordinator.terminateSoon(after: .seconds(2))
    }

    private static func serveDirectSSHKeyList(
        client: Int32,
        request: AuthBrokerDirectSSHKeyRequest,
        accessGroup: String
    ) throws {
        let response: AuthBrokerDirectSSHKeyResponse
        do {
            let records = try DirectSecureEnclaveKeyStore(accessGroup: accessGroup).list()
                .map(AuthBrokerDirectSSHKeyRecord.init)
            response = AuthBrokerDirectSSHKeyResponse(
                authorizationID: request.authorizationID,
                operation: .list,
                status: .success,
                records: records
            )
        } catch {
            response = AuthBrokerDirectSSHKeyResponse(
                authorizationID: request.authorizationID,
                operation: .list,
                status: self.directSSHKeyStatus(for: error)
            )
        }
        try AuthBrokerSocketIO.writeMessage(.directSSHKeyResponse(response), to: client, timeout: 10)
    }

    private static func serveSSHMigrationList(
        client: Int32,
        request: AuthBrokerSSHMigrationRequest,
        accessGroup: String
    ) throws {
        let response: AuthBrokerSSHMigrationResponse
        do {
            let document = try MacopAuthSSHKeyMigrationStateStore(accessGroup: accessGroup).load()
            response = AuthBrokerSSHMigrationResponse(
                requestID: request.requestID,
                action: .list,
                status: .success,
                generation: document?.generation ?? 0,
                entries: document?.entries ?? []
            )
        } catch {
            response = AuthBrokerSSHMigrationResponse(
                requestID: request.requestID,
                action: .list,
                status: .unavailable,
                generation: 0
            )
        }
        try AuthBrokerSocketIO.writeMessage(.sshMigrationResponse(response), to: client, timeout: 10)
    }

    private static func serveSSHMigrationTransition(
        client: Int32,
        approval: AuthBrokerApprovalRequest,
        accessGroup: String,
        coordinator: AuthApprovalCoordinator
    ) async {
        let request: AuthBrokerSSHMigrationRequest
        do {
            guard case let .sshMigrationRequest(received) = try AuthBrokerSocketIO.readMessage(
                from: client,
                timeout: 30
            ), received.requestID == approval.requestID,
            received.action == .transition else { throw AgentProtocolError.denied }
            try self.validateRoot(approval)
            try self.validateSSHMigrationTransition(received, approval: approval)
            request = received
        } catch {
            await coordinator.complete("SSH鍵の移行要求を検証できませんでした", isSuccess: false)
            return
        }

        let response: AuthBrokerSSHMigrationResponse
        do {
            let store = try MacopAuthSSHKeyMigrationStateStore(accessGroup: accessGroup)
            guard let current = try store.load() else {
                throw SSHKeyMigrationBrokerFailure.notFound
            }
            guard current.generation == request.expectedGeneration else {
                throw SSHKeyMigrationBrokerFailure.generationConflict(current.generation)
            }
            guard let index = current.entries.firstIndex(where: { $0.label == request.label }),
                  let transition = request.transition
            else { throw SSHKeyMigrationBrokerFailure.notFound }
            let selected = current.entries[index]
            guard constantTimeEqual(
                Data(selected.directFingerprint.utf8),
                Data(approval.credentialFingerprint.utf8)
            ) else { throw SSHKeyMigrationBrokerFailure.denied }
            if transition == .confirmDirectKeyDeleted {
                response = try self.deletePreparedDirectSSHKey(
                    request: request,
                    current: current,
                    selectedIndex: index,
                    accessGroup: accessGroup,
                    migrationStore: store
                )
            } else {
                guard current.generation < UInt64.max,
                      let updated = try selected.applying(transition)
                else { throw SSHKeyMigrationBrokerFailure.denied }
                var entries = current.entries
                entries[index] = updated
                let next = try SSHKeyMigrationDocument(generation: current.generation + 1, entries: entries)
                guard try store.compareAndSwap(expectedGeneration: current.generation, next: next) else {
                    throw try SSHKeyMigrationBrokerFailure.generationConflict((store.load())?.generation ?? 0)
                }
                response = AuthBrokerSSHMigrationResponse(
                    requestID: request.requestID,
                    action: .transition,
                    status: .success,
                    generation: next.generation,
                    entries: next.entries
                )
            }
        } catch let failure as SSHKeyMigrationBrokerFailure {
            response = AuthBrokerSSHMigrationResponse(
                requestID: request.requestID,
                action: .transition,
                status: failure.status,
                generation: failure.generation
            )
        } catch {
            response = AuthBrokerSSHMigrationResponse(
                requestID: request.requestID,
                action: .transition,
                status: .failed,
                generation: request.expectedGeneration
            )
        }

        do {
            try self.validateRoot(approval)
            try AuthBrokerSocketIO.writeMessage(.sshMigrationResponse(response), to: client, timeout: 30)
            await coordinator.complete(
                response.status == .success ? "SSH鍵の移行状態を更新しました" : "SSH鍵の移行状態を更新できませんでした",
                isSuccess: response.status == .success
            )
        } catch {
            await coordinator.complete("移行結果を要求元へ通知できませんでした", isSuccess: false)
        }
    }

    private static func deletePreparedDirectSSHKey(
        request: AuthBrokerSSHMigrationRequest,
        current: SSHKeyMigrationDocument,
        selectedIndex: Int,
        accessGroup: String,
        migrationStore: MacopAuthSSHKeyMigrationStateStore
    ) throws -> AuthBrokerSSHMigrationResponse {
        let selected = current.entries[selectedIndex]
        guard selected.phase == .prepared || selected.phase == .deleting else {
            throw SSHKeyMigrationBrokerFailure.denied
        }
        var deletingDocument = current
        if selected.phase == .prepared {
            guard current.generation < UInt64.max else { throw SSHKeyMigrationBrokerFailure.denied }
            var entries = current.entries
            entries[selectedIndex] = try selected.changingPhase(to: .deleting)
            deletingDocument = try SSHKeyMigrationDocument(
                generation: current.generation + 1,
                entries: entries
            )
            guard try migrationStore.compareAndSwap(
                expectedGeneration: current.generation,
                next: deletingDocument
            ) else {
                throw try SSHKeyMigrationBrokerFailure.generationConflict(
                    migrationStore.load()?.generation ?? 0
                )
            }
        }

        do {
            try DirectSecureEnclaveKeyStore(accessGroup: accessGroup).delete(
                id: selected.directKeyID,
                expectedPublicKeyBlob: selected.directPublicKeyBlob
            )
        } catch DirectSecureEnclaveKeyStoreError.notFound {
            // A prior attempt can crash after deleting the key but before the
            // final CAS. The protected deleting marker makes that retry safe.
        }

        guard let afterDeletion = try migrationStore.load(),
              afterDeletion.generation < UInt64.max,
              let deletingIndex = afterDeletion.entries.firstIndex(where: {
                  $0.label == selected.label
                      && $0.directKeyID == selected.directKeyID
                      && $0.phase == .deleting
              })
        else { throw SSHKeyMigrationBrokerFailure.notFound }
        var remaining = afterDeletion.entries
        remaining.remove(at: deletingIndex)
        let final = try SSHKeyMigrationDocument(
            generation: afterDeletion.generation + 1,
            entries: remaining
        )
        guard try migrationStore.compareAndSwap(
            expectedGeneration: afterDeletion.generation,
            next: final
        ) else {
            throw try SSHKeyMigrationBrokerFailure.generationConflict(
                migrationStore.load()?.generation ?? 0
            )
        }
        return AuthBrokerSSHMigrationResponse(
            requestID: request.requestID,
            action: .transition,
            status: .success,
            generation: final.generation,
            entries: final.entries
        )
    }

    private static func validateSSHMigrationTransition(
        _ request: AuthBrokerSSHMigrationRequest,
        approval: AuthBrokerApprovalRequest
    ) throws {
        guard request.label == approval.credentialLabel, let transition = request.transition else {
            throw AgentProtocolError.denied
        }
        let valid = switch approval.purpose {
        case .sshMigrationConfirmExternal: transition == .confirmExternalRegistration
        case .sshMigrationActivate: transition == .activateDirectBackend
        case .sshMigrationBeginRetirement: transition == .beginLegacyRetirement
        case .sshMigrationConfirmRetired: transition == .confirmLegacyRetired
        case .sshMigrationRollback:
            transition == .returnToPreparation || transition == .returnToExternalRegistration
                || transition == .returnToActive
        case .sshMigrationDeletePrepared: transition == .confirmDirectKeyDeleted
        default: false
        }
        guard valid else { throw AgentProtocolError.denied }
    }

    private static func signer(
        for request: AuthBrokerApprovalRequest,
        authenticationContext: LAContext?
    ) throws -> any AgentKeySigning {
        switch request.sshKeyBackend {
        case .legacyCTK:
            if let accessGroup = AuthBrokerRuntimeCapabilities.sshKeyAccessGroup {
                let migration = try MacopAuthSSHKeyMigrationStateStore(accessGroup: accessGroup)
                    .load()?.entries.first(where: { $0.label == request.credentialLabel })
                if let migration {
                    guard migration.selectedBackend == .legacyCTK,
                          constantTimeEqual(
                              Data(migration.legacyFingerprint.utf8),
                              Data(request.credentialFingerprint.utf8)
                          )
                    else { throw AgentProtocolError.denied }
                }
            }
            return try SSHCommand.makeVerifiedSessionSigner(label: request.credentialLabel)
        case .directSecureEnclaveV1:
            guard let authenticationContext else { throw AgentProtocolError.denied }
            guard let accessGroup = AuthBrokerRuntimeCapabilities.sshKeyAccessGroup else {
                throw DirectSecureEnclaveKeyStoreError.invalidAccessGroup
            }
            guard let migration = try MacopAuthSSHKeyMigrationStateStore(accessGroup: accessGroup)
                .load()?.entries.first(where: { $0.label == request.credentialLabel }),
                // The externally-registered phase permits an explicit
                // pre-activation SSH proof. Normal selection remains on the
                // legacy backend; only `ssh test --migration-candidate`
                // requests the exact direct fingerprint in this phase.
                migration.permitsDirectSigning,
                constantTimeEqual(
                    Data(migration.directFingerprint.utf8),
                    Data(request.credentialFingerprint.utf8)
                )
            else { throw AgentProtocolError.denied }
            let store = try DirectSecureEnclaveKeyStore(accessGroup: accessGroup)
            return try store.signer(
                id: migration.directKeyID,
                expectedPublicKeyBlob: migration.directPublicKeyBlob,
                authenticationContext: authenticationContext
            )
        }
    }

    private static func serveDirectSSHKeyMutation(
        client: Int32,
        approval: AuthBrokerApprovalRequest,
        accessGroup: String,
        coordinator: AuthApprovalCoordinator
    ) async {
        let request: AuthBrokerDirectSSHKeyRequest
        do {
            guard case let .directSSHKeyRequest(received) = try AuthBrokerSocketIO.readMessage(
                from: client,
                timeout: 30
            ), received.authorizationID == approval.requestID else {
                throw AgentProtocolError.denied
            }
            try self.validateRoot(approval)
            try self.validateDirectSSHKeyMutation(received, approval: approval)
            request = received
        } catch {
            await coordinator.complete("SSH鍵の操作要求を検証できませんでした", isSuccess: false)
            return
        }

        let response: AuthBrokerDirectSSHKeyResponse
        do {
            let store = try DirectSecureEnclaveKeyStore(accessGroup: accessGroup)
            switch request.operation {
            case .create:
                let migrationStore = try MacopAuthSSHKeyMigrationStateStore(accessGroup: accessGroup)
                let current = try migrationStore.load()
                let generation = current?.generation ?? 0
                guard generation == request.expectedGeneration,
                      current?.entries.allSatisfy({ $0.label != request.label }) ?? true,
                      generation < UInt64.max
                else { throw DirectSSHKeyMutationFailure.generationConflict }
                let record = try store.create(label: request.label)
                do {
                    let entry = try SSHKeyMigrationEntry(
                        label: record.label,
                        legacyFingerprint: request.legacyFingerprint,
                        directKeyID: record.id,
                        directPublicKeyBlob: record.publicKeyBlob,
                        phase: .prepared
                    )
                    let next = try SSHKeyMigrationDocument(
                        generation: generation + 1,
                        entries: (current?.entries ?? []) + [entry]
                    )
                    guard try migrationStore.compareAndSwap(
                        expectedGeneration: current?.generation,
                        next: next
                    ) else { throw DirectSSHKeyMutationFailure.generationConflict }
                } catch {
                    do {
                        try store.delete(id: record.id, expectedPublicKeyBlob: record.publicKeyBlob)
                    } catch {
                        throw DirectSSHKeyMutationFailure.indeterminate
                    }
                    throw error
                }
                response = AuthBrokerDirectSSHKeyResponse(
                    authorizationID: request.authorizationID,
                    operation: .create,
                    status: .success,
                    records: [AuthBrokerDirectSSHKeyRecord(record)]
                )
            case .delete:
                guard let id = request.id else { throw AgentProtocolError.denied }
                let migration = try MacopAuthSSHKeyMigrationStateStore(accessGroup: accessGroup).load()
                guard migration?.entries.allSatisfy({ $0.directKeyID != id }) ?? true else {
                    throw DirectSSHKeyMutationFailure.protectedRecord
                }
                try store.delete(id: id, expectedPublicKeyBlob: request.expectedPublicKeyBlob)
                response = AuthBrokerDirectSSHKeyResponse(
                    authorizationID: request.authorizationID,
                    operation: .delete,
                    status: .success
                )
            case .list:
                throw AgentProtocolError.denied
            }
        } catch {
            response = AuthBrokerDirectSSHKeyResponse(
                authorizationID: request.authorizationID,
                operation: request.operation,
                status: self.directSSHKeyStatus(for: error)
            )
        }

        do {
            try self.validateRoot(approval)
            try AuthBrokerSocketIO.writeMessage(.directSSHKeyResponse(response), to: client, timeout: 30)
            let success = response.status == .success
            let message = switch (request.operation, response.status) {
            case (.create, .success): "Secure Enclave SSH鍵を作成しました"
            case (.delete, .success): "Secure Enclave SSH鍵を削除しました"
            case (_, .indeterminate): "SSH鍵の操作結果を確定できません。再実行前に一覧を確認してください"
            default: "Secure Enclave SSH鍵を操作できませんでした"
            }
            await coordinator.complete(message, isSuccess: success)
        } catch {
            await coordinator.complete(
                "SSH鍵の操作は完了した可能性がありますが、要求元への通知を確認できません",
                isSuccess: false
            )
        }
    }

    private static func validateDirectSSHKeyMutation(
        _ request: AuthBrokerDirectSSHKeyRequest,
        approval: AuthBrokerApprovalRequest
    ) throws {
        switch (approval.operation, request.operation) {
        case (.directSSHKeyCreate, .create):
            guard request.label == approval.credentialLabel,
                  constantTimeEqual(
                      Data(request.legacyFingerprint.utf8),
                      Data(approval.credentialFingerprint.utf8)
                  )
            else { throw AgentProtocolError.denied }
        case (.directSSHKeyDelete, .delete):
            guard request.label == approval.credentialLabel,
                  constantTimeEqual(
                      Data(sshFingerprint(for: request.expectedPublicKeyBlob).utf8),
                      Data(approval.credentialFingerprint.utf8)
                  )
            else { throw AgentProtocolError.denied }
        default:
            throw AgentProtocolError.denied
        }
    }

    private static func directSSHKeyStatus(for error: Error) -> AuthBrokerDirectSSHKeyStatus {
        switch error {
        case DirectSSHKeyMutationFailure.generationConflict:
            .generationConflict
        case DirectSSHKeyMutationFailure.protectedRecord:
            .denied
        case DirectSSHKeyMutationFailure.indeterminate:
            .indeterminate
        case DirectSecureEnclaveKeyStoreError.notFound:
            .notFound
        case DirectSecureEnclaveKeyStoreError.duplicateLabel:
            .duplicate
        case DirectSecureEnclaveKeyStoreError.fingerprintMismatch:
            .denied
        case DirectSecureEnclaveKeyStoreError.indeterminate:
            .indeterminate
        case DirectSecureEnclaveKeyStoreError.invalidAccessGroup,
             DirectSecureEnclaveKeyStoreError.malformedStore,
             DirectSecureEnclaveKeyStoreError.creationFailed:
            .unavailable
        case DirectSecureEnclaveKeyStoreError.securityFailure:
            .failed
        default:
            .failed
        }
    }

    private static func serveGitClientTrustVerify(
        client: Int32,
        request: AuthBrokerGitClientTrustVerifyRequest,
        accessGroup: String
    ) throws {
        let document = try GitClientTrustDocument.decodeCanonical(request.canonicalDocument)
        let digest = try document.digest()
        guard constantTimeEqual(digest, request.digest) else { throw AgentProtocolError.denied }
        let state = try MacopAuthGitClientTrustStateStore(accessGroup: accessGroup).load()
        let trusted = state.map {
            $0.generation == document.generation && constantTimeEqual($0.documentDigest, digest)
        } ?? false
        try AuthBrokerSocketIO.writeMessage(.gitClientTrustVerifyResponse(
            AuthBrokerGitClientTrustVerifyResponse(
                requestID: request.requestID, digest: request.digest, generation: document.generation,
                status: trusted ? .trusted : (state == nil ? .unavailable : .mismatch)
            )
        ), to: client, timeout: 5)
    }

    private static func serveGitClientTrustState(
        client: Int32,
        request: AuthBrokerGitClientTrustStateRequest,
        accessGroup: String
    ) throws {
        let state = try MacopAuthGitClientTrustStateStore(accessGroup: accessGroup).load()
        try AuthBrokerSocketIO.writeMessage(.gitClientTrustStateResponse(
            AuthBrokerGitClientTrustStateResponse(
                requestID: request.requestID, generation: state?.generation ?? 0,
                status: state == nil ? .unavailable : .trusted
            )
        ), to: client, timeout: 5)
    }

    private static func serveGitClientTrustMutation(
        client: Int32,
        request: AuthBrokerGitClientTrustMutationRequest,
        peer: AuthBrokerVerifiedPeer,
        accessGroup: String,
        coordinator: AuthApprovalCoordinator
    ) async throws {
        let document = try GitClientTrustDocument.decodeCanonical(request.canonicalDocument)
        let digest = try document.digest()
        guard constantTimeEqual(digest, request.digest), document.generation == request.expectedGeneration + 1 else {
            throw AgentProtocolError.denied
        }
        let store = MacopAuthGitClientTrustStateStore(accessGroup: accessGroup)
        let state = try store.load()
        // The protected state is advanced before the CLI atomically publishes
        // the file.  If power loss occurs in that gap, retrying the exact same
        // command is safe and completes publication without silently accepting
        // a different set.
        // swiftformat:disable wrapMultilineStatementBraces
        if let state, state.generation == document.generation,
           constantTimeEqual(state.documentDigest, digest) {
            try self.writeTrustMutationResponse(
                client: client,
                request: request,
                generation: document.generation,
                status: .approved
            )
            await coordinator.complete("Gitクライアントの信頼設定はすでに更新されています")
            return
        }
        // swiftformat:enable wrapMultilineStatementBraces
        let expected: UInt64? = if state == nil && (request.expectedGeneration == 0 || request.operation == .reset) {
            nil
        } else {
            request.expectedGeneration
        }
        guard state?.generation == expected || (state == nil && expected == nil) else {
            try self.writeTrustMutationResponse(
                client: client,
                request: request,
                generation: document.generation,
                status: .generationConflict
            )
            await coordinator.complete(
                "信頼設定は別の変更によって更新されました。内容を確認してもう一度実行してください",
                isSuccess: false
            )
            return
        }
        guard await coordinator.requestGitClientTrustMutation(
            document,
            operation: request.operation,
            peer: peer
        ) else {
            try self.writeTrustMutationResponse(
                client: client,
                request: request,
                generation: document.generation,
                status: .rejected
            )
            await coordinator.completeRejection(
                .cancelled,
                message: "Gitクライアントの信頼設定変更をキャンセルしました"
            )
            return
        }
        // Recheck immediately before CAS; an independent MacopAuth process may
        // have advanced the set while the native sheet was visible.
        try self.validateTrustMutationPeer(peer)
        guard try store.compareAndSwap(
            expectedGeneration: expected,
            next: GitClientTrustProtectedState(generation: document.generation, documentDigest: digest)
        ) else {
            try self.writeTrustMutationResponse(
                client: client,
                request: request,
                generation: document.generation,
                status: .generationConflict
            )
            await coordinator.complete(
                "認証中に信頼設定が変更されました。内容を確認してもう一度実行してください",
                isSuccess: false
            )
            return
        }
        try self.writeTrustMutationResponse(
            client: client,
            request: request,
            generation: document.generation,
            status: .approved
        )
        await coordinator.complete("Gitクライアントの信頼設定を更新しました")
    }

    private static func validateTrustMutationPeer(_ peer: AuthBrokerVerifiedPeer) throws {
        let inspector = SystemRequesterInspector()
        guard inspector.snapshot(of: peer.peer.pid) == peer.peerSnapshot else { throw AgentProtocolError.denied }
        let identity = try LiveCodeIdentityInspector.inspect(pid: peer.peer.pid).identity
        guard identity == peer.peerIdentity,
              let teamID = peer.peerIdentity.teamID,
              AuthBrokerPeerVerifier(expectedTeamID: teamID).acceptsPeerIdentity(identity)
        else {
            throw AgentProtocolError.denied
        }
    }

    private static func writeTrustMutationResponse(
        client: Int32,
        request: AuthBrokerGitClientTrustMutationRequest,
        generation: UInt64,
        status: AuthBrokerGitClientTrustStatus
    ) throws {
        try AuthBrokerSocketIO.writeMessage(.gitClientTrustMutationResponse(
            AuthBrokerGitClientTrustMutationResponse(
                authorizationID: request.authorizationID, digest: request.digest, generation: generation, status: status
            )
        ), to: client, timeout: 10)
    }

    private static func approvedCompletion(
        operation: AuthBrokerOperation,
        resultStatus: OSStatus
    ) -> (message: String, isSuccess: Bool) {
        guard resultStatus == errSecSuccess else {
            let message = switch operation {
            case .managedKeychainRead:
                "Keychain項目を読み取れませんでした"
            case .managedKeychainDelete:
                "Keychain項目の削除に失敗しました"
            case .directSSHKeyCreate, .directSSHKeyDelete, .sshMigrationTransition:
                "Secure Enclave SSH鍵の操作に失敗しました"
            default:
                "許可後の処理に失敗しました"
            }
            return (message, false)
        }
        let message = switch operation {
        case .sshSession, .sshSign:
            "SSH鍵の使用を許可しました"
        case .managedKeychainRead:
            "Keychain項目を読み取りました"
        case .managedKeychainImport:
            "Keychain項目の登録を許可しました"
        case .managedKeychainUpdate:
            "Keychain項目の更新を許可しました"
        case .managedKeychainDelete:
            "Keychainから削除しました"
        case .gitSSHSign:
            "Git SSH署名を許可しました"
        case .passwordAutoFill:
            "資格情報の使用を許可しました"
        case .directSSHKeyCreate:
            "Secure Enclave SSH鍵の作成を許可しました"
        case .directSSHKeyDelete:
            "Secure Enclave SSH鍵の削除を許可しました"
        case .sshMigrationTransition:
            "Secure Enclave SSH鍵の移行状態変更を許可しました"
        }
        return (message, true)
    }

    private static func serveManagedKeychainImport(
        client: Int32,
        request: AuthBrokerApprovalRequest,
        context: LAContext,
        coordinator: AuthApprovalCoordinator
    ) async {
        let importRequest: AuthBrokerManagedKeychainImportRequest
        do {
            guard case let .managedKeychainImportRequest(received) = try AuthBrokerSocketIO.readMessage(
                from: client,
                timeout: 30
            ), received.authorizationID == request.requestID else {
                throw AgentProtocolError.denied
            }
            try self.validateRoot(request)
            importRequest = received
        } catch {
            let presentation = ManagedKeychainEffectPresentation(
                updating: request.operation == .managedKeychainUpdate,
                outcome: .notStarted,
                delivery: .notAttempted
            )
            await coordinator.complete(presentation.message, isSuccess: false)
            return
        }
        let mutation = if request.operation == .managedKeychainUpdate {
            ManagedKeychainStore.updateSecret(
                importRequest.secret,
                service: request.keychainService,
                account: request.keychainAccount,
                synchronizable: request.keychainSynchronizable,
                authenticationContext: context
            )
        } else {
            ManagedKeychainStore.importSecret(
                importRequest.secret,
                service: request.keychainService,
                account: request.keychainAccount,
                synchronizable: request.keychainSynchronizable,
                authenticationContext: context
            )
        }
        let outcome: ManagedKeychainEffectOutcome = switch mutation {
        case .committed: .committed
        case .failed: .failed
        case .indeterminate: .indeterminate
        }
        let response = AuthBrokerMessage.managedKeychainImportResponse(
            AuthBrokerManagedKeychainImportResponse(
                authorizationID: request.requestID,
                outcome: mutation.brokerOutcome,
                status: mutation.status
            )
        )
        let presentation = AuthEffectPipeline.managedMutation(
            updating: request.operation == .managedKeychainUpdate,
            outcome: outcome
        ) {
            try AuthBrokerSocketIO.writeMessage(response, to: client, timeout: 30)
        }
        await coordinator.complete(presentation.message, isSuccess: presentation.isSuccess)
    }

    private static func serveSigning(
        client: Int32,
        request: AuthBrokerApprovalRequest,
        signer: any AgentKeySigning,
        coordinator: AuthApprovalCoordinator
    ) async {
        var completedSignature = false
        func completeNoSignatureIfNeeded() async {
            guard !completedSignature else { return }
            let presentation = SSHSigningEffectPresentation(
                operation: request.operation,
                outcome: .noSignatureRequested,
                delivery: .notAttempted
            )
            await coordinator.complete(presentation.message, isSuccess: false)
        }
        while true {
            let now = UInt64(Date().timeIntervalSince1970 * 1000)
            if now >= request.expiresAtMilliseconds {
                break
            }
            let remaining = TimeInterval(request.expiresAtMilliseconds - now) / 1000
            let message: AuthBrokerMessage
            do {
                message = try AuthBrokerSocketIO.readMessage(
                    from: client,
                    timeout: min(remaining, 600),
                    nowMilliseconds: now
                )
            } catch {
                break
            }
            guard case let .sshSignRequest(signRequest) = message,
                  signRequest.authorizationID == request.requestID
            else {
                break
            }
            await coordinator.beginProcessing()
            let presentation = AuthEffectPipeline.signing(
                operation: request.operation,
                prepare: {
                    try self.validateRoot(request)
                },
                sign: {
                    try signer.sign(data: signRequest.data, flags: signRequest.flags)
                },
                revalidate: {
                    try self.validateRoot(request)
                },
                deliver: { outcome, signature in
                    try AuthBrokerSocketIO.writeMessage(.sshSignResponse(AuthBrokerSSHSignResponse(
                        authorizationID: request.requestID,
                        outcome: outcome,
                        signature: signature
                    )), to: client, timeout: 30)
                }
            )
            await coordinator.complete(presentation.message, isSuccess: presentation.isSuccess)
            guard presentation.isSuccess else { return }
            completedSignature = true
        }
        await completeNoSignatureIfNeeded()
    }

    private static func completeSigningFailure(
        client: Int32,
        request: AuthBrokerApprovalRequest,
        failure: SSHSigningEffectFailure,
        coordinator: AuthApprovalCoordinator
    ) async {
        let presentation = AuthEffectPipeline.signingFailure(
            operation: request.operation,
            failure: failure
        ) { responseOutcome, signature in
            try AuthBrokerSocketIO.writeMessage(.sshSignResponse(AuthBrokerSSHSignResponse(
                authorizationID: request.requestID,
                outcome: responseOutcome,
                signature: signature
            )), to: client, timeout: 5)
        }
        await coordinator.complete(presentation.message, isSuccess: presentation.isSuccess)
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
                Group {
                    if pending.request.operation == .passwordAutoFill {
                        PasswordAutoFillRequestView(
                            pending: pending,
                            submit: { username, password, save, passwordOnly in
                                self.coordinator.submitCredential(
                                    username: username,
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
                            authenticate: { self.coordinator.authenticate(pending) },
                            continueToSystemSigningAuthentication: {
                                self.coordinator.continueToSystemSigningAuthentication(pending)
                            },
                            usePassword: { self.coordinator.authenticateWithPassword(pending) },
                            cancel: self.coordinator.cancel
                        )
                        .task(id: pending.request.requestID) {
                            if !pending.request.purpose.requiresExplicitDestructiveConfirmation,
                               pending.request.operation.phaseTwoKind != .signing
                               || pending.request.sshKeyBackend == .directSecureEnclaveV1
                            // swiftlint:disable:next opening_brace
                            {
                                self.coordinator.authenticate(pending)
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            case .processing:
                ProgressView("処理しています…")
            case let .completed(completion):
                ResultView(
                    kind: completion.isSuccess ? .success : .warning,
                    title: completion.message,
                    dismiss: self.coordinator.dismissResult
                )
            case let .cancelled(message):
                ResultView(kind: .cancelled, title: message, dismiss: self.coordinator.dismissResult)
            case let .denied(message):
                ResultView(kind: .failure, title: message, dismiss: self.coordinator.dismissResult)
            case let .failed(message):
                ResultView(kind: .failure, title: message, dismiss: self.coordinator.dismissResult)
            }
        }
        .padding(28)
    }
}

private struct PasswordAutoFillRequestView: View {
    let pending: AuthApprovalCoordinator.PendingApproval
    let submit: (String, String, Bool, Bool) -> Void
    let cancel: () -> Void
    @State private var password = ""
    @State private var username = ""
    @State private var saveToKeychain = false

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
                VStack(alignment: .leading, spacing: 5) {
                    Text("ユーザー名").font(.caption).foregroundStyle(.secondary)
                    AutoFillTextField(
                        text: self.$username,
                        placeholder: self.pending.request.keychainAccount,
                        accessibilityLabel: "ユーザー名",
                        contentType: .username,
                        secure: false
                    )
                }
                VStack(alignment: .leading, spacing: 5) {
                    Text("パスワード").font(.caption).foregroundStyle(.secondary)
                    AutoFillTextField(
                        text: self.$password,
                        placeholder: "Passwordsから選択",
                        accessibilityLabel: "パスワード",
                        contentType: .password,
                        secure: true
                    )
                }
            }
            if !self.username.isEmpty, self.username != self.pending.request.keychainAccount {
                Text("選択したユーザー名が設定済みアカウントと一致しません。")
                    .font(.caption)
                    .foregroundStyle(.red)
            } else if self.username.isEmpty, !self.password.isEmpty {
                Text("Passwordsがユーザー名を返さなかった場合は、設定済みアカウントを入力して確認してください。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Toggle("macop管理のKeychainにも保存・更新する", isOn: self.$saveToKeychain)
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                self.row("サービス", self.pending.request.keychainService)
                self.row("保存先", self.pending.request.keychainAccount)
                self.row("操作", self.pending.request.purpose.displayName)
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
                        Button("Macのログインパスワード") {
                            self.submit(self.username, self.password, self.saveToKeychain, true)
                            self.username = ""
                            self.password = ""
                        }
                        Button("Touch IDまたはApple Watch") {
                            self.submit(self.username, self.password, self.saveToKeychain, false)
                            self.username = ""
                            self.password = ""
                        }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                    }
                    .fixedSize(horizontal: true, vertical: false)
                    .disabled(self.password.isEmpty || self.username != self.pending.request.keychainAccount)
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
    let accessibilityLabel: String
    let contentType: NSTextContentType
    let secure: Bool

    func makeCoordinator() -> Coordinator {
        Coordinator(text: self.$text)
    }

    func makeNSView(context: Context) -> NSTextField {
        let field: NSTextField = self.secure ? NSSecureTextField() : NSTextField()
        field.placeholderString = self.placeholder
        field.setAccessibilityLabel(self.accessibilityLabel)
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
    private struct SSHSessionTargetPresentation {
        let application: String
        let signingAuthority: String
        let cdHash: String
        let verification: String
    }

    @State private var destructiveAuthenticationStarted = false
    @State private var technicalDetailsExpanded = false
    let pending: AuthApprovalCoordinator.PendingApproval
    let authenticate: () -> Void
    let continueToSystemSigningAuthentication: () -> Void
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
            VStack(alignment: .leading, spacing: 12) {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                    if self.isManagedKeychainRequest {
                        self.row("内容", self.managedKeychainAction)
                        if self.isDeleteAllRequest {
                            self.row("対象", "macop管理のKeychain項目すべて")
                        } else {
                            self.row("サービス", self.pending.request.keychainService)
                            self.row("アカウント", self.pending.request.keychainAccount)
                        }
                        self.row("コマンド", self.pending.request.purpose.displayName)
                    } else if self.isDirectSSHKeyManagementRequest {
                        self.row("対象", self.directSSHKeyManagementAction)
                        self.row("鍵", self.pending.request.credentialLabel)
                        if !self.pending.request.credentialFingerprint.isEmpty {
                            self.row("フィンガープリント", self.pending.request.credentialFingerprint)
                        }
                        self.row("保護", "Touch ID、Apple Watch、Macのログインパスワード")
                        self.row("コマンド", self.pending.request.purpose.displayName)
                    } else {
                        if let target = self.sshSessionTargetPresentation {
                            self.row("実行対象", target.application)
                        }
                        self.row("接続先", self.pending.request.host.isEmpty ? "SSHセッション" : self.pending.request.host)
                        self.row("使用する鍵", self.pending.request.credentialLabel)
                        self.row("フィンガープリント", self.pending.request.credentialFingerprint)
                        self.row("操作", self.pending.request.purpose.displayName)
                    }
                }
                if let target = self.sshSessionTargetPresentation {
                    DisclosureGroup("技術情報", isExpanded: self.$technicalDetailsExpanded) {
                        Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                            self.row("署名", target.signingAuthority)
                            self.row("コードハッシュ", target.cdHash)
                            self.row("検証", target.verification)
                        }
                        .padding(.top, 8)
                    }
                    .font(.callout)
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
            if self.usesEmbeddedAuthentication {
                if self.showsDestructiveConfirmation {
                    DestructiveConfirmationView(
                        title: self.destructiveConfirmationTitle,
                        message: self.destructiveConfirmationMessage,
                        buttonTitle: self.destructiveConfirmationButtonTitle,
                        confirm: self.beginDestructiveAuthentication,
                        cancel: self.cancel
                    )
                } else {
                    LocalAuthenticationView("Touch IDまたはApple Watchで承認", context: self.pending.context)
                        .controlSize(.regular)
                    self.embeddedAuthenticationActions
                }
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    Label("次にmacOSの鍵認証が1回表示されます", systemImage: "lock.shield")
                        .font(.headline)
                    Text(self.signingAuthenticationDescription)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Text("現在のプロセスと要求内容にだけ有効")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("キャンセル", action: self.cancel)
                            .keyboardShortcut(.cancelAction)
                        Button(
                            "Touch IDまたはMacのログインパスワード認証へ進む",
                            action: self.continueToSystemSigningAuthentication
                        )
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                    }
                }
            }
        }
    }

    private var embeddedAuthenticationActions: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("現在のプロセスと要求内容にだけ有効")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Button("キャンセル", action: self.cancel)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Macのログインパスワードを使用", action: self.usePassword)
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
    }

    private var isSigningRequest: Bool {
        self.pending.request.operation.phaseTwoKind == .signing
    }

    private var usesEmbeddedAuthentication: Bool {
        !self.isSigningRequest || self.pending.request.sshKeyBackend == .directSecureEnclaveV1
    }

    private var showsDestructiveConfirmation: Bool {
        self.pending.request.purpose.requiresExplicitDestructiveConfirmation
            && !self.destructiveAuthenticationStarted
    }

    private var signingAuthenticationDescription: String {
        "CTKCardTokenでTouch IDまたはMacのログインパスワードを使用します。"
            + "このSecure Enclave鍵はApple Watchでは解除できません。"
    }

    private var destructiveConfirmationTitle: String {
        self.isDeleteAllRequest ? "管理項目をすべて削除します" : "この項目を削除します"
    }

    private var destructiveConfirmationMessage: String {
        if self.isDeleteAllRequest {
            return "macop管理のKeychain項目がすべて削除されます。この操作は元に戻せません。"
        }
        if self.pending.request.purpose == .sshMigrationDeletePrepared {
            return "外部登録前の準備済みSSH鍵を削除します。この操作は元に戻せません。"
        }
        if self.pending.request.operation == .directSSHKeyDelete {
            return "表示されたSecure Enclave SSH鍵を削除します。この操作は元に戻せません。"
        }
        return "表示されたKeychain項目を削除します。この操作は元に戻せません。"
    }

    private var destructiveConfirmationButtonTitle: String {
        if self.isDeleteAllRequest {
            return "管理項目をすべて削除"
        }
        let deletesSSHKey = self.pending.request.operation == .directSSHKeyDelete
            || self.pending.request.purpose == .sshMigrationDeletePrepared
        if deletesSSHKey {
            return "SSH鍵を削除"
        }
        return "Keychain項目を削除"
    }

    private func beginDestructiveAuthentication() {
        self.destructiveAuthenticationStarted = true
        Task { @MainActor in
            await Task.yield()
            self.authenticate()
        }
    }

    private var directSSHKeyManagementAction: String {
        switch self.pending.request.operation {
        case .directSSHKeyCreate: "SSH鍵の新規作成"
        case .directSSHKeyDelete: "SSH鍵の削除"
        case .sshMigrationTransition: self.pending.request.purpose.displayName
        default: "SSH鍵の操作"
        }
    }

    private var requesterIdentity: LiveCodeIdentity {
        self.pending.peer.requestingApplication ?? self.pending.peer.peerIdentity
    }

    private var isManagedKeychainRequest: Bool {
        self.pending.request.operation.family == .managedKeychain
    }

    private var isDirectSSHKeyManagementRequest: Bool {
        self.pending.request.operation.family == .directSSHKeyManagement
    }

    private var sshSessionTargetPresentation: SSHSessionTargetPresentation? {
        guard case let .sshSessionTarget(application, signingAuthority, cdHash, verification) =
            self.pending.request.presentation
        else { return nil }
        return SSHSessionTargetPresentation(
            application: application,
            signingAuthority: signingAuthority,
            cdHash: cdHash,
            verification: verification
        )
    }

    private var isDeleteAllRequest: Bool {
        self.pending.request.operation == .managedKeychainDelete
            && self.pending.request.keychainService.isEmpty
            && self.pending.request.keychainAccount.isEmpty
    }

    private var managedKeychainAction: String {
        switch self.pending.request.operation {
        case .managedKeychainRead: "読み取り"
        case .managedKeychainUpdate: self.pending.request.purpose.concernsOTP ? "OTP seedの更新" : "更新"
        case .managedKeychainDelete: "削除"
        default: self.pending.request.purpose.concernsOTP ? "OTP seedの登録" : "登録"
        }
    }

    private var requestTitle: String {
        if self.isManagedKeychainRequest {
            return "\(self.requesterName) がKeychain項目の\(self.managedKeychainAction)を要求しています"
        }
        if self.isDirectSSHKeyManagementRequest {
            return "\(self.requesterName) が\(self.directSSHKeyManagementAction)を要求しています"
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

private struct DestructiveConfirmationView: View {
    let title: String
    let message: String
    let buttonTitle: String
    let confirm: () -> Void
    let cancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(self.title, systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)
            Text(self.message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("キャンセル", action: self.cancel)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(self.buttonTitle, role: .destructive, action: self.confirm)
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
            }
        }
        .padding(14)
        .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct ResultView: View {
    enum Kind: Equatable {
        case success
        case warning
        case cancelled
        case failure

        var symbol: String {
            switch self {
            case .success: "checkmark.circle.fill"
            case .warning: "exclamationmark.triangle.fill"
            case .cancelled: "xmark.circle"
            case .failure: "xmark.octagon.fill"
            }
        }

        var tint: Color {
            switch self {
            case .success: .green
            case .warning: .orange
            case .cancelled: .gray
            case .failure: .red
            }
        }

        var requiresManualDismissal: Bool {
            self == .warning || self == .failure
        }
    }

    let kind: Kind
    let title: String
    let dismiss: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: self.kind.symbol)
                .font(.system(size: 42))
                .foregroundStyle(self.kind.tint)
                .accessibilityHidden(true)
            Text(self.title)
                .font(.headline)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            if self.kind.requiresManualDismissal {
                HStack(spacing: 10) {
                    Button("メッセージをコピー", action: self.copyDetails)
                    Button("閉じる", action: self.dismiss)
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func copyDetails() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(self.title, forType: .string)
    }
}
