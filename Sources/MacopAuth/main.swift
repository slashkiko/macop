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

    private static func isProbe() -> Bool {
        CommandLine.arguments.dropFirst().contains("--probe")
    }
}

@MainActor
// swiftlint:disable:next type_body_length
private final class AuthApprovalCoordinator: ObservableObject {
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

    @Published private(set) var state: State = .starting
    private let socketPath: String?
    private let probe: Bool
    private var started = false
    private var continuation: CheckedContinuation<ApprovalOutcome, Never>?

    init(socketPath: String?, probe: Bool = false) {
        self.socketPath = socketPath
        self.probe = probe
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
            NSApplication.shared.terminate(nil)
        }
    }

    private func finish(
        _ status: AuthBrokerApprovalStatus,
        credential: Data? = nil,
        username: String? = nil,
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
                ? "OTP seedをTouch ID、Apple Watch、またはMacパスワードで保護して登録します。"
                : "Touch ID、Apple Watch、またはMacパスワードで保護するKeychain項目を登録します。"
        case .managedKeychainUpdate:
            request.purpose.concernsOTP
                ? "OTP seedをTouch ID、Apple Watch、またはMacパスワードで更新します。"
                : "macop管理のKeychain項目を更新します。"
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
        if AuthBrokerRuntimeCapabilities.gitClientTrustAccessGroup != nil {
            capabilities |= AuthBrokerCapability.gitClientTrust.rawValue
        }
        if AuthBrokerRuntimeCapabilities.hasManagedKeychainEntitlements() {
            capabilities |= AuthBrokerCapability.managedKeychain.rawValue
                | AuthBrokerCapability.passwordAutoFill.rawValue
                | AuthBrokerCapability.passwordAutoFillUsername.rawValue
        }
        return capabilities
    }()

    private static func hasManagedKeychainEntitlements() -> Bool {
        self.gitClientTrustAccessGroup != nil
    }

    static let gitClientTrustAccessGroup: String? = {
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
        let expectedSuffix = ".io.github.slashkiko.macop.auth"
        guard applicationIdentifier.hasSuffix(expectedSuffix),
              let teamID = applicationIdentifier.split(separator: ".").first,
              applicationIdentifier == "\(teamID)\(expectedSuffix)",
              accessGroups.contains(applicationIdentifier) else { return nil }
        return applicationIdentifier
    }()
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
        try self.validateRoot(request)
        let outcome = await coordinator.requestApproval(request, peer: peer)
        let signer: (any AgentKeySigning)?
        var resultStatus = outcome.status == .approved ? errSecSuccess : errSecAuthFailed
        var resultData = Data()
        var resultMessage = ""
        let isSigningRequest = request.operation.phaseTwoKind == .signing
        if outcome.status == .approved, let context = outcome.context, isSigningRequest {
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
            let candidate: CTKIdentitySigner
            do {
                candidate = try SSHCommand.makeVerifiedSessionSigner(
                    label: request.credentialLabel,
                    authenticationContext: context
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
        }
        await coordinator.terminateSoon(
            after: request.operation == .passwordAutoFill ? .seconds(2) : .milliseconds(250)
        )
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
            return
        }
        try self.writeTrustMutationResponse(
            client: client,
            request: request,
            generation: document.generation,
            status: .approved
        )
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
                        usePassword: { self.coordinator.authenticateWithPassword(pending) },
                        cancel: self.coordinator.cancel
                    )
                    .task(id: pending.request.requestID) { self.coordinator.authenticate(pending) }
                }
            case .processing:
                ProgressView("処理しています…")
            case let .completed(completion):
                ResultView(
                    symbol: completion.isSuccess ? "checkmark.circle.fill" : "exclamationmark.triangle",
                    title: completion.message
                )
            case let .cancelled(message):
                ResultView(symbol: "xmark.circle", title: message)
            case let .denied(message):
                ResultView(symbol: "exclamationmark.triangle", title: message)
            case let .failed(message):
                ResultView(symbol: "exclamationmark.triangle", title: message)
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
                    text: self.$username,
                    placeholder: "ユーザー名（\(self.pending.request.keychainAccount)）",
                    contentType: .username,
                    secure: false
                )
                AutoFillTextField(
                    text: self.$password,
                    placeholder: "パスワード",
                    contentType: .password,
                    secure: true
                )
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
            Toggle("選んだパスワードをmacop管理のKeychainに保存・更新する", isOn: self.$saveToKeychain)
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
                        Button("Macパスワード") {
                            self.submit(self.username, self.password, self.saveToKeychain, true)
                            self.username = ""
                            self.password = ""
                        }
                        Button("Touch ID／Apple Watch") {
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
    private struct SSHSessionTargetPresentation {
        let application: String
        let signingAuthority: String
        let cdHash: String
        let verification: String
    }

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
            LocalAuthenticationView("Touch ID／Apple Watchで許可", context: self.pending.context)
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
                    if let target = self.sshSessionTargetPresentation {
                        self.row("実行対象", target.application)
                        self.row("署名", target.signingAuthority)
                        self.row("コードハッシュ", target.cdHash)
                        self.row("検証", target.verification)
                    }
                    self.row("接続先", self.pending.request.host.isEmpty ? "SSHセッション" : self.pending.request.host)
                    self.row("使用する鍵", self.pending.request.credentialLabel)
                    self.row("フィンガープリント", self.pending.request.credentialFingerprint)
                }
                self.row("操作", self.pending.request.purpose.displayName)
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
        self.pending.request.operation.family == .managedKeychain
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
