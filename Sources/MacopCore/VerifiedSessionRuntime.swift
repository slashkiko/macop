import Dispatch
import Foundation
import LocalAuthentication

/// The service interface is deliberately small so runtime tests can exercise
/// the transaction with a real Unix listener while replacing only platform UI
/// and process-launch boundaries.
public protocol VerifiedSessionRunning: Sendable {
    func serve() throws
    func stop()
    func waitUntilListening(timeout: TimeInterval) -> Bool
}

extension VerifiedSessionAgent: VerifiedSessionRunning {}

public final class DeferredAgentConnectionBuilder: AgentConnectionBuilding, @unchecked Sendable {
    private let lock = NSLock()
    private let requester: RequesterVerifier
    private var builder: DefaultAgentConnectionBuilder?

    public init(requester: RequesterVerifier = RequesterVerifier()) {
        self.requester = requester
    }

    public func install(_ signer: any AgentKeySigning, registry: SessionRegistry) {
        self.lock.lock(); defer { self.lock.unlock() }
        self.builder = DefaultAgentConnectionBuilder(requester: self.requester, registry: registry, signer: signer)
    }

    public func makeConnection(for sessionID: UUID) throws -> AgentConnection {
        self.lock.lock(); let value = self.builder; self.lock.unlock()
        guard let value else { throw AgentProtocolError.denied }
        return try value.makeConnection(for: sessionID)
    }
}

public struct VerifiedSessionRuntimeLaunch: @unchecked Sendable {
    public let request: VerifiedSessionLaunchRequest
    public let waitForExit: @Sendable () throws -> Int32
    public let cancel: @Sendable () -> Void

    public init(
        request: VerifiedSessionLaunchRequest,
        waitForExit: @escaping @Sendable () throws -> Int32,
        cancel: @escaping @Sendable () -> Void
    ) {
        self.request = request
        self.waitForExit = waitForExit
        self.cancel = cancel
    }
}

public struct VerifiedSessionRuntimeDependencies: @unchecked Sendable {
    public let selectIdentity: @Sendable (_ label: String) throws -> SSHCommand.VerifiedSessionIdentity
    public let launch: @Sendable (_ reservation: VerifiedSessionReservation) throws -> VerifiedSessionRuntimeLaunch
    public let activate: @Sendable (_ reservation: VerifiedSessionReservation,
                                    _ request: VerifiedSessionLaunchRequest) throws -> VerifiedSession
    public let prompt: any SessionAuthorizationResultPrompting
    public let makeSigner: @Sendable (_ label: String, _ context: LAContext) throws -> any AgentKeySigning
    public let makeAgent: @Sendable (_ registry: SessionRegistry, _ sessionID: UUID,
                                     _ connections: any AgentConnectionBuilding) -> any VerifiedSessionRunning
    public let isCancellationRequested: @Sendable () -> Bool

    public init(
        selectIdentity: @escaping @Sendable (_ label: String) throws -> SSHCommand.VerifiedSessionIdentity,
        launch: @escaping @Sendable (_ reservation: VerifiedSessionReservation) throws -> VerifiedSessionRuntimeLaunch,
        activate: @escaping @Sendable (
            _ reservation: VerifiedSessionReservation,
            _ request: VerifiedSessionLaunchRequest
        ) throws -> VerifiedSession,
        prompt: any SessionAuthorizationResultPrompting,
        makeSigner: @escaping @Sendable (_ label: String, _ context: LAContext) throws -> any AgentKeySigning,
        makeAgent: @escaping @Sendable (_ registry: SessionRegistry, _ sessionID: UUID,
                                        _ connections: any AgentConnectionBuilding) -> any VerifiedSessionRunning,
        isCancellationRequested: @escaping @Sendable () -> Bool = { false }
    ) {
        self.selectIdentity = selectIdentity; self.launch = launch; self.activate = activate; self.prompt = prompt
        self.makeSigner = makeSigner; self.makeAgent = makeAgent; self.isCancellationRequested = isCancellationRequested
    }
}

/// Owns the fail-closed verified-session sequence. The prompt is deliberately
/// constructed only from the activated registry record, and a grant is added
/// only after construction of a signer tied to that prompt's LAContext.
public final class VerifiedSessionRuntime: @unchecked Sendable {
    private let registry: SessionRegistry
    private let dependencies: VerifiedSessionRuntimeDependencies
    private let duration: TimeInterval
    private let clock: @Sendable () -> Date

    public init(
        registry: SessionRegistry,
        dependencies: VerifiedSessionRuntimeDependencies,
        duration: TimeInterval = 600,
        clock: @escaping @Sendable () -> Date = Date.init
    ) {
        self.registry = registry; self.dependencies = dependencies; self.duration = duration; self.clock = clock
    }

    public func run(label: String) throws -> Int32 {
        guard !self.dependencies.isCancellationRequested() else { throw AgentProtocolError.denied }
        let identity = try self.dependencies.selectIdentity(label)
        let reservation = try self.registry.reserve(
            keyFingerprint: identity.fingerprint,
            expiresAt: self.clock().addingTimeInterval(self.duration)
        )
        let connections = DeferredAgentConnectionBuilder()
        let agent = self.dependencies.makeAgent(self.registry, reservation.id, connections)
        defer { agent.stop(); self.registry.revoke(reservation.id) }
        DispatchQueue.global(qos: .userInitiated).async { try? agent.serve() }
        guard agent.waitUntilListening(timeout: 2) else { throw AgentProtocolError.denied }

        let launched = try self.dependencies.launch(reservation)
        var completed = false
        defer {
            if !completed {
                launched.cancel()
            }
        }
        guard !self.dependencies.isCancellationRequested() else { throw AgentProtocolError.denied }
        let session = try self.dependencies.activate(reservation, launched.request)
        // Activation pins the exact designated requirement in the registry.
        // The launch boundary independently checked the canonical executable
        // path and retained this one live signing snapshot for the UI.
        let launchedIdentity = launched.request.codeIdentity
        let presentationIdentity = launched.request.presentationIdentity ?? launchedIdentity
        let result = try self.prompt(SessionAuthorizationPresentation(
            identityLabel: label,
            application: launched.request.presentedApplication,
            verification: launched.request.presentationVerification ?? presentationIdentity.provenanceSummary,
            signingAuthority: presentationIdentity.signatureSummary,
            cdHash: Self.abbreviatedCDHash(presentationIdentity.cdHash),
            fingerprint: session.keyFingerprint,
            rootPID: session.rootPID,
            rootStartTime: session.rootStartTime,
            rootIdentifier: session.bundleID,
            rootCodeRequirement: session.codeRequirement,
            sessionID: session.id,
            expiresAt: session.expiresAt,
            rootExecutablePath: launchedIdentity.canonicalPath
        ))
        if let failure = result.brokerFailure {
            throw failure
        }
        guard !self.dependencies.isCancellationRequested(), result.approved else { throw AgentProtocolError.denied }
        let signer: any AgentKeySigning
        if let remote = result.signer {
            signer = remote
        } else if let context = result.authenticationContext {
            signer = try self.dependencies.makeSigner(label, context)
        } else {
            throw AgentProtocolError.denied
        }
        guard constantTimeEqual(Data(signer.fingerprint.utf8), Data(session.keyFingerprint.utf8)) else {
            throw AgentProtocolError.denied
        }
        connections.install(signer, registry: self.registry)
        guard self.registry.authorize(session.id) else { throw AgentProtocolError.denied }
        let status = try launched.waitForExit()
        guard !self.dependencies.isCancellationRequested() else { throw AgentProtocolError.denied }
        completed = true
        return status
    }

    private func prompt(_ presentation: SessionAuthorizationPresentation) throws -> SessionAuthorizationResult {
        let state = RuntimePromptState()
        self.dependencies.prompt.authorizeResult(presentation) { result in state.finish(result) }
        guard let result = state.wait(until: self.dependencies.isCancellationRequested) else {
            throw AgentProtocolError.denied
        }
        return result
    }

    private static func abbreviatedCDHash(_ value: String?) -> String {
        guard let value, !value.isEmpty else { return "unavailable" }
        return value.count > 16 ? "\(value.prefix(12))…\(value.suffix(4))" : value
    }
}

private final class RuntimePromptState: @unchecked Sendable {
    private let lock = NSCondition()
    private var result: SessionAuthorizationResult?

    func finish(_ result: SessionAuthorizationResult) {
        self.lock.lock(); self.result = result; self.lock.broadcast(); self.lock.unlock()
    }

    func wait(until isCancelled: @escaping @Sendable () -> Bool) -> SessionAuthorizationResult? {
        self.lock.lock(); defer { self.lock.unlock() }
        while self.result == nil {
            if isCancelled() {
                return nil
            }
            _ = self.lock.wait(until: Date().addingTimeInterval(0.05))
        }
        return self.result
    }
}
