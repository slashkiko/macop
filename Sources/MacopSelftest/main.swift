import Darwin

// swiftlint:disable file_length
import CryptoKit
import Foundation
import LocalAuthentication
import MacopCore
import Security

struct SelftestFailure: Error {
    let message: String
}

private struct ConfigSelectorFixture {
    let name: String
    let itemKey: String
    let fields: String
}

let appleTableHeader = "Key Type  Public Key Hash                            Prot  Label                 Common Name  Email Address  Valid To  Valid\n"
func appleTableRow(_ hash: String, _ label: String, commonName: String = "") -> String {
    let keyType = "p-256-ne"
    return keyType + String(repeating: " ", count: 10 - keyType.count)
        + hash + String(repeating: " ", count: 53 - 10 - hash.count)
        + "bio" + String(repeating: " ", count: 59 - 53 - 3)
        + label + String(repeating: " ", count: max(1, 81 - 59 - label.count))
        + commonName + "\n"
}

final class StreamCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Data()
    func append(_ data: Data) {
        self.lock.lock(); defer { self.lock.unlock() }; self.value.append(data)
    }

    func read() -> Data {
        self.lock.lock(); defer { self.lock.unlock() }; return self.value
    }
}

final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock(); private var value = 0
    func increment() {
        self.lock.lock(); self.value += 1; self.lock.unlock()
    }

    func read() -> Int {
        self.lock.lock(); defer { lock.unlock() }; return self.value
    }
}

private func openFileDescriptorCount() throws -> Int {
    try FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count
}

final class RecordingSSHExecutor: SSHStreamingExecuting, @unchecked Sendable {
    struct Invocation { let path: String; let arguments: [String]; let environment: [String: String] }
    var invocations = [Invocation]()
    private var listCount = 0
    func execute(path: String, arguments: [String], environment: CommandEnvironment) throws -> CommandResult {
        self.invocations.append(Invocation(path: path, arguments: arguments, environment: environment))
        if path == SSHCommand.scAuth, arguments.first == "list-ctk-identities" {
            self.listCount += 1
            return CommandResult(
                exitCode: 0,
                stdout: self.listCount == 1 ? appleTableHeader
                    : appleTableHeader + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github")
            )
        }
        if path == SSHCommand.sshKeygen {
            return CommandResult(exitCode: 0, stdout: "ecdsa-sha2-nistp256 AAAA github\n")
        }
        if path == SSHCommand.ssh, arguments.first == "-G" {
            return CommandResult(
                exitCode: 0,
                stdout: "forwardagent no\npkcs11provider /usr/lib/ssh-keychain.dylib\nidentitiesonly yes\n"
            )
        }
        return CommandResult(exitCode: 0)
    }

    func executeStreaming(
        path: String, arguments: [String], environment: CommandEnvironment,
        stdout: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32 {
        self.invocations.append(Invocation(path: path, arguments: arguments, environment: environment))
        stdout(Data("streamed-child-output\n".utf8))
        return 23
    }
}

private struct AgentTestInspector: RequesterInspecting {
    func snapshot(of pid: Int32) -> ProcessSnapshot? {
        pid == 42 ? ProcessSnapshot(pid: 42, parentPID: 1, startTime: 7) : ProcessSnapshot(
            pid: pid,
            parentPID: 42,
            startTime: 8
        )
    }

    func validatedCodeIdentity(pid _: Int32, requirement: String) throws -> String {
        guard requirement == "anchor test" else { throw AgentProtocolError.denied }
        return "test.agent"
    }
}

private struct SnapshotInspector: RequesterInspecting {
    let snapshots: [Int32: ProcessSnapshot]
    let valid: Bool
    let identity: String
    init(snapshots: [Int32: ProcessSnapshot], valid: Bool, identity: String = "test.agent") {
        self.snapshots = snapshots; self.valid = valid; self.identity = identity
    }

    func snapshot(of pid: Int32) -> ProcessSnapshot? {
        self.snapshots[pid]
    }

    func validatedCodeIdentity(pid _: Int32, requirement: String) throws -> String {
        guard self.valid, requirement == "anchor test" else { throw AgentProtocolError.denied }
        return self.identity
    }
}

private let agentTestKey = Data([0, 0, 0, 4, 116, 101, 115, 116]) // string("test")
private struct AgentTestSigner: AgentKeySigning {
    let publicKeyBlob: Data
    let fingerprint: String
    init(publicKeyBlob: Data = agentTestKey, fingerprint: String? = nil) {
        self.publicKeyBlob = publicKeyBlob
        self.fingerprint = fingerprint ?? sshFingerprint(for: publicKeyBlob)
    }

    func sign(data: Data, flags: UInt32) throws -> Data {
        guard flags == 0 else { throw AgentProtocolError.denied }
        return Data("signature:".utf8) + data
    }
}

private struct AgentTestBindingVerifier: SessionBindingVerifying {
    func verify(hostKey: Data, sessionID: Data, signature: Data) throws {
        guard hostKey == Data("host".utf8), sessionID == Data("session".utf8), signature == Data("proof".utf8) else {
            throw AgentProtocolError.denied
        }
    }
}

private final class RuntimeState: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var presentation: SessionAuthorizationPresentation?
    private(set) var cancelled = false
    private(set) var reservationID: UUID?
    func record(_ presentation: SessionAuthorizationPresentation) {
        self.lock.lock(); self.presentation = presentation; self.lock.unlock()
    }

    func cancel() {
        self.lock.lock(); self.cancelled = true; self.lock.unlock()
    }

    func recordReservation(_ id: UUID) {
        self.lock.lock(); self.reservationID = id; self.lock.unlock()
    }

    func snapshot() -> (SessionAuthorizationPresentation?, Bool) {
        self.lock.lock(); defer { lock.unlock() }; return (
            self.presentation,
            self.cancelled
        )
    }

    func recordedReservation() -> UUID? {
        self.lock.lock(); defer { self.lock.unlock() }
        return self.reservationID
    }
}

private struct RuntimePrompt: SessionAuthorizationResultPrompting {
    let approved: Bool; let state: RuntimeState
    typealias Completion = @Sendable (SessionAuthorizationResult) -> Void
    func authorizeResult(_ presentation: SessionAuthorizationPresentation, completion: @escaping Completion) {
        self.state.record(presentation)
        completion(SessionAuthorizationResult(
            approved: self.approved,
            authenticationContext: self.approved ? LAContext() : nil
        ))
    }
}

private struct RuntimeAgent: VerifiedSessionRunning {
    func serve() throws {}
    func stop() {}
    func waitUntilListening(timeout _: TimeInterval) -> Bool {
        true
    }
}

// swiftlint:disable large_tuple opening_brace statement_position
private func runtimeSelftests() throws {
    func runRuntime(approved: Bool, signer: AgentTestSigner,
                    exit: Int32, cancelAfterLaunch: Bool = false) throws -> (Int32?, RuntimeState, SessionRegistry)
    {
        let root = URL(fileURLWithPath: "/tmp/macop-runtime-\(UUID().uuidString)", isDirectory: true)
        let registry = try SessionRegistry(root: root)
        let state = RuntimeState()
        let inspector = AgentTestInspector()
        let dependencies = VerifiedSessionRuntimeDependencies(
            selectIdentity: { _ in SSHCommand.VerifiedSessionIdentity(
                fingerprint: sshFingerprint(for: agentTestKey), label: "test", publicKeyBlob: agentTestKey
            ) },
            launch: { reservation in
                state.recordReservation(reservation.id)
                if cancelAfterLaunch {
                    state.cancel()
                }
                return VerifiedSessionRuntimeLaunch(
                    request: VerifiedSessionLaunchRequest(
                        rootPID: 42,
                        rootStartTime: 7,
                        bundleID: "test.agent",
                        codeRequirement: "anchor test"
                    ),
                    waitForExit: { exit }, cancel: { state.cancel() }
                )
            },
            activate: { reservation, request in
                state.recordReservation(reservation.id)
                return try registry.activate(
                    reservation: reservation, rootPID: request.rootPID, rootStartTime: request.rootStartTime,
                    bundleID: request.bundleID, codeRequirement: request.codeRequirement, inspector: inspector
                )
            },
            prompt: RuntimePrompt(approved: approved, state: state),
            makeSigner: { _, _ in signer },
            makeAgent: { _, _, _ in RuntimeAgent() },
            isCancellationRequested: { state.snapshot().1 }
        )
        let result: Int32?
        do { result = try VerifiedSessionRuntime(registry: registry, dependencies: dependencies).run(label: "test") }
        catch { result = nil }
        return (result, state, registry)
    }
    let (success, state, _) = try runRuntime(approved: true, signer: AgentTestSigner(), exit: 143)
    try expect(success == 143, "runtime must preserve conventional signal exit status")
    let presentation = state.snapshot().0
    try expect(presentation?.identityLabel == "test" && presentation?.application == "test.agent"
        && presentation?.fingerprint == sshFingerprint(for: agentTestKey)
        && presentation?.verification == "verified (code requirement matched)",
        "runtime presentation must be derived from the activated registry session")
    let mismatched = AgentTestSigner(publicKeyBlob: agentTestKey, fingerprint: "SHA256:other")
    let (failed, mismatchState, _) = try runRuntime(approved: true, signer: mismatched, exit: 0)
    try expect(failed == nil && mismatchState.snapshot().1, "fingerprint mismatch must deny and cancel launched root")
    let (denied, deniedState, _) = try runRuntime(approved: false, signer: AgentTestSigner(), exit: 0)
    try expect(denied == nil && deniedState.snapshot().1, "prompt denial must cancel launched root")
    let (cancelled, cancellationState, cancellationRegistry) = try runRuntime(
        approved: true, signer: AgentTestSigner(), exit: 0, cancelAfterLaunch: true
    )
    try expect(cancelled == nil && cancellationState.snapshot().1,
               "cancellation after launch must cancel the owned root")
    guard let reservationID = cancellationState.recordedReservation() else {
        throw SelftestFailure(message: "cancellation test must record its reservation")
    }
    try expect(cancellationRegistry.reservation(reservationID) == nil,
               "cancellation after launch must revoke the pending session")
}

// swiftlint:enable large_tuple opening_brace statement_position

private func agentSelftests() throws {
    var selfCode: SecCode?
    guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode else {
        throw SelftestFailure(message: "self code identity test requires a live SecCode")
    }
    var selfStaticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(selfCode, [], &selfStaticCode) == errSecSuccess, let selfStaticCode else {
        throw SelftestFailure(message: "self code identity test requires static signing information")
    }
    var selfRequirementRef: SecRequirement?
    var selfRequirementText: CFString?
    guard SecCodeCopyDesignatedRequirement(selfStaticCode, [], &selfRequirementRef) == errSecSuccess,
          let selfRequirementRef,
          SecRequirementCopyString(selfRequirementRef, [], &selfRequirementText) == errSecSuccess,
          let selfRequirement = selfRequirementText as String?
    else {
        throw SelftestFailure(message: "self code identity test requires a designated requirement")
    }
    let selfIdentifier = try SystemRequesterInspector().validatedCodeIdentity(
        pid: getpid(),
        requirement: selfRequirement
    )
    try expect(!selfIdentifier.isEmpty, "self process must pass its own designated requirement")

    var peerSockets = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &peerSockets) == 0 else {
        throw SelftestFailure(message: "socketpair must be available for peer evidence test")
    }
    defer { _ = close(peerSockets[0]); _ = close(peerSockets[1]) }
    let peerEvidence = try SocketPeerEvidence.read(from: peerSockets[0])
    try expect(peerEvidence.pid == getpid(), "LOCAL_PEERPID must identify the connected local process")
    try expect(peerEvidence.uid == Int32(getuid()), "LOCAL_PEERCRED must identify the connected local user")
    var peerCredentials = xucred(); peerCredentials.cr_version = UInt32(XUCRED_VERSION); peerCredentials
        .cr_uid = uid_t(getuid())
    let peerLength = socklen_t(MemoryLayout<pid_t>.size)
    let credentialLength = socklen_t(MemoryLayout.offset(of: \xucred.cr_uid)! + MemoryLayout<uid_t>.size)
    let validatedPeer = try SocketPeerEvidence.validate(
        pid: getpid(),
        pidLength: peerLength,
        credentials: peerCredentials,
        credentialLength: credentialLength
    )
    try expect(validatedPeer == peerEvidence,
               "validated peer evidence must accept complete socket credentials")
    func expectPeerEvidenceFailure(_ action: () throws -> Void, _ message: String) throws {
        do { try action(); throw SelftestFailure(message: message) } catch AgentProtocolError.denied {}
    }
    try expectPeerEvidenceFailure({ _ = try SocketPeerEvidence.validate(
                                      pid: getpid(),
                                      pidLength: peerLength - 1,
                                      credentials: peerCredentials,
                                      credentialLength: credentialLength
                                  ) },
                                  "short peer PID evidence must fail")
    try expectPeerEvidenceFailure({ _ = try SocketPeerEvidence.validate(
                                      pid: getpid(),
                                      pidLength: peerLength,
                                      credentials: peerCredentials,
                                      credentialLength: credentialLength - 1
                                  ) },
                                  "short peer credential evidence must fail")
    peerCredentials.cr_version = UInt32.max
    try expectPeerEvidenceFailure({ _ = try SocketPeerEvidence.validate(
                                      pid: getpid(),
                                      pidLength: peerLength,
                                      credentials: peerCredentials,
                                      credentialLength: credentialLength
                                  ) },
                                  "unknown peer credential versions must fail")
    peerCredentials.cr_version = UInt32(XUCRED_VERSION); peerCredentials.cr_uid = uid_t.max
    try expectPeerEvidenceFailure({ _ = try SocketPeerEvidence.validate(
                                      pid: getpid(),
                                      pidLength: peerLength,
                                      credentials: peerCredentials,
                                      credentialLength: credentialLength
                                  ) },
                                  "invalid peer credential UID must fail")

    let payload = Data(repeating: 0xAB, count: 6)
    var fragmented = try SSHWire.frame(payload)
    let original = fragmented
    fragmented.removeLast()
    let partial = try SSHWire.takeFrame(from: &fragmented)
    try expect(partial == nil, "agent frame must wait for complete payload")
    fragmented.append(original.last!)
    let completed = try SSHWire.takeFrame(from: &fragmented)
    try expect(
        completed == payload && fragmented.isEmpty,
        "agent frame must consume exactly one frame"
    )
    var oversized = try SSHWire.u32(UInt32(SSHWire.maxFrameLength + 1))
    do { _ = try SSHWire.takeFrame(from: &oversized); throw SelftestFailure(message: "agent oversize frame must fail")
    } catch AgentProtocolError.tooLarge {}

    let registryRoot = FileManager.default.temporaryDirectory
        .appendingPathComponent("macop-agent-selftest-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: registryRoot) }
    let symlinkRoot = registryRoot.appendingPathComponent("symlink-root")
    try FileManager.default.createDirectory(
        at: registryRoot,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    guard symlink(registryRoot.path, symlinkRoot.path) == 0 else {
        throw SelftestFailure(message: "symlink root test requires a local symbolic link")
    }
    do {
        _ = try SessionRegistry(root: symlinkRoot)
        throw SelftestFailure(message: "a symlink registry root must be rejected")
    } catch AgentProtocolError.denied {}
    let descriptorsBeforeRegistryDeinit = try openFileDescriptorCount()
    do {
        let deinitRegistry = try SessionRegistry(root: registryRoot.appendingPathComponent("deinit"))
        _ = try deinitRegistry.create(
            rootPID: 42,
            rootStartTime: 7,
            bundleID: "test.agent",
            codeRequirement: "anchor test",
            keyFingerprint: sshFingerprint(for: agentTestKey),
            expiresAt: .now.addingTimeInterval(60), inspector: AgentTestInspector()
        )
        let descriptorsWithRegistry = try openFileDescriptorCount()
        try expect(
            descriptorsWithRegistry >= descriptorsBeforeRegistryDeinit + 2,
            "a live registry must retain its root and session directory descriptors"
        )
    }
    let descriptorsAfterRegistryDeinit = try openFileDescriptorCount()
    try expect(
        descriptorsAfterRegistryDeinit == descriptorsBeforeRegistryDeinit,
        "registry deinitialization must close retained directory descriptors"
    )
    let registry = try SessionRegistry(root: registryRoot)
    let reservation = try registry.reserve(
        keyFingerprint: sshFingerprint(for: agentTestKey),
        expiresAt: .now.addingTimeInterval(60)
    )
    let reservationEnvironment = VerifiedSessionLauncher.environment(for: reservation)
    try expect(reservationEnvironment["SSH_AUTH_SOCK"] == reservation.socketPath.path,
               "a reservation must provide only its short-lived socket path to the launcher")
    try expect(reservationEnvironment["MACOP_SESSION_NONCE"] == nil,
               "the opaque reservation nonce must not be exposed to the launched root")
    try expect(registry.session(reservation.id) == nil && !registry.authorize(reservation.id)
        && registry.verifySign(sessionID: reservation.id, signerFingerprint: sshFingerprint(for: agentTestKey)) == nil,
        "a pending reservation must reject lookup, authorization, and signing")
    let activatedReservation = try registry.activate(
        reservation: reservation,
        rootPID: 42,
        rootStartTime: 7,
        bundleID: "test.agent",
        codeRequirement: "anchor test",
        inspector: AgentTestInspector()
    )
    try expect(activatedReservation.id == reservation.id && activatedReservation.nonce == reservation.nonce,
               "activation must retain the reserved nonce and immutable session identity")

    // Exercise the real Darwin AF_UNIX listener, rather than only its protocol
    // state machine. A client may connect before the root is activated, but no
    // bytes are interpreted until a signer has been installed and granted.
    let liveSuffix = String(UUID().uuidString.prefix(8))
    let liveRoot = URL(fileURLWithPath: "/tmp/ma-\(liveSuffix)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: liveRoot) }
    let liveRegistry = try SessionRegistry(root: liveRoot)
    let liveReservation = try liveRegistry.reserve(
        keyFingerprint: sshFingerprint(for: agentTestKey), expiresAt: .now.addingTimeInterval(60)
    )
    try expect(
        liveReservation.socketPath.path.utf8.count < MemoryLayout<sockaddr_un>.size,
        "live AF_UNIX fixture path must fit Darwin sun_path"
    )
    let liveInspector = SnapshotInspector(
        snapshots: [getpid(): ProcessSnapshot(pid: getpid(), parentPID: 1, startTime: 9)], valid: true
    )
    let deferredConnections = DeferredAgentConnectionBuilder(
        requester: RequesterVerifier(inspector: liveInspector, currentUID: Int32(getuid()))
    )
    let liveAgent = VerifiedSessionAgent(
        registry: liveRegistry, sessionID: liveReservation.id, connections: deferredConnections,
        inspector: liveInspector, frameReadTimeout: 0.15, maximumClients: 1
    )
    DispatchQueue.global().async { try? liveAgent.serve() }
    try expect(liveAgent.waitUntilListening(timeout: 2), "reserved listener must bind before child launch")
    func connectLiveAgent() throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw SelftestFailure(message: "AF_UNIX socket must be available") }
        var address = sockaddr_un(); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size); address
            .sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) {
            $0.copyBytes(from: Array(liveReservation.socketPath.path.utf8) + [0])
        }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0
        else { close(descriptor); throw SelftestFailure(message: "absolute reserved socket path must connect") }
        return descriptor
    }
    let pendingClient = try connectLiveAgent()
    defer { _ = close(pendingClient) }
    let identitiesRequest = try SSHWire.frame(Data([AgentMessage.requestIdentities]))
    let pendingSent = identitiesRequest.withUnsafeBytes {
        send(pendingClient, $0.baseAddress!, identitiesRequest.count, Int32(MSG_NOSIGNAL))
    }
    try expect(pendingSent == identitiesRequest.count, "pending client must send an identities request")
    var pendingPoll = pollfd(fd: pendingClient, events: Int16(POLLIN), revents: 0)
    try expect(
        poll(&pendingPoll, 1, 100) == 0,
        "pending client must receive no response before activation and signer install"
    )
    let cappedClient = try connectLiveAgent()
    defer { _ = close(cappedClient) }
    var cappedPoll = pollfd(fd: cappedClient, events: Int16(POLLIN | POLLHUP), revents: 0)
    try expect(poll(&cappedPoll, 1, 1000) > 0, "client above configured cap must be rejected promptly")
    _ = try liveRegistry.activate(
        reservation: liveReservation, rootPID: getpid(), rootStartTime: 9, bundleID: "test.agent",
        codeRequirement: "anchor test", inspector: liveInspector
    )
    deferredConnections.install(AgentTestSigner(), registry: liveRegistry)
    try expect(liveRegistry.authorize(liveReservation.id), "live session must grant only after signer installation")
    var replyPoll = pollfd(fd: pendingClient, events: Int16(POLLIN), revents: 0)
    try expect(poll(&replyPoll, 1, 2000) > 0, "activated client must receive identities response")
    var response = [UInt8](repeating: 0, count: 64)
    let received = recv(pendingClient, &response, response.count, 0)
    try expect(received >= 5 && response[4] == AgentMessage.identitiesAnswer,
               "real listener must bind peer evidence and reply with exact identities message")
    let partialHeader = Data([0, 0, 0, 1])
    let partialSent = partialHeader.prefix(1).withUnsafeBytes {
        send(pendingClient, $0.baseAddress!, 1, Int32(MSG_NOSIGNAL))
    }
    try expect(partialSent == 1, "dribbling client must send its partial header")
    var timeoutPoll = pollfd(fd: pendingClient, events: Int16(POLLIN | POLLHUP), revents: 0)
    try expect(poll(&timeoutPoll, 1, 1000) > 0, "absolute frame deadline must close a dribbling client")
    usleep(50000)
    let freshClient = try connectLiveAgent(); defer { _ = close(freshClient) }
    let freshSent = identitiesRequest.withUnsafeBytes {
        send(freshClient, $0.baseAddress!, identitiesRequest.count, Int32(MSG_NOSIGNAL))
    }
    try expect(freshSent == identitiesRequest.count, "fresh client must send an identities request")
    var freshPoll = pollfd(fd: freshClient, events: Int16(POLLIN), revents: 0)
    try expect(poll(&freshPoll, 1, 2000) > 0, "each fresh socket must receive its own connection binding")
    // A same-UID process can replace a filesystem socket name. The listener
    // must notice the changed object before it processes another request.
    _ = shutdown(freshClient, SHUT_RDWR)
    var freshClosedPoll = pollfd(fd: freshClient, events: Int16(POLLIN | POLLHUP), revents: 0)
    try expect(poll(&freshClosedPoll, 1, 1000) > 0, "fresh connection must close before substitution fixture")
    let substitutionClient = try connectLiveAgent()
    defer { _ = close(substitutionClient) }
    var originalSocketStat = stat()
    try expect(lstat(liveReservation.socketPath.path, &originalSocketStat) == 0,
               "fixture must capture the original pathname object")
    let attackerSocket = socket(AF_UNIX, SOCK_STREAM, 0)
    guard attackerSocket >= 0 else { throw SelftestFailure(message: "attacker socket fixture must be available") }
    defer { _ = close(attackerSocket) }
    let attackerPath = liveReservation.directory.appendingPathComponent("attacker.sock").path
    var attackerAddress = sockaddr_un()
    attackerAddress.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    attackerAddress.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &attackerAddress.sun_path) {
        $0.copyBytes(from: Array(attackerPath.utf8) + [0])
    }
    let attackerBound = withUnsafePointer(to: &attackerAddress) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.bind(attackerSocket, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    try expect(attackerBound == 0
        && Darwin.rename(attackerPath, liveReservation.socketPath.path) == 0,
        "fixture must atomically replace the reserved pathname with a different socket")
    var replacementSocketStat = stat()
    try expect(
        lstat(liveReservation.socketPath.path, &replacementSocketStat) == 0
            && (replacementSocketStat.st_dev != originalSocketStat.st_dev
                || replacementSocketStat.st_ino != originalSocketStat.st_ino
                || replacementSocketStat.st_ctimespec.tv_sec != originalSocketStat.st_ctimespec.tv_sec
                || replacementSocketStat.st_ctimespec.tv_nsec != originalSocketStat.st_ctimespec.tv_nsec),
        "attacker fixture must replace the original socket object"
    )
    // The listener may already have observed the substituted pathname and
    // closed this connection. MSG_NOSIGNAL keeps that expected race local.
    _ = identitiesRequest.withUnsafeBytes {
        send(substitutionClient, $0.baseAddress!, identitiesRequest.count, Int32(MSG_NOSIGNAL))
    }
    var substitutionPoll = pollfd(fd: substitutionClient, events: Int16(POLLIN | POLLHUP), revents: 0)
    var substitutionRevoked = false
    for _ in 0 ..< 20 {
        _ = poll(&substitutionPoll, 1, 50)
        if liveRegistry.reservation(liveReservation.id) == nil {
            substitutionRevoked = true
            break
        }
        usleep(50000)
    }
    try expect(substitutionRevoked,
               "socket substitution must revoke the session before a request can be processed")
    liveAgent.stop()
    usleep(100_000)
    try expect(liveRegistry.reservation(liveReservation.id) == nil
        && !FileManager.default.fileExists(atPath: liveReservation.socketPath.path),
        "stopping listener must revoke session and remove its socket immediately")

    // A non-reading peer must not pin a listener worker in a blocking send.
    // The identities reply is deliberately larger than the Darwin socket send
    // buffer, so the test exercises the POLLOUT deadline rather than a write.
    let saturatedRoot = URL(fileURLWithPath: "/tmp/ma-saturated-\(liveSuffix)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: saturatedRoot) }
    let saturatedRegistry = try SessionRegistry(root: saturatedRoot)
    // Agent identity blobs are capped below SSHWire.maxStringLength, while
    // repeated replies still exceed the socket queue without client reads.
    let largeKey = Data(repeating: 0x61, count: 120 * 1024)
    let saturatedSession = try saturatedRegistry.create(
        rootPID: getpid(), rootStartTime: 9, bundleID: "test.agent", codeRequirement: "anchor test",
        keyFingerprint: sshFingerprint(for: largeKey), expiresAt: .now.addingTimeInterval(60),
        inspector: liveInspector
    )
    try expect(saturatedRegistry.authorize(saturatedSession.id), "saturated fixture must authorize its session")
    let saturatedAgent = VerifiedSessionAgent(
        registry: saturatedRegistry, sessionID: saturatedSession.id,
        connections: DefaultAgentConnectionBuilder(
            requester: RequesterVerifier(inspector: liveInspector, currentUID: Int32(getuid())),
            registry: saturatedRegistry, signer: AgentTestSigner(publicKeyBlob: largeKey)
        ), inspector: liveInspector, frameWriteTimeout: 0.15, clientSendBuffer: 1024,
        maximumClientOutput: 256 * 1024
    )
    DispatchQueue.global().async { try? saturatedAgent.serve() }
    try expect(saturatedAgent.waitUntilListening(timeout: 2), "saturated listener must bind")
    let saturatedClient = socket(AF_UNIX, SOCK_STREAM, 0)
    guard saturatedClient >= 0 else { throw SelftestFailure(message: "saturated client socket must be available") }
    defer { _ = close(saturatedClient) }
    var receiveBuffer: Int32 = 1024
    try expect(
        setsockopt(
            saturatedClient,
            SOL_SOCKET,
            SO_RCVBUF,
            &receiveBuffer,
            socklen_t(MemoryLayout.size(ofValue: receiveBuffer))
        ) == 0,
        "saturated client must constrain its receive buffer"
    )
    var saturatedAddress = sockaddr_un()
    saturatedAddress.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    saturatedAddress.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &saturatedAddress.sun_path) {
        $0.copyBytes(from: Array(saturatedSession.socketPath.path.utf8) + [0])
    }
    let saturatedConnected = withUnsafePointer(to: &saturatedAddress) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(saturatedClient, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    try expect(saturatedConnected == 0, "saturated client must connect")
    let saturatedSent = identitiesRequest.withUnsafeBytes {
        send(saturatedClient, $0.baseAddress!, identitiesRequest.count, Int32(MSG_NOSIGNAL))
    }
    try expect(saturatedSent == identitiesRequest.count, "saturated client must send an identities request")
    for _ in 0 ..< 8 {
        let sent = identitiesRequest.withUnsafeBytes {
            send(saturatedClient, $0.baseAddress!, identitiesRequest.count, Int32(MSG_NOSIGNAL))
        }
        try expect(sent == identitiesRequest.count,
                   "non-reading client must queue repeated large-response requests")
    }
    // Darwin does not report POLLHUP while unread bytes remain queued. Do not
    // read until after the write deadline, then drain non-blockingly to EOF.
    usleep(1_000_000)
    let saturatedFlags = fcntl(saturatedClient, F_GETFL)
    try expect(saturatedFlags >= 0 && fcntl(saturatedClient, F_SETFL, saturatedFlags | O_NONBLOCK) == 0,
               "saturated client must become nonblocking for EOF verification")
    let drainDeadline = DispatchTime.now().uptimeNanoseconds + 1_500_000_000
    var drain = [UInt8](repeating: 0, count: 64 * 1024)
    var saturatedClosed = false
    var drainedBytes = 0
    while DispatchTime.now().uptimeNanoseconds < drainDeadline {
        let received = recv(saturatedClient, &drain, drain.count, 0)
        if received == 0 {
            saturatedClosed = true
            break
        }
        if received < 0 {
            if errno == EINTR {
                continue
            }
            guard errno == EAGAIN || errno == EWOULDBLOCK else { break }
            var drainPoll = pollfd(fd: saturatedClient, events: Int16(POLLIN | POLLHUP), revents: 0)
            _ = poll(&drainPoll, 1, 50)
            continue
        }
        drainedBytes += received
    }
    try expect(
        saturatedClosed && drainedBytes > 0 && drainedBytes <= 256 * 1024,
        "non-reading client must close within its 256 KiB output budget (drained \(drainedBytes) bytes)"
    )
    saturatedAgent.stop()
    // Keep the long-path case isolated from prior runs: the root itself must
    // remain a valid private directory before the socket name overflows.
    let longRoot = URL(
        fileURLWithPath: "/tmp/ma-long-\(liveSuffix)-" + String(repeating: "x", count: 80),
        isDirectory: true
    )
    defer { try? FileManager.default.removeItem(at: longRoot) }
    let longRegistry = try SessionRegistry(root: longRoot)
    let longReservation = try longRegistry.reserve(
        keyFingerprint: sshFingerprint(for: agentTestKey), expiresAt: .now.addingTimeInterval(60)
    )
    let longAgent = VerifiedSessionAgent(
        registry: longRegistry, sessionID: longReservation.id, connections: DeferredAgentConnectionBuilder()
    )
    DispatchQueue.global().async { try? longAgent.serve() }
    try expect(!longAgent.waitUntilListening(timeout: 1), "too-long AF_UNIX paths must fail closed before launch")
    do {
        _ = try registry.activate(
            reservation: reservation,
            rootPID: 42,
            rootStartTime: 7,
            bundleID: "test.agent",
            codeRequirement: "anchor test",
            inspector: AgentTestInspector()
        )
        throw SelftestFailure(message: "a reservation must activate exactly once")
    } catch AgentProtocolError.denied {}
    do {
        _ = try registry.create(
            rootPID: 42, rootStartTime: 7, bundleID: "test.agent", codeRequirement: "anchor test",
            keyFingerprint: sshFingerprint(for: agentTestKey), expiresAt: .now.addingTimeInterval(60),
            inspector: SnapshotInspector(
                snapshots: [42: ProcessSnapshot(pid: 42, parentPID: 1, startTime: 7)],
                valid: false
            )
        )
        throw SelftestFailure(message: "create must validate the root with its injected inspector")
    } catch AgentProtocolError.denied {}
    let session = try registry.create(
        rootPID: 42,
        rootStartTime: 7,
        bundleID: "test.agent",
        codeRequirement: "anchor test",
        keyFingerprint: sshFingerprint(for: agentTestKey),
        expiresAt: .now.addingTimeInterval(60), inspector: AgentTestInspector()
    )
    try expect(registry.authorize(session.id), "registry must issue an explicit session grant")
    let permissions = try FileManager.default
        .attributesOfItem(atPath: session.directory.path)[.posixPermissions] as? NSNumber
    try expect(permissions?.intValue == 0o700, "registry directories must be mode 0700")
    let chain = SnapshotInspector(snapshots: [
        42: ProcessSnapshot(pid: 42, parentPID: 1, startTime: 7),
        100: ProcessSnapshot(pid: 100, parentPID: 42, startTime: 8),
        101: ProcessSnapshot(pid: 101, parentPID: 999, startTime: 8)
    ], valid: true)
    let verifier = RequesterVerifier(inspector: chain, currentUID: Int32(getuid()))
    try expect(verifier.verify(peer: RequesterPeer(pid: 100, uid: Int32(getuid())), session: session),
               "a differently signed descendant must be accepted by ancestry")
    try expect(!verifier.verify(peer: RequesterPeer(pid: 101, uid: Int32(getuid())), session: session),
               "an external process must be rejected")
    try expect(!RequesterVerifier(inspector: SnapshotInspector(
        snapshots: [42: ProcessSnapshot(pid: 42, parentPID: 1, startTime: 7)], valid: false
    ), currentUID: Int32(getuid())).verify(peer: RequesterPeer(pid: 42, uid: Int32(getuid())), session: session),
    "a root whose code validity check fails must be rejected")
    try expect(!RequesterVerifier(inspector: SnapshotInspector(
        snapshots: [42: ProcessSnapshot(pid: 42, parentPID: 1, startTime: 7)], valid: true, identity: "other.agent"
    ), currentUID: Int32(getuid())).verify(peer: RequesterPeer(pid: 42, uid: Int32(getuid())), session: session),
    "a root whose validated identity changes must be rejected")
    try expect(
        !RequesterVerifier(inspector: SnapshotInspector(
            snapshots: [42: ProcessSnapshot(pid: 42, parentPID: 1, startTime: 9)],
            valid: true
        ), currentUID: Int32(getuid())).verify(peer: RequesterPeer(pid: 42, uid: Int32(getuid())), session: session),
        "PID reuse/root exit must be rejected"
    )
    let connection = AgentConnection(
        requester: RequesterVerifier(inspector: AgentTestInspector(), currentUID: Int32(getuid())),
        registry: registry,
        sessionID: session.id,
        signer: AgentTestSigner(),
        bindingVerifier: AgentTestBindingVerifier()
    )
    let peer = RequesterPeer(pid: 100, uid: Int32(getuid()))
    try expect(
        connection.reply(peer: peer, payload: Data([AgentMessage.signRequest])) == Data([AgentMessage.failure]),
        "agent must reject a sign before session binding"
    )
    let unknownExtension = try Data([AgentMessage.extensionRequest]) + (SSHWire.string("other")) +
        (SSHWire.string(Data()))
    try expect(
        connection.reply(peer: peer, payload: unknownExtension) == Data([AgentMessage.extensionFailure]),
        "unknown extension must use extension failure"
    )
    let forwardingState = SessionBindingState()
    let forwardingBind = try SSHWire.string("session-bind@openssh.com") + SSHWire.string(Data("host".utf8)) + SSHWire
        .string(Data("session".utf8)) + SSHWire.string(Data("proof".utf8)) + SSHWire.boolean(true)
    do { try forwardingState.accept(payload: forwardingBind, verifier: AgentTestBindingVerifier())
        throw SelftestFailure(message: "forwarded bindings must fail closed")
    } catch AgentProtocolError.denied {}
    let bind = try Data([AgentMessage.extensionRequest]) + (SSHWire.string("session-bind@openssh.com")) + SSHWire
        .string(Data("host".utf8)) + SSHWire.string(Data("session".utf8)) + SSHWire.string(Data("proof".utf8)) + SSHWire
        .boolean(false)
    try expect(
        connection.reply(peer: peer, payload: bind) == Data([AgentMessage.success]),
        "valid binding must acknowledge success"
    )
    try expect(
        connection.reply(peer: peer, payload: bind) == Data([AgentMessage.extensionFailure]),
        "duplicate binding must fail closed"
    )
    let signData = try SSHWire.string(Data("session".utf8)) + Data([50]) + SSHWire.string("user") + SSHWire
        .string("ssh-connection") + SSHWire.string("publickey") + SSHWire.boolean(true) + SSHWire
        .string("test") + SSHWire.string(agentTestKey)
    let sign = try Data([AgentMessage.signRequest]) + (SSHWire.string(agentTestKey)) + SSHWire
        .string(signData) + SSHWire.u32(0)
    let fullSignReply = connection.reply(peer: peer, payload: sign)
    let expectedSignReply = try Data([AgentMessage.signResponse]) + SSHWire.string(Data("signature:".utf8) + signData)
    try expect(fullSignReply == expectedSignReply, "bound signer must return the complete exact SSH sign response")
    var hostboundData = try SSHWire.string(Data("session".utf8))
    hostboundData.append(50)
    hostboundData += try SSHWire.string("user")
    hostboundData += try SSHWire.string("ssh-connection")
    hostboundData += try SSHWire.string("publickey-hostbound-v00@openssh.com")
    hostboundData += SSHWire.boolean(true)
    hostboundData += try SSHWire.string("test")
    hostboundData += try SSHWire.string(agentTestKey)
    let hostboundPrefix = hostboundData
    hostboundData += try SSHWire.string(Data("host".utf8))
    let hostboundSign = try Data([AgentMessage.signRequest]) + SSHWire.string(agentTestKey) + SSHWire
        .string(hostboundData) + SSHWire.u32(0)
    try expect(connection.reply(peer: peer, payload: hostboundSign).first == AgentMessage.signResponse,
               "host-bound userauth must match the verified host key")
    let wrongHostboundData = try hostboundPrefix + SSHWire.string(Data("other".utf8))
    let wrongHostbound = try Data([AgentMessage.signRequest]) + SSHWire.string(agentTestKey) + SSHWire
        .string(wrongHostboundData) + SSHWire.u32(0)
    try expect(connection.reply(peer: peer, payload: wrongHostbound) == Data([AgentMessage.failure]),
               "host-bound userauth must reject a different host key")

    for invalidSessionLength in [0, 129] {
        let malformedBind = try SSHWire.string("session-bind@openssh.com") + SSHWire.string(Data("host".utf8)) +
            SSHWire.string(Data(repeating: 1, count: invalidSessionLength)) + SSHWire.string(Data("proof".utf8)) +
            SSHWire.boolean(false)
        do {
            try SessionBindingState().accept(payload: malformedBind, verifier: AgentTestBindingVerifier())
            throw SelftestFailure(message: "session binding IDs outside the permitted length must fail")
        } catch AgentProtocolError.denied {}
    }

    let concurrentBinding = SessionBindingState(); let bindSuccesses = LockedCounter()
    DispatchQueue.concurrentPerform(iterations: 32) { _ in
        let didBind = (try? concurrentBinding.accept(
            payload: Data(bind.dropFirst()),
            verifier: AgentTestBindingVerifier()
        )) != nil
        if didBind {
            bindSuccesses.increment()
        }
    }
    try expect(bindSuccesses.read() == 1, "concurrent duplicate bindings must admit exactly one")
    let wrongSessionData = try SSHWire.string(Data("other-session".utf8)) + Data([50]) + SSHWire
        .string("user") + SSHWire
        .string("ssh-connection") + SSHWire.string("publickey") + SSHWire.boolean(true) + SSHWire
        .string("test") + SSHWire.string(agentTestKey)
    let wrongSession = try Data([AgentMessage.signRequest]) + SSHWire.string(agentTestKey) + SSHWire
        .string(wrongSessionData) + SSHWire.u32(0)
    try expect(connection.reply(peer: peer, payload: wrongSession) == Data([AgentMessage.failure]),
               "bound agent must reject a different SSH session ID")
    let wrongKeyData = try SSHWire.string(Data("session".utf8)) + Data([50]) + SSHWire.string("user") + SSHWire
        .string("ssh-connection") + SSHWire.string("publickey") + SSHWire.boolean(true) + SSHWire
        .string("test") + SSHWire.string(Data([
            0,
            0,
            0,
            5,
            111,
            116,
            104,
            101,
            114
        ]))
    let wrongKey = try Data([AgentMessage.signRequest]) + SSHWire.string(agentTestKey) + SSHWire
        .string(wrongKeyData) + SSHWire.u32(0)
    try expect(connection.reply(peer: peer, payload: wrongKey) == Data([AgentMessage.failure]),
               "bound agent must reject a different public-key blob")
    registry.revoke(session.id)
    try expect(connection.reply(peer: peer, payload: sign) == Data([AgentMessage.failure]),
               "revoked authorization must prevent signing")
    try expect(!FileManager.default.fileExists(atPath: session.directory.path),
               "revocation must remove the registry-owned session directory")

    let raceRegistry = try SessionRegistry(root: registryRoot.appendingPathComponent("race"))
    let raceSession = try raceRegistry.create(
        rootPID: 42,
        rootStartTime: 7,
        bundleID: "test.agent",
        codeRequirement: "anchor test",
        keyFingerprint: sshFingerprint(for: agentTestKey),
        expiresAt: .now.addingTimeInterval(60), inspector: AgentTestInspector()
    )
    try expect(raceRegistry.authorize(raceSession.id), "race session must authorize")
    let raceConnection = AgentConnection(
        requester: RequesterVerifier(inspector: AgentTestInspector(), currentUID: Int32(getuid())),
        registry: raceRegistry,
        sessionID: raceSession.id,
        signer: AgentTestSigner(),
        bindingVerifier: AgentTestBindingVerifier()
    )
    _ = raceConnection.reply(peer: peer, payload: bind)
    DispatchQueue.concurrentPerform(iterations: 32) { index in
        if index == 0 {
            raceRegistry.revoke(raceSession.id)
        } else {
            _ = raceConnection.reply(peer: peer, payload: sign)
        }
    }
    try expect(raceConnection.reply(peer: peer, payload: sign) == Data([AgentMessage.failure]),
               "revoke must deny every subsequently observed sign request")

    let substitutionRegistry = try SessionRegistry(root: registryRoot.appendingPathComponent("substitution"))
    let substituted = try substitutionRegistry.create(rootPID: 42, rootStartTime: 7, bundleID: "test.agent",
                                                      codeRequirement: "anchor test",
                                                      keyFingerprint: sshFingerprint(for: agentTestKey),
                                                      expiresAt: .now.addingTimeInterval(60),
                                                      inspector: AgentTestInspector())
    let originalDirectory = substituted.directory.appendingPathExtension("original")
    try FileManager.default.moveItem(at: substituted.directory, to: originalDirectory)
    try FileManager.default.createDirectory(
        at: substituted.directory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    substitutionRegistry.revoke(substituted.id)
    try expect(FileManager.default.fileExists(atPath: substituted.directory.path),
               "same-UID replacement directory must not be removed")
    try? FileManager.default.removeItem(at: originalDirectory)

    let symlinkRegistry = try SessionRegistry(root: registryRoot.appendingPathComponent("session-symlink"))
    let symlinkSession = try symlinkRegistry.create(rootPID: 42, rootStartTime: 7, bundleID: "test.agent",
                                                    codeRequirement: "anchor test",
                                                    keyFingerprint: sshFingerprint(for: agentTestKey),
                                                    expiresAt: .now.addingTimeInterval(60),
                                                    inspector: AgentTestInspector())
    let outsideDirectory = registryRoot.appendingPathComponent("outside")
    try FileManager.default.createDirectory(at: outsideDirectory, withIntermediateDirectories: false)
    try FileManager.default.moveItem(at: symlinkSession.directory,
                                     to: symlinkSession.directory.appendingPathExtension("original"))
    guard symlink(outsideDirectory.path, symlinkSession.directory.path) == 0 else {
        throw SelftestFailure(message: "session symlink test requires a local symbolic link")
    }
    symlinkRegistry.revoke(symlinkSession.id)
    try expect(FileManager.default.fileExists(atPath: outsideDirectory.path),
               "a substituted session symlink target must remain untouched")

    let bindingVerifier = SecuritySessionBindingVerifier(); let edPrivate = Curve25519.Signing.PrivateKey()
    let edHost = try SSHWire.string("ssh-ed25519") + SSHWire.string(edPrivate.publicKey.rawRepresentation)
    let edSession = Data("ed25519-session".utf8)
    let edSignature = try SSHWire.string("ssh-ed25519") + SSHWire.string(edPrivate.signature(for: edSession))
    try bindingVerifier.verify(hostKey: edHost, sessionID: edSession, signature: edSignature)
    do { try bindingVerifier.verify(hostKey: edHost, sessionID: Data("changed".utf8), signature: edSignature)
        throw SelftestFailure(message: "Ed25519 binding signature must cover the exact session ID")
    } catch AgentProtocolError.denied {}
    do { try bindingVerifier.verify(
        hostKey: SSHWire.string("ssh-rsa") + SSHWire.string(Data([1])),
        sessionID: edSession,
        signature: edSignature
    )
    throw SelftestFailure(message: "RSA host keys must fail closed")
    } catch AgentProtocolError.unsupported {}
    do { try bindingVerifier.verify(
        hostKey: SSHWire.string("ssh-ed25519-cert-v01@openssh.com") + SSHWire.string(Data()),
        sessionID: edSession,
        signature: edSignature
    )
    throw SelftestFailure(message: "host certificates must fail closed")
    } catch AgentProtocolError.unsupported {}
    var p256Error: Unmanaged<CFError>?
    guard let p256Private = SecKeyCreateRandomKey([
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256
    ] as CFDictionary, &p256Error), let p256Public = SecKeyCopyPublicKey(p256Private),
                                        let p256Point = SecKeyCopyExternalRepresentation(p256Public,
                                                                                         &p256Error) as Data?
    else {
        throw SelftestFailure(message: "P-256 binding vector requires a local Security key")
    }
    let p256Host = try SSHWire.string("ecdsa-sha2-nistp256") + SSHWire.string("nistp256") + SSHWire.string(p256Point)
    let p256Session = Data("p256-session".utf8)
    guard let p256DER = SecKeyCreateSignature(
        p256Private,
        .ecdsaSignatureMessageX962SHA256,
        p256Session as CFData,
        &p256Error
    ) as Data? else {
        throw SelftestFailure(message: "P-256 binding vector must sign")
    }
    let rawP256 = try CTKIdentitySigner.strictDERToRawP256(p256DER)
    func mpint(_ raw: Data) -> Data {
        let trimmed = Data(raw.drop { $0 == 0 }); let value = trimmed.isEmpty ? Data([0]) : trimmed
        return value.first! & 0x80 == 0 ? value : Data([0]) + value
    }
    let p256Signature = try SSHWire.string("ecdsa-sha2-nistp256") + SSHWire.string(
        SSHWire.string(mpint(Data(rawP256.prefix(32)))) + SSHWire.string(mpint(Data(rawP256.suffix(32))))
    )
    try bindingVerifier.verify(hostKey: p256Host, sessionID: p256Session, signature: p256Signature)
    let expiredRegistry = try SessionRegistry(root: registryRoot.appendingPathComponent("expired"))
    let expired = try expiredRegistry.create(
        rootPID: 42,
        rootStartTime: 7,
        bundleID: "test.agent",
        codeRequirement: "anchor test",
        keyFingerprint: sshFingerprint(for: agentTestKey),
        expiresAt: .now.addingTimeInterval(1), inspector: AgentTestInspector()
    )
    expiredRegistry.revoke(expired.id)
    let expiredConnection = AgentConnection(
        requester: RequesterVerifier(inspector: AgentTestInspector(), currentUID: Int32(getuid())),
        registry: expiredRegistry,
        sessionID: expired.id,
        signer: AgentTestSigner(),
        bindingVerifier: AgentTestBindingVerifier()
    )
    try expect(
        expiredConnection
            .reply(peer: peer, payload: Data([AgentMessage.requestIdentities])) == Data([AgentMessage.failure]),
        "revoked sessions must fail closed"
    )
    let malformedDER = Data([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
    do {
        _ = try CTKIdentitySigner
            .strictDERToRawP256(malformedDER); throw SelftestFailure(message: "noncanonical DER must fail")
    } catch AgentProtocolError.malformed {}
}

final class SequencedSSHExecutor: CommandExecuting, @unchecked Sendable {
    struct Invocation { let path: String; let arguments: [String] }
    var invocations = [Invocation]()
    var lists: [String]

    init(lists: [String]) {
        self.lists = lists
    }

    func execute(path: String, arguments: [String], environment _: CommandEnvironment) throws -> CommandResult {
        self.invocations.append(Invocation(path: path, arguments: arguments))
        if path == SSHCommand.scAuth, arguments.first == "list-ctk-identities" {
            return CommandResult(exitCode: 0, stdout: self.lists.isEmpty ? "" : self.lists.removeFirst())
        }
        if path == SSHCommand.sshKeygen {
            return CommandResult(exitCode: 0, stdout: "ecdsa-sha2-nistp256 AAAA My SSH Key\n")
        }
        return CommandResult(exitCode: 0)
    }
}

final class GitHubTestExecutor: SSHStreamingExecuting, @unchecked Sendable {
    let output: String
    let code: Int32
    init(output: String, code: Int32) {
        self.output = output; self.code = code
    }

    func execute(path: String, arguments: [String], environment _: CommandEnvironment) throws -> CommandResult {
        if path == SSHCommand.scAuth, arguments.first == "list-ctk-identities" {
            return CommandResult(exitCode: 0, stdout: appleTableHeader
                + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github"))
        }
        return CommandResult(exitCode: self.code, stderr: self.output)
    }

    func executeStreaming(
        path _: String, arguments _: [String], environment _: CommandEnvironment,
        stdout _: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32 {
        stderr(Data(self.output.utf8)); return self.code
    }
}

private func write(_ text: String, to handle: FileHandle) {
    try? handle.write(contentsOf: Data(text.utf8))
}

/// Small process-level harnesses used by `make test-pty`. They deliberately
/// exercise the same public MacopCore entry points as MacopCLI, while keeping
/// Keychain access deterministic and local to the test executable.
private func runHarnessIfRequested() -> Never? {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let mode = arguments.first else { return nil }
    let processEnvironment = ProcessInfo.processInfo.environment
    let pipedSecret: String? = {
        guard let descriptorText = processEnvironment["MACOP_SELFTEST_FAKE_SECRET_FD"],
              let descriptor = Int32(descriptorText)
        else { return nil }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        let data = handle.readDataToEndOfFile()
        try? handle.close()
        return String(data: data, encoding: .utf8)
    }()
    let secret = mode == "--pty-run-large-stdin" ? String(repeating: "large-stdin-secret-", count: 32768)
        : pipedSecret ?? "test-secret"
    let app = MacopApp(keychainClient: FakeKeychainClient(response: .success(Data(secret.utf8))))
    var harnessEnvironment = processEnvironment
    harnessEnvironment.removeValue(forKey: "MACOP_SELFTEST_FAKE_SECRET_FD")
    let runReference = harnessEnvironment.removeValue(forKey: "MACOP_SELFTEST_RUN_REFERENCE")
        ?? "keychain://generic/service/account"

    switch mode {
    case "--pty-run", "--pty-run-large-stdin":
        let argv = ["macop"] + Array(arguments.dropFirst())
        let environment = harnessEnvironment.merging(
            ["GH_TOKEN": runReference]
        ) { _, supplied in supplied }
        let result = app.runInteractivelyIfNeeded(argv: argv, env: environment)
            ?? app.runStreamingIfNeeded(
                argv: argv,
                env: environment,
                stdout: { try? FileHandle.standardOutput.write(contentsOf: $0) },
                stderr: { try? FileHandle.standardError.write(contentsOf: $0) }
            )
            ?? app.run(argv: argv, env: environment)
        write(result.stdout, to: .standardOutput)
        write(result.stderr, to: .standardError)
        exit(result.exitCode)
    case "--inject-stdin":
        let input = FileHandle.standardInput.readDataToEndOfFile()
        let argv = ["macop"] + Array(arguments.dropFirst()) + ["inject"]
        let result = app.run(argv: argv, env: harnessEnvironment, input: input)
        write(result.stdout, to: .standardOutput)
        write(result.stderr, to: .standardError)
        exit(result.exitCode)
    case "--doctor-probe":
        let result = app.run(argv: ["macop", "doctor", "--format=json"], env: [:])
        write(result.stdout, to: .standardOutput)
        write(result.stderr, to: .standardError)
        exit(result.exitCode)
    default:
        return nil
    }
}

func run() throws {
    do { try agentSelftests() } catch { throw SelftestFailure(message: "agent selftests: \(error)") }
    do { try runtimeSelftests() } catch { throw SelftestFailure(message: "runtime selftests: \(error)") }
    try runKeychainIntegrationIfRequested()
    let app = MacopApp(keychainClient: FakeKeychainClient(response: .success(Data("test-secret".utf8))))
    let fileManager = FileManager.default
    let tempRoot = fileManager.temporaryDirectory
        .appendingPathComponent("macop-selftest-\(UUID().uuidString)", isDirectory: true)
    defer { try? fileManager.removeItem(at: tempRoot) }

    try fileManager.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    let configDirectory = tempRoot.path

    let sessionRoot = tempRoot.appendingPathComponent("sessions", isDirectory: true)
    let sessionRegistry = try SessionRegistry(root: sessionRoot)
    let verifiedSession = try sessionRegistry.create(
        rootPID: 123,
        rootStartTime: 456,
        bundleID: "com.example.macop-test",
        codeRequirement: "anchor test",
        keyFingerprint: "SHA256:test",
        expiresAt: Date().addingTimeInterval(60), inspector: SnapshotInspector(
            snapshots: [123: ProcessSnapshot(pid: 123, parentPID: 1, startTime: 456)],
            valid: true, identity: "com.example.macop-test"
        )
    )
    let sessionEnvironment = VerifiedSessionLauncher.environment(for: verifiedSession)
    try expect(
        sessionEnvironment == ["SSH_AUTH_SOCK": verifiedSession.socketPath.path],
        "verified-session launcher must pass only the dedicated socket"
    )
    try expect(
        VerifiedSessionLauncher.notice(for: verifiedSession).contains("direct Apple provider use is not controlled"),
        "verified-session notice must state the Apple-provider boundary"
    )
    let presentation = SessionAuthorizationPresentation(
        identityLabel: "test",
        application: "macop-test",
        verification: "verified",
        fingerprint: "SHA256:test",
        sessionID: verifiedSession.id,
        expiresAt: verifiedSession.expiresAt
    )
    try expect(
        presentation.verification == "verified" && presentation.fingerprint == "SHA256:test"
            && sessionRegistry.authorize(verifiedSession.id),
        "only the registry-owned runtime may grant its activated session"
    )
    try expect(
        sessionRegistry.verifySign(sessionID: verifiedSession.id, signerFingerprint: "SHA256:test") != nil,
        "only the registry-owned grant may authorize the session fingerprint"
    )

    var terminalSelectionPipe = [Int32](repeating: -1, count: 2)
    try expect(pipe(&terminalSelectionPipe) == 0, "selftest should create a non-terminal descriptor")
    defer { _ = close(terminalSelectionPipe[0]); _ = close(terminalSelectionPipe[1]) }
    try expect(
        !RunCommand.isInteractiveTerminal(stdin: terminalSelectionPipe[0], stdout: terminalSelectionPipe[1]),
        "PTY selection must require both parent descriptors to be terminals"
    )

    let version = app.run(argv: ["macop", "--version"], env: [:])
    try expect(version.exitCode == 0, "version should exit 0")
    try expect(version.stdout.contains("macop 0.1.0"), "version output should contain current version")

    let compatibility = app.run(argv: ["macop", "compatibility", "--format", "json"], env: [:])
    try expect(compatibility.exitCode == 0, "compatibility json should exit 0")
    guard let compatibilityObject = try JSONSerialization
        .jsonObject(with: Data(compatibility.stdout.utf8)) as? [String: Any],
        let entries = compatibilityObject["entries"] as? [[String: Any]]
    else {
        throw SelftestFailure(message: "compatibility JSON should match the published schema")
    }
    try expect(compatibilityObject["schema_version"] as? Int == 3, "compatibility schema version should be stable")
    try expect(
        entries.first { $0["command"] as? String == "run" }?["status"] as? String == "supported",
        "run must be marked supported once implemented"
    )
    try expect(
        entries.allSatisfy { $0["kind"] is String && $0["id"] is String },
        "compatibility entries should declare kind and ID"
    )
    let expectedCompatibilityIDs: Set = [
        "read", "read --no-newline", "read --otp", "read --ssh-format", "read --out-file", "read --file-mode",
        "read --force",
        "run", "run --env-file",
        "run --stdin",
        "run --no-masking", "run --environment", "inject", "inject -i", "inject --in-file", "inject --out-file",
        "inject --file-mode",
        "inject --force", "item list", "item list --long", "item list --format", "item list --vault",
        "item list --categories", "item list --tags", "item list --favorite", "item list --include-archive",
        "item list --otp", "item list --share-link", "item get", "item get --fields",
        "item get --reveal",
        "item get --format", "item get --id", "item get --stdin", "item get --vault", "item get --categories",
        "item get --tags",
        "item get --favorite",
        "item get --include-archive", "item get --otp", "item get --share-link", "item create", "item edit",
        "item delete",
        "item move", "item share", "item template", "completion", "completion bash", "completion zsh",
        "completion fish",
        "completion powershell", "help", "version", "whoami",
        "signin", "signout",
        "update", "vault", "vault list", "account", "user", "group", "service-account", "connect", "events-api",
        "document",
        "environment",
        "plugin", "compatibility", "config init", "config validate", "doctor", "ssh", "ssh create",
        "ssh create --touch-id",
        "ssh list", "ssh public-key", "ssh test", "ssh run", "ssh delete", "ssh agent", "ssh agent shell",
        "ssh agent application",
        "reference ?attribute=otp", "reference ?ssh-format=openssh", "--help", "--version",
        "--format",
        "--config", "--no-color", "--debug", "--encoding=utf-8", "--account", "--session", "--cache",
        "--iso-timestamps",
        "--encoding=<non-UTF-8>"
    ]
    let actualCompatibilityIDs = Set(entries.compactMap { $0["id"] as? String })
    try expect(
        actualCompatibilityIDs == expectedCompatibilityIDs,
        "compatibility matrix should enumerate every documented operation and flag"
    )
    let compatibilityHuman = app.run(argv: ["macop", "compatibility"], env: [:])
    try expect(
        compatibilityHuman.stdout.contains("read, run, inject"),
        "human compatibility must list implemented commands as supported"
    )
    try expect(
        compatibilityHuman.stdout.contains("Supported or partial op commands:"),
        "human matrix should label commands"
    )
    try expect(
        compatibilityHuman.stdout
            .contains("Macop extensions: compatibility, config init, config validate, doctor, ssh"),
        "human matrix should label extensions"
    )
    try expect(compatibilityHuman.stdout.contains("Flags:"), "human matrix should label flags separately")
    try expect(
        compatibilityHuman.stdout.contains("Reference query modes:"),
        "human matrix should group documented reference query modes separately"
    )

    let sshExecutor = RecordingSSHExecutor()
    let sshApp = MacopApp(keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: sshExecutor)
    let createdIdentity = sshApp.run(argv: ["macop", "ssh", "create", "github", "--touch-id"], env: [:])
    try expect(createdIdentity.exitCode == 0, "ssh create should use the injectable Apple command executor")
    let createdJSONExecutor = SequencedSSHExecutor(lists: [
        appleTableHeader,
        appleTableHeader + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "new-github")
    ])
    let createdJSONApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: createdJSONExecutor
    )
    let createdJSON = createdJSONApp.run(
        argv: ["macop", "ssh", "create", "new-github", "--touch-id", "--format=json"], env: [:]
    )
    let createdObject = try JSONSerialization.jsonObject(with: Data(createdJSON.stdout.utf8)) as? [String: Any]
    try expect(
        (createdObject?["identities"] as? [[String: Any]])?.first?["public_key_hash"] as? String
            == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ssh create JSON must return the verified public-key hash"
    )
    try expect(
        sshExecutor.invocations.contains {
            $0.arguments == [
                "create-ctk-identity",
                "-l",
                "github",
                "-k",
                "p-256-ne",
                "-t",
                "bio"
            ]
        },
        "ssh create must request a non-exportable P-256 key protected by biometrics"
    )
    let publicKey = sshApp.run(argv: ["macop", "ssh", "public-key", "github", "--format=json"], env: [:])
    try expect(
        publicKey.exitCode == 0 && publicKey.stdout.contains("ecdsa-sha2-nistp256"),
        "ssh public-key should return provider public material only"
    )
    let tableFixture = appleTableHeader
        + appleTableRow("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "GitHub Work", commonName: "Example User")
        + appleTableRow("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "personal key")
        + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github")
    let tableExecutor = SequencedSSHExecutor(lists: [tableFixture])
    let tableApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: tableExecutor
    )
    let listed = tableApp.run(argv: ["macop", "ssh", "list", "--format=json"], env: [:])
    let listedJSON = try JSONSerialization.jsonObject(with: Data(listed.stdout.utf8)) as? [String: Any]
    let listedIdentities = listedJSON?["identities"] as? [[String: Any]]
    try expect(
        listedIdentities?.count == 3
            && listedIdentities?.contains { $0["label"] as? String == "GitHub Work" } == true
            && listedIdentities?.contains { $0["label"] as? String == "personal key" } == true,
        "ssh list must parse Apple table rows and labels with spaces"
    )
    let malformedTable = tableFixture + "p-256-ne  DDDD                                               bio  malformed\n"
    let malformedExecutor = SequencedSSHExecutor(lists: [malformedTable, malformedTable])
    let malformedApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: malformedExecutor
    )
    try expect(
        malformedApp.run(argv: ["macop", "ssh", "list"], env: [:]).exitCode == 4
            && malformedApp.run(argv: ["macop", "ssh", "create", "fresh-key"], env: [:]).exitCode == 4
            && !malformedExecutor.invocations.contains { $0.arguments.first == "create-ctk-identity" },
        "a malformed table row must fail closed and prevent create mutation"
    )
    let legacyExecutor = SequencedSSHExecutor(lists: [
        "CTK Identity\nLabel: github\nPublic Key Hash: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    ])
    let legacyApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: legacyExecutor
    )
    try expect(
        legacyApp.run(argv: ["macop", "ssh", "create", "fresh-key"], env: [:]).exitCode == 4
            && !legacyExecutor.invocations.contains { $0.arguments.first == "create-ctk-identity" },
        "undocumented legacy CTK blocks must fail closed before create mutation"
    )
    let spacedLabelExecutor = SequencedSSHExecutor(lists: Array(repeating: appleTableHeader
            + appleTableRow("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "開発 SSH 鍵"), count: 4))
    let spacedLabelApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: spacedLabelExecutor
    )
    try expect(
        spacedLabelApp.run(argv: ["macop", "ssh", "public-key", "開発 SSH 鍵"], env: [:]).exitCode == 0
            && spacedLabelApp.run(argv: ["macop", "ssh", "run", "開発 SSH 鍵", "--", "git", "status"], env: [:])
            .exitCode == 0
            && spacedLabelApp.run(argv: ["macop", "ssh", "delete", "開発 SSH 鍵"], env: [:]).exitCode == 0,
        "safe Unicode labels must select public-key, run, and delete exactly"
    )
    let existingExecutor = SequencedSSHExecutor(lists: [tableFixture])
    let existingApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: existingExecutor
    )
    let duplicateCreate = existingApp.run(argv: ["macop", "ssh", "create", "github"], env: [:])
    try expect(
        duplicateCreate.exitCode == 2 && !existingExecutor.invocations
            .contains { $0.arguments.first == "create-ctk-identity" },
        "ssh create must preflight an exact existing label without mutating CTK"
    )
    let emptyTable = appleTableHeader
    let missingPostExecutor = SequencedSSHExecutor(lists: [emptyTable, emptyTable])
    let missingPostApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: missingPostExecutor
    )
    let missingPostCreate = missingPostApp.run(argv: ["macop", "ssh", "create", "new-key"], env: [:])
    try expect(
        missingPostCreate.exitCode == 4,
        "ssh create must fail when post-create identity verification is missing"
    )
    let duplicatePost = appleTableHeader
        + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "new-key")
        + appleTableRow("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "new-key")
    let duplicatePostExecutor = SequencedSSHExecutor(lists: [emptyTable, duplicatePost])
    let duplicatePostApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: duplicatePostExecutor
    )
    let duplicatePostCreate = duplicatePostApp.run(argv: ["macop", "ssh", "create", "new-key"], env: [:])
    try expect(
        duplicatePostCreate.exitCode == 4,
        "ssh create must fail when post-create identity verification is ambiguous"
    )
    let publicKeyJSON = try JSONSerialization.jsonObject(with: Data(publicKey.stdout.utf8)) as? [String: Any]
    try expect(
        publicKeyJSON?["schema_version"] as? Int == 1 && publicKeyJSON?["label"] as? String == "github"
            && publicKeyJSON?["public_key"] is String && publicKeyJSON?["provider"] as? String == "ssh-keychain",
        "ssh public-key JSON must conform to its typed schema"
    )
    let deletedIdentity = sshApp.run(argv: ["macop", "ssh", "delete", "github"], env: [:])
    try expect(deletedIdentity.exitCode == 0, "ssh delete should resolve a single public hash before deletion")
    try expect(
        sshExecutor.invocations.last?.arguments == [
            "delete-ctk-identity", "-h", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ],
        "ssh delete must never perform a broad CTK deletion"
    )
    let gitRun = sshApp.run(
        argv: ["macop", "ssh", "run", "github", "--", "git", "clone", "git@github.com:owner/repo.git"],
        env: [:]
    )
    try expect(gitRun.exitCode == 0, "ssh run should invoke git without a shell")
    let notGitRun = sshApp.run(argv: ["macop", "ssh", "run", "github", "--", "notgit", "status"], env: [:])
    try expect(notGitRun.exitCode == 3, "ssh run must reject executables whose basename is not exactly git")
    let absoluteGitRun = sshApp.run(
        argv: ["macop", "ssh", "run", "github", "--", "/usr/bin/git", "status"], env: [:]
    )
    try expect(absoluteGitRun.exitCode == 0, "ssh run should accept an absolute executable whose basename is git")
    try expect(
        sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?
            .contains("PKCS11Provider=/usr/lib/ssh-keychain.dylib") == true
            && sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?.contains("ForwardAgent=no") == true,
        "ssh run must force the Apple provider and disable forwarding"
    )
    try expect(
        sshExecutor.invocations.last?
            .environment["KEYCHAIN_CERTIFICATES"] == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ssh run must restrict the Apple provider to the selected public-key hash"
    )
    let streamedSSH = StreamCollector()
    let streamingSSH = sshApp.runStreamingIfNeeded(
        argv: ["macop", "ssh", "run", "github", "--", "git", "status"], env: [:],
        stdout: { streamedSSH.append($0) }, stderr: { _ in }
    )
    try expect(
        streamingSSH?.exitCode == 23
            && String(bytes: streamedSSH.read(), encoding: .utf8) == "streamed-child-output\n",
        "ssh run should use the streaming executor and preserve the child exit status"
    )
    let greeting = "Hi user! You've successfully authenticated, but GitHub does not provide shell access.\n"
    let greetingApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: GitHubTestExecutor(output: greeting, code: 1)
    )
    let greetingResult = greetingApp.run(argv: ["macop", "ssh", "test", "github", "--format=json"], env: [:])
    let greetingJSON = try JSONSerialization.jsonObject(with: Data(greetingResult.stdout.utf8)) as? [String: Any]
    try expect(
        greetingResult.exitCode == 0 && greetingJSON?["raw_exit_code"] as? Int == 1
            && greetingJSON?["status"] as? String == "authenticated",
        "GitHub's documented authenticated greeting at raw exit 1 must normalize to success"
    )
    let greetingStream = StreamCollector()
    let streamedGreeting = greetingApp.runStreamingIfNeeded(
        argv: ["macop", "ssh", "test", "github"], env: [:],
        stdout: { greetingStream.append($0) }, stderr: { greetingStream.append($0) }
    )
    try expect(
        streamedGreeting?.exitCode == 0 && String(bytes: greetingStream.read(), encoding: .utf8) == greeting,
        "streaming GitHub test must normalize success while preserving visible output"
    )
    let unrelatedExit = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: GitHubTestExecutor(output: "permission denied\n", code: 1)
    ).run(argv: ["macop", "ssh", "test", "github"], env: [:])
    try expect(unrelatedExit.exitCode == 1, "arbitrary GitHub exit 1 must remain a failure")
    let transportFailure = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: GitHubTestExecutor(output: greeting, code: 255)
    ).run(argv: ["macop", "ssh", "test", "github"], env: [:])
    try expect(transportFailure.exitCode == 255, "GitHub transport exit 255 must remain a failure")
    let unsafeLabel = sshApp.run(argv: ["macop", "ssh", "create", "bad\nlabel"], env: [:])
    try expect(unsafeLabel.exitCode == 2, "ssh labels must reject argument-injection characters")
    let unicodeNewlineLabel = sshApp.run(argv: ["macop", "ssh", "create", "bad\u{2028}label"], env: [:])
    try expect(unicodeNewlineLabel.exitCode == 2, "ssh labels must reject Unicode line separators")
    let doctor = sshApp.run(argv: ["macop", "doctor", "--format=json"], env: [:])
    let doctorJSON = try JSONSerialization.jsonObject(with: Data(doctor.stdout.utf8)) as? [String: Any]
    try expect(doctorJSON?["schema_version"] as? Int == 1 && doctorJSON?["status"] is String
        && doctorJSON?["checks"] is [[String: Any]] && !doctor.stdout.contains("test-secret"),
        "doctor JSON must be typed and secret-free")
    let resolvedSelftestExecutable = try RunningExecutable.path()
    let doctorLink = tempRoot.appendingPathComponent("doctor-via-symlink")
    try fileManager.createSymbolicLink(atPath: doctorLink.path, withDestinationPath: resolvedSelftestExecutable)
    let doctorProbe = Process()
    let doctorProbeOutput = Pipe()
    doctorProbe.executableURL = doctorLink
    doctorProbe.arguments = ["--doctor-probe"]
    doctorProbe.standardOutput = doctorProbeOutput
    doctorProbe.standardError = Pipe()
    try doctorProbe.run()
    doctorProbe.waitUntilExit()
    let doctorProbeData = try doctorProbeOutput.fileHandleForReading.readToEnd() ?? Data()
    guard let doctorProbeJSON = try JSONSerialization.jsonObject(with: doctorProbeData) as? [String: Any],
          let doctorChecks = doctorProbeJSON["checks"] as? [[String: Any]],
          let executableCheck = doctorChecks.first(where: { $0["name"] as? String == "current_executable" })
    else { throw SelftestFailure(message: "doctor symlink probe must emit typed JSON") }
    try expect(
        executableCheck["detail"] as? String == resolvedSelftestExecutable,
        "doctor must resolve the running image rather than argv[0] or its symlink"
    )
    let brokenCTKExecutor = SequencedSSHExecutor(lists: ["Error: Failed to get TKTokenDriver configuration\n"])
    let brokenDoctor = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: brokenCTKExecutor
    ).run(argv: ["macop", "doctor", "--format=json"], env: [:])
    let brokenDoctorJSON = try JSONSerialization.jsonObject(with: Data(brokenDoctor.stdout.utf8)) as? [String: Any]
    let brokenChecks = brokenDoctorJSON?["checks"] as? [[String: Any]]
    try expect(
        brokenDoctor.exitCode == 4
            && brokenChecks?.first(where: { $0["name"] as? String == "cryptotokenkit" })?["status"] as? String == "fail"
            && brokenCTKExecutor.invocations.contains { $0.path == "/usr/bin/codesign" },
        "doctor must reject exit-zero CTK error text and continue later checks"
    )

    let compatibilityEquals = app.run(argv: ["macop", "compatibility", "--format=json"], env: [:])
    try expect(compatibilityEquals.exitCode == 0, "equals global format should be accepted after command")
    try expect(compatibilityEquals.stdout.contains("\"schema_version\""), "equals format should render JSON")

    let successfulDebug = app.run(argv: ["macop", "compatibility", "--format=json", "--debug"], env: [:])
    _ = try JSONSerialization.jsonObject(with: Data(successfulDebug.stdout.utf8))
    try expect(
        successfulDebug.stderr.contains("debug exit_code=0"),
        "successful commands should render safe debug output"
    )
    try expect(
        successfulDebug.stderr.contains("command=compatibility"),
        "success debug should include a sanitized command category"
    )
    let streamingDebugFailure = app.runStreamingIfNeeded(
        argv: ["macop", "run", "--format=json", "--debug"],
        env: [:],
        stdout: { _ in },
        stderr: { _ in }
    )
    guard let streamingDebugFailure,
          let streamingErrorObject = try JSONSerialization
          .jsonObject(with: Data(streamingDebugFailure.stderr.utf8)) as? [String: Any],
          let streamingError = streamingErrorObject["error"] as? [String: Any]
    else {
        throw SelftestFailure(message: "streaming run errors should remain one JSON object")
    }
    try expect(streamingError["debug"] != nil, "streaming run errors should retain safe debug metadata")

    let configInit = app.run(argv: ["macop", "--config", configDirectory, "config", "init"], env: [:])
    try expect(configInit.exitCode == 0, "config init should exit 0")

    let configValidate = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(configValidate.exitCode == 0, "config validate should exit 0")

    let configValidateEquals = app.run(argv: ["macop", "config", "validate", "--config=\(configDirectory)"], env: [:])
    try expect(configValidateEquals.exitCode == 0, "equals config should be accepted after command")

    let configInitWithExtraArg = app.run(
        argv: ["macop", "--config", configDirectory, "config", "init", "extra"],
        env: [:]
    )
    try expect(configInitWithExtraArg.exitCode == 2, "config init should reject extra args")

    let configPath = tempRoot.appendingPathComponent("config.json")
    let config = """
    {
      "items" : {
        "Local/GitHub" : {
          "account" : "me@example.com",
          "fields" : [
            "token"
          ],
          "provider" : "keychain-generic",
          "service" : "github-token"
        }
      },
      "version" : 1
    }
    """
    guard let configData = config.data(using: .utf8) else {
        throw SelftestFailure(message: "failed to encode config fixture")
    }
    try configData.write(to: configPath, options: [.atomic])

    let providerPending = app.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(providerPending.exitCode == 0, "read should fetch through the injected Keychain client")
    try expect(providerPending.stdout == "test-secret\n", "read should append a newline by default")

    let injected = app.run(
        argv: ["macop", "--config", configDirectory, "inject"],
        env: [:],
        input: Data("token=op://Local/GitHub/token\n".utf8)
    )
    try expect(injected.exitCode == 0, "inject stdin should succeed")
    try expect(injected.stdout == "token=test-secret\n", "inject should resolve references in memory")
    let adjacentReferences = app.run(
        argv: ["macop", "--config", configDirectory, "inject"],
        env: [:],
        input: Data("a=op://Local/GitHub/tokenkeychain://generic/service/account.\n".utf8)
    )
    try expect(
        adjacentReferences.stdout == "a=test-secrettest-secret.\n",
        "inject should resolve adjacent references without consuming trailing punctuation"
    )
    let unsupportedInjectedProvider = app.run(
        argv: ["macop", "inject"],
        env: [:],
        input: Data("apple-passwords://example.com/account".utf8)
    )
    try expect(unsupportedInjectedProvider.exitCode == 3, "inject should reject unsupported reference schemes")
    let templatePath = tempRoot.appendingPathComponent("config.tpl")
    try Data("a=op://Local/GitHub/token;b=op://Local/GitHub/token".utf8).write(to: templatePath)
    let injectedFile = app.run(
        argv: ["macop", "--config", configDirectory, "inject", "--in-file", templatePath.path], env: [:]
    )
    try expect(injectedFile.stdout == "a=test-secret;b=test-secret", "inject file should resolve multiple references")
    let forbiddenInjectOutput = app.run(
        argv: ["macop", "inject", "--out-file=result"], env: [:]
    )
    try expect(forbiddenInjectOutput.exitCode == 3, "inject persistent output must be rejected")

    let runMasked = app.run(
        argv: ["macop", "run", "--", "/usr/bin/printenv", "GH_TOKEN"],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(runMasked.exitCode == 0, "run should launch a command directly")
    try expect(runMasked.stdout == "<concealed by macop>\n", "run should mask environment secrets by default")
    let runUnmasked = app.run(
        argv: ["macop", "run", "--no-masking", "--", "/usr/bin/printenv", "GH_TOKEN"],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(runUnmasked.stdout == "test-secret\n", "run --no-masking should be the explicit bypass")
    let opaqueClient = QuerySensitiveKeychainClient()
    let opaqueApp = MacopApp(keychainClient: opaqueClient)
    let opaqueRun = opaqueApp.run(
        argv: ["macop", "run", "--no-masking", "--", "/usr/bin/printenv", "OPAQUE_SECRET"],
        env: ["OPAQUE_SECRET": "keychain://generic/service/account"]
    )
    try expect(
        opaqueRun.stdout == "keychain://generic/other/account\n" && opaqueClient.queries.count == 1,
        "provider-returned URI-looking secret must remain opaque after exactly one resolution"
    )
    let compositeRun = app.run(
        argv: [
            "macop", "run", "--", "/bin/sh", "-c",
            "printf '%s' test-secret; printf '%s' test-secret >&2"
        ],
        env: ["AUTH": "Bearer keychain://generic/service/account"]
    )
    try expect(
        compositeRun.stdout == "<concealed by macop>" && compositeRun.stderr == "<concealed by macop>",
        "composite environment references must register each source secret for both streams"
    )
    let dotenvPath = tempRoot.appendingPathComponent(".env")
    try Data("FIRST=one\nGH_TOKEN=op://Local/GitHub/token\n".utf8).write(to: dotenvPath)
    let dotenvRun = app.run(
        argv: [
            "macop",
            "--config",
            configDirectory,
            "run",
            "--env-file",
            dotenvPath.path,
            "--",
            "/usr/bin/printenv",
            "GH_TOKEN"
        ],
        env: [:]
    )
    try expect(dotenvRun.stdout == "<concealed by macop>\n", "dotenv references should be resolved and masked")
    let compositeDotenvPath = tempRoot.appendingPathComponent("composite.env")
    try Data("AUTH=Bearer keychain://generic/service/account:keychain://generic/service/account\n".utf8)
        .write(to: compositeDotenvPath)
    let compositeDotenvRun = app.run(
        argv: [
            "macop", "run", "--env-file", compositeDotenvPath.path, "--", "/bin/sh", "-c",
            "printf '%s' test-secret; printf '%s' test-secret >&2"
        ], env: [:]
    )
    try expect(
        compositeDotenvRun.stdout == "<concealed by macop>"
            && compositeDotenvRun.stderr == "<concealed by macop>",
        "composite dotenv templates with duplicate references must register original secrets"
    )
    let escapedDotenvPath = tempRoot.appendingPathComponent("escaped.env")
    try Data(#"ESCAPED="line\nquote:\" slash:\\ tab:\t dollar:\$""#.utf8).write(to: escapedDotenvPath)
    let escapedDotenv = app.run(
        argv: ["macop", "run", "--env-file", escapedDotenvPath.path, "--", "/usr/bin/printenv", "ESCAPED"], env: [:]
    )
    try expect(
        escapedDotenv.stdout == "line\nquote:\" slash:\\ tab:\t dollar:$\n",
        "dotenv double quotes should decode conventional escapes"
    )
    for expansion in ["PLAIN=$NAME\n", "BRACED=${NAME}\n", "QUOTED=\"$NAME\"\n"] {
        let expansionPath = tempRoot.appendingPathComponent("expansion.env")
        try Data(expansion.utf8).write(to: expansionPath)
        let expansionRun = app.run(
            argv: ["macop", "run", "--env-file", expansionPath.path, "--", "/usr/bin/true"], env: [:]
        )
        try expect(expansionRun.exitCode == 3, "unescaped dotenv variable expansion must be explicitly unsupported")
    }
    let singleQuotedPath = tempRoot.appendingPathComponent("single.env")
    try Data("LITERAL='$NAME'\n".utf8).write(to: singleQuotedPath)
    let singleQuotedRun = app.run(
        argv: ["macop", "run", "--env-file", singleQuotedPath.path, "--", "/usr/bin/printenv", "LITERAL"], env: [:]
    )
    try expect(singleQuotedRun.stdout == "$NAME\n", "single-quoted dotenv dollars should remain literal")
    let oddSlashPath = tempRoot.appendingPathComponent("odd-slash.env")
    try Data(#"LITERAL="\$NAME""#.utf8).write(to: oddSlashPath)
    let oddSlashRun = app.run(
        argv: ["macop", "run", "--env-file", oddSlashPath.path, "--", "/usr/bin/printenv", "LITERAL"], env: [:]
    )
    try expect(oddSlashRun.stdout == "$NAME\n", "odd backslash parity should escape dotenv expansion")
    let evenSlashPath = tempRoot.appendingPathComponent("even-slash.env")
    try Data(#"EXPANSION="\\$NAME""#.utf8).write(to: evenSlashPath)
    let evenSlashRun = app.run(
        argv: ["macop", "run", "--env-file", evenSlashPath.path, "--", "/usr/bin/true"], env: [:]
    )
    try expect(evenSlashRun.exitCode == 3, "even backslash parity must not escape dotenv expansion")
    let firstEnvPath = tempRoot.appendingPathComponent("first.env")
    let laterEnvPath = tempRoot.appendingPathComponent("later.env")
    try Data("GH_TOKEN=keychain://generic/service/$ACCOUNT\nACCOUNT=wrong\n".utf8).write(to: firstEnvPath)
    try Data("ACCOUNT=account\n".utf8).write(to: laterEnvPath)
    let precedenceRun = app.run(
        argv: [
            "macop", "run", "--env-file", firstEnvPath.path, "--env-file", laterEnvPath.path,
            "--", "/usr/bin/printenv", "GH_TOKEN"
        ],
        env: [:]
    )
    try expect(
        precedenceRun.stdout == "<concealed by macop>\n",
        "dotenv references should expand against the final last-file-wins environment"
    )
    let stdinRun = app.run(
        argv: ["macop", "--config", configDirectory, "run", "--stdin", "op://Local/GitHub/token", "--", "/bin/cat"],
        env: [:]
    )
    try expect(stdinRun.stdout == "<concealed by macop>", "run --stdin should inject without argv exposure")
    let redactor = SecretRedactor(secrets: ["test-secret", "secret"])
    let firstChunk = redactor.process(Data("before test-".utf8))
    let secondChunk = redactor.process(Data("secret after".utf8), final: true)
    try expect(
        String(bytes: firstChunk + secondChunk, encoding: .utf8) == "before <concealed by macop> after",
        "redactor must mask an overlapping secret across chunk boundaries"
    )
    let collisionRedactor = SecretRedactor(secrets: ["<concealed by macop>", "aba", "ba"])
    let collisionOutput = collisionRedactor.process(Data("aba<concealed ".utf8))
        + collisionRedactor.process(Data("by macop>aba".utf8), final: true)
    try expect(
        String(bytes: collisionOutput, encoding: .utf8) ==
            "<concealed by macop><concealed by macop><concealed by macop>",
        "redactor must use longest source matches and never rescan replacements"
    )
    let stderrMasked = app.run(
        argv: ["macop", "run", "--", "/bin/sh", "-c", "printf '%s' \"$GH_TOKEN\" >&2"],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(stderrMasked.stderr == "<concealed by macop>", "run should mask stderr independently")
    let stderrUnmasked = app.run(
        argv: ["macop", "run", "--no-masking", "--", "/bin/sh", "-c", "printf '%s' \"$GH_TOKEN\" >&2"],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(stderrUnmasked.stderr == "test-secret", "--no-masking should also bypass stderr masking")

    let largeOutput = app.run(
        argv: [
            "macop", "run", "--", "/bin/sh", "-c",
            "i=0; while [ \"$i\" -lt 20000 ]; do printf 'out:%s\\n' \"$GH_TOKEN\"; printf 'err:%s\\n' \"$GH_TOKEN\" >&2; i=$((i + 1)); done"
        ],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(largeOutput.exitCode == 0, "large stdout and stderr command should complete")
    try expect(!largeOutput.stdout.contains("test-secret") && !largeOutput.stderr.contains("test-secret"),
               "large output must mask every secret across real pipe reads")
    try expect(largeOutput.stdout.components(separatedBy: "<concealed by macop>").count == 20001,
               "large stdout should retain every redacted record")
    try expect(largeOutput.stderr.components(separatedBy: "<concealed by macop>").count == 20001,
               "large stderr should retain every redacted record")

    let earlyClose = app.run(
        argv: ["macop", "run", "--stdin", "keychain://generic/service/account", "--", "/bin/sh", "-c", "exit 0"],
        env: [:]
    )
    try expect(earlyClose.exitCode == 0, "run --stdin should tolerate a child that closes stdin early")
    let largeSecret = String(repeating: "large-stdin-secret-", count: 32768)
    let largeInputApp = MacopApp(keychainClient: FakeKeychainClient(response: .success(Data(largeSecret.utf8))))
    let largeInput = largeInputApp.run(
        argv: ["macop", "run", "--stdin", "keychain://generic/service/account", "--", "/bin/cat"], env: [:]
    )
    try expect(largeInput.exitCode == 0 && largeInput.stdout == "<concealed by macop>",
               "run --stdin should deliver and mask large input without deadlocking")
    let noNewlineRead = app.run(
        argv: ["macop", "--config", configDirectory, "read", "--no-newline", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(noNewlineRead.stdout == "test-secret", "read --no-newline should not append a newline")
    let itemList = app.run(argv: ["macop", "--config", configDirectory, "item", "list", "--format=json"], env: [:])
    let itemListObject = try JSONSerialization.jsonObject(with: Data(itemList.stdout.utf8)) as? [String: Any]
    try expect(itemListObject?["schema_version"] as? Int == 1, "item list JSON should use the macop schema")
    let listEntries = itemListObject?["items"] as? [[String: Any]]
    try expect(listEntries?.first?["name"] as? String == "Local/GitHub", "item list JSON should expose configured name")
    try expect(
        listEntries?.first?["provider"] as? String == "keychain-generic",
        "item list JSON should expose provider"
    )
    let longList = app.run(
        argv: ["macop", "--config", configDirectory, "item", "list", "--long", "--format=json"],
        env: [:]
    )
    let longEntries = try (JSONSerialization
        .jsonObject(with: Data(longList.stdout.utf8)) as? [String: Any])?["items"] as? [[String: Any]]
    try expect(
        longEntries?.first?["account"] as? String == "me@example.com",
        "item list --long should expose non-secret account metadata"
    )
    try expect(
        longEntries?.first?["locator"] as? String == "github-token",
        "item list --long should expose non-secret locator metadata"
    )
    let maskedItem = app.run(
        argv: ["macop", "--config", configDirectory, "item", "get", "GitHub", "--fields", "label=token",
               "--format=json"],
        env: [:]
    )
    try expect(maskedItem.stdout.contains("<concealed by macop>"), "item get should mask without reveal")
    try expect(!maskedItem.stdout.contains("test-secret"), "masked item output must not leak secrets")
    let maskedObject = try JSONSerialization.jsonObject(with: Data(maskedItem.stdout.utf8)) as? [String: Any]
    let maskedFields = (maskedObject?["items"] as? [String: Any])?["fields"] as? [[String: Any]]
    try expect(maskedFields?.first?["label"] as? String == "token", "item get JSON should preserve field label")
    try expect(
        maskedFields?.first?["value"] as? String == "<concealed by macop>",
        "item get JSON should mask by default"
    )
    let revealedItem = app.run(
        argv: ["macop", "--config", configDirectory, "item", "get", "GitHub", "--fields=label=token", "--reveal",
               "--format=json"],
        env: [:]
    )
    try expect(revealedItem.stdout.contains("test-secret"), "item get reveal should fetch the selected field")
    let revealedObject = try JSONSerialization.jsonObject(with: Data(revealedItem.stdout.utf8)) as? [String: Any]
    let revealedFields = (revealedObject?["items"] as? [String: Any])?["fields"] as? [[String: Any]]
    try expect(
        revealedFields?.first?["value"] as? String == "test-secret",
        "item get JSON should reveal only with --reveal"
    )

    let recordingClient = RecordingKeychainClient(.success(Data("test-secret".utf8)))
    let recordingApp = MacopApp(keychainClient: recordingClient)
    _ = recordingApp.run(argv: ["macop", "read", "keychain://generic/service/account"], env: [:])
    try expect(
        recordingClient.queries == [.generic(service: "service", account: "account")],
        "generic URI query should preserve service/account"
    )
    _ = recordingApp.run(argv: ["macop", "read", "keychain://internet/server.example/account"], env: [:])
    try expect(
        recordingClient.queries.last == .internet(server: "server.example", account: "account"),
        "internet URI query should preserve server/account"
    )
    for (status, expected) in [
        (errSecItemNotFound, Int32(6)),
        (errSecAuthFailed, Int32(5)),
        (errSecUserCanceled, Int32(5)),
        (errSecNotAvailable, Int32(4)),
        (-9999, Int32(1))
    ] {
        let statusApp = MacopApp(keychainClient: FakeKeychainClient(response: .failure(KeychainFailure(status))))
        let result = statusApp.run(argv: ["macop", "read", "keychain://generic/service/account"], env: [:])
        try expect(result.exitCode == expected, "OSStatus should map to the documented exit code")
    }
    for invalid in [Data([0xFF]), Data("secret\0value".utf8)] {
        let invalidApp = MacopApp(keychainClient: FakeKeychainClient(response: .success(invalid)))
        let result = invalidApp.run(argv: ["macop", "read", "keychain://generic/service/account"], env: [:])
        try expect(result.exitCode == 1, "invalid UTF-8 or NUL Keychain data should fail at runtime")
        try expect(!result.stderr.contains("secret\0value"), "invalid secret values must not leak")
    }
    let equalsOutputFlag = app.run(
        argv: ["macop", "read", "--out-file=token", "keychain://generic/service/account"],
        env: [:]
    )
    try expect(equalsOutputFlag.exitCode == 3, "persistent output equals flags should be unsupported")

    let invalidProviderConfig = """
    {
      "items" : {
        "Local/GitHub" : {
          "provider" : "bogus"
        }
      },
      "version" : 1
    }
    """
    guard let invalidProviderConfigData = invalidProviderConfig.data(using: .utf8) else {
        throw SelftestFailure(message: "failed to encode invalid provider fixture")
    }
    try invalidProviderConfigData.write(to: configPath, options: [.atomic])

    let unsupportedConfiguredProvider = app.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(unsupportedConfiguredProvider.exitCode == 3, "unknown configured provider should be unsupported")
    try expect(
        unsupportedConfiguredProvider.stderr.contains("unsupported provider"),
        "unknown configured provider should render unsupported provider"
    )

    try configData.write(to: configPath, options: [.atomic])
    try fileManager.setAttributes([.posixPermissions: 0o000], ofItemAtPath: configPath.path)
    let unreadableConfig = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configPath.path)
    try expect(unreadableConfig.exitCode == 2, "non-owner-only config mode should be rejected")
    try expect(
        unreadableConfig.stderr.contains("permissions must be owner-only"),
        "unsafe config mode should be explained"
    )

    let unsupportedProvider = app.run(argv: ["macop", "read", "apple-passwords://example.com/me/password"], env: [:])
    try expect(unsupportedProvider.exitCode == 3, "apple-passwords should be unsupported")

    let unsupportedPath = app.run(
        argv: ["macop", "vault", "list", "potential-secret", "--format=json"],
        env: [:]
    )
    try expect(unsupportedPath.exitCode == 3, "unsupported command should exit 3")
    try expect(
        unsupportedPath.stderr.contains("\"command\" : \"vault list\""),
        "recognized unsupported path should be typed"
    )
    try expect(
        !unsupportedPath.stderr.contains("potential-secret"),
        "unsupported errors must not echo arbitrary arguments"
    )
    try expect(unsupportedPath.stderr.contains("documentation"), "unsupported JSON errors should include guidance")
    let debugJSONError = app.run(argv: ["macop", "vault", "list", "--format=json", "--debug"], env: [:])
    guard let debugObject = try JSONSerialization.jsonObject(with: Data(debugJSONError.stderr.utf8)) as? [String: Any],
          let debugError = debugObject["error"] as? [String: Any]
    else {
        throw SelftestFailure(message: "debug JSON error should remain a single JSON object")
    }
    try expect(debugError["debug"] != nil, "JSON debug errors should retain safe debug metadata")
    try expect(
        (debugError["debug"] as? [String: Any])?["context"] as? String == "command=vault",
        "error debug should include a sanitized command category"
    )
    try expect(!debugJSONError.stderr.contains("op://"), "debug errors must not include secret references")

    let unknownRoot = app.run(argv: ["macop", "frobnicate", "potential-secret", "--format=json"], env: [:])
    try expect(unknownRoot.exitCode == 2, "an arbitrary root command must be syntax, not unsupported")
    try expect(
        !unknownRoot.stderr.contains("potential-secret"),
        "syntax errors must not echo unknown command arguments"
    )
    let unknownItem = app.run(argv: ["macop", "item", "frobnicate", "potential-secret"], env: [:])
    try expect(unknownItem.exitCode == 2, "an arbitrary item subcommand must be syntax, not unsupported")
    let unsupportedItem = app.run(argv: ["macop", "item", "create", "potential-secret"], env: [:])
    try expect(unsupportedItem.exitCode == 3, "a documented unsupported item subcommand must exit 3")
    try expect(
        unsupportedItem.stderr.contains("macop compatibility") && !unsupportedItem.stderr.contains("potential-secret"),
        "human unsupported errors must provide safe support-matrix guidance"
    )
    try expect(
        unsupportedItem.stderr.contains("Supported op-compatible commands:")
            && unsupportedItem.stderr.contains("macop extensions:"),
        "human unsupported errors must derive command and extension guidance from the matrix"
    )
    let unsupportedItemListFlags = [
        "--vault", "--categories=login", "--tags", "--favorite", "--include-archive", "--otp", "--share-link"
    ]
    for flag in unsupportedItemListFlags {
        let result = app.run(argv: ["macop", "item", "list", flag, "potential-value"], env: [:])
        try expect(result.exitCode == 3, "documented unsupported item list flag \(flag) must exit 3")
        try expect(
            result.stderr.contains("macop compatibility"),
            "unsupported item list flags need compatibility guidance"
        )
    }
    try expect(
        app.run(argv: ["macop", "item", "list", "--not-a-flag"], env: [:]).exitCode == 2,
        "unknown item list flags must be syntax errors"
    )
    let powershell = app.run(argv: ["macop", "completion", "powershell", "--format=json"], env: [:])
    try expect(powershell.exitCode == 3, "documented unsupported completion target must exit 3")
    guard let powershellJSON = try JSONSerialization.jsonObject(with: Data(powershell.stderr.utf8)) as? [String: Any],
          let powershellError = powershellJSON["error"] as? [String: Any]
    else { throw SelftestFailure(message: "unsupported completion JSON must be one typed object") }
    try expect(
        powershellError["code"] as? String == "unsupported_command"
            && powershellError["command"] as? String == "completion powershell"
            && powershellError["guidance"] is String,
        "unsupported completion JSON must retain typed support guidance"
    )
    try expect(
        app.run(argv: ["macop", "completion", "elvish"], env: [:]).exitCode == 2,
        "unknown completion targets must be syntax errors"
    )
    let rawDebugError = app.run(
        argv: ["macop", "--debug", "--format=not-a-format"],
        env: ["OP_DEBUG": "0"]
    )
    try expect(
        rawDebugError.stderr.contains("debug exit_code=2"),
        "explicit debug should override false OP_DEBUG during parse errors"
    )
    let childFlagsAreOpaque = app.run(
        argv: ["macop", "run", "nope", "--", "/bin/echo", "--format", "json", "--debug"], env: [:]
    )
    try expect(
        childFlagsAreOpaque.exitCode == 2 && !childFlagsAreOpaque.stderr.contains("\"error\"")
            && !childFlagsAreOpaque.stderr.contains("debug exit_code"),
        "run child flags after -- must not change error format or enable debug"
    )
    let prefixGlobalFlags = app.run(
        argv: ["macop", "run", "--format=json", "--debug", "nope", "--", "/bin/echo"], env: [:]
    )
    guard let prefixGlobalJSON = try JSONSerialization
        .jsonObject(with: Data(prefixGlobalFlags.stderr.utf8)) as? [String: Any],
        let prefixGlobalError = prefixGlobalJSON["error"] as? [String: Any]
    else { throw SelftestFailure(message: "global prefix flags should retain JSON debug errors") }
    try expect(
        prefixGlobalFlags.exitCode == 2 && prefixGlobalError["debug"] != nil,
        "global flags before a child boundary must still affect parse errors"
    )
    let agentChildFlagsAreOpaque = app.run(
        argv: ["macop", "ssh", "agent", "shell", "--", "/bin/echo", "--format=json", "--debug"], env: [:]
    )
    try expect(
        agentChildFlagsAreOpaque.exitCode == 2 && !agentChildFlagsAreOpaque.stderr.contains("\"error\"")
            && !agentChildFlagsAreOpaque.stderr.contains("debug exit_code"),
        "ssh agent shell child flags after -- must remain opaque on usage errors"
    )

    let unsupportedGlobal = app.run(argv: ["macop", "read", "--account=team", "op://Local/GitHub/token"], env: [:])
    try expect(unsupportedGlobal.exitCode == 3, "known unsupported global flags should exit 3")
    let unknownGlobal = app.run(argv: ["macop", "--not-a-flag", "read"], env: [:])
    try expect(unknownGlobal.exitCode == 2, "unknown global syntax should exit 2")
    let utf8Encoding = app.run(argv: ["macop", "compatibility", "--encoding=utf-8"], env: [:])
    try expect(utf8Encoding.exitCode == 0, "UTF-8 encoding should be accepted")
    let nonUTF8Encoding = app.run(argv: ["macop", "compatibility", "--encoding", "utf-16"], env: [:])
    try expect(nonUTF8Encoding.exitCode == 3, "non-UTF-8 encoding should be unsupported")

    let queryReference = app.run(argv: ["macop", "read", "op://Local/GitHub/token?attribute=otp"], env: [:])
    try expect(queryReference.exitCode == 3, "reference query parameters should be unsupported")
    let cyclicReference = app.run(argv: ["macop", "read", "$A"], env: ["A": "$B", "B": "$A"])
    try expect(cyclicReference.exitCode == 2, "cyclic reference environment expansion should fail")
    let undefinedReference = app.run(argv: ["macop", "read", "$MISSING_REFERENCE"], env: [:])
    try expect(undefinedReference.exitCode == 2, "undefined reference environment expansion should fail")

    let secureEnclaveRead = app.run(argv: ["macop", "read", "secure-enclave://github"], env: [:])
    try expect(secureEnclaveRead.exitCode == 3, "secure-enclave reads must be unsupported rather than unavailable")

    let duplicateFieldsConfig = """
    { "version": 1, "items": { "Local/GitHub": { "provider": "keychain-generic", "service": "github", "account": "me", "fields": ["token", "token"] } } }
    """
    try duplicateFieldsConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let duplicateFields = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(duplicateFields.exitCode == 2, "duplicate fields should fail schema validation")

    // Config selectors are decoded, static counterparts of op:// path
    // segments. Exercise both explicit validation and ordinary config loading
    // so malformed mappings cannot reach a provider query through another
    // command path.
    let invalidSelectorFixtures = [
        ConfigSelectorFixture(
            name: "double slash key", itemKey: "Local//GitHub", fields: "[\"token\"]"
        ),
        ConfigSelectorFixture(
            name: "leading slash key", itemKey: "/Local/GitHub", fields: "[\"token\"]"
        ),
        ConfigSelectorFixture(
            name: "trailing slash key", itemKey: "Local/GitHub/", fields: "[\"token\"]"
        ),
        ConfigSelectorFixture(
            name: "empty namespace component", itemKey: "a//b", fields: "[\"token\"]"
        ),
        ConfigSelectorFixture(
            name: "three component field", itemKey: "Local/GitHub", fields: "[\"a/b/c\"]"
        ),
        ConfigSelectorFixture(
            name: "empty field component", itemKey: "Local/GitHub", fields: "[\"credentials//password\"]"
        )
    ]
    for fixture in invalidSelectorFixtures {
        let invalidSelectorConfig = """
        { "version": 1, "items": {
          "\(fixture.itemKey)": {
            "provider": "keychain-generic", "service": "github", "account": "me", "fields": \(fixture.fields)
          }
        } }
        """
        try invalidSelectorConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
        let validateResult = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
        try expect(validateResult.exitCode == 2, "\(fixture.name) must fail config validate")

        let noQueryClient = RecordingKeychainClient(.success(Data("unexpected".utf8)))
        let loadResult = MacopApp(keychainClient: noQueryClient).run(
            argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/token"], env: [:]
        )
        try expect(loadResult.exitCode == 2, "\(fixture.name) must fail normal config loading")
        try expect(noQueryClient.queries.isEmpty, "\(fixture.name) must not issue a Keychain query")
    }
    let invalidSelectorJSON = app.run(
        argv: ["macop", "--config", configDirectory, "config", "validate", "--format=json"], env: [:]
    )
    guard let invalidSelectorObject = try JSONSerialization
        .jsonObject(with: Data(invalidSelectorJSON.stderr.utf8)) as? [String: Any],
        let invalidSelectorError = invalidSelectorObject["error"] as? [String: Any]
    else { throw SelftestFailure(message: "invalid selector JSON error must remain typed") }
    try expect(
        invalidSelectorError["code"] as? String == "invalid_arguments",
        "invalid selector JSON error must classify as invalid arguments"
    )

    let validSectionFieldConfig = """
    { "version": 1, "items": {
      "Local/GitHub": {
        "provider": "keychain-generic", "service": "github", "account": "me", "fields": ["credentials/password"]
      }
    } }
    """
    try validSectionFieldConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let validSectionFieldValidate = app.run(
        argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:]
    )
    try expect(validSectionFieldValidate.exitCode == 0, "section/field config selectors must validate")
    let validSectionFieldClient = RecordingKeychainClient(.success(Data("test-secret".utf8)))
    let validSectionFieldLoad = MacopApp(keychainClient: validSectionFieldClient).run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/credentials/password"],
        env: [:]
    )
    try expect(validSectionFieldLoad.exitCode == 0, "section/field config selectors must load normally")
    try expect(
        validSectionFieldClient.queries.count == 1,
        "valid section/field selector must resolve its Keychain mapping"
    )

    let literalSelectorConfig = """
    { "version": 1, "items": {
      "Local/100%": {
        "provider": "keychain-generic", "service": "github", "account": "me", "fields": ["$HOME"]
      }
    } }
    """
    try literalSelectorConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let literalSelectorValidate = app.run(
        argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:]
    )
    try expect(literalSelectorValidate.exitCode == 0, "decoded literal percent and dollar config names must validate")
    let literalSelectorClient = RecordingKeychainClient(.success(Data("test-secret".utf8)))
    let literalSelectorApp = MacopApp(keychainClient: literalSelectorClient)
    let encodedLiteralReference = literalSelectorApp.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/100%25/%24HOME"], env: [:]
    )
    try expect(encodedLiteralReference.exitCode == 0, "encoded reference selectors must resolve literal config names")
    try expect(
        literalSelectorClient.queries == [.generic(service: "github", account: "me")],
        "encoded selectors must resolve the exact configured Keychain mapping"
    )
    let expandedLiteralReference = literalSelectorApp.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/$ITEM/$FIELD"],
        env: ["ITEM": "100%25", "FIELD": "%24HOME"]
    )
    try expect(
        expandedLiteralReference.exitCode == 0 && literalSelectorClient.queries.count == 2,
        "raw environment forms must expand before percent-decoded reference matching"
    )

    let secretConfig = """
    { "version": 1, "items": { "Local/GitHub": { "provider": "keychain-generic", "service": "github", "account": "me", "secret": "do-not-store" } } }
    """
    try secretConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let secretConfigResult = app.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(secretConfigResult.exitCode == 2, "normal config load must reject secret-looking keys")

    let duplicateKeyConfig = """
    { "version": 1, "version": 1, "items": {} }
    """
    try duplicateKeyConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let duplicateKey = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(duplicateKey.exitCode == 2, "duplicate JSON keys should fail validation")

    let escapedDuplicateKeyConfig = """
    {
      "version": 1,
      "items": {
        "Local/GitHub": { "provider": "keychain-generic", "service": "github", "account": "me" },
        "Local\\u002fGitHub": { "provider": "keychain-generic", "service": "github", "account": "me" }
      }
    }
    """
    try escapedDuplicateKeyConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let escapedDuplicateKey = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(escapedDuplicateKey.exitCode == 2, "escaped semantic duplicate keys should fail validation")

    let malformedConfig = "{ \"version\": 1, \"items\": "
    try malformedConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let malformedValidate = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(malformedValidate.exitCode == 2, "malformed config validate should be invalid arguments")
    let malformedLoad = app.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(malformedLoad.exitCode == 2, "malformed normal config load should be invalid arguments")

    let secureConfig = """
    { "version": 1, "items": {
      "Local/GitHub": { "provider": "keychain-generic", "service": "github-token", "account": "me@example.com", "fields": ["token"] },
      "Local/SSH": { "provider": "secure-enclave", "label": "github" }
    } }
    """
    try secureConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let secureRecording = RecordingKeychainClient(.success(Data("test-secret".utf8)))
    let secureApp = MacopApp(keychainClient: secureRecording)
    let filteredList = secureApp.run(
        argv: ["macop", "--config", configDirectory, "item", "list", "--format=json"],
        env: [:]
    )
    try expect(!filteredList.stdout.contains("Local/SSH"), "item list must exclude secure-enclave config entries")
    let queriesBefore = secureRecording.queries.count
    let secureGet = secureApp.run(
        argv: ["macop", "--config", configDirectory, "item", "get", "SSH", "--reveal"],
        env: [:]
    )
    try expect(secureGet.exitCode != 0, "secure-enclave item get reveal must fail closed")
    try expect(secureRecording.queries.count == queriesBefore, "secure-enclave item get must not query Keychain")

    let zshCompletion = app.run(argv: ["macop", "completion", "zsh"], env: [:])
    try expect(zshCompletion.stdout.contains("commands=(read run inject"), "zsh completion should offer commands")
    try expect(zshCompletion.stdout.contains("compdef _macop macop op"), "zsh completion should register both names")
    let bashCompletion = app.run(argv: ["macop", "completion", "bash"], env: [:])
    try expect(bashCompletion.stdout.contains("init validate"), "bash completion should offer config subcommands")
    let fishCompletion = app.run(argv: ["macop", "completion", "fish"], env: [:])
    try expect(fishCompletion.stdout.contains("-l format"), "fish completion should offer format values")
}

if runHarnessIfRequested() == nil {
    do {
        try run()
        print("selftest passed")
        exit(0)
    } catch let error as SelftestFailure {
        FileHandle.standardError.write(Data("selftest failed: \(error.message)\n".utf8))
        exit(1)
    } catch {
        FileHandle.standardError.write(Data("selftest failed: unexpected error\n".utf8))
        exit(1)
    }
}
