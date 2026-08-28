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

private func decodeFishSingleQuotedArgument(_ encoded: String) throws -> String {
    let scalars = Array(encoded.unicodeScalars)
    guard scalars.count >= 2, scalars.first?.value == 0x27, scalars.last?.value == 0x27 else {
        throw SelftestFailure(message: "fish fixture expected one single-quoted argument")
    }
    var decoded = ""
    var index = 1
    while index < scalars.count - 1 {
        let scalar = scalars[index]
        if scalar.value == 0x5C {
            index += 1
            guard index < scalars.count - 1,
                  scalars[index].value == 0x5C || scalars[index].value == 0x27
            else { throw SelftestFailure(message: "fish fixture found an invalid single-quote escape") }
            decoded.unicodeScalars.append(scalars[index])
        } else {
            decoded.unicodeScalars.append(scalar)
        }
        index += 1
    }
    return decoded
}

private func safeExecutableOnPATH(
    named name: String,
    environment: [String: String]
) -> String? {
    guard !name.isEmpty, !name.contains("/"), let path = environment["PATH"] else { return nil }
    for component in path.split(separator: ":", omittingEmptySubsequences: false) {
        guard component.first == "/" else { continue }
        let directory = URL(fileURLWithPath: String(component), isDirectory: true).standardizedFileURL
        let candidate = directory.appendingPathComponent(name, isDirectory: false).standardizedFileURL
        guard candidate.deletingLastPathComponent() == directory else { continue }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory),
              !isDirectory.boolValue,
              FileManager.default.isExecutableFile(atPath: candidate.path)
        else { continue }
        return candidate.path
    }
    return nil
}

private struct ProcessCapture {
    let status: Int32
    let stdout: String
    let stderr: String
}

private func runProcess(
    executable: String,
    arguments: [String],
    environment: [String: String]? = nil
) throws -> ProcessCapture {
    let process = Process()
    let output = Pipe()
    let error = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.environment = environment
    process.standardOutput = output
    process.standardError = error
    try process.run()
    process.waitUntilExit()
    return ProcessCapture(
        status: process.terminationStatus,
        stdout: String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
        stderr: String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    )
}

final class RecordingSSHExecutor: SSHStreamingExecuting, @unchecked Sendable {
    struct Invocation { let path: String; let arguments: [String]; let environment: [String: String] }
    var invocations = [Invocation]()
    private var listCount: Int
    private let appleGitTrusted: Bool

    init(identityAlreadyExists: Bool = false, appleGitTrusted: Bool = true) {
        self.listCount = identityAlreadyExists ? 1 : 0
        self.appleGitTrusted = appleGitTrusted
    }

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
        if path == SSHCommand.ssh, arguments.first == "-G" {
            return CommandResult(
                exitCode: 0,
                stdout: "forwardagent no\npkcs11provider none\nidentitiesonly no\n"
                    + "identityfile none\nidentityagent SSH_AUTH_SOCK\npreferredauthentications publickey\n"
            )
        }
        if path == "/usr/bin/codesign" {
            return CommandResult(exitCode: 0, stderr: "Signature=adhoc\n")
        }
        if path == "/usr/bin/xcrun" {
            return CommandResult(exitCode: 0, stdout: "/usr/bin/git\n")
        }
        return CommandResult(exitCode: 0)
    }

    func validateAppleGitExecutable(path: String) throws {
        guard self.appleGitTrusted, path == "/usr/bin/git" else { throw AgentProtocolError.denied }
    }

    func publicKeyBlob(identityLabel _: String, publicKeyHash _: String) throws -> Data {
        Data([0, 0, 0, 4, 1, 2, 3, 4])
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

extension RecordingSSHExecutor: CTKPublicKeyResolving, AppleGitTrustValidating {}

private final class GitSigningExecutor: CommandExecuting, CTKPublicKeyResolving, @unchecked Sendable {
    private let publicKey: Data

    init(publicKey: Data) {
        self.publicKey = publicKey
    }

    func execute(path: String, arguments: [String], environment _: CommandEnvironment) throws -> CommandResult {
        guard path == SSHCommand.scAuth, arguments.first == "list-ctk-identities" else {
            return CommandResult(exitCode: 1)
        }
        return CommandResult(
            exitCode: 0,
            stdout: appleTableHeader + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "git-signing")
        )
    }

    func publicKeyBlob(identityLabel: String, publicKeyHash: String) throws -> Data {
        guard identityLabel == "git-signing",
              publicKeyHash == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        else { throw AgentProtocolError.denied }
        return self.publicKey
    }
}

private final class RecordingGitSigningProvider: GitSSHSigningProviding, @unchecked Sendable {
    private(set) var identity: SSHCommand.VerifiedSessionIdentity?
    private(set) var signedData = Data()
    private let privateKey: P256.Signing.PrivateKey
    let publicKeyBlob: Data

    init() throws {
        let privateKey = P256.Signing.PrivateKey()
        self.privateKey = privateKey
        self.publicKeyBlob = try SSHWire.string("ecdsa-sha2-nistp256")
            + SSHWire.string("nistp256")
            + SSHWire.string(privateKey.publicKey.x963Representation)
    }

    func sign(
        identity: SSHCommand.VerifiedSessionIdentity,
        data: Data,
        requesterPID _: Int32
    ) throws -> GitSSHSignature {
        self.identity = identity
        self.signedData = data
        let der = try self.privateKey.signature(for: data).derRepresentation
        let raw = try CTKIdentitySigner.strictDERToRawP256(der)
        let signature = try SSHWire.string("ecdsa-sha2-nistp256")
            + SSHWire.string(
                SSHWire.string(self.mpint(raw.prefix(32)))
                    + SSHWire.string(self.mpint(raw.suffix(32)))
            )
        return GitSSHSignature(publicKeyBlob: identity.publicKeyBlob, signatureBlob: signature)
    }

    private func mpint(_ bytes: Data.SubSequence) -> Data {
        let trimmed = bytes.drop { $0 == 0 }
        let value = trimmed.isEmpty ? Data([0]) : Data(trimmed)
        return value.first! & 0x80 == 0 ? value : Data([0]) + value
    }
}

private struct AllowingGitSigningRequesterValidator: GitSSHSigningRequesterValidating {
    func validateRequester() throws -> Int32 {
        42
    }
}

private struct MismatchingPasswordAutoFillProvider: PasswordAutoFillProviding {
    func acquire(
        service _: String, account _: String, synchronizable _: Bool, purpose _: PasswordAutoFillPurpose
    ) throws -> PasswordAutoFillCredential {
        PasswordAutoFillCredential(
            username: "another-user", secret: Data("never-return-this".utf8), saveStatus: .notRequested
        )
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
                        codeRequirement: "anchor test",
                        codeIdentity: LiveCodeIdentity(
                            canonicalPath: "/tmp/test-agent",
                            identifier: "test.agent",
                            teamID: nil,
                            signingAuthority: nil,
                            cdHash: "00112233445566778899",
                            hasTrustedPublisher: false
                        )
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
    try expect(presentation?.identityLabel == "test" && presentation?.application == "/tmp/test-agent"
        && presentation?.fingerprint == sshFingerprint(for: agentTestKey)
        && presentation?.verification == "exact image pinned; publisher unverified"
        && presentation?.cdHash == "001122334455…8899",
        "runtime presentation must be derived from the activated registry session")
    let trustedMain = LiveCodeIdentity(
        canonicalPath: "/Applications/macop", identifier: "macop", teamID: "TEAM123",
        signingAuthority: "Developer ID Application: Example", cdHash: "aabbccdd",
        signatureFlags: LiveCodeIdentity.hardenedRuntimeFlag,
        hasTrustedPublisher: true
    )
    let trustedHelper = LiveCodeIdentity(
        canonicalPath: "/Applications/macop-agent", identifier: "macop-agent", teamID: "TEAM123",
        signingAuthority: "Developer ID Application: Example", cdHash: "eeff0011",
        signatureFlags: LiveCodeIdentity.hardenedRuntimeFlag,
        hasTrustedPublisher: true
    )
    try expect(
        TrustedAgentHelperVerifier.isTrustedPair(main: trustedMain, helper: trustedHelper),
        "matching anchored team-signed helper pair must be eligible"
    )
    let spoofedTerminal = LiveCodeIdentity(
        canonicalPath: "/tmp/Terminal", identifier: "com.apple.Terminal", teamID: nil,
        signingAuthority: nil, cdHash: "11223344", hasTrustedPublisher: false
    )
    try expect(
        !TrustedAgentHelperVerifier.isTrustedPair(main: spoofedTerminal, helper: trustedHelper)
            && spoofedTerminal.provenanceSummary == "exact image pinned; publisher unverified",
        "an ad-hoc process using an Apple identifier must never gain publisher provenance"
    )
    let wrongIdentifierMain = LiveCodeIdentity(
        canonicalPath: trustedMain.canonicalPath, identifier: "com.example.macop", teamID: trustedMain.teamID,
        signingAuthority: trustedMain.signingAuthority, cdHash: trustedMain.cdHash, hasTrustedPublisher: true
    )
    try expect(
        !TrustedAgentHelperVerifier.isTrustedPair(main: wrongIdentifierMain, helper: trustedHelper),
        "a trusted main executable with any identifier other than macop must be rejected"
    )
    let wrongTeamHelper = LiveCodeIdentity(
        canonicalPath: trustedHelper.canonicalPath, identifier: trustedHelper.identifier, teamID: "OTHERTEAM",
        signingAuthority: trustedHelper.signingAuthority, cdHash: trustedHelper.cdHash, hasTrustedPublisher: true
    )
    try expect(
        !TrustedAgentHelperVerifier.isTrustedPair(main: trustedMain, helper: wrongTeamHelper),
        "a helper signed by another team must be rejected"
    )
    let wrongIdentifierHelper = LiveCodeIdentity(
        canonicalPath: trustedHelper.canonicalPath, identifier: "macop-helper", teamID: trustedHelper.teamID,
        signingAuthority: trustedHelper.signingAuthority, cdHash: trustedHelper.cdHash, hasTrustedPublisher: true
    )
    try expect(
        !TrustedAgentHelperVerifier.isTrustedPair(main: trustedMain, helper: wrongIdentifierHelper),
        "a trusted helper with any identifier other than macop-agent must be rejected"
    )
    let emptyTeamMain = LiveCodeIdentity(
        canonicalPath: trustedMain.canonicalPath, identifier: "macop", teamID: "",
        signingAuthority: trustedMain.signingAuthority, cdHash: trustedMain.cdHash, hasTrustedPublisher: true
    )
    try expect(
        !TrustedAgentHelperVerifier.isTrustedPair(main: emptyTeamMain, helper: trustedHelper),
        "an empty signing Team ID must be rejected"
    )
    let nonRuntimeHelper = LiveCodeIdentity(
        canonicalPath: trustedHelper.canonicalPath, identifier: trustedHelper.identifier,
        teamID: trustedHelper.teamID, signingAuthority: trustedHelper.signingAuthority,
        cdHash: trustedHelper.cdHash, hasTrustedPublisher: true
    )
    try expect(
        !TrustedAgentHelperVerifier.isTrustedPair(main: trustedMain, helper: nonRuntimeHelper),
        "a team-signed helper without hardened runtime must be rejected"
    )
    let libraryValidationDisabledHelper = LiveCodeIdentity(
        canonicalPath: trustedHelper.canonicalPath, identifier: trustedHelper.identifier,
        teamID: trustedHelper.teamID, signingAuthority: trustedHelper.signingAuthority,
        cdHash: trustedHelper.cdHash, signatureFlags: LiveCodeIdentity.hardenedRuntimeFlag,
        hasTrustedPublisher: true, disablesLibraryValidation: true
    )
    try expect(
        !TrustedAgentHelperVerifier.isTrustedPair(main: trustedMain, helper: libraryValidationDisabledHelper),
        "a helper that disables library validation must be rejected"
    )
    try expect(
        !LiveCodeIdentityInspector.matchesExpectedPath(actual: "/tmp/other-root", expected: "/tmp/test-agent"),
        "a launched root whose executable differs from the selected path must be rejected"
    )
    let forbiddenSideEffect = URL(fileURLWithPath: "/tmp/macop-suspended-child-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: forbiddenSideEffect) }
    do {
        _ = try RunCommand.captureTrustedAgent(
            argv: ["/usr/bin/touch", forbiddenSideEffect.path],
            environment: ProcessInfo.processInfo.environment,
            policy: TrustedAgentLaunchPolicy(
                executablePath: "/usr/bin/touch", teamID: "ATTACKER", identifier: "macop-agent"
            ),
            limit: 1024
        )
        throw SelftestFailure(message: "a substituted helper must fail live validation")
    } catch let error as CLIError {
        guard case .denied = error else { throw error }
    }
    try expect(
        !FileManager.default.fileExists(atPath: forbiddenSideEffect.path),
        "a helper rejected after suspended spawn must never execute its first side effect"
    )
    for signalNumber in [SIGINT, SIGTERM] {
        let cancelledSideEffect = URL(
            fileURLWithPath: "/tmp/macop-suspended-cancel-\(signalNumber)-\(UUID().uuidString)"
        )
        defer { try? FileManager.default.removeItem(at: cancelledSideEffect) }
        let cancelled = try RunCommand.captureSuspendedFixture(
            argv: ["/usr/bin/touch", cancelledSideEffect.path],
            environment: ProcessInfo.processInfo.environment,
            limit: 1024,
            validate: { _ in
                usleep(20000)
                _ = raise(signalNumber)
                usleep(20000)
            }
        )
        try expect(
            cancelled.exitCode == 128 + signalNumber,
            "a cancellation arriving during streaming validation must return its signal status"
        )
        try expect(
            !FileManager.default.fileExists(atPath: cancelledSideEffect.path),
            "a streaming child cancelled during validation must never be resumed"
        )
    }
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

private func authBrokerSelftests() throws {
    let nonce = Data(repeating: 0xA5, count: 32)
    let hello = AuthBrokerMessage.hello(AuthBrokerHello(
        minimumVersion: AuthBrokerWire.currentVersion,
        maximumVersion: AuthBrokerWire.currentVersion,
        capabilities: AuthBrokerCapability.approvalUI.rawValue | AuthBrokerCapability.sshSigning.rawValue,
        nonce: nonce
    ))
    var helloFrame = try AuthBrokerWire.frame(hello)
    let decodedHello = try AuthBrokerWire.takeFrame(from: &helloFrame)
    try expect(
        decodedHello == hello && helloFrame.isEmpty,
        "auth broker hello must round-trip exactly"
    )

    let request = AuthBrokerApprovalRequest(
        requestID: UUID(),
        issuedAtMilliseconds: 1000,
        expiresAtMilliseconds: 2000,
        operation: .sshSession,
        rootPID: 42,
        rootStartTime: 7,
        rootIdentifier: "test.agent",
        rootCodeRequirement: "anchor test",
        rootExecutablePath: "/tmp/test-agent",
        purpose: .sshSession,
        credentialLabel: "github",
        credentialFingerprint: "SHA256:test",
        host: "github.com"
    )
    var requestFrame = try AuthBrokerWire.frame(.approvalRequest(request))
    let decodedRequest = try AuthBrokerWire.takeFrame(from: &requestFrame, nowMilliseconds: 1500)
    try expect(
        decodedRequest == .approvalRequest(request),
        "auth broker request must round-trip exactly"
    )
    var unknownPurposeFrame = try AuthBrokerWire.frame(.approvalRequest(request))
    unknownPurposeFrame[68] = 0xFF
    do {
        _ = try AuthBrokerWire.takeFrame(from: &unknownPurposeFrame, nowMilliseconds: 1500)
        throw SelftestFailure(message: "unknown approval purposes must fail closed")
    } catch AuthBrokerProtocolError.malformed {}
    var skewedPurposeFrame = try AuthBrokerWire.frame(.approvalRequest(request))
    skewedPurposeFrame[68] = AuthBrokerPurpose.otpRead.rawValue
    do {
        _ = try AuthBrokerWire.takeFrame(from: &skewedPurposeFrame, nowMilliseconds: 1500)
        throw SelftestFailure(message: "operation/purpose skew must fail closed during decoding")
    } catch AuthBrokerProtocolError.malformed {}
    let managedReadPurposes: [AuthBrokerPurpose] = [
        .managedKeychainRead, .otpRead, .otpRun, .otpInject, .otpProfile, .otpItem,
        .passwordRun, .passwordInject, .passwordProfile, .passwordItemGet, .passwordItemAcquire
    ]
    for purpose in managedReadPurposes {
        let managedReadRequest = AuthBrokerApprovalRequest(
            requestID: UUID(),
            issuedAtMilliseconds: 1000,
            expiresAtMilliseconds: 2000,
            operation: .managedKeychainRead,
            rootPID: 42,
            rootStartTime: 7,
            rootIdentifier: "test.agent",
            rootCodeRequirement: "anchor test",
            rootExecutablePath: "/tmp/test-agent",
            purpose: purpose,
            credentialLabel: "fixture",
            credentialFingerprint: "",
            host: "",
            keychainService: "fixture-service",
            keychainAccount: "fixture-account"
        )
        var managedReadFrame = try AuthBrokerWire.frame(.approvalRequest(managedReadRequest))
        let decodedManagedRead = try AuthBrokerWire.takeFrame(
            from: &managedReadFrame, nowMilliseconds: 1500
        )
        try expect(
            decodedManagedRead == .approvalRequest(managedReadRequest),
            "every closed managed-read purpose must round-trip with its only permitted operation"
        )
    }
    let managedImport = AuthBrokerManagedKeychainImportRequest(
        authorizationID: request.requestID,
        secret: Data("secret".utf8)
    )
    var managedImportFrame = try AuthBrokerWire.frame(.managedKeychainImportRequest(managedImport))
    let decodedManagedImport = try AuthBrokerWire.takeFrame(from: &managedImportFrame)
    try expect(
        decodedManagedImport == .managedKeychainImportRequest(managedImport),
        "managed Keychain import messages must round-trip exactly"
    )
    try expect(
        AuthBrokerPurpose.managedKeychainGenerate.isValid(for: .managedKeychainImport)
            && !AuthBrokerPurpose.managedKeychainGenerate.isValid(for: .managedKeychainUpdate),
        "generated managed creation must have a truthful create-only broker purpose"
    )
    let maximumOTPAccount = String(repeating: "a", count: AuthBrokerWire.maximumMetadataLength)
    let maximumOTPRequest = AuthBrokerApprovalRequest(
        requestID: UUID(),
        issuedAtMilliseconds: 1000,
        expiresAtMilliseconds: 2000,
        operation: .managedKeychainImport,
        rootPID: 42,
        rootStartTime: 7,
        rootIdentifier: "test.agent",
        rootCodeRequirement: "anchor test",
        rootExecutablePath: "/tmp/test-agent",
        purpose: .otpImport,
        credentialLabel: ManagedKeychainPresentationLabel.otpSeed,
        credentialFingerprint: "",
        host: "",
        keychainService: "otp-service",
        keychainAccount: maximumOTPAccount
    )
    var maximumOTPFrame = try AuthBrokerWire.frame(.approvalRequest(maximumOTPRequest))
    let decodedMaximumOTP = try AuthBrokerWire.takeFrame(from: &maximumOTPFrame, nowMilliseconds: 1500)
    try expect(
        ManagedKeychainStore.validSelector(maximumOTPAccount)
            && ManagedKeychainPresentationLabel.otpSeed.utf8.count <= AuthBrokerWire.maximumMetadataLength
            && decodedMaximumOTP == .approvalRequest(maximumOTPRequest),
        "a maximum-length OTP account must retain a bounded truthful broker presentation label"
    )
    let indeterminateImport = AuthBrokerManagedKeychainImportResponse(
        authorizationID: request.requestID,
        outcome: .indeterminate,
        status: errSecSuccess
    )
    var indeterminateImportFrame = try AuthBrokerWire.frame(.managedKeychainImportResponse(indeterminateImport))
    let decodedIndeterminateImport = try AuthBrokerWire.takeFrame(from: &indeterminateImportFrame)
    try expect(
        decodedIndeterminateImport == .managedKeychainImportResponse(indeterminateImport),
        "broker v4 must preserve server-side post-mutation uncertainty"
    )
    let passwordAutoFillRequest = AuthBrokerApprovalRequest(
        requestID: UUID(),
        issuedAtMilliseconds: 1000,
        expiresAtMilliseconds: 2000,
        operation: .passwordAutoFill,
        rootPID: 42,
        rootStartTime: 7,
        rootIdentifier: "test.agent",
        rootCodeRequirement: "anchor test",
        rootExecutablePath: "/tmp/test-agent",
        purpose: .passwordAutoFillRead,
        credentialLabel: "me",
        credentialFingerprint: "",
        host: "",
        keychainService: "github.com",
        keychainAccount: "me"
    )
    var passwordAutoFillFrame = try AuthBrokerWire.frame(.approvalRequest(passwordAutoFillRequest))
    let decodedPasswordAutoFill = try AuthBrokerWire.takeFrame(
        from: &passwordAutoFillFrame,
        nowMilliseconds: 1500
    )
    try expect(
        decodedPasswordAutoFill == .approvalRequest(passwordAutoFillRequest),
        "Password AutoFill approval requests must round-trip exactly"
    )
    let autoFillPurposes: [PasswordAutoFillPurpose] = [.read, .run, .inject, .profile, .itemAcquire]
    try expect(
        autoFillPurposes.allSatisfy { $0.brokerPurpose.isValid(for: .passwordAutoFill) },
        "every bounded AutoFill caller purpose must be valid only for Password AutoFill"
    )
    try expect(
        autoFillPurposes.allSatisfy { !$0.brokerPurpose.isValid(for: .managedKeychainRead) },
        "AutoFill caller purposes must fail closed for managed Keychain reads"
    )
    let passwordAutoFillResponse = AuthBrokerApprovalResponse(
        requestID: passwordAutoFillRequest.requestID,
        status: .approved,
        message: "not_requested",
        resultStatus: errSecSuccess,
        resultData: Data("fixture-password".utf8),
        verifiedUsername: "verified-user"
    )
    var passwordAutoFillResponseFrame = try AuthBrokerWire.frame(.approvalResponse(passwordAutoFillResponse))
    let decodedPasswordAutoFillResponse = try AuthBrokerWire.takeFrame(from: &passwordAutoFillResponseFrame)
    try expect(
        decodedPasswordAutoFillResponse == .approvalResponse(passwordAutoFillResponse),
        "Password AutoFill username attestation must round-trip in broker v4"
    )
    let validAutoFillOutcomes: [(String, OSStatus, PasswordAutoFillSaveStatus)] = [
        ("saved", errSecSuccess, .saved),
        ("not_requested", errSecSuccess, .notRequested),
        ("save_failed", errSecAuthFailed, .failed),
        ("save_indeterminate", errSecSuccess, .indeterminate)
    ]
    for (message, status, expectedSaveStatus) in validAutoFillOutcomes {
        let response = AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID,
            status: .approved,
            message: message,
            resultStatus: status,
            resultData: Data("classifier-fixture".utf8),
            verifiedUsername: "verified-user"
        )
        var frame = try AuthBrokerWire.frame(.approvalResponse(response))
        guard let decoded = try AuthBrokerWire.takeFrame(from: &frame) else {
            throw SelftestFailure(message: "AutoFill response classifier fixture must decode")
        }
        let credential = try PasswordAutoFillResponseClassifier.classify(
            decoded,
            requestID: passwordAutoFillRequest.requestID,
            expectedUsername: "verified-user"
        )
        try expect(
            credential.saveStatus == expectedSaveStatus,
            "AutoFill response classifier must accept each valid save outcome/status combination"
        )
    }
    let invalidAutoFillResponses = [
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "saved",
            resultStatus: errSecAuthFailed, resultData: Data("classifier-fixture".utf8),
            verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "not_requested",
            resultStatus: errSecAuthFailed, resultData: Data("classifier-fixture".utf8),
            verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "save_failed",
            resultStatus: errSecSuccess, resultData: Data("classifier-fixture".utf8),
            verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "save_indeterminate",
            resultStatus: errSecAuthFailed, resultData: Data("classifier-fixture".utf8),
            verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "unknown_outcome",
            resultStatus: errSecSuccess, resultData: Data("classifier-fixture".utf8),
            verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "saved",
            resultStatus: errSecSuccess, resultData: Data(), verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "not_requested",
            resultStatus: errSecSuccess, resultData: Data([0xFF, 0xFE]), verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "not_requested",
            resultStatus: errSecSuccess, resultData: Data("nul\0credential".utf8),
            verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "saved",
            resultStatus: errSecSuccess,
            resultData: Data(repeating: 0x41, count: ManagedKeychainStore.maximumSecretLength + 1),
            verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "saved",
            resultStatus: errSecSuccess, resultData: Data("classifier-fixture".utf8)
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .approved, message: "saved",
            resultStatus: errSecSuccess, resultData: Data("classifier-fixture".utf8),
            verifiedUsername: "different-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: UUID(), status: .approved, message: "saved",
            resultStatus: errSecSuccess, resultData: Data("classifier-fixture".utf8),
            verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .denied, message: "saved",
            resultStatus: errSecAuthFailed, resultData: Data("classifier-fixture".utf8),
            verifiedUsername: "verified-user"
        ),
        AuthBrokerApprovalResponse(
            requestID: passwordAutoFillRequest.requestID, status: .denied,
            resultStatus: errSecSuccess
        )
    ]
    for response in invalidAutoFillResponses {
        var frame = try AuthBrokerWire.frame(.approvalResponse(response))
        guard let decoded = try AuthBrokerWire.takeFrame(from: &frame) else {
            throw SelftestFailure(message: "invalid AutoFill response classifier fixture must decode")
        }
        do {
            _ = try PasswordAutoFillResponseClassifier.classify(
                decoded,
                requestID: passwordAutoFillRequest.requestID,
                expectedUsername: "verified-user"
            )
            throw SelftestFailure(message: "contradictory AutoFill responses must fail closed")
        } catch let failure as PasswordAutoFillFailure {
            try expect(
                failure == .invalidResponse,
                "every post-send invalid AutoFill response must retain typed indeterminate state"
            )
        }
    }
    do {
        _ = try PasswordAutoFillResponseClassifier.classify(
            .approvalResponse(AuthBrokerApprovalResponse(
                requestID: passwordAutoFillRequest.requestID,
                status: .cancelled,
                resultStatus: errSecAuthFailed
            )),
            requestID: passwordAutoFillRequest.requestID,
            expectedUsername: "verified-user"
        )
        throw SelftestFailure(message: "valid AutoFill cancellation must remain denied")
    } catch let error as CLIError {
        if case .denied = error {} else {
            throw SelftestFailure(message: "valid AutoFill cancellation must remain a denial")
        }
    }
    do {
        _ = try PasswordAutoFillResponseClassifier.classify(
            .hello(AuthBrokerHello(
                minimumVersion: AuthBrokerWire.currentVersion,
                maximumVersion: AuthBrokerWire.currentVersion,
                capabilities: 0,
                nonce: Data(repeating: 0, count: 32)
            )),
            requestID: passwordAutoFillRequest.requestID,
            expectedUsername: "verified-user"
        )
        throw SelftestFailure(message: "mismatched AutoFill response message types must fail closed")
    } catch let failure as PasswordAutoFillFailure {
        try expect(
            failure == .invalidResponse,
            "post-send response type mismatch must retain typed indeterminate state"
        )
    }
    for saveStatus in [PasswordAutoFillSaveStatus.failed, .indeterminate] {
        let delivered = PasswordAutoFillCompletionPresentation(
            saveStatus: saveStatus,
            delivery: .delivered
        )
        let unknown = PasswordAutoFillCompletionPresentation(
            saveStatus: saveStatus,
            delivery: .unknown
        )
        try expect(
            !delivered.isSuccess && !unknown.isSuccess,
            "failed or indeterminate AutoFill saves must never use a success presentation"
        )
    }
    let unknownNoSave = PasswordAutoFillCompletionPresentation(
        saveStatus: .notRequested,
        delivery: .unknown
    )
    try expect(
        !unknownNoSave.isSuccess
            && unknownNoSave.message.contains("受け渡しは確認できません")
            && !unknownNoSave.message.contains("今回のみ使用"),
        "response write loss must not claim that an unsaved credential was used"
    )
    for status in [AuthBrokerApprovalStatus.cancelled, .denied] {
        let delivered = PasswordAutoFillRejectionPresentation(
            status: status,
            delivery: .delivered
        )
        let rejection = PasswordAutoFillRejectionPresentation(
            status: status,
            delivery: .unknown
        )
        try expect(
            !delivered.isSuccess
                && !rejection.isSuccess
                && (status == .cancelled
                    ? delivered.message == "キャンセルしました"
                    : delivered.message == "承認しませんでした")
                && rejection.message.contains("結果通知は確認できません")
                && !rejection.message.contains("安全に検証できませんでした"),
            "known cancellation and denial must remain distinct across delivered and response-loss UI states"
        )
    }
    for updating in [false, true] {
        let notStarted = ManagedKeychainEffectPresentation(
            updating: updating,
            outcome: .notStarted,
            delivery: .notAttempted
        )
        let committed = ManagedKeychainEffectPresentation(
            updating: updating,
            outcome: .committed,
            delivery: .delivered
        )
        let failed = ManagedKeychainEffectPresentation(
            updating: updating,
            outcome: .failed,
            delivery: .delivered
        )
        let indeterminate = ManagedKeychainEffectPresentation(
            updating: updating,
            outcome: .indeterminate,
            delivery: .delivered
        )
        let committedResponseLost = ManagedKeychainEffectPresentation(
            updating: updating,
            outcome: .committed,
            delivery: .unknown
        )
        let failedResponseLost = ManagedKeychainEffectPresentation(
            updating: updating,
            outcome: .failed,
            delivery: .unknown
        )
        let indeterminateResponseLost = ManagedKeychainEffectPresentation(
            updating: updating,
            outcome: .indeterminate,
            delivery: .unknown
        )
        try expect(
            !notStarted.isSuccess
                && notStarted.message.contains("Keychainは変更していません")
                && committed.isSuccess
                && !failed.isSuccess
                && failed.message.contains("失敗")
                && !indeterminate.isSuccess
                && indeterminate.message.contains("結果を確認できません")
                && !committedResponseLost.isSuccess
                && committedResponseLost.message.contains(updating ? "更新しました" : "登録しました")
                && committedResponseLost.message.contains("結果通知は確認できません")
                && !failedResponseLost.isSuccess
                && failedResponseLost.message.contains("失敗しました")
                && failedResponseLost.message.contains("結果通知は確認できません")
                && !indeterminateResponseLost.isSuccess
                && indeterminateResponseLost.message.contains("結果と、要求元への結果通知を確認できません"),
            "managed import/update UI must separate pre-mutation, mutation, and response-delivery states"
        )
    }
    for operation in [AuthBrokerOperation.sshSession, .gitSSHSign] {
        let noRequest = SSHSigningEffectPresentation(
            operation: operation,
            outcome: .noSignatureRequested,
            delivery: .notAttempted
        )
        let signFailed = SSHSigningEffectPresentation(
            operation: operation,
            outcome: .signatureFailed,
            delivery: .notAttempted
        )
        let preparationFailed = SSHSigningEffectPresentation(
            operation: operation,
            outcome: .preparationFailed,
            delivery: .notAttempted
        )
        let delivered = SSHSigningEffectPresentation(
            operation: operation,
            outcome: .signed,
            delivery: .delivered
        )
        let responseLost = SSHSigningEffectPresentation(
            operation: operation,
            outcome: .signed,
            delivery: .unknown
        )
        try expect(
            !noRequest.isSuccess
                && noRequest.message.contains("署名要求は受信しませんでした")
                && !preparationFailed.isSuccess
                && preparationFailed.message.contains("署名は実行していません")
                && !signFailed.isSuccess
                && signFailed.message.contains("署名結果は返していません")
                && delivered.isSuccess
                && delivered.message.contains("完了しました")
                && !responseLost.isSuccess
                && responseLost.message.contains("署名は完了しました")
                && responseLost.message.contains("受け渡しは確認できません"),
            "SSH and Git signing UI must separate approval, signature outcome, and response delivery"
        )
    }
    let mutationDelivered = AuthEffectPipeline.managedMutation(
        updating: false,
        outcome: .committed,
        deliver: {}
    )
    let mutationResponseLost = AuthEffectPipeline.managedMutation(
        updating: true,
        outcome: .committed,
        deliver: { throw SelftestFailure(message: "fixture mutation response loss") }
    )
    try expect(
        mutationDelivered.isSuccess
            && !mutationResponseLost.isSuccess
            && mutationResponseLost.message.contains("更新しました")
            && mutationResponseLost.message.contains("結果通知は確認できません"),
        "managed mutation delivery faults must preserve the known committed server state"
    )
    var signingDeliveryAttempted = false
    var signingAttempted = false
    let signingPreparationFailed = AuthEffectPipeline.signing(
        operation: .sshSession,
        prepare: { throw SelftestFailure(message: "fixture requester revalidation failure") },
        sign: {
            signingAttempted = true
            return Data("must-not-be-signed".utf8)
        },
        deliver: { _ in signingDeliveryAttempted = true }
    )
    try expect(
        !signingPreparationFailed.isSuccess
            && signingPreparationFailed.message.contains("署名は実行していません")
            && !signingAttempted
            && !signingDeliveryAttempted,
        "requester revalidation or signer preparation failure must remain distinct from an attempted signature"
    )
    let signingFailed = AuthEffectPipeline.signing(
        operation: .gitSSHSign,
        sign: {
            signingAttempted = true
            throw SelftestFailure(message: "fixture signer failure")
        },
        deliver: { _ in signingDeliveryAttempted = true }
    )
    try expect(
        !signingFailed.isSuccess
            && signingFailed.message.contains("署名結果は返していません")
            && signingAttempted
            && !signingDeliveryAttempted,
        "a signature failure must not attempt a response or claim a completed signature"
    )
    let fixtureSignature = Data("fixture-signature".utf8)
    var deliveredSignature = Data()
    let signingDelivered = AuthEffectPipeline.signing(
        operation: .sshSession,
        sign: { fixtureSignature },
        deliver: { deliveredSignature = $0 }
    )
    let signingResponseLost = AuthEffectPipeline.signing(
        operation: .sshSession,
        sign: { fixtureSignature },
        deliver: { _ in throw SelftestFailure(message: "fixture signature response loss") }
    )
    try expect(
        signingDelivered.isSuccess
            && deliveredSignature == fixtureSignature
            && !signingResponseLost.isSuccess
            && signingResponseLost.message.contains("署名は完了しました")
            && signingResponseLost.message.contains("受け渡しは確認できません"),
        "signature delivery faults must preserve the known successful signing effect without leaking it"
    )
    for operation in [
        AuthBrokerOperation.managedKeychainImport,
        .managedKeychainUpdate,
        .sshSession,
        .gitSSHSign
    ] {
        let route = AuthApprovalOrchestration.deliveredRoute(
            operation: operation,
            status: .approved,
            hasSigner: operation == .sshSession || operation == .gitSSHSign
        )
        try expect(
            route == .approvedPhaseTwo,
            "delivered approved phase-two server operations must remain processing instead of entering rejection UI"
        )
    }
    try expect(
        AuthApprovalOrchestration.deliveredRoute(
            operation: .managedKeychainRead,
            status: .approved,
            hasSigner: false
        ) == .approvedImmediate
            && AuthApprovalOrchestration.deliveredRoute(
                operation: .passwordAutoFill,
                status: .approved,
                hasSigner: false
            ) == .passwordAutoFill,
        "delivered server orchestration must retain immediate and AutoFill routes"
    )
    for status in [AuthBrokerApprovalStatus.cancelled, .denied] {
        for operation in [
            AuthBrokerOperation.managedKeychainImport,
            .managedKeychainUpdate,
            .sshSession,
            .gitSSHSign,
            .passwordAutoFill
        ] {
            try expect(
                AuthApprovalOrchestration.deliveredRoute(
                    operation: operation,
                    status: status,
                    hasSigner: false
                ) == .rejected(status),
                "cancelled and denied server operations must route only to rejection presentation"
            )
        }
    }
    let managedDeleteRequest = AuthBrokerApprovalRequest(
        requestID: UUID(),
        issuedAtMilliseconds: 1000,
        expiresAtMilliseconds: 2000,
        operation: .managedKeychainDelete,
        rootPID: 42,
        rootStartTime: 7,
        rootIdentifier: "test.agent",
        rootCodeRequirement: "anchor test",
        rootExecutablePath: "/tmp/test-agent",
        purpose: .managedKeychainDelete,
        credentialLabel: "me",
        credentialFingerprint: "",
        host: "",
        keychainService: "github.com",
        keychainAccount: "me"
    )
    var managedDeleteFrame = try AuthBrokerWire.frame(.approvalRequest(managedDeleteRequest))
    let decodedManagedDelete = try AuthBrokerWire.takeFrame(from: &managedDeleteFrame, nowMilliseconds: 1500)
    try expect(
        decodedManagedDelete == .approvalRequest(managedDeleteRequest),
        "managed Keychain delete requests must round-trip exactly"
    )
    var expiredFrame = try AuthBrokerWire.frame(.approvalRequest(request))
    do {
        _ = try AuthBrokerWire.takeFrame(from: &expiredFrame, nowMilliseconds: 2000)
        throw SelftestFailure(message: "expired auth broker requests must fail closed")
    } catch AuthBrokerProtocolError.expired {}

    do {
        _ = try AuthBrokerWire.frame(.approvalRequest(AuthBrokerApprovalRequest(
            requestID: UUID(),
            issuedAtMilliseconds: 1,
            expiresAtMilliseconds: 2,
            operation: .sshSession,
            rootPID: 42,
            rootStartTime: 7,
            rootIdentifier: "test.agent",
            rootCodeRequirement: "anchor test",
            rootExecutablePath: "/tmp/test-agent",
            purpose: .otpRead,
            credentialLabel: "key",
            credentialFingerprint: "SHA256:test",
            host: "github.com"
        )))
        throw SelftestFailure(message: "mismatched approval purpose must be rejected")
    } catch AuthBrokerProtocolError.malformed {}

    var unsupportedVersion = try AuthBrokerWire.frame(hello)
    unsupportedVersion[9] = UInt8(AuthBrokerWire.currentVersion + 1)
    do {
        _ = try AuthBrokerWire.takeFrame(from: &unsupportedVersion)
        throw SelftestFailure(message: "unknown auth broker versions must fail closed")
    } catch AuthBrokerProtocolError.unsupportedVersion {}

    let peerIdentity = LiveCodeIdentity(
        canonicalPath: "/usr/local/bin/macop",
        identifier: "macop",
        teamID: "TEAM123456",
        signingAuthority: "Developer ID Application",
        cdHash: "00112233",
        hasTrustedPublisher: true
    )
    let shellIdentity = LiveCodeIdentity(
        canonicalPath: "/bin/zsh",
        identifier: "com.apple.zsh",
        teamID: "APPLE",
        signingAuthority: "Software Signing",
        cdHash: "11223344",
        hasTrustedPublisher: true
    )
    let appIdentity = LiveCodeIdentity(
        canonicalPath: "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
        identifier: "com.apple.Terminal",
        teamID: "APPLE",
        signingAuthority: "Software Signing",
        cdHash: "22334455",
        hasTrustedPublisher: true
    )
    let snapshots = SnapshotInspector(snapshots: [
        50: ProcessSnapshot(pid: 50, parentPID: 40, startTime: 500),
        40: ProcessSnapshot(pid: 40, parentPID: 30, startTime: 400),
        30: ProcessSnapshot(pid: 30, parentPID: 1, startTime: 300)
    ], valid: true)
    let identities: [Int32: LiveCodeIdentity] = [50: peerIdentity, 40: shellIdentity, 30: appIdentity]
    let verifier = AuthBrokerPeerVerifier(expectedTeamID: "TEAM123456", currentUID: 501)
    let verified = try verifier.verify(
        peer: RequesterPeer(pid: 50, uid: 501),
        inspector: snapshots,
        identityInspector: { pid in
            guard let identity = identities[pid] else { throw AgentProtocolError.denied }
            return identity
        }
    )
    try expect(
        verified.peerIdentity.identifier == "macop"
            && verified.requestingApplication?.identifier == "com.apple.Terminal",
        "broker must attribute a trusted peer to a live ancestor app"
    )
    let wrongTeam = AuthBrokerPeerVerifier(expectedTeamID: "OTHERTEAM", currentUID: 501)
    try expect(!wrongTeam.acceptsPeerIdentity(peerIdentity), "broker must reject a different signing team")
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
    let selfPath = try RunningExecutable.path()
    let liveInspection = try LiveCodeIdentityInspector.inspect(pid: getpid(), expectedPath: selfPath)
    let liveSigning = liveInspection.identity
    let staticSigning = try LiveCodeIdentityInspector.inspectStatic(path: selfPath)
    try expect(
        LiveCodeIdentityInspector.matchesExpectedPath(actual: liveSigning.canonicalPath, expected: selfPath)
            && liveSigning.identifier == selfIdentifier && liveSigning.identifier == staticSigning.identifier
            && liveSigning.cdHash != nil && liveSigning.cdHash == staticSigning.cdHash
            && liveSigning.signatureFlags != 0 && liveSigning.signatureFlags == staticSigning.signatureFlags,
        "live signing extraction must include the snapshot executable path, identifier, cdhash, and signing flags"
    )
    try expect(
        liveInspection.codeRequirement.contains("cdhash H\"")
            && liveInspection.codeRequirement.contains("identifier \"")
            && !liveInspection.codeRequirement.contains("com.apple.Terminal"),
        "live inspection must return its exact identifier+cdhash-bound requirement"
    )
    let activeGitResult = try RunCommand.capture(
        argv: ["/usr/bin/xcrun", "--no-cache", "--find", "git"],
        environment: ProcessInfo.processInfo.environment, limit: 4096
    )
    let activeGitPath = activeGitResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    try expect(activeGitResult.exitCode == 0 && !activeGitPath.isEmpty, "xcrun must resolve active Apple Git")
    let activeGitIdentity = try LiveCodeIdentityInspector.inspectExpectedAppleGitStatic(path: activeGitPath)
    try expect(
        activeGitIdentity.identifier == "com.apple.git" && activeGitIdentity.requiresLibraryValidation,
        "resolved Git must satisfy Apple's Git requirement and library validation before launch"
    )
    let liveGit = try RunCommand.captureSuspendedFixture(
        argv: [activeGitPath, "--version"], environment: ProcessInfo.processInfo.environment, limit: 4096,
        validate: { pid in
            _ = try LiveCodeIdentityInspector.inspectExpectedAppleGit(pid: pid, expectedPath: activeGitPath)
        }
    )
    try expect(liveGit.exitCode == 0, "suspended active Git must satisfy the live Apple requirement")
    let mismatchedPathCandidate = LiveCodeIdentity(
        canonicalPath: "/tmp/macop-forged-main-executable",
        identifier: liveSigning.identifier,
        teamID: liveSigning.teamID,
        signingAuthority: liveSigning.signingAuthority,
        cdHash: liveSigning.cdHash,
        signatureFlags: liveSigning.signatureFlags,
        hasTrustedPublisher: liveSigning.hasTrustedPublisher
    )
    do {
        _ = try LiveCodeIdentityInspector.validateCandidateForTesting(
            pid: getpid(), expectedPath: selfPath, candidate: mismatchedPathCandidate
        )
        throw SelftestFailure(message: "same live metadata with another main executable path must fail")
    } catch AgentProtocolError.denied {}
    let forgedHashCandidate = LiveCodeIdentity(
        canonicalPath: liveSigning.canonicalPath,
        identifier: liveSigning.identifier,
        teamID: liveSigning.teamID,
        signingAuthority: liveSigning.signingAuthority,
        cdHash: String(repeating: "0", count: liveSigning.cdHash?.count ?? 40),
        signatureFlags: liveSigning.signatureFlags,
        hasTrustedPublisher: liveSigning.hasTrustedPublisher
    )
    do {
        _ = try LiveCodeIdentityInspector.validateCandidateForTesting(
            pid: getpid(), expectedPath: selfPath, candidate: forgedHashCandidate
        )
        throw SelftestFailure(message: "same-identifier metadata with another cdhash must fail live validation")
    } catch AgentProtocolError.denied {}
    let forgedTeamCandidate = LiveCodeIdentity(
        canonicalPath: liveSigning.canonicalPath,
        identifier: liveSigning.identifier,
        teamID: "TEAMBBBBBB",
        signingAuthority: "Forged Team B",
        cdHash: liveSigning.cdHash,
        signatureFlags: liveSigning.signatureFlags,
        hasTrustedPublisher: true
    )
    do {
        _ = try LiveCodeIdentityInspector.validateCandidateForTesting(
            pid: getpid(), expectedPath: selfPath, candidate: forgedTeamCandidate
        )
        throw SelftestFailure(message: "Team B metadata must fail against another live signer")
    } catch AgentProtocolError.denied {}
    if ProcessInfo.processInfo.environment["MACOP_REQUIRE_TEAM_SIGNED_TEST"] == "1" {
        try expect(
            liveSigning.hasTrustedPublisher && liveSigning.teamID?.isEmpty == false
                && liveSigning.signingAuthority?.isEmpty == false,
            "team-signed integration mode requires Apple-anchored Team ID and certificate metadata"
        )
    }
    if let signedMain = ProcessInfo.processInfo.environment["MACOP_TEAM_SIGNED_MAIN"] {
        if let signedHelper = ProcessInfo.processInfo.environment["MACOP_TEAM_SIGNED_HELPER"] {
            let mainIdentity = try LiveCodeIdentityInspector.inspectStatic(path: signedMain)
            let helperIdentity = try LiveCodeIdentityInspector.inspectStatic(path: signedHelper)
            try expect(
                TrustedAgentHelperVerifier.isTrustedPair(main: mainIdentity, helper: helperIdentity),
                "team-signed integration paths must identify an anchored same-Team macop/helper pair"
            )
            guard let teamID = mainIdentity.teamID else {
                throw SelftestFailure(message: "team-signed integration main must expose a Team ID")
            }
            let launch = try RunCommand.captureTrustedAgent(
                argv: [helperIdentity.canonicalPath],
                environment: ProcessInfo.processInfo.environment,
                policy: TrustedAgentLaunchPolicy(
                    executablePath: helperIdentity.canonicalPath,
                    teamID: teamID,
                    identifier: TrustedAgentHelperVerifier.helperIdentifier
                ),
                limit: 4096
            )
            try expect(
                launch.exitCode == ExitCode.invalidArguments.rawValue,
                "team-signed integration helper must pass suspended live validation before its usage error"
            )
        }
    }

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
        inspector: liveInspector, frameReadTimeout: 0.15, maximumClients: 2, maximumPendingClients: 1
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
    func receiveLiveAgentFrame(from descriptor: Int32, timeoutMilliseconds: Int32 = 2000) throws -> Data {
        func readExactly(_ count: Int) throws -> Data {
            var result = Data(repeating: 0, count: count)
            var offset = 0
            while offset < count {
                var ready = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
                guard poll(&ready, 1, timeoutMilliseconds) > 0,
                      ready.revents & Int16(POLLIN) != 0
                else { throw SelftestFailure(message: "live agent must return a complete frame") }
                let received = result.withUnsafeMutableBytes { buffer in
                    recv(descriptor, buffer.baseAddress!.advanced(by: offset), count - offset, 0)
                }
                guard received > 0 else {
                    throw SelftestFailure(message: "live agent must not close during a response frame")
                }
                offset += received
            }
            return result
        }
        let header = try readExactly(4)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= UInt32(SSHWire.maxFrameLength) else {
            throw SelftestFailure(message: "live agent response frame must respect the protocol limit")
        }
        return try readExactly(Int(length))
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
    let response = try receiveLiveAgentFrame(from: pendingClient)
    try expect(response.first == AgentMessage.identitiesAnswer,
               "real listener must bind peer evidence and reply with exact identities message")
    usleep(250_000)
    let idleSent = identitiesRequest.withUnsafeBytes {
        send(pendingClient, $0.baseAddress!, identitiesRequest.count, Int32(MSG_NOSIGNAL))
    }
    try expect(idleSent == identitiesRequest.count, "idle client must send a second complete request")
    var idlePoll = pollfd(fd: pendingClient, events: Int16(POLLIN), revents: 0)
    try expect(
        poll(&idlePoll, 1, 2000) > 0,
        "a complete request after the frame timeout must retain the active connection"
    )
    let idleResponse = try receiveLiveAgentFrame(from: pendingClient)
    try expect(
        idleResponse.first == AgentMessage.identitiesAnswer,
        "frame timeout must apply only after the next frame starts"
    )
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
    let signerPublicBlob = try CTKIdentitySigner.publicBlob(for: p256Public)
    try expect(
        signerPublicBlob == p256Host,
        "CTK signer must encode a P-256 certificate key as an SSH public blob"
    )
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
    for coordinateLength in [34, 256] {
        let oversizedSignature = try SSHWire.string("ecdsa-sha2-nistp256") + SSHWire.string(
            SSHWire.string(Data(repeating: 1, count: coordinateLength)) + SSHWire.string(Data([1]))
        )
        do {
            try bindingVerifier.verify(hostKey: p256Host, sessionID: p256Session, signature: oversizedSignature)
            throw SelftestFailure(message: "oversized P-256 coordinates must fail without trapping")
        } catch AgentProtocolError.malformed {}
    }
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

final class SequencedSSHExecutor: CTKPublicKeyResolving, @unchecked Sendable {
    struct Invocation { let path: String; let arguments: [String]; let environment: CommandEnvironment }
    var invocations = [Invocation]()
    var lists: [String]
    let createResult: CommandResult
    let providerResult: CommandResult

    init(
        lists: [String],
        createResult: CommandResult = CommandResult(exitCode: 0),
        providerResult: CommandResult = CommandResult(
            exitCode: 0,
            stdout: "ecdsa-sha2-nistp256 AAAA My SSH Key\n"
        )
    ) {
        self.lists = lists
        self.createResult = createResult
        self.providerResult = providerResult
    }

    func execute(path: String, arguments: [String], environment: CommandEnvironment) throws -> CommandResult {
        self.invocations.append(Invocation(path: path, arguments: arguments, environment: environment))
        if path == SSHCommand.scAuth, arguments.first == "list-ctk-identities" {
            return CommandResult(exitCode: 0, stdout: self.lists.isEmpty ? "" : self.lists.removeFirst())
        }
        if path == SSHCommand.scAuth, arguments.first == "create-ctk-identity" {
            return self.createResult
        }
        return CommandResult(exitCode: 0)
    }

    func publicKeyBlob(identityLabel _: String, publicKeyHash _: String) throws -> Data {
        guard self.providerResult.exitCode == 0,
              let encoded = self.providerResult.stdout.split(separator: " ").dropFirst().first,
              let blob = Data(base64Encoded: String(encoded))
        else { throw AgentProtocolError.denied }
        return blob
    }
}

struct AvailableBiometricChecker: BiometricAvailabilityChecking {
    func checkAvailability() -> BiometricAvailability {
        .available
    }
}

struct UnavailableBiometricChecker: BiometricAvailabilityChecking {
    let reason: String
    func checkAvailability() -> BiometricAvailability {
        .unavailable(reason: self.reason)
    }
}

final class GitHubTestExecutor: SSHStreamingExecuting, @unchecked Sendable {
    let output: String
    let code: Int32
    var invocations = [(path: String, arguments: [String])]()
    init(output: String, code: Int32) {
        self.output = output; self.code = code
    }

    func execute(path: String, arguments: [String], environment _: CommandEnvironment) throws -> CommandResult {
        self.invocations.append((path: path, arguments: arguments))
        if path == SSHCommand.scAuth, arguments.first == "list-ctk-identities" {
            return CommandResult(exitCode: 0, stdout: appleTableHeader
                + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github"))
        }
        return CommandResult(exitCode: self.code, stderr: self.output)
    }

    func executeStreaming(
        path: String, arguments: [String], environment _: CommandEnvironment,
        stdout _: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32 {
        self.invocations.append((path: path, arguments: arguments))
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
    case "--suspended-interactive":
        do {
            let status = try RunCommand.runSuspendedInteractiveFixture(
                argv: Array(arguments.dropFirst()),
                environment: harnessEnvironment,
                validate: { _ in
                    if let readyPath = processEnvironment["MACOP_SUSPENDED_VALIDATION_READY"] {
                        FileManager.default.createFile(atPath: readyPath, contents: Data())
                    }
                    let delay = processEnvironment["MACOP_SUSPENDED_VALIDATION_DELAY_US"].flatMap(useconds_t.init)
                    if let delay {
                        usleep(delay)
                    }
                }
            )
            exit(status)
        } catch {
            exit(ExitCode.runtimeError.rawValue)
        }
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
    case "--pty-ssh-test":
        let greeting = "Hi user! You've successfully authenticated, but GitHub does not provide shell access.\n"
        let sshApp = MacopApp(
            keychainClient: FakeKeychainClient(response: .success(Data())),
            commandExecutor: GitHubTestExecutor(output: greeting, code: 1)
        )
        let argv = ["macop", "ssh", "test", "github"]
        let result = sshApp.runInteractivelyIfNeeded(argv: argv, env: harnessEnvironment)
            ?? sshApp.runStreamingIfNeeded(
                argv: argv,
                env: harnessEnvironment,
                stdout: { try? FileHandle.standardOutput.write(contentsOf: $0) },
                stderr: { try? FileHandle.standardError.write(contentsOf: $0) }
            )
            ?? sshApp.run(argv: argv, env: harnessEnvironment)
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
    do { try authBrokerSelftests() } catch { throw SelftestFailure(message: "auth broker selftests: \(error)") }
    try runKeychainIntegrationIfRequested()
    let app = MacopApp(keychainClient: FakeKeychainClient(response: .success(Data("test-secret".utf8))))
    let fileManager = FileManager.default
    let tempRoot = fileManager.temporaryDirectory
        .appendingPathComponent("macop-selftest-\(UUID().uuidString)", isDirectory: true)
    defer { try? fileManager.removeItem(at: tempRoot) }

    try fileManager.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    let configDirectory = tempRoot.path

    let gitSigningDirectory = tempRoot.appendingPathComponent("git-signing", isDirectory: true)
    try fileManager.createDirectory(at: gitSigningDirectory, withIntermediateDirectories: false)
    let gitSigningKey = gitSigningDirectory.appendingPathComponent("key.pub")
    let gitSigningMessage = gitSigningDirectory.appendingPathComponent("message")
    let gitSigningProvider = try RecordingGitSigningProvider()
    let publicKeyBlob = gitSigningProvider.publicKeyBlob
    let publicKeyText = "ecdsa-sha2-nistp256 \(publicKeyBlob.base64EncodedString()) git-signing\n"
    try Data(publicKeyText.utf8).write(to: gitSigningKey)
    let gitMessage = Data("tree 0000000000000000000000000000000000000000\n".utf8)
    try gitMessage.write(to: gitSigningMessage)
    let gitSigningResult = GitSSHSigningCommand.run(
        argv: [
            "macop", "-Y", "sign", "-n", "git", "-f", gitSigningKey.path, gitSigningMessage.path
        ],
        env: [:],
        executor: GitSigningExecutor(publicKey: publicKeyBlob),
        provider: gitSigningProvider,
        requesterValidator: AllowingGitSigningRequesterValidator()
    )
    try expect(gitSigningResult.exitCode == 0, "Git SSH adapter must accept Git's exact ssh-keygen invocation")
    try expect(
        gitSigningProvider.identity?.label == "git-signing"
            && gitSigningProvider.identity?.publicKeyBlob == publicKeyBlob,
        "Git SSH adapter must select exactly the CTK identity matching user.signingKey"
    )
    var signedCursor = SSHCursor(Data(gitSigningProvider.signedData.dropFirst("SSHSIG".utf8.count)))
    let signedNamespace = try signedCursor.string()
    let signedReserved = try signedCursor.string()
    let signedHashAlgorithm = try signedCursor.string()
    let signedDigest = try signedCursor.string()
    try expect(
        gitSigningProvider.signedData.starts(with: Data("SSHSIG".utf8))
            && String(data: signedNamespace, encoding: .utf8) == "git"
            && signedReserved.isEmpty
            && String(data: signedHashAlgorithm, encoding: .utf8) == "sha256"
            && signedDigest == Data(SHA256.hash(data: gitMessage))
            && signedCursor.isAtEnd,
        "Git SSH adapter must sign the canonical SSHSIG preimage with the git namespace"
    )
    let signaturePath = URL(fileURLWithPath: gitSigningMessage.path + ".sig")
    let armored = try String(contentsOf: signaturePath, encoding: .utf8)
    try expect(
        armored.hasPrefix("-----BEGIN SSH SIGNATURE-----\n")
            && armored.hasSuffix("-----END SSH SIGNATURE-----\n"),
        "Git SSH adapter must write OpenSSH armored signature output"
    )
    let signatureValidation = try RunCommand.capture(
        argv: [
            "/bin/sh", "-c",
            "exec /usr/bin/ssh-keygen -Y check-novalidate -n git -s \"$2\" < \"$1\"",
            "macop-selftest", gitSigningMessage.path, signaturePath.path
        ],
        environment: [:],
        limit: 4096
    )
    try expect(
        signatureValidation.exitCode == 0,
        "OpenSSH must validate the generated SSHSIG envelope and signature"
    )
    let repeatedGitSigning = GitSSHSigningCommand.run(
        argv: [
            "macop", "-Y", "sign", "-n", "git", "-f", gitSigningKey.path, gitSigningMessage.path
        ],
        env: [:],
        executor: GitSigningExecutor(publicKey: publicKeyBlob),
        provider: gitSigningProvider,
        requesterValidator: AllowingGitSigningRequesterValidator()
    )
    try expect(repeatedGitSigning.exitCode == 5, "Git SSH adapter must not overwrite an existing signature file")

    let sentinel = open("/dev/null", O_RDONLY)
    guard sentinel >= 3 else { throw SelftestFailure(message: "ambient FD sentinel must be available") }
    defer { _ = close(sentinel) }
    let sentinelFlags = fcntl(sentinel, F_GETFD)
    try expect(sentinelFlags >= 0 && fcntl(sentinel, F_SETFD, sentinelFlags & ~FD_CLOEXEC) == 0,
               "ambient FD sentinel must intentionally lack CLOEXEC")
    let sentinelEnvironment = ["MACOP_SENTINEL_FD": "\(sentinel)"]
    let sentinelCommand = ["/bin/sh", "-c", "test ! -e /dev/fd/$MACOP_SENTINEL_FD"]
    let pipeSentinel: CommandResult
    do {
        pipeSentinel = try RunCommand.capture(argv: sentinelCommand, environment: sentinelEnvironment, limit: 1024)
    } catch {
        throw SelftestFailure(message: "pipe sentinel launch failed: \(error)")
    }
    try expect(
        pipeSentinel.exitCode == 0,
        "pipe child must not inherit an ambient non-CLOEXEC FD"
    )

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
        VerifiedSessionLauncher.notice(for: verifiedSession).contains("direct CTK access outside it is not controlled"),
        "verified-session notice must state the direct-CTK-access boundary"
    )
    let presentation = SessionAuthorizationPresentation(
        identityLabel: "test",
        application: "macop-test",
        verification: "verified",
        signingAuthority: "test signature",
        cdHash: "00112233",
        fingerprint: "SHA256:test",
        rootPID: 123,
        rootStartTime: 456,
        rootIdentifier: "com.example.macop-test",
        rootCodeRequirement: "anchor test",
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
    let readOTPCompatibility = entries.first { $0["id"] as? String == "read --otp" }
    let itemOTPCompatibility = entries.first { $0["id"] as? String == "item get --otp" }
    try expect(
        (readOTPCompatibility?["alternative"] as? String)?.contains("attribute=otp") == true
            && (itemOTPCompatibility?["alternative"] as? String) == "Use item otp <name>."
            && !(readOTPCompatibility?["reason"] as? String ?? "").contains("outside the MVP"),
        "unsupported 1Password OTP flags must advertise the supported macop OTP alternatives"
    )
    let expectedCompatibilityIDs: Set = [
        "read", "read --no-newline", "read --otp", "read --ssh-format", "read --out-file", "read --file-mode",
        "read --force",
        "run", "run --env-file",
        "run --stdin",
        "run --no-masking", "run --environment", "inject", "inject -i", "inject --in-file", "inject --out-file",
        "inject --file-mode",
        "inject --force", "generate password", "item generate", "item generate --replace",
        "item otp", "item otp import", "item otp edit", "item otp delete",
        "profile run", "profile shell-init", "item list", "item list --long", "item list --format", "item list --vault",
        "item list --categories", "item list --tags", "item list --favorite", "item list --include-archive",
        "item list --otp", "item list --share-link", "item get", "item get --fields",
        "item get --reveal", "item import", "item acquire", "item acquire --from-passwords",
        "item get --format", "item get --id", "item get --stdin", "item get --vault", "item get --categories",
        "item get --tags",
        "item get --favorite",
        "item get --include-archive", "item get --otp", "item get --share-link", "item create", "item edit",
        "item delete", "passwords direct-provider",
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
        "ssh agent application", "ssh shell-init", "ssh git-signing-config", "ssh connect", "ssh host-config",
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
        compatibilityHuman.stdout.contains("Macop extensions:")
            && compatibilityHuman.stdout.contains("item generate")
            && compatibilityHuman.stdout.contains("profile run")
            && compatibilityHuman.stdout.contains("ssh connect"),
        "human matrix should label extensions"
    )
    try expect(compatibilityHuman.stdout.contains("Flags:"), "human matrix should label flags separately")
    try expect(
        compatibilityHuman.stdout.contains("Reference query modes:"),
        "human matrix should group documented reference query modes separately"
    )

    let sshExecutor = RecordingSSHExecutor()
    let sshApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: sshExecutor,
        biometricChecker: AvailableBiometricChecker()
    )
    let zshIntegration = sshApp.run(argv: ["macop", "ssh", "shell-init", "zsh"], env: [:])
    try expect(zshIntegration.exitCode == 0, "zsh shell integration must render without CTK access")
    try expect(
        zshIntegration.stdout.contains("MACOP_SHELL_INTEGRATION_ACTIVE")
            && zshIntegration.stdout.contains("exec macop ssh agent shell")
            && zshIntegration.stdout.contains("$MACOP_SSH_IDENTITY"),
        "shell integration must be guarded against recursion and bind each tab to a verified root"
    )
    let fishIntegration = sshApp.run(argv: ["macop", "ssh", "shell-init", "fish"], env: [:])
    try expect(
        fishIntegration.exitCode == 0 && fishIntegration.stdout.contains("status is-interactive"),
        "fish shell integration must render its native guard"
    )
    let unsupportedShell = sshApp.run(argv: ["macop", "ssh", "shell-init", "tcsh"], env: [:])
    try expect(unsupportedShell.exitCode == 2, "unsupported shell integration must fail explicitly")
    let gitConfigApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: RecordingSSHExecutor(identityAlreadyExists: true),
        biometricChecker: AvailableBiometricChecker()
    )
    let gitSigningConfig = gitConfigApp.run(
        argv: ["macop", "ssh", "git-signing-config", "github"], env: [:]
    )
    try expect(
        gitSigningConfig.exitCode == 0
            && gitSigningConfig.stdout.contains("git config --local gpg.format ssh")
            && gitSigningConfig.stdout.contains("user.signingkey")
            && gitSigningConfig.stdout.contains("gpg.ssh.program"),
        "Git signing config must emit repository-local commands without changing Git config"
    )
    let createdIdentity = sshApp.run(argv: ["macop", "ssh", "create", "github", "--touch-id"], env: [:])
    try expect(createdIdentity.exitCode == 0, "ssh create should use the injectable Apple command executor")
    let agentIdentityExecutor = SequencedSSHExecutor(
        lists: [appleTableHeader + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github")],
        providerResult: CommandResult(exitCode: 1)
    )
    let agentIdentity = try SSHCommand.verifiedSessionIdentity(
        label: "github",
        env: [:],
        executor: agentIdentityExecutor,
        publicKeyResolver: { label, hash in
            guard label == "github", hash == String(repeating: "A", count: 40) else {
                throw AgentProtocolError.denied
            }
            return agentTestKey
        }
    )
    try expect(
        agentIdentity.fingerprint == sshFingerprint(for: agentTestKey),
        "verified-session identity selection must derive public material without the Apple SSH provider"
    )
    let createdJSONExecutor = SequencedSSHExecutor(lists: [
        appleTableHeader,
        appleTableHeader + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "new-github")
    ])
    let createdJSONApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: createdJSONExecutor,
        biometricChecker: AvailableBiometricChecker()
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
        commandExecutor: missingPostExecutor,
        biometricChecker: AvailableBiometricChecker()
    )
    let missingPostCreate = missingPostApp.run(argv: ["macop", "ssh", "create", "new-key"], env: [:])
    try expect(
        missingPostCreate.exitCode == 4
            && missingPostCreate.stderr.contains("returned exit 0")
            && missingPostCreate.stderr.contains("cancelled, unavailable")
            && !missingPostCreate.stderr.contains("reported success"),
        "ssh create must fail when post-create identity verification is missing"
    )
    let duplicatePost = appleTableHeader
        + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "new-key")
        + appleTableRow("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "new-key")
    let duplicatePostExecutor = SequencedSSHExecutor(lists: [emptyTable, duplicatePost])
    let duplicatePostApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: duplicatePostExecutor,
        biometricChecker: AvailableBiometricChecker()
    )
    let duplicatePostCreate = duplicatePostApp.run(argv: ["macop", "ssh", "create", "new-key"], env: [:])
    try expect(
        duplicatePostCreate.exitCode == 4,
        "ssh create must fail when post-create identity verification is ambiguous"
    )
    let unusableSecurityIdentityExecutor = SequencedSSHExecutor(
        lists: [
            emptyTable,
            appleTableHeader + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "unsupported-key")
        ],
        providerResult: CommandResult(exitCode: 0)
    )
    let unusableSecurityIdentityApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: unusableSecurityIdentityExecutor,
        biometricChecker: AvailableBiometricChecker()
    )
    let unusableSecurityIdentityCreate = unusableSecurityIdentityApp.run(
        argv: ["macop", "ssh", "create", "unsupported-key"], env: [:]
    )
    try expect(
        unusableSecurityIdentityCreate.exitCode == 4
            && unusableSecurityIdentityCreate.stderr.contains("identity was created")
            && unusableSecurityIdentityCreate.stderr
            .contains("Security.framework cannot resolve exactly one public key"),
        "ssh create must report a persisted identity that Security.framework cannot resolve"
    )
    let failedCreateExecutor = SequencedSSHExecutor(
        lists: [emptyTable, emptyTable],
        createResult: CommandResult(exitCode: 1)
    )
    let failedCreateApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: failedCreateExecutor,
        biometricChecker: AvailableBiometricChecker()
    )
    let failedCreate = failedCreateApp.run(argv: ["macop", "ssh", "create", "failed-key"], env: [:])
    try expect(
        failedCreate.exitCode == 4
            && failedCreate.stderr.contains("did not create a matching identity")
            && !failedCreate.stderr.contains("may have completed"),
        "a nonzero create with a verified-empty post-list must report a definite failure"
    )
    let cancelledCreateExecutor = SequencedSSHExecutor(
        lists: [emptyTable, emptyTable],
        createResult: CommandResult(exitCode: 128 + SIGINT)
    )
    let cancelledCreateApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: cancelledCreateExecutor,
        biometricChecker: AvailableBiometricChecker()
    )
    let cancelledCreate = cancelledCreateApp.run(
        argv: ["macop", "ssh", "create", "cancelled-key", "--format=json"], env: [:]
    )
    try expect(
        cancelledCreate.exitCode == 5
            && cancelledCreate.stderr.contains("\"code\" : \"denied\"")
            && cancelledCreate.stderr.contains("interrupted by the user")
            && !cancelledCreate.stderr.contains("Touch ID identity creation was cancelled"),
        "an identifiable user interrupt must return denied without claiming a Touch ID UI outcome"
    )
    let terminatedCreateExecutor = SequencedSSHExecutor(
        lists: [emptyTable, emptyTable],
        createResult: CommandResult(exitCode: 128 + SIGTERM)
    )
    let terminatedCreateApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: terminatedCreateExecutor,
        biometricChecker: AvailableBiometricChecker()
    )
    let terminatedCreate = terminatedCreateApp.run(
        argv: ["macop", "ssh", "create", "terminated-key", "--format=json"], env: [:]
    )
    try expect(
        terminatedCreate.exitCode == 4
            && terminatedCreate.stderr.contains("\"code\" : \"provider_unavailable\"")
            && terminatedCreate.stderr.contains("exit 143")
            && !terminatedCreate.stderr.contains("interrupted by the user"),
        "SIGTERM must remain an unclassified provider failure rather than a user cancellation"
    )
    let unavailableCreateExecutor = SequencedSSHExecutor(lists: [emptyTable])
    let unavailableCreateApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: unavailableCreateExecutor,
        biometricChecker: UnavailableBiometricChecker(reason: "Touch ID is unavailable in this test session.")
    )
    let unavailableCreate = unavailableCreateApp.run(
        argv: ["macop", "ssh", "create", "unavailable-key"], env: [:]
    )
    try expect(
        unavailableCreate.exitCode == 4
            && unavailableCreate.stderr.contains("Touch ID is unavailable")
            && !unavailableCreateExecutor.invocations.contains { $0.arguments.first == "create-ctk-identity" },
        "unavailable biometrics must fail before CTK mutation with an actionable reason"
    )
    let publicKeyJSON = try JSONSerialization.jsonObject(with: Data(publicKey.stdout.utf8)) as? [String: Any]
    try expect(
        publicKeyJSON?["schema_version"] as? Int == 1 && publicKeyJSON?["label"] as? String == "github"
            && publicKeyJSON?["public_key"] is String
            && publicKeyJSON?["provider"] as? String == "security-framework",
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
    try expect(notGitRun.exitCode == 3, "ssh run must reject non-Git executables")
    let renamedGitRun = sshApp.run(
        argv: ["macop", "ssh", "run", "github", "--", "/tmp/git", "status"], env: [:]
    )
    try expect(
        renamedGitRun.exitCode == 3,
        "ssh run must not treat an arbitrary executable named git as a trusted Git image"
    )
    let absoluteGitRun = sshApp.run(
        argv: ["macop", "ssh", "run", "github", "--", "/usr/bin/git", "status"], env: [:]
    )
    try expect(absoluteGitRun.exitCode == 0, "ssh run should accept an absolute executable whose basename is git")
    try expect(
        sshExecutor.invocations.last?.path == "macop-agent"
            && sshExecutor.invocations.last?.arguments.prefix(4) == ["git", "github", "--", "/usr/bin/git"]
            && sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?
            .contains("PKCS11Provider=none") == true
            && sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?.contains("ForwardAgent=no") == true
            && sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?.contains("-F /dev/null") == true
            && sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?.contains("IdentityFile=none") == true
            && sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?
            .contains("IdentityAgent=SSH_AUTH_SOCK") == true
            && sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?.contains("IdentitiesOnly=no") == true
            && sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?
            .contains("PreferredAuthentications=publickey") == true,
        "ssh run must launch git under the one-shot agent and isolate SSH from user identities"
    )
    let controlledLookupExecutor = RecordingSSHExecutor(identityAlreadyExists: true)
    let controlledLookupApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: controlledLookupExecutor
    )
    let controlledLookup = controlledLookupApp.run(
        argv: ["macop", "ssh", "run", "github", "--", "git", "status"],
        env: [
            "DEVELOPER_DIR": "/tmp/forged-developer",
            "SDKROOT": "/tmp/forged-sdk",
            "TOOLCHAINS": "forged",
            "xcrun_log": "1",
            "xcrun_nocache": "0",
            "xcrun_verbose": "1"
        ]
    )
    let xcrunInvocation = controlledLookupExecutor.invocations.first { $0.path == "/usr/bin/xcrun" }
    try expect(
        controlledLookup.exitCode == 0
            && xcrunInvocation?.arguments == ["--no-cache", "--find", "git"]
            && xcrunInvocation?.environment["DEVELOPER_DIR"] == nil
            && xcrunInvocation?.environment["SDKROOT"] == nil
            && xcrunInvocation?.environment["TOOLCHAINS"] == nil
            && xcrunInvocation?.environment.keys.contains(where: { $0.hasPrefix("xcrun_") }) == false,
        "ssh run must remove xcrun lookup overrides and bypass its mutable cache"
    )
    let untrustedGitExecutor = RecordingSSHExecutor(identityAlreadyExists: true, appleGitTrusted: false)
    let untrustedGitApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: untrustedGitExecutor
    )
    let untrustedGit = untrustedGitApp.run(
        argv: ["macop", "ssh", "run", "github", "--", "git", "status"], env: [:]
    )
    try expect(
        untrustedGit.exitCode == ExitCode.providerUnavailable.rawValue
            && untrustedGit.stderr.contains("Apple-signed, library-validated Git image")
            && !untrustedGitExecutor.invocations.contains(where: { $0.path == "macop-agent" }),
        "ssh run must reject untrusted xcrun output before launching the agent"
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
    let greetingExecutor = GitHubTestExecutor(output: greeting, code: 1)
    let greetingApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: greetingExecutor
    )
    let greetingResult = greetingApp.run(argv: ["macop", "ssh", "test", "github", "--format=json"], env: [:])
    let greetingJSON = try JSONSerialization.jsonObject(with: Data(greetingResult.stdout.utf8)) as? [String: Any]
    try expect(
        greetingResult.exitCode == 0 && greetingJSON?["raw_exit_code"] as? Int == 1
            && greetingJSON?["status"] as? String == "authenticated",
        "GitHub's documented authenticated greeting at raw exit 1 must normalize to success"
    )
    try expect(
        greetingExecutor.invocations.last?.path == "macop-agent"
            && greetingExecutor.invocations.last?.arguments == [
                "shell", "github", "--", "/usr/bin/ssh",
                "-F", "/dev/null",
                "-o", "PKCS11Provider=none",
                "-o", "ForwardAgent=no",
                "-o", "IdentitiesOnly=no",
                "-o", "IdentityFile=none",
                "-o", "IdentityAgent=SSH_AUTH_SOCK",
                "-o", "PreferredAuthentications=publickey",
                "-T", "git@github.com"
            ],
        "ssh test must run through the one-shot agent and ignore user identities"
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
    let doctorResultChecks = doctorJSON?["checks"] as? [[String: Any]]
    try expect(
        doctorResultChecks?
            .first(where: { $0["name"] as? String == "code_signature" })?["status"] as? String == "warn"
            && doctorResultChecks?
            .first(where: { $0["name"] as? String == "code_signature" })?["detail"] as? String
            == "ad-hoc signature; Keychain ACL and XARA authorization may repeat after rebuilds",
        "doctor must identify ad-hoc signing as a repeat-authorization risk"
    )
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
    let unusableDoctorExecutor = SequencedSSHExecutor(
        lists: [appleTableHeader + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github")],
        providerResult: CommandResult(exitCode: 1)
    )
    let unusableDoctor = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: unusableDoctorExecutor
    ).run(argv: ["macop", "doctor", "--format=json"], env: [:])
    let unusableDoctorJSON = try JSONSerialization.jsonObject(
        with: Data(unusableDoctor.stdout.utf8)
    ) as? [String: Any]
    let unusableDoctorChecks = unusableDoctorJSON?["checks"] as? [[String: Any]]
    try expect(
        unusableDoctor.exitCode == 4
            && unusableDoctorChecks?
            .first(where: { $0["name"] as? String == "security_identity_keys" })?["status"] as? String == "fail",
        "doctor must fail when Security.framework cannot resolve a selected CTK public key"
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
    let initializedConfigPath = URL(fileURLWithPath: configDirectory).appendingPathComponent("config.json").path
    let configMode = try FileManager.default
        .attributesOfItem(atPath: initializedConfigPath)[.posixPermissions] as? NSNumber
    try expect(configMode?.intValue == 0o600, "config init must create the file with mode 0600")
    let initializedObject = try JSONSerialization.jsonObject(
        with: Data(contentsOf: URL(fileURLWithPath: initializedConfigPath))
    ) as? [String: Any]
    try expect(initializedObject?["version"] as? Int == 2, "config init must create explicit schema v2")

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
    let injectReadsStdin = try InjectCommand.requiresStandardInput(args: [])
    let injectFileReadsStdin = try InjectCommand.requiresStandardInput(args: ["--in-file", "template"])
    try expect(injectReadsStdin, "inject without an input file must read stdin")
    try expect(
        !injectFileReadsStdin,
        "inject with an input file must not read stdin"
    )
    let itemNamedInject = try ArgumentParser.parse(argv: ["macop", "item", "get", "inject"], env: [:])
    try expect(itemNamedInject.command == .item, "an argument named inject must not select the inject command")
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
    let compositeValueRun = app.run(
        argv: ["macop", "run", "--", "/bin/sh", "-c", "printf '%s' \"$AUTH\""],
        env: ["AUTH": "Bearer keychain://generic/service/account"]
    )
    try expect(
        compositeValueRun.stdout == "Bearer <concealed by macop>",
        "masking must conceal only the resolved secret inside a composite value"
    )
    let executableDirectory = tempRoot.appendingPathComponent("child-path", isDirectory: true)
    try FileManager.default.createDirectory(at: executableDirectory, withIntermediateDirectories: false)
    let executable = executableDirectory.appendingPathComponent("macop-path-probe")
    try Data("#!/bin/sh\nprintf 'child-path\\n'\n".utf8).write(to: executable)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    let childPathRun = app.run(
        argv: ["macop", "run", "--no-masking", "--", "macop-path-probe"],
        env: ["PATH": executableDirectory.path]
    )
    try expect(
        childPathRun.exitCode == 0 && childPathRun.stdout == "child-path\n",
        "non-interactive run must resolve executables from the child PATH"
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

    let persistentReference = Data([0x01, 0x02, 0x03])
    let sharedContextAccess = RecordingKeychainSecurityAccess(
        referenceResponses: [
            KeychainSecurityResult(status: errSecSuccess, result: persistentReference as CFData)
        ],
        valueResponses: [
            KeychainSecurityResult(status: errSecSuccess, result: Data("context-secret".utf8) as CFData)
        ]
    )
    let sharedContextClient = SystemKeychainClient(securityAccess: sharedContextAccess)
    let sharedContextRead = sharedContextClient.read(.generic(service: "service", account: "account"))
    guard case let .success(sharedContextValue) = sharedContextRead else {
        throw SelftestFailure(message: "exact-one Security boundary should return the unique item")
    }
    try expect(
        String(data: sharedContextValue, encoding: .utf8) == "context-secret"
            && sharedContextAccess.referenceContexts.count == 1
            && sharedContextAccess.valueContexts.count == 1
            && sharedContextAccess.referenceContexts[0] === sharedContextAccess.valueContexts[0],
        "an exact-one read must enumerate once and perform one data read with the shared context"
    )

    let noMatchAccess = RecordingKeychainSecurityAccess(
        referenceResponses: [KeychainSecurityResult(status: errSecItemNotFound)]
    )
    guard case let .failure(noMatchFailure) = SystemKeychainClient(securityAccess: noMatchAccess)
        .read(.generic(service: "missing", account: "account"))
    else { throw SelftestFailure(message: "zero Keychain matches must fail") }
    try expect(
        noMatchFailure.status == errSecItemNotFound && noMatchAccess.valueContexts.isEmpty,
        "zero matches must map to not found without attempting a value read"
    )

    let ambiguousAccess = RecordingKeychainSecurityAccess(
        referenceResponses: [
            KeychainSecurityResult(
                status: errSecSuccess,
                result: NSArray(array: [persistentReference, Data([0x04, 0x05])])
            )
        ]
    )
    guard case let .failure(ambiguousFailure) = SystemKeychainClient(securityAccess: ambiguousAccess)
        .read(.internet(server: "server.example", account: "account"))
    else { throw SelftestFailure(message: "multiple Keychain matches must fail") }
    try expect(
        ambiguousFailure.isAmbiguous && ambiguousAccess.valueContexts.isEmpty,
        "multiple persistent references must be rejected before reading any secret"
    )

    let existingCreateAccess = RecordingKeychainSecurityAccess(referenceResponses: [
        KeychainSecurityResult(status: errSecSuccess, result: persistentReference as CFData)
    ])
    do {
        try SystemKeychainMutator(securityAccess: existingCreateAccess).create(
            Data("must-not-be-added".utf8),
            query: .internet(server: "server.example", account: "account")
        )
        throw SelftestFailure(message: "legacy create must reject any existing broad-selector match")
    } catch let error as CLIError {
        guard case .invalidArguments = error else { throw error }
    }
    try expect(
        existingCreateAccess.queries == [.internet(server: "server.example", account: "account")],
        "legacy create must enumerate zero exact-selector matches before SecItemAdd"
    )

    let createdReference = Data([0x10, 0x11, 0x12])
    let competingReference = Data([0x20, 0x21, 0x22])
    let concurrentCreateAccess = RecordingKeychainSecurityAccess(
        referenceResponses: [
            KeychainSecurityResult(status: errSecItemNotFound),
            KeychainSecurityResult(
                status: errSecSuccess,
                result: NSArray(array: [createdReference, competingReference])
            )
        ],
        addResponses: [
            KeychainSecurityResult(status: errSecSuccess, result: createdReference as CFData)
        ],
        deleteResponses: [errSecSuccess]
    )
    do {
        try SystemKeychainMutator(securityAccess: concurrentCreateAccess).create(
            Data("fixture-race-secret".utf8),
            query: .internet(server: "server.example", account: "account")
        )
        throw SelftestFailure(message: "a concurrent broad-selector add must fail closed")
    } catch let error as CLIError {
        guard case .invalidArguments = error else { throw error }
    }
    try expect(
        concurrentCreateAccess.queries == [
            .internet(server: "server.example", account: "account"),
            .internet(server: "server.example", account: "account")
        ]
            && concurrentCreateAccess.deletedReferences == [createdReference]
            && concurrentCreateAccess.addedContexts[0] === concurrentCreateAccess.deletedContexts[0],
        "postflight ambiguity must roll back only the persistent reference created by this process"
    )
    let missingCreateReferenceAccess = RecordingKeychainSecurityAccess(
        referenceResponses: [KeychainSecurityResult(status: errSecItemNotFound)],
        addResponses: [KeychainSecurityResult(status: errSecSuccess)]
    )
    do {
        try SystemKeychainMutator(securityAccess: missingCreateReferenceAccess).create(
            Data("fixture-missing-reference".utf8),
            query: .internet(server: "missing-ref.invalid", account: "account")
        )
        throw SelftestFailure(message: "successful add without persistent reference must be indeterminate")
    } catch let error as CLIError {
        guard case let .runtimeError(message) = error else { throw error }
        try expect(
            message.contains("indeterminate") && message.contains("may remain")
                && message.contains("No broad deletion was attempted")
                && missingCreateReferenceAccess.deletedReferences.isEmpty,
            "missing created reference must diagnose possible orphan without broad deletion"
        )
    }
    let failedRollbackAccess = RecordingKeychainSecurityAccess(
        referenceResponses: [
            KeychainSecurityResult(status: errSecItemNotFound),
            KeychainSecurityResult(
                status: errSecSuccess,
                result: NSArray(array: [createdReference, competingReference])
            )
        ],
        addResponses: [
            KeychainSecurityResult(status: errSecSuccess, result: createdReference as CFData)
        ],
        deleteResponses: [errSecAuthFailed]
    )
    do {
        try SystemKeychainMutator(securityAccess: failedRollbackAccess).create(
            Data("fixture-rollback-failure".utf8),
            query: .internet(server: "rollback.invalid", account: "account")
        )
        throw SelftestFailure(message: "unconfirmed targeted rollback must fail with reconciliation guidance")
    } catch let error as CLIError {
        guard case let .runtimeError(message) = error else { throw error }
        try expect(
            failedRollbackAccess.deletedReferences == [createdReference]
                && message.contains("may remain")
                && message.contains("No broad deletion was attempted"),
            "rollback failure must attempt only the created reference and diagnose possible orphan"
        )
    }

    let retryAccess = RecordingKeychainSecurityAccess(
        referenceResponses: [
            KeychainSecurityResult(status: errSecSuccess, result: persistentReference as CFData),
            KeychainSecurityResult(status: errSecSuccess, result: persistentReference as CFData)
        ],
        valueResponses: [
            KeychainSecurityResult(status: errSecAuthFailed),
            KeychainSecurityResult(status: errSecSuccess, result: Data("retry-secret".utf8) as CFData)
        ]
    )
    let retryClient = SystemKeychainClient(securityAccess: retryAccess)
    guard case let .failure(firstRetryFailure) = retryClient.read(.generic(service: "service", account: "account")),
          case .success = retryClient.read(.generic(service: "service", account: "account"))
    else { throw SelftestFailure(message: "Keychain authentication must be retryable after failure") }
    try expect(
        firstRetryFailure.status == errSecAuthFailed
            && retryAccess.referenceContexts[0] === retryAccess.valueContexts[0]
            && retryAccess.referenceContexts[1] === retryAccess.valueContexts[1]
            && retryAccess.referenceContexts[0] !== retryAccess.referenceContexts[1],
        "each read must use one fresh, internally shared LAContext"
    )

    for (status, expected) in [
        (errSecItemNotFound, Int32(6)),
        (errSecAuthFailed, Int32(5)),
        (errSecUserCanceled, Int32(5)),
        (errSecInteractionNotAllowed, Int32(5)),
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
    let ambiguousInternetApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .failure(.ambiguousInternetItem))
    )
    let ambiguousInternet = ambiguousInternetApp.run(
        argv: ["macop", "read", "keychain://internet/server.example/account"], env: [:]
    )
    try expect(ambiguousInternet.exitCode == 2, "ambiguous internet items must be rejected")
    try expect(!ambiguousInternet.stderr.contains("test-secret"), "ambiguous item errors must not leak values")
    let ambiguousGeneric = ambiguousInternetApp.run(
        argv: ["macop", "read", "keychain://generic/service/account"], env: [:]
    )
    try expect(ambiguousGeneric.exitCode == 2, "ambiguous generic items must be rejected")

    let secretLikeExpansion = "do-not-print-\(UUID().uuidString)"
    let invalidExpansion = app.run(
        argv: ["macop", "read", "keychain://generic/$SECRET_SELECTOR/account"],
        env: ["SECRET_SELECTOR": "\(secretLikeExpansion)?unsupported"]
    )
    try expect(invalidExpansion.exitCode == 3, "expanded invalid reference must fail")
    try expect(
        !invalidExpansion.stderr.contains(secretLikeExpansion),
        "reference expansion errors must not echo environment values"
    )
    let equalsOutputFlag = app.run(
        argv: ["macop", "read", "--out-file=token", "keychain://generic/service/account"],
        env: [:]
    )
    try expect(equalsOutputFlag.exitCode == 3, "persistent output equals flags should be unsupported")

    let expandedSelector = "secret-like-selector-\(UUID().uuidString)"
    struct ExpansionErrorCase {
        let arguments: [String]
        let expectedExitCode: Int32
        let description: String
    }
    let expansionErrorCases = [
        ExpansionErrorCase(arguments: ["macop", "read", "keychain://$SELECTOR/service/account"],
                           expectedExitCode: 2, description: "unsupported expanded keychain kind"),
        ExpansionErrorCase(arguments: ["macop", "--config", configDirectory, "read", "op://$SELECTOR/GitHub/token"],
                           expectedExitCode: 6, description: "missing expanded config mapping"),
        ExpansionErrorCase(arguments: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/$SELECTOR"],
                           expectedExitCode: 6, description: "missing expanded field"),
        ExpansionErrorCase(
            arguments: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/$SELECTOR/token"],
            expectedExitCode: 6,
            description: "missing expanded section"
        ),
        ExpansionErrorCase(arguments: ["macop", "read", "keychain://generic/$SELECTOR?attribute=otp/account"],
                           expectedExitCode: 3, description: "expanded query parameter")
    ]
    for errorCase in expansionErrorCases {
        let arguments = errorCase.arguments
        let expectedExitCode = errorCase.expectedExitCode
        let description = errorCase.description
        let environment = ["SELECTOR": expandedSelector]
        let human = app.run(argv: arguments, env: environment)
        try expect(human.exitCode == expectedExitCode, "\(description) should keep its typed exit code")
        try expect(
            !human.stderr.contains(expandedSelector),
            "\(description) must redact expanded values in human errors"
        )

        let json = app.run(argv: arguments + ["--format=json", "--debug"], env: environment)
        try expect(json.exitCode == expectedExitCode, "\(description) JSON should keep its typed exit code")
        _ = try JSONSerialization.jsonObject(with: Data(json.stderr.utf8))
        try expect(
            !json.stderr.contains(expandedSelector),
            "\(description) must redact expanded values in JSON/debug errors"
        )
    }

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
    let linkedConfigDirectory = tempRoot.deletingLastPathComponent()
        .appendingPathComponent("config-symlink-\(UUID().uuidString)")
    guard symlink(tempRoot.path, linkedConfigDirectory.path) == 0 else {
        throw SelftestFailure(message: "config directory symlink fixture requires a local symbolic link")
    }
    defer { _ = unlink(linkedConfigDirectory.path) }
    let directorySymlinkConfig = app.run(
        argv: ["macop", "--config", linkedConfigDirectory.path, "config", "validate"], env: [:]
    )
    try expect(directorySymlinkConfig.exitCode == 2, "config directory symlinks must be rejected")

    let originalConfigPath = tempRoot.appendingPathComponent("config-original.json")
    try fileManager.moveItem(at: configPath, to: originalConfigPath)
    guard symlink(originalConfigPath.path, configPath.path) == 0 else {
        throw SelftestFailure(message: "config file symlink fixture requires a local symbolic link")
    }
    let fileSymlinkConfig = app.run(
        argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:]
    )
    try expect(fileSymlinkConfig.exitCode == 2, "config file symlinks must be rejected")
    try fileManager.removeItem(at: configPath)
    try fileManager.moveItem(at: originalConfigPath, to: configPath)

    if ProcessInfo.processInfo.environment["MACOP_RUN_ACL_INTEGRATION"] == "1" {
        let chmod = Process()
        chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
        chmod.arguments = ["+a", "everyone allow read", configPath.path]
        try chmod.run()
        chmod.waitUntilExit()
        guard chmod.terminationStatus == 0 else {
            throw SelftestFailure(message: "ACL integration fixture could not grant an extended ACL")
        }
        let aclRejected = app.run(
            argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:]
        )
        try expect(aclRejected.exitCode == 2, "config file extended ACLs must be rejected")
        guard let emptyACL = acl_init(0) else {
            throw SelftestFailure(message: "ACL integration fixture could not construct an empty ACL")
        }
        defer { acl_free(UnsafeMutableRawPointer(emptyACL)) }
        guard acl_set_file(configPath.path, ACL_TYPE_EXTENDED, emptyACL) == 0 else {
            throw SelftestFailure(message: "ACL integration fixture could not clear the extended ACL")
        }
    }

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
    let unsupportedItem = app.run(argv: ["macop", "item", "move", "potential-secret"], env: [:])
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
    try expect(queryReference.exitCode == 6, "OTP query should require configured OTP metadata")
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

    for metadata in [
        String(repeating: "a", count: AuthBrokerWire.maximumMetadataLength + 1),
        "unsafe\nselector",
        "unsafe\u{202E}selector"
    ] {
        let unsafeManagedConfig: [String: Any] = [
            "version": 2,
            "items": [
                "Local/Managed": [
                    "provider": "keychain-managed", "service": metadata, "account": "fixture-account"
                ]
            ]
        ]
        try JSONSerialization.data(withJSONObject: unsafeManagedConfig).write(to: configPath, options: [.atomic])
        let result = app.run(
            argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:]
        )
        try expect(
            result.exitCode == ExitCode.invalidArguments.rawValue,
            "managed selector length, control, and bidi metadata must fail before broker transport"
        )

        let legacyConfig: [String: Any] = [
            "version": 1,
            "items": [
                "Local/Legacy": [
                    "provider": "keychain-generic", "service": metadata, "account": "fixture-account"
                ]
            ]
        ]
        try JSONSerialization.data(withJSONObject: legacyConfig).write(to: configPath, options: [.atomic])
        let legacyResult = app.run(
            argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:]
        )
        try expect(
            legacyResult.exitCode == 0,
            "schema v1 must preserve its prior selector metadata acceptance contract"
        )

        let legacyManagedConfig: [String: Any] = [
            "version": 1,
            "items": [
                "Local/LegacyManaged": [
                    "provider": "keychain-managed", "service": metadata, "account": "fixture-account"
                ]
            ]
        ]
        try JSONSerialization.data(withJSONObject: legacyManagedConfig).write(to: configPath, options: [.atomic])
        let legacyManagedResult = app.run(
            argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:]
        )
        try expect(
            legacyManagedResult.exitCode == ExitCode.invalidArguments.rawValue,
            "schema v1 managed selectors must still fit the mandatory broker wire contract"
        )
    }

    let safeLegacyManagedConfig = """
    { "version": 1, "items": {
      "Local/LegacyManaged": {
        "provider": "keychain-managed", "service": "legacy-managed", "account": "fixture-account"
      }
    } }
    """
    try safeLegacyManagedConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    try expect(
        app.run(
            argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:]
        ).exitCode == 0,
        "wire-safe schema v1 managed selectors must remain supported"
    )

    let validSectionFieldConfig = """
    { "version": 2, "items": {
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

    let mutationConfig = """
    { "version": 1, "items": {
      "Local/Generic": {
        "provider": "keychain-generic", "service": "mutation-service", "account": "mutation-account"
      },
      "Local/Internet": {
        "provider": "keychain-internet", "server": "example.invalid", "account": "mutation-account"
      }
    } }
    """
    try mutationConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let keychainMutator = RecordingKeychainMutator()
    let mutationApp = MacopApp(
        keychainClient: RecordingKeychainClient(.success(Data())),
        keychainMutator: keychainMutator
    )
    let createSecret = Data("create-secret".utf8)
    let createResult = mutationApp.run(
        argv: ["macop", "--config", configDirectory, "item", "create", "Generic"],
        env: [:],
        input: createSecret
    )
    try expect(createResult.exitCode == 0, "item create must accept exact generic selectors")
    try expect(
        keychainMutator.creates.count == 1
            && keychainMutator.creates[0].secret == createSecret
            && keychainMutator.creates[0].query == .generic(
                service: "mutation-service",
                account: "mutation-account"
            ),
        "item create must forward only secret stdin and the configured selector"
    )
    let editSecret = Data("edit-secret".utf8)
    let editResult = mutationApp.run(
        argv: ["macop", "--config", configDirectory, "item", "edit", "Internet"],
        env: [:],
        input: editSecret
    )
    try expect(editResult.exitCode == 0, "item edit must accept exact internet selectors")
    try expect(
        keychainMutator.edits.count == 1
            && keychainMutator.edits[0].secret == editSecret
            && keychainMutator.edits[0].query == .internet(
                server: "example.invalid",
                account: "mutation-account"
            ),
        "item edit must forward only secret stdin and the configured selector"
    )
    let deleteResult = mutationApp.run(
        argv: ["macop", "--config", configDirectory, "item", "delete", "Generic"], env: [:]
    )
    try expect(deleteResult.exitCode == 0, "item delete must accept configured generic items")
    try expect(
        keychainMutator.deletes == [.generic(service: "mutation-service", account: "mutation-account")],
        "item delete must forward the exact configured generic selector"
    )
    let emptyCreate = mutationApp.run(
        argv: ["macop", "--config", configDirectory, "item", "create", "Generic"], env: [:]
    )
    try expect(emptyCreate.exitCode == 2, "item create must reject empty stdin before Keychain access")
    let generatedCreate = mutationApp.run(
        argv: ["macop", "--config", configDirectory, "item", "generate", "Generic", "--length", "32"],
        env: [:]
    )
    let generatedEdit = mutationApp.run(
        argv: [
            "macop", "--config", configDirectory, "item", "generate", "--replace", "Generic", "--length", "36"
        ],
        env: [:]
    )
    try expect(
        generatedCreate.exitCode == 0 && generatedEdit.exitCode == 0
            && keychainMutator.creates.last?.secret.count == 32
            && keychainMutator.edits.last?.secret.count == 36,
        "legacy item generation must distinguish create from exact-item replacement"
    )

    let itemNameResolutionConfig = """
    { "version": 2, "items": {
      "Dogfood/Managed": {
        "provider": "keychain-managed", "service": "dogfood-managed", "account": "dogfood-user",
        "fields": ["token"],
        "otp": {
          "service": "dogfood-otp", "account": "dogfood-otp-user",
          "algorithm": "SHA1", "digits": 6, "period": 30
        }
      },
      "Other/Managed": {
        "provider": "keychain-managed", "service": "other-managed", "account": "other-user",
        "fields": ["token"],
        "otp": {
          "service": "other-otp", "account": "other-otp-user",
          "algorithm": "SHA1", "digits": 6, "period": 30
        }
      },
      "Dogfood/Unique": {
        "provider": "keychain-generic", "service": "unique-generic", "account": "unique-user",
        "fields": ["token"]
      },
      "Legacy/Scoped": {
        "provider": "keychain-generic", "service": "legacy-scoped", "account": "legacy-user"
      },
      "Dogfood/Scoped": {
        "provider": "keychain-managed", "service": "managed-scoped", "account": "managed-user"
      },
      "Dogfood/SSH": { "provider": "secure-enclave", "label": "item-name-fixture" }
    } }
    """
    try itemNameResolutionConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let nameResolutionImporter = RecordingManagedKeychainImporter()
    let nameResolutionDeleter = RecordingManagedKeychainDeleter()
    let nameResolutionMutator = RecordingKeychainMutator()
    let nameResolutionClient = RecordingKeychainClient(.success(Data("name-resolution-secret".utf8)))
    let nameResolutionApp = MacopApp(
        keychainClient: nameResolutionClient,
        managedKeychainImporter: nameResolutionImporter,
        managedKeychainDeleter: nameResolutionDeleter,
        keychainMutator: nameResolutionMutator
    )
    let fullList = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "list"], env: [:]
    )
    try expect(
        fullList.stdout.contains("Dogfood/Managed") && fullList.stdout.contains("Other/Managed"),
        "item list must expose the full keys accepted by subsequent item operations"
    )
    let exactFullGenerate = nameResolutionApp.run(
        argv: [
            "macop", "--config", configDirectory, "item", "generate", "Dogfood/Managed", "--length", "32"
        ],
        env: [:]
    )
    let disambiguatedFullGenerate = nameResolutionApp.run(
        argv: [
            "macop", "--config", configDirectory, "item", "generate", "Other/Managed", "--length", "32"
        ],
        env: [:]
    )
    try expect(
        exactFullGenerate.exitCode == 0 && disambiguatedFullGenerate.exitCode == 0
            && nameResolutionImporter.generatedImports.map(\.service) == ["dogfood-managed", "other-managed"],
        "exact full item keys must take priority and disambiguate duplicate leaves"
    )
    let ambiguousLeafGenerate = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "generate", "Managed"], env: [:]
    )
    try expect(
        ambiguousLeafGenerate.exitCode == ExitCode.invalidArguments.rawValue
            && ambiguousLeafGenerate.stderr.contains("ambiguous")
            && ambiguousLeafGenerate.stderr.contains("Dogfood/Managed")
            && ambiguousLeafGenerate.stderr.contains("Other/Managed")
            && nameResolutionImporter.generatedImports.count == 2,
        "duplicate leaf item names must require a full key without invoking a provider"
    )
    let ambiguousManagedImport = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "import", "Managed"],
        env: [:],
        input: Data("ambiguous-import-secret".utf8)
    )
    try expect(
        ambiguousManagedImport.exitCode == ExitCode.invalidArguments.rawValue
            && ambiguousManagedImport.stderr.contains("ambiguous")
            && nameResolutionImporter.imports.isEmpty,
        "managed-only item operations must reject duplicate leaves before broker access"
    )
    let uniqueLeafCreate = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "create", "Unique"],
        env: [:],
        input: Data("unique-create-secret".utf8)
    )
    let fullEdit = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "edit", "Dogfood/Unique"],
        env: [:],
        input: Data("unique-edit-secret".utf8)
    )
    let fullGet = nameResolutionApp.run(
        argv: [
            "macop", "--config", configDirectory, "item", "get", "Dogfood/Unique",
            "--fields", "label=token", "--reveal"
        ],
        env: [:]
    )
    try expect(
        uniqueLeafCreate.exitCode == 0 && fullEdit.exitCode == 0 && fullGet.exitCode == 0
            && nameResolutionMutator.creates.last?.query == .generic(
                service: "unique-generic", account: "unique-user"
            )
            && nameResolutionMutator.edits.last?.query == .generic(
                service: "unique-generic", account: "unique-user"
            ),
        "legacy create/edit/get must accept unique leaf and exact full item keys consistently"
    )
    let fullImport = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "import", "Dogfood/Managed"],
        env: [:],
        input: Data("full-import-secret".utf8)
    )
    let fullAcquire = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "acquire", "Dogfood/Managed"], env: [:]
    )
    let providerScopedAcquire = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "acquire", "Scoped"], env: [:]
    )
    let fullDelete = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "delete", "Other/Managed"], env: [:]
    )
    try expect(
        fullImport.exitCode == 0 && fullAcquire.exitCode == 0
            && providerScopedAcquire.exitCode == 0 && fullDelete.exitCode == 0
            && nameResolutionImporter.imports.last?.service == "dogfood-managed"
            && nameResolutionClient.queries.contains(.managed(
                service: "dogfood-managed", account: "dogfood-user"
            ))
            && nameResolutionClient.queries.contains(.managed(
                service: "managed-scoped", account: "managed-user"
            ))
            && nameResolutionDeleter.deletes.first?.service == "other-managed",
        "managed import/acquire/delete must share full-key and provider-scoped leaf resolution"
    )
    let otpNameApp = MacopApp(
        otpSeedClient: RecordingKeychainClient(.success(Data("JBSWY3DPEHPK3PXP".utf8)))
    )
    let fullOTP = otpNameApp.run(
        argv: ["macop", "--config", configDirectory, "item", "otp", "Dogfood/Managed"], env: [:]
    )
    let ambiguousOTP = otpNameApp.run(
        argv: ["macop", "--config", configDirectory, "item", "otp", "Managed"], env: [:]
    )
    try expect(
        fullOTP.exitCode == 0
            && ambiguousOTP.exitCode == ExitCode.invalidArguments.rawValue
            && ambiguousOTP.stderr.contains("ambiguous"),
        "OTP operations must accept full keys and reject ambiguous leaf names"
    )
    let unsupportedFullItem = nameResolutionApp.run(
        argv: ["macop", "--config", configDirectory, "item", "get", "Dogfood/SSH"], env: [:]
    )
    try expect(
        unsupportedFullItem.exitCode == ExitCode.unsupported.rawValue
            && unsupportedFullItem.stderr.contains("secure-enclave")
            && nameResolutionClient.queries.count == 3,
        "an exact full key with an unsupported provider must fail before provider access"
    )

    let managedConfig = """
    { "version": 2, "items": {
      "Local/Managed": {
        "provider": "keychain-managed", "service": "github-token", "account": "me", "fields": ["token"]
      },
      "Local/Cloud": {
        "provider": "keychain-managed", "service": "cloud-token", "account": "me",
        "fields": ["token"], "synchronization": "icloud"
      }
    }, "profiles": {
      "autofill-profile": {
        "executable": "/usr/bin/printenv",
        "environment": { "AUTOFILL_PROFILE_SECRET": "op://Local/Managed/password" }
      }
    } }
    """
    try managedConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let managedClient = RecordingKeychainClient(.success(Data("managed-secret".utf8)))
    let managedImporter = RecordingManagedKeychainImporter()
    let managedDeleter = RecordingManagedKeychainDeleter()
    let managedApp = MacopApp(
        keychainClient: managedClient,
        managedKeychainImporter: managedImporter,
        managedKeychainDeleter: managedDeleter
    )
    let managedRead = managedApp.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/Managed/token"], env: [:]
    )
    try expect(managedRead.exitCode == 0, "managed Keychain config items must be readable")
    try expect(
        managedClient.queries == [.managed(service: "github-token", account: "me")],
        "managed config items must route to the managed Keychain query"
    )
    let managedSecret = Data("new-managed-secret".utf8)
    let managedImportResult = managedApp.run(
        argv: ["macop", "--config", configDirectory, "item", "import", "Managed"],
        env: [:],
        input: managedSecret
    )
    try expect(managedImportResult.exitCode == 0, "item import must accept configured managed items")
    try expect(
        managedImporter.imports.count == 1
            && managedImporter.imports[0].secret == managedSecret
            && managedImporter.imports[0].service == "github-token"
            && managedImporter.imports[0].account == "me"
            && !managedImporter.imports[0].synchronizable,
        "item import must forward exact stdin and configured selectors"
    )
    let emptyManagedImport = managedApp.run(
        argv: ["macop", "--config", configDirectory, "item", "import", "Managed"], env: [:]
    )
    try expect(emptyManagedImport.exitCode == 2, "item import must reject empty stdin before broker access")
    let cloudImport = managedApp.run(
        argv: ["macop", "--config", configDirectory, "item", "import", "Cloud"],
        env: [:],
        input: managedSecret
    )
    try expect(cloudImport.exitCode == 0, "item import must accept an explicit iCloud managed item")
    try expect(
        managedImporter.imports.count == 2
            && managedImporter.imports[1].service == "cloud-token"
            && managedImporter.imports[1].synchronizable,
        "iCloud synchronization must be explicit and reach the managed Keychain boundary"
    )
    let managedDelete = managedApp.run(
        argv: ["macop", "--config", configDirectory, "item", "delete", "Managed"], env: [:]
    )
    try expect(managedDelete.exitCode == 0, "item delete must accept a configured managed item")
    try expect(
        managedDeleter.deletes.count == 1
            && managedDeleter.deletes[0].service == "github-token"
            && managedDeleter.deletes[0].account == "me"
            && !managedDeleter.deletes[0].synchronizable,
        "item delete must forward the exact configured selectors"
    )
    let managedDeleteAll = managedApp.run(
        argv: ["macop", "item", "delete", "--all-managed"], env: [:]
    )
    try expect(managedDeleteAll.exitCode == 0, "item delete --all-managed must not require config")
    try expect(managedDeleter.deleteAllCount == 1, "item delete --all-managed must use scoped bulk deletion")

    let unusedAutoFill = RecordingPasswordAutoFillProvider()
    let existingAcquireApp = MacopApp(
        keychainClient: managedClient,
        managedKeychainImporter: managedImporter,
        passwordAutoFillProvider: unusedAutoFill
    )
    let existingAcquire = existingAcquireApp.run(
        argv: ["macop", "--config", configDirectory, "item", "acquire", "Managed"], env: [:]
    )
    try expect(existingAcquire.exitCode == 0, "item acquire must prefer an available managed Keychain item")
    try expect(existingAcquire.stdout == "managed-secret\n", "item acquire must return the available credential")
    try expect(unusedAutoFill.requests.isEmpty, "an available managed item must not launch Password AutoFill")

    let missingManagedClient = RecordingKeychainClient(.failure(KeychainFailure(errSecItemNotFound)))
    let automaticAutoFill = RecordingPasswordAutoFillProvider(saveStatus: .notRequested)
    let missingAcquire = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: automaticAutoFill
    ).run(argv: ["macop", "--config", configDirectory, "item", "acquire", "Managed"], env: [:])
    try expect(missingAcquire.exitCode == 0, "a missing managed item must fall back to Password AutoFill")
    try expect(missingAcquire.stdout == "passwords-secret\n", "item acquire must return the selected password")
    try expect(
        automaticAutoFill.requests.count == 1
            && automaticAutoFill.requests[0].service == "github-token"
            && automaticAutoFill.requests[0].account == "me"
            && automaticAutoFill.requests[0].purpose == .itemAcquire,
        "Password AutoFill must receive the exact configured selectors"
    )

    let fallbackReadAutoFill = RecordingPasswordAutoFillProvider(secret: Data("fallback-read-secret".utf8))
    let fallbackRead = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: fallbackReadAutoFill
    ).run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/Managed/token"], env: [:]
    )
    try expect(fallbackRead.exitCode == 0, "read must fall back when a managed item is missing")
    try expect(fallbackRead.stdout == "fallback-read-secret\n", "read must return the selected password")
    try expect(
        fallbackReadAutoFill.requests.count == 1
            && fallbackReadAutoFill.requests[0].purpose == .read,
        "read fallback must identify the actual requesting command"
    )

    let fallbackInjectAutoFill = RecordingPasswordAutoFillProvider(secret: Data("fallback-inject-secret".utf8))
    let fallbackInject = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: fallbackInjectAutoFill
    ).run(
        argv: ["macop", "--config", configDirectory, "inject"],
        env: [:],
        input: Data("op://Local/Managed/token op://Local/Managed/token".utf8)
    )
    try expect(fallbackInject.exitCode == 0, "inject must fall back when a managed item is missing")
    try expect(
        fallbackInject.stdout == "fallback-inject-secret fallback-inject-secret",
        "inject must use the selected password for every matching reference"
    )
    try expect(
        fallbackInjectAutoFill.requests.count == 1
            && fallbackInjectAutoFill.requests[0].purpose == .inject,
        "one command must cache a Passwords selection instead of prompting twice"
    )

    let fallbackRunAutoFill = RecordingPasswordAutoFillProvider(secret: Data("fallback-run-secret".utf8))
    let fallbackRun = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: fallbackRunAutoFill
    ).run(
        argv: [
            "macop", "--config", configDirectory, "run", "--no-masking", "--",
            "/usr/bin/printenv", "MACOP_FALLBACK_SECRET"
        ],
        env: ["MACOP_FALLBACK_SECRET": "op://Local/Managed/token"]
    )
    try expect(fallbackRun.exitCode == 0, "run must fall back when a managed item is missing")
    try expect(fallbackRun.stdout == "fallback-run-secret\n", "run must inject the selected password")
    try expect(
        fallbackRunAutoFill.requests.count == 1
            && fallbackRunAutoFill.requests[0].purpose == .run,
        "run fallback must identify the actual requesting command"
    )

    let fallbackProfileAutoFill = RecordingPasswordAutoFillProvider(
        secret: Data("fallback-profile-secret".utf8)
    )
    let fallbackProfile = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: fallbackProfileAutoFill
    ).run(
        argv: [
            "macop", "--config", configDirectory, "profile", "run", "autofill-profile", "--",
            "/usr/bin/printenv", "AUTOFILL_PROFILE_SECRET"
        ],
        env: [:]
    )
    try expect(fallbackProfile.exitCode == 0, "profile must fall back when a managed item is missing")
    try expect(
        fallbackProfileAutoFill.requests.count == 1
            && fallbackProfileAutoFill.requests[0].purpose == .profile,
        "profile fallback must attest its operation-specific AutoFill purpose"
    )

    let indeterminateSaveSecret = "autofill-indeterminate-secret"
    let indeterminateSaveProvider = RecordingPasswordAutoFillProvider(
        secret: Data(indeterminateSaveSecret.utf8),
        saveStatus: .indeterminate
    )
    let indeterminateSaveApp = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: indeterminateSaveProvider
    )
    let indeterminateSaveResults = [
        indeterminateSaveApp.run(
            argv: ["macop", "--config", configDirectory, "read", "op://Local/Managed/password"], env: [:]
        ),
        indeterminateSaveApp.run(
            argv: ["macop", "--config", configDirectory, "inject"], env: [:],
            input: Data("op://Local/Managed/password".utf8)
        ),
        indeterminateSaveApp.run(
            argv: ["macop", "--config", configDirectory, "run", "--", "/usr/bin/true"],
            env: ["AUTOFILL_SECRET": "op://Local/Managed/password"]
        ),
        indeterminateSaveApp.run(
            argv: [
                "macop", "--config", configDirectory, "profile", "run", "autofill-profile", "--",
                "/usr/bin/printenv", "AUTOFILL_PROFILE_SECRET"
            ],
            env: [:]
        ),
        indeterminateSaveApp.run(
            argv: ["macop", "--config", configDirectory, "item", "acquire", "Managed"], env: [:]
        )
    ]
    try expect(
        indeterminateSaveResults.allSatisfy {
            $0.exitCode == ExitCode.runtimeError.rawValue
                && $0.stderr.contains("save verification was indeterminate")
                && !$0.stdout.contains(indeterminateSaveSecret)
                && !$0.stderr.contains(indeterminateSaveSecret)
        },
        "read/run/inject/profile/item-acquire must preserve and display AutoFill save-indeterminate outcomes"
    )
    let failedSave = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: RecordingPasswordAutoFillProvider(
            saveStatus: .failed,
            saveResultStatus: errSecAuthFailed
        )
    ).run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/Managed/password"], env: [:]
    )
    try expect(
        failedSave.exitCode == ExitCode.runtimeError.rawValue
            && failedSave.stderr.contains("managed Keychain save failed")
            && failedSave.stderr.contains("OSStatus \(errSecAuthFailed)"),
        "received AutoFill save failures must not be discarded"
    )
    let lostAutoFillResponse = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: FailingPasswordAutoFillProvider(failure: .responseLost)
    ).run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/Managed/password"], env: [:]
    )
    try expect(
        lostAutoFillResponse.exitCode == ExitCode.runtimeError.rawValue
            && lostAutoFillResponse.stderr.contains("request may have been delivered")
            && lostAutoFillResponse.stderr.contains("save may have completed"),
        "post-send AutoFill response loss must retain secret-free reconciliation guidance"
    )
    let lostForcedAutoFillResponse = MacopApp(
        keychainClient: RecordingKeychainClient(.success(Data("unused-managed-secret".utf8))),
        passwordAutoFillProvider: FailingPasswordAutoFillProvider(failure: .responseLost)
    ).run(
        argv: [
            "macop", "--config", configDirectory, "item", "acquire", "Managed", "--from-passwords"
        ],
        env: [:]
    )
    try expect(
        lostForcedAutoFillResponse.exitCode == ExitCode.runtimeError.rawValue
            && lostForcedAutoFillResponse.stderr.contains("request may have been delivered"),
        "forced AutoFill must preserve the same typed post-send response-loss outcome"
    )
    let runAutoFillCallers: (any PasswordAutoFillProviding) -> [CommandResult] = { provider in
        let callerApp = MacopApp(
            keychainClient: missingManagedClient,
            passwordAutoFillProvider: provider
        )
        return [
            callerApp.run(
                argv: ["macop", "--config", configDirectory, "read", "op://Local/Managed/password"], env: [:]
            ),
            callerApp.run(
                argv: ["macop", "--config", configDirectory, "inject"], env: [:],
                input: Data("op://Local/Managed/password".utf8)
            ),
            callerApp.run(
                argv: ["macop", "--config", configDirectory, "run", "--", "/usr/bin/true"],
                env: ["AUTOFILL_SECRET": "op://Local/Managed/password"]
            ),
            callerApp.run(
                argv: [
                    "macop", "--config", configDirectory, "profile", "run", "autofill-profile", "--",
                    "/usr/bin/printenv", "AUTOFILL_PROFILE_SECRET"
                ],
                env: [:]
            ),
            callerApp.run(
                argv: ["macop", "--config", configDirectory, "item", "acquire", "Managed"], env: [:]
            )
        ]
    }
    let invalidAutoFillCallerResults = runAutoFillCallers(
        FailingPasswordAutoFillProvider(failure: .invalidResponse)
    )
    try expect(
        invalidAutoFillCallerResults.allSatisfy {
            $0.exitCode == ExitCode.runtimeError.rawValue
                && $0.stderr.contains("invalid response")
                && $0.stderr.contains("may have been delivered")
                && !$0.stderr.contains("classifier-fixture")
        },
        "post-send invalid AutoFill responses must reach every caller as secret-free typed uncertainty"
    )
    for invalidCredential in [
        Data(),
        Data([0xFF, 0xFE]),
        Data("nul\0credential".utf8),
        Data(repeating: 0x41, count: ManagedKeychainStore.maximumSecretLength + 1)
    ] {
        let invalidCredentialResults = runAutoFillCallers(
            ClassifyingPasswordAutoFillProvider(secret: invalidCredential)
        )
        try expect(
            invalidCredentialResults.allSatisfy {
                $0.exitCode == ExitCode.runtimeError.rawValue
                    && $0.stderr.contains("invalid response")
                    && $0.stderr.contains("reconcile the configured item")
                    && $0.stdout.isEmpty
            },
            "empty, oversized, invalid UTF-8, or NUL AutoFill credentials must be rejected before every caller "
                + "can cache or use them"
        )
    }

    let deniedFallback = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: DenyingPasswordAutoFillProvider()
    ).run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/Managed/token"], env: [:]
    )
    try expect(deniedFallback.exitCode == 5, "cancelled Password AutoFill must remain an access denial")

    let legacyMissingAutoFill = RecordingPasswordAutoFillProvider()
    let legacyMissing = MacopApp(
        keychainClient: missingManagedClient,
        passwordAutoFillProvider: legacyMissingAutoFill
    ).run(
        argv: ["macop", "read", "keychain://generic/missing/me"], env: [:]
    )
    try expect(legacyMissing.exitCode == 6, "legacy Keychain misses must remain not found")
    try expect(
        legacyMissingAutoFill.requests.isEmpty,
        "legacy Keychain providers must never trigger the managed Passwords fallback"
    )

    let forcedManagedClient = RecordingKeychainClient(.success(Data("stale-secret".utf8)))
    let forcedAutoFill = RecordingPasswordAutoFillProvider()
    let forcedAcquire = MacopApp(
        keychainClient: forcedManagedClient,
        passwordAutoFillProvider: forcedAutoFill
    ).run(
        argv: [
            "macop", "--config", configDirectory, "item", "acquire", "Managed", "--from-passwords"
        ],
        env: [:]
    )
    try expect(forcedAcquire.exitCode == 0, "explicit Passwords fallback must succeed")
    try expect(forcedAcquire.stdout == "passwords-secret\n", "explicit fallback must return the selected password")
    try expect(
        forcedManagedClient.queries.isEmpty
            && forcedAutoFill.requests.count == 1
            && forcedAutoFill.requests[0].purpose == .itemAcquire,
        "explicit Passwords fallback must not re-read a known-bad managed credential"
    )

    let deniedManagedClient = RecordingKeychainClient(.failure(KeychainFailure(errSecUserCanceled)))
    let deniedAutoFill = RecordingPasswordAutoFillProvider()
    let deniedAcquire = MacopApp(
        keychainClient: deniedManagedClient,
        passwordAutoFillProvider: deniedAutoFill
    ).run(argv: ["macop", "--config", configDirectory, "item", "acquire", "Managed"], env: [:])
    try expect(deniedAcquire.exitCode != 0, "cancelled Keychain access must not silently fall back")
    try expect(deniedAutoFill.requests.isEmpty, "cancelled Keychain access must preserve user cancellation")

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
    try expect(zshCompletion.stdout.contains("'otp command' import edit delete"), "zsh should complete OTP lifecycle")
    try expect(
        zshCompletion.stdout.contains("__macop_zsh_next_positional_index")
            && zshCompletion.stdout.contains("--config|--format|--encoding")
            && zshCompletion.stdout.contains("--config=*|--format=*|--encoding=*"),
        "zsh completion must parse valued global options before positional commands"
    )
    let bashCompletion = app.run(argv: ["macop", "completion", "bash"], env: [:])
    try expect(bashCompletion.stdout.contains("init validate"), "bash completion should offer config subcommands")
    try expect(bashCompletion.stdout.contains("import edit delete"), "bash should complete OTP lifecycle")
    try expect(
        bashCompletion.stdout.contains("__macop_bash_next_positional_index")
            && bashCompletion.stdout.contains("--config|--format|--encoding")
            && bashCompletion.stdout.contains("--config=*|--format=*|--encoding=*"),
        "bash completion must parse valued global options before positional commands"
    )
    for (shell, executable, completion, setup) in [
        (
            "zsh", "/bin/zsh", zshCompletion.stdout,
            "compdef() { :; }; _arguments() { :; }; _values() { printf '<%s>\\n' \"$@\"; }; "
                + "words=(macop item --format json otp ''); CURRENT=6; _macop"
        ),
        (
            "bash", "/bin/bash", bashCompletion.stdout,
            "COMP_WORDS=(macop item --format json otp ''); COMP_CWORD=5; _macop_complete; "
                + "printf '<%s>\\n' \"${COMPREPLY[@]}\""
        )
    ] {
        let separated = try runProcess(
            executable: executable,
            arguments: [
                "-c",
                (shell == "zsh" ? "compdef() { :; }\n" : "") + completion + "\n" + setup
            ]
        )
        try expect(
            separated.status == 0
                && separated.stdout.contains("<import>")
                && separated.stdout.contains("<edit>")
                && separated.stdout.contains("<delete>")
                && !separated.stdout.contains("<list>")
                && separated.stderr.isEmpty,
            "\(shell) completion must recognize item --format json otp positionally"
        )
        let joinedSetup = if shell == "zsh" {
            "compdef() { :; }; _arguments() { :; }; _values() { printf '<%s>\\n' \"$@\"; }; "
                + "words=(macop --config /tmp item --format=json otp ''); CURRENT=7; _macop"
        } else {
            "COMP_WORDS=(macop --config /tmp item --format=json otp ''); COMP_CWORD=6; "
                + "_macop_complete; printf '<%s>\\n' \"${COMPREPLY[@]}\""
        }
        let joined = try runProcess(
            executable: executable,
            arguments: [
                "-c",
                (shell == "zsh" ? "compdef() { :; }\n" : "") + completion + "\n" + joinedSetup
            ]
        )
        try expect(
            joined.status == 0
                && joined.stdout.contains("<import>")
                && joined.stdout.contains("<edit>")
                && joined.stdout.contains("<delete>")
                && !joined.stdout.contains("<list>")
                && joined.stderr.isEmpty,
            "\(shell) completion must skip global options before command and between item and otp"
        )
    }
    let fishCompletion = app.run(argv: ["macop", "completion", "fish"], env: [:])
    try expect(fishCompletion.stdout.contains("-l format"), "fish completion should offer format values")
    try expect(fishCompletion.stdout.contains("import edit delete"), "fish should complete OTP lifecycle")
    try expect(
        fishCompletion.stdout.contains("function __macop_next_positional_index")
            && fishCompletion.stdout.contains("function __macop_command_index")
            && fishCompletion.stdout.contains("case --config --format --encoding")
            && fishCompletion.stdout.contains("case '--config=*' '--format=*' '--encoding=*' --no-color --debug")
            && fishCompletion.stdout.contains("string match -q -- $argv[1] (__macop_command)")
            && fishCompletion.stdout.contains("__macop_command_position item")
            && fishCompletion.stdout.contains("set -l command_index (__macop_command_index)")
            && fishCompletion.stdout.contains(
                "set -l otp_index (__macop_next_positional_index (math $command_index + 1))"
            )
            && fishCompletion.stdout.contains("string match -q -- otp $words[$otp_index]")
            && fishCompletion.stdout.contains("__macop_item_position; and not __macop_otp_position")
            && fishCompletion.stdout.contains("__macop_item_position; and __macop_otp_position")
            && fishCompletion.stdout.contains("__macop_command_position generate")
            && fishCompletion.stdout.contains("__macop_command_position profile")
            && fishCompletion.stdout.contains("__macop_command_position config")
            && fishCompletion.stdout.contains("__macop_command_position ssh")
            && !fishCompletion.stdout.contains("__fish_seen_subcommand_from"),
        "fish completion must skip valued/global flags before commands and between item and OTP positions"
    )
    let currentHelp = app.run(argv: ["macop", "--help"], env: [:])
    try expect(
        !currentHelp.stdout.contains("MVP scaffold")
            && currentHelp.stdout.contains("item list")
            && currentHelp.stdout.contains("item acquire")
            && currentHelp.stdout.contains("item delete")
            && currentHelp.stdout.contains("full <namespace>/<item> key"),
        "help must advertise the established item operations without stale MVP scaffold wording"
    )
}

private func runKeychainNativeExtensions() throws {
    let mutationSecret = Data("managed-mutation-fixture".utf8)
    let readbackFailureAccess = FaultingManagedKeychainStoreAccess(
        readResult: .failure(KeychainFailure(errSecInteractionNotAllowed))
    )
    let addReadbackFailure = ManagedKeychainStore.importSecret(
        mutationSecret, service: "fixture-service", account: "fixture-account",
        synchronizable: false, authenticationContext: LAContext(), access: readbackFailureAccess
    )
    try expect(
        addReadbackFailure == .indeterminate
            && PasswordAutoFillSaveStatus(mutationOutcome: addReadbackFailure) == .indeterminate,
        "a successful managed add followed by readback failure must be indeterminate, including AutoFill save"
    )
    let mismatchAccess = FaultingManagedKeychainStoreAccess(
        readResult: .success(Data("different-readback".utf8))
    )
    let updateReadbackMismatch = ManagedKeychainStore.updateSecret(
        mutationSecret, service: "fixture-service", account: "fixture-account",
        synchronizable: false, authenticationContext: LAContext(), access: mismatchAccess
    )
    try expect(
        updateReadbackMismatch == .indeterminate && mismatchAccess.updateCount == 1
            && mismatchAccess.readCount == 1,
        "a successful managed update followed by mismatched readback must be indeterminate"
    )
    let upsertReadbackFailure = ManagedKeychainStore.upsertSecret(
        mutationSecret, service: "fixture-service", account: "fixture-account",
        synchronizable: false, authenticationContext: LAContext(), access: readbackFailureAccess
    )
    try expect(
        upsertReadbackFailure == .indeterminate,
        "a successful AutoFill upsert followed by failed readback must not report definite save failure"
    )
    let committedAccess = FaultingManagedKeychainStoreAccess(readResult: .success(mutationSecret))
    try expect(
        ManagedKeychainStore.importSecret(
            mutationSecret, service: "fixture-service", account: "fixture-account",
            synchronizable: false, authenticationContext: LAContext(), access: committedAccess
        ) == .committed,
        "managed mutation must report committed only after equal readback"
    )

    let sha1Vector = try TOTPGenerator.code(
        seed: Data("12345678901234567890".utf8), algorithm: "SHA1", digits: 8, period: 30,
        date: Date(timeIntervalSince1970: 59)
    )
    try expect(
        sha1Vector == "94287082",
        "RFC 6238 SHA1 vector must match"
    )
    let sha256Vector = try TOTPGenerator.code(
        seed: Data("12345678901234567890123456789012".utf8), algorithm: "SHA256", digits: 8, period: 30,
        date: Date(timeIntervalSince1970: 59)
    )
    try expect(
        sha256Vector == "46119246",
        "RFC 6238 SHA256 vector must match"
    )
    let sha512Vector = try TOTPGenerator.code(
        seed: Data("1234567890123456789012345678901234567890123456789012345678901234".utf8),
        algorithm: "SHA512", digits: 8, period: 30, date: Date(timeIntervalSince1970: 59)
    )
    try expect(
        sha512Vector == "90693936",
        "RFC 6238 SHA512 vector must match"
    )
    try expect(
        (try? TOTPGenerator.parse("otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP")) == nil,
        "HOTP URI must be rejected"
    )
    try expect((try? TOTPGenerator.decodeBase32("JBSW=Y3DP")) == nil, "padded or malformed Base32 must fail")
    try expect((try? TOTPGenerator.decodeBase32("AAA")) == nil, "non-canonical Base32 lengths must fail")
    try expect(
        (try? TOTPGenerator.decodeBase32("JBSWY3DPEHPK3PXſ")) == nil
            && (try? TOTPGenerator.decodeBase32("JBSWY3DPEHPK3PXı")) == nil,
        "Unicode case folding must not create valid Base32 ASCII"
    )
    try expect(
        (try? TOTPGenerator.parse("otpauth://totp/?secret=JBSWY3DPEHPK3PXP")) == nil,
        "OTP URI must require a non-empty label"
    )
    try expect(
        (try? TOTPGenerator.parse("otpauth://totp:443/Label?secret=JBSWY3DPEHPK3PXP")) == nil,
        "OTP URI authority must not contain a port"
    )
    try expect(
        [
            "otpauth://%74otp/Label?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp:/Label?secret=JBSWY3DPEHPK3PXP",
            "otpauth://user@totp/Label?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp@host/Label?secret=JBSWY3DPEHPK3PXP"
        ].allSatisfy { (try? TOTPGenerator.parse($0)) == nil },
        "OTP URI raw authority must be exactly the ASCII token totp"
    )
    try expect(
        (try? TOTPGenerator.parse("otpauth://totp/Issuer/user?secret=JBSWY3DPEHPK3PXP")) == nil
            && (try? TOTPGenerator.parse(
                "otpauth://totp/Issuer%2Fuser?secret=JBSWY3DPEHPK3PXP"
            )) == nil,
        "OTP URI must contain exactly one label path segment"
    )
    try expect(
        (try? TOTPGenerator.parse(
            "otpauth://totp/Issuer:user?secret=JBSWY3DPEHPK3PXP&issuer=Other"
        )) == nil,
        "OTP URI issuer must agree with the label issuer"
    )
    try expect(
        (try? TOTPGenerator.parse(
            "otpauth://totp/Issuer:user:extra?secret=JBSWY3DPEHPK3PXP&issuer=Issuer"
        )) == nil,
        "OTP URI label must contain at most one issuer/account separator"
    )
    try expect(
        [
            "otpauth://totp/Issuer:\u{FE0F}:user?secret=JBSWY3DPEHPK3PXP&issuer=Issuer",
            "otpauth://totp/Issuer:\u{0301}:user?secret=JBSWY3DPEHPK3PXP&issuer=Issuer"
        ].allSatisfy { (try? TOTPGenerator.parse($0)) == nil },
        "OTP URI colon separators with variation or combining scalars must not evade separator counting"
    )
    try expect(
        [
            "otpauth://totp/Issuer:\u{FE0F}user?secret=JBSWY3DPEHPK3PXP&issuer=Other",
            "otpauth://totp/Issuer:\u{0301}user?secret=JBSWY3DPEHPK3PXP&issuer=Other"
        ].allSatisfy { (try? TOTPGenerator.parse($0)) == nil },
        "OTP URI scalar separators followed by variation or combining marks must still bind the label issuer"
    )
    let boundarySeed = Data("12345678901234567890".utf8)
    let beforeBoundary = try TOTPGenerator.code(
        seed: boundarySeed, algorithm: "SHA1", digits: 6, period: 30, date: Date(timeIntervalSince1970: 29.999)
    )
    let atBoundary = try TOTPGenerator.code(
        seed: boundarySeed, algorithm: "SHA1", digits: 6, period: 30, date: Date(timeIntervalSince1970: 30)
    )
    try expect(beforeBoundary != atBoundary, "OTP must advance exactly at the configured period boundary")
    try expect(
        (try? TOTPGenerator.code(
            seed: boundarySeed, algorithm: "SHA1", digits: 6, period: 30,
            date: Date(timeIntervalSince1970: -1)
        )) == nil,
        "OTP must reject time before the Unix epoch"
    )

    for _ in 0 ..< 200 {
        let generated = try PasswordGenerator.generate(PasswordGenerationOptions(
            length: 32, includeDigits: true, includeSymbols: true, excluded: Set("0O1l")
        ))
        try expect(generated.count == 32, "generated passwords must preserve requested length")
        try expect(generated.allSatisfy { !Set("0O1l").contains($0) }, "excluded characters must not occur")
        try expect(generated.contains(where: \.isNumber), "generated passwords must contain a digit")
        try expect(
            generated.contains { "!@#$%^&*()-_=+[]{}:,.?".contains($0) },
            "generated passwords must contain a symbol"
        )
    }

    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("macop-native-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    defer { try? FileManager.default.removeItem(at: directory) }
    let config = """
    {
      "version": 2,
      "items": {
        "Local/Login": {
          "provider": "keychain-managed", "service": "login-secret", "account": "expected-user",
          "fields": ["token"],
          "otp": {
            "service": "otp-seed", "account": "expected-user", "algorithm": "SHA1", "digits": 8,
            "period": 30, "label": "Issuer:expected-user", "issuer": "Issuer"
          }
        }
      },
      "profiles": {
        "demo": { "executable": "/usr/bin/printenv", "environment": { "PROFILE_SECRET": "op://Local/Login/password" } }
      },
      "ssh_hosts": {
        "demo-host": { "hostname": "example.com", "user": "git", "port": 2222, "identity": "github" }
      }
    }
    """
    let configURL = directory.appendingPathComponent("config.json")
    try config.data(using: .utf8)!.write(to: configURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    let purposeClient = RecordingPurposeClient(.success(Data("purpose-secret".utf8)))
    let purposeApp = MacopApp(keychainClient: purposeClient)
    let purposeReference = "op://Local/Login/password"
    let purposeResults = [
        purposeApp.run(
            argv: ["macop", "--config", directory.path, "read", purposeReference], env: [:]
        ),
        purposeApp.run(
            argv: ["macop", "--config", directory.path, "run", "--", "/usr/bin/true"],
            env: ["PURPOSE_SECRET": purposeReference]
        ),
        purposeApp.run(
            argv: ["macop", "--config", directory.path, "inject"],
            env: [:], input: Data(purposeReference.utf8)
        ),
        purposeApp.run(
            argv: [
                "macop", "--config", directory.path, "profile", "run", "demo", "--",
                "/usr/bin/printenv", "PROFILE_SECRET"
            ],
            env: [:]
        ),
        purposeApp.run(
            argv: [
                "macop", "--config", directory.path, "item", "get", "Login", "--fields",
                "label=password", "--reveal"
            ],
            env: [:]
        ),
        purposeApp.run(
            argv: ["macop", "--config", directory.path, "item", "acquire", "Login"], env: [:]
        )
    ]
    try expect(
        purposeResults.allSatisfy { $0.exitCode == 0 },
        "every managed password caller-purpose fixture must complete"
    )
    try expect(
        purposeClient.presentations == [
            .readPassword, .runPassword, .injectPassword, .profilePassword,
            .itemGetPassword, .itemAcquirePassword
        ],
        "read/run/inject/profile/item get/item acquire must bind distinct closed managed-password purposes"
    )
    let passwordClient = RecordingKeychainClient(.success(Data("pair-password".utf8)))
    let app = MacopApp(keychainClient: passwordClient)
    let username = app.run(
        argv: ["macop", "--config", directory.path, "read", "op://Local/Login/username"], env: [:]
    )
    try expect(
        username.stdout == "expected-user\n",
        "username field must resolve from account metadata (exit \(username.exitCode): \(username.stderr))"
    )
    try expect(passwordClient.queries.isEmpty, "username field must not read secret data")
    let itemUsername = app.run(
        argv: ["macop", "--config", directory.path, "item", "get", "Login", "--fields", "label=username"],
        env: [:]
    )
    try expect(
        itemUsername.stdout.contains("expected-user") && passwordClient.queries.isEmpty,
        "item get must expose username metadata without a secret read"
    )
    let password = app.run(
        argv: ["macop", "--config", directory.path, "read", "op://Local/Login/password"], env: [:]
    )
    let token = app.run(
        argv: ["macop", "--config", directory.path, "read", "op://Local/Login/token"], env: [:]
    )
    try expect(
        password.stdout == "pair-password\n" && token.stdout == password.stdout,
        "password and legacy token must resolve the secret"
    )
    let unknownField = app.run(
        argv: ["macop", "--config", directory.path, "read", "op://Local/Login/not-configured"], env: [:]
    )
    try expect(unknownField.exitCode == ExitCode.notFound.rawValue, "unknown credential fields must fail closed")

    let v1Config = """
    {
      "version": 1,
      "items": {
        "Local/Legacy": {
          "provider": "keychain-generic", "service": "legacy", "account": "metadata-account",
          "fields": ["username", "password"]
        }
      }
    }
    """
    try v1Config.data(using: .utf8)!.write(to: configURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    let legacyClient = RecordingKeychainClient(.success(Data("legacy-secret".utf8)))
    let legacyUsername = MacopApp(keychainClient: legacyClient).run(
        argv: ["macop", "--config", directory.path, "read", "op://Local/Legacy/username"], env: [:]
    )
    try expect(
        legacyUsername.stdout == "legacy-secret\n" && legacyClient.queries.count == 1,
        "genuine config v1 username fields must preserve their legacy secret semantics"
    )

    let v1ExpandedConfig = """
    { "version": 1, "items": {
      "Local/Legacy": {
        "provider": "keychain-generic", "service": "legacy", "account": "account",
        "otp": { "service": "otp", "account": "account", "algorithm": "SHA1", "digits": 6, "period": 30 }
      }
    } }
    """
    try v1ExpandedConfig.data(using: .utf8)!.write(to: configURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    try expect(
        MacopApp().run(
            argv: ["macop", "--config", directory.path, "config", "validate"], env: [:]
        ).exitCode == ExitCode.invalidArguments.rawValue,
        "config v1 must reject v2-only OTP schema rather than reinterpret it"
    )

    let collidingOTPConfig = """
    { "version": 2, "items": {
      "Local/One": {
        "provider": "keychain-managed", "service": "same", "account": "same",
        "otp": { "service": "same", "account": "same", "algorithm": "SHA1", "digits": 6, "period": 30 }
      }
    } }
    """
    try collidingOTPConfig.data(using: .utf8)!.write(to: configURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    try expect(
        MacopApp().run(
            argv: ["macop", "--config", directory.path, "config", "validate"], env: [:]
        ).exitCode == ExitCode.invalidArguments.rawValue,
        "OTP and password selectors must never alias"
    )

    let crossItemOTPConfig = """
    { "version": 2, "items": {
      "Local/One": {
        "provider": "keychain-generic", "service": "one", "account": "one",
        "otp": { "service": "shared-otp", "account": "same", "algorithm": "SHA1", "digits": 6, "period": 30 }
      },
      "Local/Two": {
        "provider": "keychain-internet", "server": "two.invalid", "account": "two",
        "otp": { "service": "shared-otp", "account": "same", "algorithm": "SHA1", "digits": 6, "period": 30 }
      }
    } }
    """
    try crossItemOTPConfig.data(using: .utf8)!.write(to: configURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    try expect(
        MacopApp().run(
            argv: ["macop", "--config", directory.path, "config", "validate"], env: [:]
        ).exitCode == ExitCode.invalidArguments.rawValue,
        "OTP selectors must be unique across items"
    )

    let injectedIdentityConfig = """
    { "version": 2, "items": {}, "ssh_hosts": {
      "unsafe": { "hostname": "example.com", "identity": "github\\nProxyCommand unsafe" }
    } }
    """
    try injectedIdentityConfig.data(using: .utf8)!.write(to: configURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    try expect(
        MacopApp().run(
            argv: ["macop", "--config", directory.path, "ssh", "host-config"], env: [:]
        ).exitCode == ExitCode.invalidArguments.rawValue,
        "SSH identities containing line breaks must fail before config rendering"
    )
    for (label, description) in [
        (" github", "surrounding whitespace"),
        (String(repeating: "x", count: 129), "labels over 128 UTF-8 bytes"),
        ("git\u{200D}hub", "Unicode format characters")
    ] {
        let unsafeHostObject: [String: Any] = [
            "version": 2,
            "items": [:],
            "ssh_hosts": [
                "unsafe": ["hostname": "example.com", "identity": label]
            ]
        ]
        try JSONSerialization.data(withJSONObject: unsafeHostObject).write(to: configURL, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
        let validate = MacopApp().run(
            argv: ["macop", "--config", directory.path, "config", "validate"], env: [:]
        )
        let connect = MacopApp(commandExecutor: RecordingSSHExecutor(identityAlreadyExists: true)).run(
            argv: ["macop", "--config", directory.path, "ssh", "connect", "unsafe"], env: [:]
        )
        try expect(
            validate.exitCode == ExitCode.invalidArguments.rawValue
                && connect.exitCode == ExitCode.invalidArguments.rawValue,
            "config validate and ssh connect must both reject \(description)"
        )
    }
    try config.data(using: .utf8)!.write(to: configURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)

    let otpClient = RecordingKeychainClient(.success(boundarySeed))
    let otpPasswordClient = RecordingKeychainClient(.failure(KeychainFailure(errSecItemNotFound)))
    let otpFallback = RecordingPasswordAutoFillProvider()
    let otpApp = MacopApp(
        keychainClient: otpPasswordClient,
        otpSeedClient: otpClient,
        passwordAutoFillProvider: otpFallback
    )
    let otp = otpApp.run(
        argv: ["macop", "--config", directory.path, "read", "op://Local/Login/password?attribute=otp"], env: [:]
    )
    try expect(
        otp.exitCode == 0 && otp.stdout.trimmingCharacters(in: .whitespacesAndNewlines).count == 8,
        "OTP query must resolve current code"
    )
    try expect(
        otpClient.queries == [.managed(service: "otp-seed", account: "expected-user")],
        "OTP must use its separate managed Keychain selector"
    )
    try expect(
        otpPasswordClient.queries.isEmpty && otpFallback.requests.isEmpty,
        "OTP reads must never route through password Keychain or Passwords AutoFill fallback"
    )

    let missingOTPClient = RecordingKeychainClient(.failure(KeychainFailure(errSecItemNotFound)))
    let missingOTPFallback = RecordingPasswordAutoFillProvider()
    let missingOTP = MacopApp(
        keychainClient: RecordingKeychainClient(.failure(KeychainFailure(errSecItemNotFound))),
        otpSeedClient: missingOTPClient,
        passwordAutoFillProvider: missingOTPFallback
    ).run(
        argv: ["macop", "--config", directory.path, "read", "op://Local/Login/password?attribute=otp"],
        env: [:]
    )
    try expect(
        missingOTP.exitCode == ExitCode.notFound.rawValue && missingOTPFallback.requests.isEmpty,
        "missing OTP seeds must fail without opening Passwords AutoFill"
    )

    let mismatch = MacopApp(
        keychainClient: RecordingKeychainClient(.failure(KeychainFailure(errSecItemNotFound))),
        passwordAutoFillProvider: MismatchingPasswordAutoFillProvider()
    ).run(argv: ["macop", "--config", directory.path, "item", "acquire", "Login"], env: [:])
    try expect(mismatch.exitCode == ExitCode.denied.rawValue, "AutoFill username mismatch must fail closed")
    try expect(
        !mismatch.stdout.contains("never-return-this") && !mismatch.stderr.contains("never-return-this"),
        "mismatched credential must not be exposed"
    )

    let mutator = RecordingKeychainMutator()
    let generatedImporter = RecordingManagedKeychainImporter()
    let generateApp = MacopApp(managedKeychainImporter: generatedImporter, keychainMutator: mutator)
    let generate = generateApp.run(
        argv: ["macop", "--config", directory.path, "item", "generate", "Login", "--length", "40"], env: [:]
    )
    try expect(
        generate.exitCode == 0 && mutator.creates.isEmpty
            && generatedImporter.generatedImports.first?.secret.count == 40,
        "managed generation must save directly through companion authorization without stdout exposure"
    )
    let rotate = generateApp.run(
        argv: [
            "macop", "--config", directory.path, "item", "generate", "--replace", "Login", "--length", "44"
        ],
        env: [:]
    )
    try expect(
        rotate.exitCode == 0 && generatedImporter.updates.count == 1
            && generatedImporter.updates[0].secret.count == 44
            && generatedImporter.generatedImports.count == 1,
        "managed password rotation must use authenticated exact-item update without creating a duplicate"
    )
    let lostPasswordImportValue = "fixture-import-response-loss"
    let lostPasswordImporter = RecordingManagedKeychainImporter(
        importFailure: ManagedKeychainMutationFailure.responseLost
    )
    let lostPasswordImport = MacopApp(managedKeychainImporter: lostPasswordImporter).run(
        argv: ["macop", "--config", directory.path, "item", "import", "Login"],
        env: [:], input: Data(lostPasswordImportValue.utf8)
    )
    try expect(
        lostPasswordImport.exitCode == ExitCode.runtimeError.rawValue
            && lostPasswordImporter.imports.count == 1
            && lostPasswordImport.stderr.contains("creation is indeterminate")
            && lostPasswordImport.stderr.contains("broker response was lost")
            && lostPasswordImport.stderr.contains("already-exists")
            && !lostPasswordImport.stderr.contains(lostPasswordImportValue),
        "managed import mutation-then-lost-response must provide secret-free create reconciliation"
    )
    let lostGeneratedImporter = RecordingManagedKeychainImporter(
        updateFailure: ManagedKeychainMutationFailure.serverIndeterminate
    )
    let lostGeneratedRotation = MacopApp(managedKeychainImporter: lostGeneratedImporter).run(
        argv: [
            "macop", "--config", directory.path, "item", "generate", "--replace", "Login",
            "--length", "43"
        ],
        env: [:]
    )
    let lostGeneratedValue = lostGeneratedImporter.updates.first
        .flatMap { String(data: $0.secret, encoding: .utf8) } ?? ""
    try expect(
        lostGeneratedRotation.exitCode == ExitCode.runtimeError.rawValue
            && lostGeneratedImporter.updates.count == 1
            && !lostGeneratedValue.isEmpty
            && lostGeneratedRotation.stderr.contains("rotation is indeterminate")
            && lostGeneratedRotation.stderr.contains("companion returned")
            && lostGeneratedRotation.stderr.contains("successful retry establishes")
            && !lostGeneratedRotation.stderr.contains(lostGeneratedValue)
            && !lostGeneratedRotation.stdout.contains(lostGeneratedValue),
        "managed generated rotation response loss must never expose the generated value and must give safe retry guidance"
    )
    let lostGeneratedCreateImporter = RecordingManagedKeychainImporter(
        importFailure: ManagedKeychainMutationFailure.responseLost
    )
    let lostGeneratedCreate = MacopApp(managedKeychainImporter: lostGeneratedCreateImporter).run(
        argv: [
            "macop", "--config", directory.path, "item", "generate", "Login", "--length", "42"
        ],
        env: [:]
    )
    let lostGeneratedCreateValue = lostGeneratedCreateImporter.generatedImports.first
        .flatMap { String(data: $0.secret, encoding: .utf8) } ?? ""
    try expect(
        lostGeneratedCreate.exitCode == ExitCode.runtimeError.rawValue
            && lostGeneratedCreate.stderr.contains("creation is indeterminate")
            && lostGeneratedCreate.stderr.contains("broker response was lost")
            && !lostGeneratedCreateValue.isEmpty
            && !lostGeneratedCreate.stderr.contains(lostGeneratedCreateValue),
        "managed generated creation must distinguish transport response loss without exposing generated data"
    )

    let otpImporter = RecordingManagedKeychainImporter()
    let otpDeleter = RecordingManagedKeychainDeleter()
    let otpLifecycleApp = MacopApp(
        otpSeedClient: otpClient,
        managedKeychainImporter: otpImporter,
        managedKeychainDeleter: otpDeleter
    )
    let otpURI = "otpauth://totp/Issuer:expected-user?secret=JBSWY3DPEHPK3PXP&issuer=Issuer&digits=8&period=30"
    let lostOTPImportImporter = RecordingManagedKeychainImporter(
        importFailure: ManagedKeychainMutationFailure.serverIndeterminate
    )
    let lostOTPImport = MacopApp(managedKeychainImporter: lostOTPImportImporter).run(
        argv: ["macop", "--config", directory.path, "item", "otp", "import", "Login"],
        env: [:], input: Data(otpURI.utf8)
    )
    try expect(
        lostOTPImport.exitCode == ExitCode.runtimeError.rawValue
            && lostOTPImportImporter.imports.count == 1
            && lostOTPImport.stderr.contains("creation is indeterminate")
            && lostOTPImport.stderr.contains("companion returned")
            && lostOTPImport.stderr.contains("already-exists")
            && !lostOTPImport.stderr.contains("JBSWY3DPEHPK3PXP"),
        "OTP import response loss must provide secret-free create reconciliation"
    )
    let lostOTPEditImporter = RecordingManagedKeychainImporter(
        updateFailure: ManagedKeychainMutationFailure.responseLost
    )
    let lostOTPEdit = MacopApp(managedKeychainImporter: lostOTPEditImporter).run(
        argv: ["macop", "--config", directory.path, "item", "otp", "edit", "Login"],
        env: [:], input: Data(otpURI.utf8)
    )
    try expect(
        lostOTPEdit.exitCode == ExitCode.runtimeError.rawValue
            && lostOTPEditImporter.updates.count == 1
            && lostOTPEdit.stderr.contains("update is indeterminate")
            && lostOTPEdit.stderr.contains("broker response was lost")
            && lostOTPEdit.stderr.contains("safe to repeat")
            && !lostOTPEdit.stderr.contains("JBSWY3DPEHPK3PXP"),
        "OTP edit response loss must provide secret-free idempotent update reconciliation"
    )
    let otpImport = otpLifecycleApp.run(
        argv: ["macop", "--config", directory.path, "item", "otp", "import", "Login"],
        env: [:], input: Data(otpURI.utf8)
    )
    let otpEdit = otpLifecycleApp.run(
        argv: ["macop", "--config", directory.path, "item", "otp", "edit", "Login"],
        env: [:], input: Data(otpURI.utf8)
    )
    let otpDelete = otpLifecycleApp.run(
        argv: ["macop", "--config", directory.path, "item", "otp", "delete", "Login"], env: [:]
    )
    try expect(
        otpImport.exitCode == 0 && otpEdit.exitCode == 0 && otpDelete.exitCode == 0
            && otpImporter.imports.count == 1 && otpImporter.updates.count == 1
            && otpDeleter.deletes.last?.service == "otp-seed"
            && otpDeleter.deletes.last?.purpose == .otpSeed,
        "OTP lifecycle must expose distinct authenticated create, exact update, and delete operations"
    )
    let lostStandaloneOTPDeleter = RecordingManagedKeychainDeleter(deleteFailures: [
        ManagedKeychainDeletionFailure.indeterminate
    ])
    let lostStandaloneOTPDelete = MacopApp(managedKeychainDeleter: lostStandaloneOTPDeleter).run(
        argv: ["macop", "--config", directory.path, "item", "otp", "delete", "Login"], env: [:]
    )
    try expect(
        lostStandaloneOTPDelete.exitCode == ExitCode.runtimeError.rawValue
            && lostStandaloneOTPDeleter.deletes.count == 1
            && lostStandaloneOTPDelete.stderr.contains("indeterminate")
            && lostStandaloneOTPDelete.stderr.contains("success or not-found")
            && !lostStandaloneOTPDelete.stderr.contains("Issuer:expected-user"),
        "standalone OTP mutation-then-lost-response must give secret-free idempotent reconciliation guidance"
    )
    let lostBulkDeleteDeleter = RecordingManagedKeychainDeleter(
        deleteAllFailure: ManagedKeychainDeletionFailure.indeterminate
    )
    let lostBulkDelete = MacopApp(managedKeychainDeleter: lostBulkDeleteDeleter).run(
        argv: ["macop", "--config", directory.path, "item", "delete", "--all-managed"], env: [:]
    )
    try expect(
        lostBulkDelete.exitCode == ExitCode.runtimeError.rawValue
            && lostBulkDeleteDeleter.deleteAllCount == 1
            && lostBulkDelete.stderr.contains("indeterminate")
            && lostBulkDelete.stderr.contains("Retry item delete --all-managed")
            && lostBulkDelete.stderr.contains("No secret value is needed"),
        "bulk mutation-then-lost-response must give secret-free idempotent reconciliation guidance"
    )
    try expect(
        ManagedKeychainReadPresentation.readOTP.brokerPurpose == .otpRead
            && ManagedKeychainReadPresentation.runOTP.brokerPurpose == .otpRun
            && ManagedKeychainReadPresentation.injectOTP.brokerPurpose == .otpInject
            && ManagedKeychainReadPresentation.profileOTP.brokerPurpose == .otpProfile
            && ManagedKeychainReadPresentation.itemOTP.brokerPurpose == .otpItem
            && ManagedKeychainDeletePurpose.otpSeed.brokerPurpose == .otpDelete,
        "bounded OTP presentations must attest each real command purpose to the native UI"
    )
    let mismatchedOTPURI = "otpauth://totp/Other:expected-user?secret=JBSWY3DPEHPK3PXP&issuer=Other&digits=8&period=30"
    let rejectedOTPImport = otpLifecycleApp.run(
        argv: ["macop", "--config", directory.path, "item", "otp", "import", "Login"],
        env: [:], input: Data(mismatchedOTPURI.utf8)
    )
    try expect(
        rejectedOTPImport.exitCode == ExitCode.invalidArguments.rawValue && otpImporter.imports.count == 1,
        "OTP URI label and issuer must exactly match configured metadata before broker access"
    )
    let deleteItemWithOTP = otpLifecycleApp.run(
        argv: ["macop", "--config", directory.path, "item", "delete", "Login"], env: [:]
    )
    try expect(
        deleteItemWithOTP.exitCode == 0 && otpDeleter.deletes.suffix(2).map(\.service) == [
            "login-secret", "otp-seed"
        ] && otpDeleter.deletes.suffix(2).map(\.purpose) == [.item, .otpSeed],
        "deleting a configured item must delete its primary before its independent OTP seed"
    )

    let primaryFailureDeleter = RecordingManagedKeychainDeleter(deleteFailures: [
        CLIError.denied(message: "fixture primary denial")
    ])
    let primaryFailure = MacopApp(managedKeychainDeleter: primaryFailureDeleter).run(
        argv: ["macop", "--config", directory.path, "item", "delete", "Login"], env: [:]
    )
    try expect(
        primaryFailure.exitCode == ExitCode.denied.rawValue
            && primaryFailureDeleter.deletes.map(\.service) == ["login-secret"],
        "primary managed deletion failure must preserve the OTP seed without requesting its deletion"
    )

    let lostPrimaryResponseDeleter = RecordingManagedKeychainDeleter(deleteFailures: [
        ManagedKeychainDeletionFailure.indeterminate
    ])
    let lostPrimaryResponse = MacopApp(managedKeychainDeleter: lostPrimaryResponseDeleter).run(
        argv: ["macop", "--config", directory.path, "item", "delete", "Login"], env: [:]
    )
    try expect(
        lostPrimaryResponse.exitCode == ExitCode.runtimeError.rawValue
            && lostPrimaryResponseDeleter.deletes.map(\.service) == ["login-secret"]
            && lostPrimaryResponse.stderr.contains("indeterminate")
            && !lostPrimaryResponse.stderr.contains("primary Keychain item was deleted"),
        "a mutation-then-lost primary response must report indeterminate state without touching OTP or claiming preservation"
    )

    let partialFailureDeleter = RecordingManagedKeychainDeleter(deleteFailures: [
        nil, CLIError.denied(message: "fixture OTP denial")
    ])
    let partialFailure = MacopApp(managedKeychainDeleter: partialFailureDeleter).run(
        argv: ["macop", "--config", directory.path, "item", "delete", "Login"], env: [:]
    )
    try expect(
        partialFailure.exitCode == ExitCode.runtimeError.rawValue
            && partialFailureDeleter.deletes.map(\.service) == ["login-secret", "otp-seed"]
            && partialFailure.stderr.contains("primary Keychain item was deleted")
            && partialFailure.stderr.contains("same configured item")
            && !partialFailure.stderr.contains("Login"),
        "secondary OTP deletion failure must report the unavoidable partial state without unsafe shell interpolation"
    )

    let nonCLIOTPFailureDeleter = RecordingManagedKeychainDeleter(deleteFailures: [
        nil, FixtureTransportFailure()
    ])
    let nonCLIOTPFailure = MacopApp(managedKeychainDeleter: nonCLIOTPFailureDeleter).run(
        argv: ["macop", "--config", directory.path, "item", "delete", "Login"], env: [:]
    )
    try expect(
        nonCLIOTPFailure.exitCode == ExitCode.runtimeError.rawValue
            && nonCLIOTPFailureDeleter.deletes.map(\.service) == ["login-secret", "otp-seed"]
            && nonCLIOTPFailure.stderr.contains("OTP seed deletion could not be confirmed")
            && nonCLIOTPFailure.stderr.contains("may remain"),
        "non-CLI OTP failures must retain an explicit primary-deleted and OTP-indeterminate recovery diagnostic"
    )

    let legacyOTPConfig = """
    { "version": 2, "items": {
      "Local/LegacyOTP": {
        "provider": "keychain-internet", "server": "legacy.invalid", "account": "user",
        "otp": { "service": "legacy-otp", "account": "user", "algorithm": "SHA1", "digits": 6, "period": 30 }
      }
    } }
    """
    try legacyOTPConfig.data(using: .utf8)!.write(to: configURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    let untouchedOTPDeleter = RecordingManagedKeychainDeleter()
    let ambiguousLegacyDelete = MacopApp(
        managedKeychainDeleter: untouchedOTPDeleter,
        keychainMutator: RecordingKeychainMutator(deleteFailure: .invalidArguments(
            message: "fixture ambiguous selector"
        ))
    ).run(
        argv: ["macop", "--config", directory.path, "item", "delete", "LegacyOTP"], env: [:]
    )
    try expect(
        ambiguousLegacyDelete.exitCode == ExitCode.invalidArguments.rawValue
            && untouchedOTPDeleter.deletes.isEmpty,
        "missing or ambiguous legacy primary selection must not delete the OTP seed"
    )
    try config.data(using: .utf8)!.write(to: configURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)

    let profile = app.run(
        argv: [
            "macop",
            "--config",
            directory.path,
            "profile",
            "run",
            "demo",
            "--",
            "/usr/bin/printenv",
            "PROFILE_SECRET"
        ],
        env: [:]
    )
    try expect(
        profile.exitCode == 0 && !profile.stdout.contains("pair-password"),
        "profile output must redact injected credentials"
    )
    let wrongExecutable = app.run(
        argv: ["macop", "--config", directory.path, "profile", "run", "demo", "--", "/bin/echo"], env: [:]
    )
    try expect(wrongExecutable.exitCode == ExitCode.denied.rawValue, "profile must reject a different executable")
    let extraReference = app.run(
        argv: ["macop", "--config", directory.path, "profile", "run", "demo", "--", "/usr/bin/printenv"],
        env: ["UNDECLARED_SECRET": "op://Local/Login/password"]
    )
    try expect(
        extraReference.exitCode == ExitCode.denied.rawValue,
        "profile must reject undeclared ambient secret references"
    )
    let wrapper = app.run(
        argv: ["macop", "--config", directory.path, "profile", "shell-init", "demo", "zsh"], env: [:]
    )
    try expect(
        wrapper.stdout.contains("macop --config") && wrapper.stdout.contains("profile run")
            && wrapper.stdout.contains("/usr/bin/printenv"),
        "profile wrapper must preserve custom config and exact executable"
    )
    let quotedConfigDirectory = directory.appendingPathComponent("quoted ' config; false", isDirectory: true)
    try FileManager.default.createDirectory(at: quotedConfigDirectory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: quotedConfigDirectory.path)
    let quotedConfigURL = quotedConfigDirectory.appendingPathComponent("config.json")
    try config.data(using: .utf8)!.write(to: quotedConfigURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: quotedConfigURL.path)
    let quotedWrapper = app.run(
        argv: [
            "macop", "--config", quotedConfigDirectory.path, "profile", "shell-init", "demo", "zsh"
        ],
        env: [:]
    )
    let shimDirectory = directory.appendingPathComponent("profile-wrapper-shim", isDirectory: true)
    try FileManager.default.createDirectory(at: shimDirectory, withIntermediateDirectories: true)
    let shimURL = shimDirectory.appendingPathComponent("macop")
    try Data("#!/bin/sh\nfor arg in \"$@\"; do printf '<%s>\\n' \"$arg\"; done\n".utf8).write(to: shimURL)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: shimURL.path)
    let wrapperProcess = Process()
    let wrapperOutput = Pipe()
    let wrapperError = Pipe()
    wrapperProcess.executableURL = URL(fileURLWithPath: "/bin/zsh")
    wrapperProcess.arguments = [
        "-c",
        quotedWrapper.stdout + "\nPATH='\(shimDirectory.path)'; rehash; macop_demo 'argument with spaces'\n"
    ]
    wrapperProcess.environment = ["PATH": shimDirectory.path]
    wrapperProcess.standardOutput = wrapperOutput
    wrapperProcess.standardError = wrapperError
    try wrapperProcess.run()
    wrapperProcess.waitUntilExit()
    let wrapperInvocation = String(
        data: wrapperOutput.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8
    ) ?? ""
    let wrapperFailure = String(
        data: wrapperError.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8
    ) ?? ""
    try expect(
        wrapperProcess.terminationStatus == 0
            && wrapperInvocation.contains("<--config>\n<\(quotedConfigDirectory.path)>\n<profile>\n<run>\n<demo>")
            && wrapperInvocation.contains("<argument with spaces>")
            && !wrapperInvocation.contains("<false>")
            && wrapperFailure.isEmpty,
        "executed wrapper must retain quoted custom config as one argument without shell injection"
    )

    let scalarInjection = "'\u{0301}; printf PWNED; #"
    let hostileExecutable = directory.appendingPathComponent("profile-tool-" + scalarInjection)
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: hostileExecutable)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: hostileExecutable.path)
    let scalarConfigDirectory = directory.appendingPathComponent(
        "scalar-config-" + scalarInjection,
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: scalarConfigDirectory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scalarConfigDirectory.path)
    guard var scalarConfigObject = try JSONSerialization.jsonObject(
        with: Data(config.utf8)
    ) as? [String: Any],
        var scalarProfiles = scalarConfigObject["profiles"] as? [String: Any],
        var scalarDemo = scalarProfiles["demo"] as? [String: Any]
    else { throw SelftestFailure(message: "profile shell fixture config must be an object") }
    scalarDemo["executable"] = hostileExecutable.path
    scalarProfiles["demo"] = scalarDemo
    scalarConfigObject["profiles"] = scalarProfiles
    let scalarConfigURL = scalarConfigDirectory.appendingPathComponent("config.json")
    try JSONSerialization.data(withJSONObject: scalarConfigObject).write(to: scalarConfigURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: scalarConfigURL.path)
    let hostileRuntimeArgument = "runtime-" + scalarInjection
    for (shell, executable) in [("zsh", "/bin/zsh"), ("bash", "/bin/bash")] {
        let hostileWrapper = app.run(
            argv: [
                "macop", "--config", scalarConfigDirectory.path,
                "profile", "shell-init", "demo", shell
            ],
            env: [:]
        )
        let process = Process()
        let output = Pipe()
        let error = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = try [
            "-c",
            hostileWrapper.stdout
                + "\nPATH="
                + (ProfileShellArgumentEncoder.quote(shimDirectory.path, shell: shell))
                + "; export PATH; hash -r; macop_demo "
                + (ProfileShellArgumentEncoder.quote(hostileRuntimeArgument, shell: shell))
                + "\n"
        ]
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        let invocation = String(
            data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8
        ) ?? ""
        let failure = error.fileHandleForReading.readDataToEndOfFile()
        let failureDescription = String(data: failure, encoding: .utf8)?.debugDescription ?? "non-UTF8"
        let expectedInvocation = [
            "--config", scalarConfigDirectory.path, "profile", "run", "demo", "--",
            hostileExecutable.path, hostileRuntimeArgument
        ].map { "<\($0)>" }.joined(separator: "\n") + "\n"
        try expect(
            hostileWrapper.exitCode == 0
                && process.terminationStatus == 0
                && invocation == expectedInvocation
                && !invocation.split(separator: "\n").contains("PWNED")
                && failure.isEmpty,
            "\(shell) wrapper must escape literal apostrophe scalars inside combining graphemes "
                + "(wrapper=\(hostileWrapper.exitCode), process=\(process.terminationStatus), "
                + "stdout=\(invocation.debugDescription), expected=\(expectedInvocation.debugDescription), "
                + "stderr=\(failureDescription))"
        )
    }

    let fishQuoteFixtures = [
        "back\\slash",
        "apostrophe's",
        "terminal\\",
        "combined\\'$(false); echo injected\\",
        "'\u{0301}; printf PWNED; #"
    ]
    for fixture in fishQuoteFixtures {
        let encoded = try ProfileShellArgumentEncoder.quote(fixture, shell: "fish")
        let decoded = try decodeFishSingleQuotedArgument(encoded)
        try expect(
            decoded == fixture,
            "fish argument encoding must round-trip backslashes, apostrophes, and shell syntax"
        )
    }
    let fishConfigDirectory = directory.appendingPathComponent(
        "fish\\'$(false); echo injected\\",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: fishConfigDirectory, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fishConfigDirectory.path)
    let fishConfigURL = fishConfigDirectory.appendingPathComponent("config.json")
    try config.data(using: .utf8)!.write(to: fishConfigURL, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fishConfigURL.path)
    let fishWrapper = app.run(
        argv: ["macop", "--config", fishConfigDirectory.path, "profile", "shell-init", "demo", "fish"],
        env: [:]
    )
    let encodedFishConfig = try ProfileShellArgumentEncoder.quote(fishConfigDirectory.path, shell: "fish")
    let decodedFishConfig = try decodeFishSingleQuotedArgument(encodedFishConfig)
    try expect(
        fishWrapper.exitCode == 0
            && fishWrapper.stdout.contains("--config \(encodedFishConfig) profile run")
            && decodedFishConfig == fishConfigDirectory.path,
        "generated fish wrappers must preserve adversarial custom config paths as one literal argument"
    )
    let arbitraryFishDirectory = directory.appendingPathComponent("nix-style-profile/bin", isDirectory: true)
    try FileManager.default.createDirectory(at: arbitraryFishDirectory, withIntermediateDirectories: true)
    let arbitraryFishExecutable = arbitraryFishDirectory.appendingPathComponent("fish")
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: arbitraryFishExecutable)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o700],
        ofItemAtPath: arbitraryFishExecutable.path
    )
    try expect(
        safeExecutableOnPATH(
            named: "fish",
            environment: ["PATH": "/relative:\(arbitraryFishDirectory.path):/opt/local/bin"]
        ) == arbitraryFishExecutable.path,
        "fish detection must safely honor arbitrary absolute PATH entries such as Nix or MacPorts profiles"
    )
    let scalarFishWrapper = app.run(
        argv: [
            "macop", "--config", scalarConfigDirectory.path,
            "profile", "shell-init", "demo", "fish"
        ],
        env: [:]
    )
    if let fishExecutable = safeExecutableOnPATH(
        named: "fish",
        environment: ProcessInfo.processInfo.environment
    ) {
        let fishProcess = Process()
        let fishOutput = Pipe()
        let fishError = Pipe()
        fishProcess.executableURL = URL(fileURLWithPath: fishExecutable)
        fishProcess.arguments = try [
            "-c",
            scalarFishWrapper.stdout
                + "\nset -gx PATH "
                + (ProfileShellArgumentEncoder.quote(shimDirectory.path, shell: "fish"))
                + "; macop_demo "
                + (ProfileShellArgumentEncoder.quote(hostileRuntimeArgument, shell: "fish"))
                + "\n"
        ]
        fishProcess.standardOutput = fishOutput
        fishProcess.standardError = fishError
        try fishProcess.run()
        fishProcess.waitUntilExit()
        let invocation = String(
            data: fishOutput.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8
        ) ?? ""
        let failure = fishError.fileHandleForReading.readDataToEndOfFile()
        let expectedInvocation = [
            "--config", scalarConfigDirectory.path, "profile", "run", "demo", "--",
            hostileExecutable.path, hostileRuntimeArgument
        ].map { "<\($0)>" }.joined(separator: "\n") + "\n"
        try expect(
            scalarFishWrapper.exitCode == 0
                && fishProcess.terminationStatus == 0
                && invocation == expectedInvocation
                && failure.isEmpty,
            "fish must scalar-escape and execute the generated wrapper without changing arguments"
        )
    }

    let sshExecutor = RecordingSSHExecutor(identityAlreadyExists: true)
    let sshApp = MacopApp(commandExecutor: sshExecutor)
    let connect = sshApp.run(
        argv: ["macop", "--config", directory.path, "ssh", "connect", "demo-host"], env: [:]
    )
    try expect(connect.exitCode == 0, "SSH host alias must create a verified-session invocation")
    let launch = sshExecutor.invocations.last
    try expect(
        launch?.arguments.contains("github") == true
            && launch?.arguments.contains("git@example.com") == true
            && launch?.arguments.contains("ForwardAgent=no") == true,
        "SSH host routing must bind one identity, destination, and forwarding denial"
    )
    let hostConfig = sshApp.run(
        argv: ["macop", "--config", directory.path, "ssh", "host-config", "demo-host"], env: [:]
    )
    try expect(
        hostConfig.stdout.contains("HostName example.com") && hostConfig.stdout.contains("ForwardAgent no"),
        "SSH fragment must contain public host metadata only"
    )
}

if runHarnessIfRequested() == nil {
    do {
        try run()
        try runKeychainNativeExtensions()
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
