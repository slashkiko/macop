import AppKit
import Darwin
import Foundation
import MacopCore
import MacopPTY
import Security

// The executable owns production launch, prompt, and signal coordination.
// swiftlint:disable file_length

private let usage = """
Usage:
  macop-agent shell <identity-label> -- <program> [arguments...]
  macop-agent application <identity-label> <application-path>

Each invocation creates one private, short-lived SSH_AUTH_SOCK. It never
publishes a shared agent socket. The launched root and its descendants alone
may use it until the root exits or the session expires.
"""

private func withDebug(_ initial: CommandResult) -> CommandResult {
    guard ProcessInfo.processInfo.environment["MACOP_AGENT_DEBUG"] == "1" else { return initial }
    let isJSON = ProcessInfo.processInfo.environment["MACOP_AGENT_FORMAT"] == "json"
    if isJSON, let rendered = jsonDebug(initial) {
        return rendered
    }
    if !isJSON {
        return CommandResult(
            exitCode: initial.exitCode,
            stdout: initial.stdout,
            stderr: initial.stderr + "macop: debug exit_code=\(initial.exitCode) command=ssh\n"
        )
    }
    return initial
}

private func jsonDebug(_ result: CommandResult) -> CommandResult? {
    guard var payload = (try? JSONSerialization.jsonObject(with: Data(result.stderr.utf8))) as? [String: Any],
          var error = payload["error"] as? [String: Any]
    else { return nil }
    error["debug"] = ["exit_code": result.exitCode, "context": "command=ssh-agent"]
    payload["error"] = error
    guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
          let stderr = String(data: data, encoding: .utf8)
    else { return nil }
    return CommandResult(exitCode: result.exitCode, stderr: stderr + "\n")
}

private func debugSuccess(_ exitCode: Int32) {
    guard ProcessInfo.processInfo.environment["MACOP_AGENT_DEBUG"] == "1",
          ProcessInfo.processInfo.environment["MACOP_AGENT_FORMAT"] != "json"
    else { return }
    FileHandle.standardError.write(Data("macop: debug exit_code=\(exitCode) command=ssh\n".utf8))
}

private func fail(_ message: String, _ code: Int32 = ExitCode.invalidArguments.rawValue) -> Never {
    let format: OutputFormat = ProcessInfo.processInfo
        .environment["MACOP_AGENT_FORMAT"] == "json" ? .json : .humanReadable
    let error: CLIError = code == ExitCode.invalidArguments.rawValue
        ? .invalidArguments(message: message)
        : code == ExitCode.providerUnavailable.rawValue
        ? .providerUnavailable(provider: "CryptoTokenKit", reason: message)
        : code == ExitCode.notFound.rawValue ? .notFound(message: message) : .denied(message: message)
    let result = withDebug(ErrorRenderer.render(error: error, format: format))
    FileHandle.standardError.write(Data(result.stderr.utf8)); exit(result.exitCode)
}

private func rootDirectory() -> URL {
    // sockaddr_un allows only 104 path bytes on Darwin. FileManager's per-user
    // temporary directory is often already too long once the UUID subdirectory
    // and socket name are appended, so use a randomized name in the short
    // system tmp namespace. Randomization prevents another user from reserving
    // one predictable path and denying every verified session for this UID.
    let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16)
    return URL(fileURLWithPath: "/tmp/macop-agent-\(getuid())-\(suffix)", isDirectory: true)
}

private func environment(for reservation: VerifiedSessionReservation) -> [String: String] {
    ProcessInfo.processInfo.environment.merging(VerifiedSessionLauncher.environment(for: reservation)) { _, new in new }
}

private func hasInteractiveTerminal() -> Bool {
    isatty(STDIN_FILENO) == 1 && isatty(STDOUT_FILENO) == 1
}

private final class SignalCoordinator: @unchecked Sendable {
    private let lock = NSLock()
    private var pendingSignal: Int32?
    private var cleanupComplete = false
    private var owned: OwnedProcess?
    private var signalDescendants: [Int32: UInt64] = [:]
    private var rootWaitActive = false
    private let signalPipe: Int32
    private let gracefulShutdownNanoseconds: UInt64

    init(gracefulShutdownNanoseconds: UInt64 = 2_000_000_000) {
        self.gracefulShutdownNanoseconds = gracefulShutdownNanoseconds
        self.signalPipe = macop_signal_pipe_install()
        precondition(self.signalPipe >= 0, "unable to install agent signal pipe")
    }

    deinit {
        macop_signal_pipe_restore()
    }

    func installOwned(_ owned: OwnedProcess) {
        self.drainSignalPipe()
        self.lock.lock(); self.owned = owned; let pending = self.pendingSignal; self.lock.unlock()
        if let pending {
            self.forward(pending, owned: owned)
        }
    }

    var exitStatus: Int32? {
        self.drainSignalPipe()
        self.lock.lock(); defer { self.lock.unlock() }
        return self.cleanupComplete ? self.pendingSignal.map { 128 + $0 } : nil
    }

    var requestedExitStatus: Int32? {
        self.drainSignalPipe()
        self.lock.lock(); defer { self.lock.unlock() }
        return self.pendingSignal.map { 128 + $0 }
    }

    func isCancellationRequested() -> Bool {
        self.drainSignalPipe()
        self.lock.lock(); defer { self.lock.unlock() }
        return self.pendingSignal != nil
    }

    func beginRootWait() {
        self.lock.lock(); self.rootWaitActive = true; self.lock.unlock()
    }

    func endRootWait() {
        self.lock.lock(); self.rootWaitActive = false; self.lock.unlock()
    }

    /// Called by the runtime defer or main return path. This is deliberately
    /// the sole synchronous cleanup/reap owner; Dispatch signal handlers only
    /// latch and forward, so they never race a foreground waitpid.
    func finalizeSignalCleanupIfNeeded() {
        self.lock.lock()
        let signalRequested = self.pendingSignal != nil
        let value = self.owned
        let descendants = self.signalDescendants
        let complete = self.cleanupComplete
        let rootWaitActive = self.rootWaitActive
        self.lock.unlock()
        guard signalRequested, !complete else { return }
        if let value {
            terminateOwnedRoot(
                value,
                additionalDescendants: descendants,
                reapRoot: !rootWaitActive,
                gracefulShutdownNanoseconds: self.gracefulShutdownNanoseconds
            )
        }
        self.lock.lock(); self.cleanupComplete = true; self.lock.unlock()
    }

    func cancelLaunch(_ owned: OwnedProcess) {
        if self.isCancellationRequested() {
            self.finalizeSignalCleanupIfNeeded()
        } else {
            terminateOwnedRoot(owned)
        }
    }

    private func drainSignalPipe() {
        var values = [UInt8](repeating: 0, count: 32)
        while true {
            let count = values.withUnsafeMutableBytes { buffer in
                Darwin.read(self.signalPipe, buffer.baseAddress, buffer.count)
            }
            guard count > 0 else { return }
            for value in values.prefix(Int(count)) {
                self.receive(Int32(value))
            }
        }
    }

    private func receive(_ number: Int32) {
        self.lock.lock()
        if self.pendingSignal == nil {
            self.pendingSignal = number
        }
        let value = self.owned
        self.lock.unlock()
        if let value {
            self.forward(number, owned: value)
        }
    }

    private func forward(_ signal: Int32, owned: OwnedProcess) {
        let descendants = captureDescendants(for: owned)
        self.lock.lock()
        self.signalDescendants.merge(descendants) { current, _ in current }
        let merged = self.signalDescendants
        self.lock.unlock()
        forwardSignal(signal, owned: owned, descendants: merged)
    }
}

#if DEBUG
    private func runSignalFixture() -> Int32 {
        let signals = SignalCoordinator(gracefulShutdownNanoseconds: 100_000_000)
        do {
            let script = "(trap '' TERM INT; exec /bin/sleep 1000) & echo $! > \"$MACOP_AGENT_SIGNAL_CHILD_FILE\"; while :; do sleep 1; done"
            let pid = try spawn(["/bin/sh", "-c", script], environment: ProcessInfo.processInfo.environment,
                                isolatedProcessGroup: true)
            let owned = try capture(pid, mode: "shell")
            signals.installOwned(owned)
            signals.beginRootWait()
            DispatchQueue.global(qos: .userInitiated).async {
                _ = try? waitForShellExit(pid) { signals.isCancellationRequested() }
                signals.endRootWait()
            }
            while signals.exitStatus == nil {
                signals.finalizeSignalCleanupIfNeeded()
                usleep(20000)
            }
            return signals.exitStatus!
        } catch {
            return signals.requestedExitStatus ?? ExitCode.denied.rawValue
        }
    }

    private func runApplicationSignalFixture() -> Int32 {
        let signals = SignalCoordinator(gracefulShutdownNanoseconds: 100_000_000)
        do {
            let script = "(trap '' TERM INT; exec /bin/sleep 1000) & echo $! > \"$MACOP_AGENT_SIGNAL_CHILD_FILE\"; while :; do sleep 1; done"
            let pid = try spawn(["/bin/sh", "-c", script], environment: ProcessInfo.processInfo.environment,
                                isolatedProcessGroup: true)
            let owned = try capture(pid, mode: "application")
            signals.installOwned(owned)
            signals.beginRootWait()
            DispatchQueue.global(qos: .userInitiated).async {
                _ = try? waitForApplicationExit(owned) { signals.isCancellationRequested() }
                signals.endRootWait()
            }
            while signals.exitStatus == nil {
                signals.finalizeSignalCleanupIfNeeded()
                usleep(20000)
            }
            return signals.exitStatus!
        } catch {
            return signals.requestedExitStatus ?? ExitCode.denied.rawValue
        }
    }
#endif

private struct LaunchCodeIdentity {
    let bundleID: String
    let requirement: String
    let snapshot: LiveCodeIdentity
}

private func identity(for pid: Int32, expectedPath: String, mode: String) throws -> LaunchCodeIdentity {
    let inspection = try mode == "git"
        ? LiveCodeIdentityInspector.inspectExpectedAppleGit(pid: pid, expectedPath: expectedPath)
        : LiveCodeIdentityInspector.inspect(pid: pid, expectedPath: expectedPath)
    return LaunchCodeIdentity(
        bundleID: inspection.identity.identifier,
        requirement: inspection.codeRequirement,
        snapshot: inspection.identity
    )
}

private func expectedExecutable(mode: String, target: [String], environment: [String: String]) throws -> String {
    guard let target = target.first else { throw AgentProtocolError.denied }
    if mode == "application" {
        let app = URL(fileURLWithPath: target).resolvingSymlinksInPath()
        guard let executable = Bundle(url: app)?.executableURL else { throw AgentProtocolError.denied }
        return LiveCodeIdentityInspector.canonicalPath(executable.path)
    }
    if target.contains("/") {
        return LiveCodeIdentityInspector.canonicalPath(target)
    }
    let searchPath = environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"
    for directory in searchPath.split(separator: ":", omittingEmptySubsequences: false) {
        let candidate = URL(fileURLWithPath: directory.isEmpty ? "." : String(directory))
            .appendingPathComponent(target).path
        if FileManager.default.isExecutableFile(atPath: candidate) {
            return LiveCodeIdentityInspector.canonicalPath(candidate)
        }
    }
    throw AgentProtocolError.denied
}

private struct PreparedRootLaunch {
    let owned: OwnedProcess
    let code: LaunchCodeIdentity
    let suspended: SuspendedProcessController?
}

private func prepareRootLaunch(
    mode: String,
    target: [String],
    environment: [String: String],
    inspect: (Int32, String, String) throws -> LaunchCodeIdentity
) throws -> PreparedRootLaunch {
    let expectedPath = try expectedExecutable(mode: mode, target: target, environment: environment)
    let shellLike = mode == "shell" || mode == "git"
    let lifecycleMode = shellLike ? "shell" : mode
    let owned: OwnedProcess
    var suspended: SuspendedProcessController?
    if shellLike {
        let isolatedProcessGroup = !hasInteractiveTerminal()
        let pid: Int32
        if mode == "git" {
            pid = try spawnSuspended(
                target, environment: environment, isolatedProcessGroup: isolatedProcessGroup
            )
            suspended = SuspendedProcessController(pid: pid)
        } else {
            pid = try spawn(target, environment: environment, isolatedProcessGroup: isolatedProcessGroup)
        }
        do {
            owned = try capture(pid, mode: lifecycleMode)
        } catch {
            if suspended?.cancelBeforeResume() != true {
                abandon(pid, mode: lifecycleMode, isolated: isolatedProcessGroup)
            }
            throw error
        }
    } else if mode == "application" {
        let application = try launchApplication(target[0], environment: environment)
        do {
            owned = try capture(application.processIdentifier, mode: mode, app: application)
        } catch {
            abandon(application.processIdentifier, mode: mode, app: application)
            throw error
        }
    } else {
        throw AgentProtocolError.denied
    }
    do {
        let code = try inspect(owned.pid, expectedPath, mode)
        return PreparedRootLaunch(owned: owned, code: code, suspended: suspended)
    } catch {
        if suspended?.cancelBeforeResume() != true {
            terminateOwnedRoot(owned)
        }
        throw error
    }
}

#if DEBUG
    private func runGitSuspendedLaunchFixture() -> Bool {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("macop-git-suspended-\(UUID().uuidString)", isDirectory: true)
        let rejectedSideEffect = root.appendingPathComponent("rejected-ran")
        let resumedSideEffect = root.appendingPathComponent("resumed-ran")
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            do {
                _ = try prepareRootLaunch(
                    mode: "git", target: ["/usr/bin/touch", rejectedSideEffect.path],
                    environment: ProcessInfo.processInfo.environment,
                    inspect: { _, _, _ in throw AgentProtocolError.denied }
                )
                return false
            } catch AgentProtocolError.denied {}
            guard !FileManager.default.fileExists(atPath: rejectedSideEffect.path) else { return false }
            let prepared = try prepareRootLaunch(
                mode: "git", target: ["/usr/bin/touch", resumedSideEffect.path],
                environment: ProcessInfo.processInfo.environment,
                inspect: { _, expectedPath, _ in
                    LaunchCodeIdentity(
                        bundleID: "fixture.git", requirement: "identifier fixture.git",
                        snapshot: LiveCodeIdentity(
                            canonicalPath: expectedPath, identifier: "fixture.git", teamID: nil,
                            signingAuthority: nil, cdHash: "00112233", hasTrustedPublisher: false
                        )
                    )
                }
            )
            guard let suspended = prepared.suspended else { return false }
            try suspended.resume()
            guard try waitForShellExit(prepared.owned.pid) == 0 else { return false }
            return FileManager.default.fileExists(atPath: resumedSideEffect.path)
        } catch {
            return false
        }
    }
#endif

private func run(mode: String, label: String, target: [String], signals: SignalCoordinator) throws -> Int32 {
    let root = rootDirectory()
    let registry = try SessionRegistry(root: root)
    defer { _ = rmdir(root.path) }
    let dependencies = VerifiedSessionRuntimeDependencies(
        selectIdentity: { try SSHCommand.verifiedSessionIdentity(label: $0) },
        launch: { reservation in
            let launchEnvironment = environment(for: reservation)
            let shellLike = mode == "shell" || mode == "git"
            let prepared = try prepareRootLaunch(
                mode: mode, target: target, environment: launchEnvironment, inspect: identity
            )
            signals.installOwned(prepared.owned)
            return VerifiedSessionRuntimeLaunch(
                request: VerifiedSessionLaunchRequest(
                    rootPID: prepared.owned.pid, rootStartTime: prepared.owned.startTime,
                    bundleID: prepared.code.bundleID, codeRequirement: prepared.code.requirement,
                    codeIdentity: prepared.code.snapshot
                ),
                waitForExit: {
                    // VerifiedSessionRuntime calls this only after activation,
                    // approval, signer installation, and registry authorization.
                    try prepared.suspended?.resume()
                    if shellLike {
                        signals.beginRootWait()
                        defer { signals.endRootWait() }
                        return try waitForShellExit(prepared.owned.pid) { signals.isCancellationRequested() }
                    }
                    signals.beginRootWait()
                    defer { signals.endRootWait() }
                    return try waitForApplicationExit(prepared.owned) { signals.isCancellationRequested() }
                },
                cancel: {
                    if prepared.suspended?.cancelBeforeResume() != true {
                        signals.cancelLaunch(prepared.owned)
                    }
                }
            )
        },
        activate: { reservation, request in
            try registry.activate(
                reservation: reservation,
                rootPID: request.rootPID,
                rootStartTime: request.rootStartTime,
                bundleID: request.bundleID,
                codeRequirement: request.codeRequirement,
                inspector: SystemRequesterInspector()
            )
        },
        prompt: CompanionAuthenticationSessionPrompt(),
        makeSigner: { try SSHCommand.makeVerifiedSessionSigner(label: $0, authenticationContext: $1) },
        makeAgent: { registry, sessionID, connections in
            VerifiedSessionAgent(registry: registry, sessionID: sessionID, connections: connections)
        },
        isCancellationRequested: { signals.isCancellationRequested() }
    )
    let status = try VerifiedSessionRuntime(registry: registry, dependencies: dependencies).run(label: label)
    signals.finalizeSignalCleanupIfNeeded()
    return signals.exitStatus ?? status
}

#if DEBUG
    if ProcessInfo.processInfo.environment["MACOP_AGENT_RUN_GIT_SUSPENDED_FIXTURE"] == "1" {
        exit(runGitSuspendedLaunchFixture() ? ExitCode.success.rawValue : ExitCode.denied.rawValue)
    }

    if ProcessInfo.processInfo.environment["MACOP_AGENT_RUN_LIFECYCLE_FIXTURES"] == "1" {
        exit(runLifecycleFixtures() ? ExitCode.success.rawValue : ExitCode.denied.rawValue)
    }

    if ProcessInfo.processInfo.environment["MACOP_AGENT_RUN_SIGNAL_FIXTURE"] == "1" {
        exit(runSignalFixture())
    }

    if ProcessInfo.processInfo.environment["MACOP_AGENT_RUN_APPLICATION_SIGNAL_FIXTURE"] == "1" {
        exit(runApplicationSignalFixture())
    }
#endif

private let signals = SignalCoordinator()
let args = Array(CommandLine.arguments.dropFirst())
guard let mode = args.first, args.count >= 3 else { fail(usage) }
let label = args[1]
do {
    try TrustedAgentHelperVerifier.requireTrustedRunningHelper()
    switch mode {
    case "shell", "git":
        guard let separator = args.firstIndex(of: "--"), separator >= 2, separator + 1 < args.count else { fail(usage) }
        let status = try run(mode: mode, label: label, target: Array(args[(separator + 1)...]), signals: signals)
        debugSuccess(status)
        exit(status)
    case "application":
        guard args.count == 3 else { fail(usage) }
        let status = try run(mode: mode, label: label, target: [args[2]], signals: signals)
        debugSuccess(status)
        exit(status)
    default: fail(usage)
    }
} catch {
    signals.finalizeSignalCleanupIfNeeded()
    if let status = signals.requestedExitStatus {
        exit(status)
    }
    if let error = error as? CLIError {
        let result = withDebug(ErrorRenderer.render(
            error: error,
            format: ProcessInfo.processInfo.environment["MACOP_AGENT_FORMAT"] == "json" ? .json : .humanReadable
        ))
        FileHandle.standardError.write(Data(result.stderr.utf8))
        exit(result.exitCode)
    }
    fail("verified session denied", ExitCode.denied.rawValue)
}
