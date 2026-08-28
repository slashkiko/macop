import Darwin

// swiftlint:disable file_length
import Dispatch
import Foundation
import LocalAuthentication
import Security

/// The small command boundary used by the Apple SSH wrapper.  Keeping it
/// injectable lets tests assert argv without invoking CTK or creating keys.
public protocol CommandExecuting: Sendable {
    func execute(path: String, arguments: [String], environment: CommandEnvironment) throws -> CommandResult
}

/// Optional streaming capability.  Test executors only need the buffered
/// protocol; the production executor uses this for long-running SSH/Git work.
public protocol SSHStreamingExecuting: CommandExecuting {
    func executeStreaming(
        path: String, arguments: [String], environment: CommandEnvironment,
        stdout: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32
}

/// Test seams may resolve public CTK material without accessing the caller's
/// Keychain. Production executors deliberately use Security.framework.
public protocol CTKPublicKeyResolving: CommandExecuting {
    func publicKeyBlob(identityLabel: String, publicKeyHash: String) throws -> Data
}

/// Deterministic seam for validating xcrun output without trusting a fixture
/// path as an Apple-signed Git image.
public protocol AppleGitTrustValidating: CommandExecuting {
    func validateAppleGitExecutable(path: String) throws
}

public typealias CommandExecutor = any CommandExecuting
public typealias CommandEnvironment = [String: String]

public enum BiometricAvailability: Sendable, Equatable {
    case available
    case unavailable(reason: String)
}

public protocol BiometricAvailabilityChecking: Sendable {
    func checkAvailability() -> BiometricAvailability
}

public struct SystemBiometricAvailabilityChecker: BiometricAvailabilityChecking {
    public init() {}

    public func checkAvailability() -> BiometricAvailability {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            let code = error.map { LAError.Code(rawValue: $0.code) }
            let reason = switch code {
            case .biometryNotAvailable: "Touch ID is unavailable in this login session."
            case .biometryNotEnrolled: "Touch ID has no enrolled fingerprints."
            case .biometryLockout: "Touch ID is locked; authenticate locally before retrying."
            default: "Touch ID cannot be evaluated in this login session."
            }
            return .unavailable(reason: reason)
        }
        return .available
    }
}

public struct SystemCommandExecutor: SSHStreamingExecuting {
    public init() {}

    public func execute(path: String, arguments: [String], environment: CommandEnvironment) throws -> CommandResult {
        try RunCommand.capture(argv: [path] + arguments, environment: environment, limit: 65536)
    }

    public func executeStreaming(
        path: String, arguments: [String], environment: CommandEnvironment,
        stdout: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32 {
        try RunCommand.relay(argv: [path] + arguments, environment: environment, stdout: stdout, stderr: stderr)
    }
}

private final class BoundedCommandCapture: @unchecked Sendable {
    private let lock = NSLock()
    private let limit: Int
    private var storage = Data()

    init(limit: Int) {
        self.limit = limit
    }

    func append(_ data: Data) {
        self.lock.lock(); defer { self.lock.unlock() }
        guard self.storage.count < self.limit else { return }
        self.storage.append(data.prefix(self.limit - self.storage.count))
    }

    var data: Data {
        self.lock.lock(); defer { self.lock.unlock() }
        return self.storage
    }
}

public enum SSHCommand {
    public struct VerifiedSessionIdentity: Sendable {
        public let fingerprint: String
        fileprivate let label: String
        fileprivate let publicKeyBlob: Data

        public init(fingerprint: String, label: String, publicKeyBlob: Data) {
            self.fingerprint = fingerprint
            self.label = label
            self.publicKeyBlob = publicKeyBlob
        }
    }

    public static let scAuth = "/usr/sbin/sc_auth"
    public static let ssh = "/usr/bin/ssh"

    public static func run(
        args: [String],
        options: GlobalOptions,
        env: [String: String],
        executor: CommandExecutor,
        biometricChecker: any BiometricAvailabilityChecking = SystemBiometricAvailabilityChecker()
    ) throws -> CommandResult {
        let context = SSHContext(env: env, executor: executor)
        guard let subcommand = args.first
        else { throw CLIError.invalidArguments(message: "ssh requires a subcommand.") }
        switch subcommand {
        case "create": return try self.create(
                Array(args.dropFirst()),
                options: options,
                context: context,
                biometricChecker: biometricChecker
            )
        case "list":
            guard args.count == 1
            else { throw CLIError.invalidArguments(message: "ssh list does not accept arguments.") }
            return try self.list(options: options, context: context)
        case "public-key": return try self.publicKey(
                Array(args.dropFirst()),
                options: options,
                context: context
            )
        case "delete": return try self.delete(Array(args.dropFirst()), options: options, context: context)
        case "test": return try self.test(Array(args.dropFirst()), options: options, context: context)
        case "run": return try self.runWrapped(Array(args.dropFirst()), context: context)
        case "agent": return try self.agent(Array(args.dropFirst()), context: context)
        default: throw CLIError.invalidArguments(message: "Unknown ssh subcommand: \(subcommand)")
        }
    }

    /// Streams only the child-producing SSH operations.  Setup (identity
    /// lookup) stays bounded; output from ssh/git is never retained by macop.
    public static func runStreaming(
        args: [String], env: [String: String], executor: CommandExecutor,
        stdout: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32? {
        guard let streaming = executor as? any SSHStreamingExecuting,
              let subcommand = args.first, subcommand == "test" || subcommand == "run" || subcommand == "agent"
        else { return nil }
        let context = SSHContext(env: env, executor: executor)
        let invocation: SSHInvocation
        switch subcommand {
        case "test": invocation = try testInvocation(Array(args.dropFirst()), context: context)
        case "run": invocation = try runInvocation(Array(args.dropFirst()), context: context)
        case "agent": invocation = try agentInvocation(Array(args.dropFirst()), context: context)
        default: return nil
        }
        let capture = BoundedCommandCapture(limit: 65536)
        let rawCode: Int32 = if let policy = invocation.trustedAgentPolicy, executor is SystemCommandExecutor {
            try RunCommand.relayTrustedAgent(
                argv: [invocation.path] + invocation.arguments,
                environment: invocation.environment,
                policy: policy,
                stdout: { data in capture.append(data); stdout(data) },
                stderr: { data in capture.append(data); stderr(data) }
            )
        } else {
            try streaming.executeStreaming(
                path: invocation.path, arguments: invocation.arguments, environment: invocation.environment,
                stdout: { data in capture.append(data); stdout(data) },
                stderr: { data in capture.append(data); stderr(data) }
            )
        }
        return subcommand == "test"
            ? self.normalizedTestExitCode(rawCode, output: capture.data, destination: self.testDestination(args))
            : rawCode
    }

    public static func runInteractively(
        args: [String], env: [String: String], executor: CommandExecutor
    ) throws -> Int32? {
        guard executor is SystemCommandExecutor, let subcommand = args.first,
              subcommand == "test" || subcommand == "run" || subcommand == "agent"
        else {
            return nil
        }
        let context = SSHContext(env: env, executor: executor)
        let invocation = try subcommand == "test"
            ? self.testInvocation(Array(args.dropFirst()), context: context)
            : subcommand == "run"
            ? self.runInvocation(Array(args.dropFirst()), context: context)
            : self.agentInvocation(Array(args.dropFirst()), context: context)
        let capture = BoundedCommandCapture(limit: 65536)
        if subcommand == "test", let policy = invocation.trustedAgentPolicy {
            let rawCode = try RunCommand.relayTrustedAgent(
                argv: [invocation.path] + invocation.arguments,
                environment: invocation.environment,
                policy: policy,
                stdout: { data in
                    capture.append(data)
                    try? FileHandle.standardOutput.write(contentsOf: data)
                },
                stderr: { data in
                    capture.append(data)
                    try? FileHandle.standardError.write(contentsOf: data)
                }
            )
            return self.normalizedTestExitCode(
                rawCode, output: capture.data, destination: self.testDestination(args)
            )
        }
        let observer: (@Sendable (Data) -> Void)? = if subcommand == "test" {
            { @Sendable data in capture.append(data) }
        } else {
            nil
        }
        let rawCode = if let policy = invocation.trustedAgentPolicy {
            try RunCommand.runTrustedAgentInteractively(
                argv: [invocation.path] + invocation.arguments,
                environment: invocation.environment,
                policy: policy
            )
        } else {
            try RunCommand.relayInteractively(
                argv: [invocation.path] + invocation.arguments,
                environment: invocation.environment,
                observer: observer
            )
        }
        return subcommand == "test"
            ? self.normalizedTestExitCode(rawCode, output: capture.data, destination: self.testDestination(args))
            : rawCode
    }

    public static func validateIdentityTable(_ output: String) throws {
        _ = try self.parseIdentities(output)
    }

    static func validatedIdentityHashes(_ output: String) throws -> [String] {
        let identities = try self.parseIdentities(output)
        let hashes = identities.compactMap(\.hash)
        guard hashes.count == identities.count, hashes.allSatisfy(self.isSHA1Hash) else {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "One or more CTK identities have no unambiguous public-key hash."
            )
        }
        return hashes
    }

    static func validatedSecurityIdentityCount(
        _ output: String,
        executor: CommandExecutor
    ) throws -> Int {
        let identities = try self.parseIdentities(output)
        for identity in identities {
            guard let hash = identity.hash else { throw AgentProtocolError.denied }
            let blob: Data = if let fixture = executor as? any CTKPublicKeyResolving {
                try fixture.publicKeyBlob(identityLabel: identity.label, publicKeyHash: hash)
            } else {
                try CTKIdentitySigner.publicKeyBlob(identityLabel: identity.label, publicKeyHash: hash)
            }
            guard !blob.isEmpty else { throw AgentProtocolError.denied }
        }
        return identities.count
    }

    static func isolatedAgentSSHOptions() -> [String] {
        [
            "-F",
            "/dev/null",
            "-o",
            "PKCS11Provider=none",
            "-o",
            "ForwardAgent=no",
            "-o",
            "IdentitiesOnly=no",
            "-o",
            "IdentityFile=none",
            "-o",
            "IdentityAgent=SSH_AUTH_SOCK",
            "-o",
            "PreferredAuthentications=publickey"
        ]
    }

    /// Selects one CTK identity without exporting private material. The label
    /// must resolve uniquely through `sc_auth`, its public-key hash must select
    /// one Keychain certificate, and the signer must reproduce that public blob.
    public static func makeVerifiedSessionSigner(
        label: String,
        env: [String: String] = ProcessInfo.processInfo.environment,
        executor: CommandExecutor = SystemCommandExecutor(),
        authenticationContext: LAContext? = nil
    ) throws -> CTKIdentitySigner {
        let selected = try self.verifiedSessionIdentity(label: label, env: env, executor: executor)
        do {
            return try CTKIdentitySigner(
                identityLabel: selected.label,
                expectedPublicKeyBlob: selected.publicKeyBlob,
                authenticationContext: authenticationContext
            )
        } catch {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "Could not construct a signer for the selected public identity."
            )
        }
    }

    /// Resolves only public identity metadata. This is safe to do before a
    /// child is launched and lets the authorization UI display the exact key.
    public static func verifiedSessionIdentity(
        label: String,
        env: [String: String] = ProcessInfo.processInfo.environment,
        executor: CommandExecutor = SystemCommandExecutor(),
        publicKeyResolver: @Sendable (String, String) throws -> Data = {
            try CTKIdentitySigner.publicKeyBlob(identityLabel: $0, publicKeyHash: $1)
        }
    ) throws -> VerifiedSessionIdentity {
        let context = SSHContext(env: env, executor: executor)
        let identity = try self.identity(label, context: context)
        guard let publicKeyHash = identity.hash else {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "Selected identity has no SHA-1 public-key hash."
            )
        }
        let blob: Data
        do {
            blob = try publicKeyResolver(label, publicKeyHash)
        } catch {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "Could not resolve exactly one Security identity for the selected CTK label."
            )
        }
        return VerifiedSessionIdentity(
            fingerprint: sshFingerprint(for: blob), label: label, publicKeyBlob: blob
        )
    }
}

private extension SSHCommand {
    private static func agent(_ args: [String], context: SSHContext) throws -> CommandResult {
        let invocation = try self.agentInvocation(args, context: context)
        return try self.execute(invocation, context: context)
    }

    /// Buffered callers must preserve the same suspended-launch verification
    /// as the streaming and interactive entry points. Otherwise a direct
    /// `SSHCommand.run` call could race replacement of the verified helper
    /// between its on-disk inspection and an ordinary spawn.
    private static func execute(_ invocation: SSHInvocation, context: SSHContext) throws -> CommandResult {
        if let policy = invocation.trustedAgentPolicy, context.executor is SystemCommandExecutor {
            return try RunCommand.captureTrustedAgent(
                argv: [invocation.path] + invocation.arguments,
                environment: invocation.environment,
                policy: policy,
                limit: 65536
            )
        }
        return try context.executor.execute(
            path: invocation.path,
            arguments: invocation.arguments,
            environment: invocation.environment
        )
    }

    private static func agentInvocation(_ args: [String], context: SSHContext) throws -> SSHInvocation {
        guard let mode = args.first, mode == "shell" || mode == "application" else {
            throw CLIError.invalidArguments(
                message: "Usage: macop ssh agent shell <identity-label> -- <program> [arguments...] | "
                    + "macop ssh agent application <identity-label> <application-path>"
            )
        }
        if mode == "shell" {
            guard args.count >= 4, args[2] == "--" else {
                throw CLIError
                    .invalidArguments(
                        message: "Usage: macop ssh agent shell <identity-label> -- <program> [arguments...]"
                    )
            }
        } else {
            guard args.count == 3 else {
                throw CLIError
                    .invalidArguments(message: "Usage: macop ssh agent application <identity-label> <application-path>")
            }
        }
        return try self.trustedHelperInvocation(args, context: context)
    }

    private static func trustedHelperInvocation(_ args: [String], context: SSHContext) throws -> SSHInvocation {
        guard context.executor is SystemCommandExecutor else {
            return SSHInvocation(path: "macop-agent", arguments: args, environment: context.env)
        }
        let policy = try TrustedAgentHelperVerifier.resolveTrustedLaunch(of: RunningExecutable.path())
        return SSHInvocation(
            path: policy.executablePath,
            arguments: args,
            environment: context.env,
            trustedAgentPolicy: policy
        )
    }

    private static func create(
        _ args: [String],
        options: GlobalOptions,
        context: SSHContext,
        biometricChecker: any BiometricAvailabilityChecking
    ) throws -> CommandResult {
        guard args.count == 1 || args.count == 2,
              let label = args.first
        else { throw CLIError.invalidArguments(message: "Usage: macop ssh create <label> [--touch-id]") }
        if args.count == 2, args[1] != "--touch-id" {
            throw CLIError.invalidArguments(message: "Unknown ssh create flag: \(args[1])")
        }
        try self.validate(label: label)
        let before = try self.identities(context: context)
        guard !before.contains(where: { $0.label == label }) else {
            throw CLIError.invalidArguments(message: "A CTK identity named \"\(label)\" already exists.")
        }
        if case let .unavailable(reason) = biometricChecker.checkAvailability() {
            throw CLIError.providerUnavailable(
                provider: "Touch ID",
                reason: "\(reason) No identity creation was attempted."
            )
        }
        // Touch ID is the secure default; --touch-id remains an explicit, compatible spelling.
        let result = try apple(
            context.executor,
            self.scAuth,
            ["create-ctk-identity", "-l", label, "-k", "p-256-ne", "-t", "bio"],
            context.env
        )
        let matches: [Identity]
        do {
            matches = try self.identities(context: context).filter { $0.label == label }
        } catch {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "Identity creation may have completed, but post-create verification failed. Inspect CTK identities before retrying."
            )
        }
        if result.exitCode != 0 {
            if matches.isEmpty, self.isUserInterruptExit(result.exitCode) {
                throw CLIError.denied(
                    message: "Identity creation was interrupted by the user. No matching CTK identity was found; inspect CTK identities before retrying."
                )
            }
            if matches.isEmpty {
                throw CLIError.providerUnavailable(
                    provider: "CryptoTokenKit",
                    reason: "Apple tooling did not create a matching identity (exit \(result.exitCode)). "
                        + "Touch ID cancellation and session availability are not exposed as structured sc_auth errors; "
                        + "inspect CTK identities before retrying."
                )
            }
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "Apple tooling failed (exit \(result.exitCode)), but \(matches.count) matching identity item(s) "
                    + "exist. Identity creation may have completed; inspect CTK identities before retrying."
            )
        }
        guard matches.count == 1, let created = matches.first else {
            let resultDescription = matches.isEmpty ? "no matching identity" : "multiple matching identities"
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "Apple tooling returned exit 0, but post-create verification found \(resultDescription). "
                    + "Creation may have been cancelled, unavailable, or otherwise produced no usable identity; "
                    + "inspect CTK identities before retrying."
            )
        }
        guard created.hash != nil else {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "The created identity has no unambiguous public-key hash. Inspect CTK identities before retrying."
            )
        }
        do {
            _ = try self.publicIdentity(created, context: context)
        } catch {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "The CTK identity was created, but Security.framework cannot resolve exactly one public key. "
                    + "Inspect the identity and remove it with `macop ssh delete \(label)` before retrying."
            )
        }
        return self.render([created], action: "created", options)
    }

    private static func isUserInterruptExit(_ exitCode: Int32) -> Bool {
        exitCode == 128 + SIGINT
    }

    private static func list(options: GlobalOptions, context: SSHContext) throws -> CommandResult {
        try self.render(self.identities(context: context), action: nil, options)
    }

    private static func publicKey(
        _ args: [String],
        options: GlobalOptions,
        context: SSHContext
    ) throws -> CommandResult {
        guard args.count == 1,
              let label = args.first
        else { throw CLIError.invalidArguments(message: "Usage: macop ssh public-key <label>") }
        let identity = try self.selectedPublicIdentity(label: label, context: context)
        let line = "ecdsa-sha2-nistp256 \(identity.publicKeyBlob.base64EncodedString()) \(label)"
        switch options.format {
        case .humanReadable: return CommandResult(exitCode: 0, stdout: line + "\n")
        case .json:
            return self.json(SSHPublicKeyResponse(label: label, publicKey: line))
        }
    }

    private static func delete(
        _ args: [String],
        options: GlobalOptions,
        context: SSHContext
    ) throws -> CommandResult {
        guard args.count == 1,
              let label = args.first
        else { throw CLIError.invalidArguments(message: "Usage: macop ssh delete <label>") }
        let selected = try identity(label, context: context)
        guard let hash = selected.hash, self.isSHA1Hash(hash) else {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "The selected identity has no unambiguous public hash; refusing deletion."
            )
        }
        let result = try apple(context.executor, self.scAuth, ["delete-ctk-identity", "-h", hash], context.env)
        try self.requireSuccess(result, provider: "CryptoTokenKit", operation: "delete identity")
        return self.render([selected], action: "deleted", options)
    }

    private static func test(
        _ args: [String], options: GlobalOptions, context: SSHContext
    ) throws -> CommandResult {
        guard args.count <= 2,
              let label = args.first
        else { throw CLIError.invalidArguments(message: "Usage: macop ssh test <label> [destination]") }
        let destination = args.count == 2 ? args[1] : "git@github.com"
        try self.validate(label: label); try self.validateDestination(destination)
        let invocation = try self.testInvocation(args, context: context)
        let raw = try self.execute(invocation, context: context)
        let combined = Data((raw.stdout + raw.stderr).utf8)
        let normalized = self.normalizedTestExitCode(raw.exitCode, output: combined, destination: destination)
        if options.format == .json {
            return self.json(SSHTestResponse(
                destination: destination,
                status: normalized == 0 ? "authenticated" : "failed",
                rawExitCode: raw.exitCode,
                exitCode: normalized
            ), exitCode: normalized)
        }
        return CommandResult(exitCode: normalized, stdout: raw.stdout, stderr: raw.stderr)
    }

    private static func runWrapped(_ args: [String], context: SSHContext) throws -> CommandResult {
        guard let separator = args.firstIndex(of: "--"),
              separator == 1
        else { throw CLIError.invalidArguments(message: "Usage: macop ssh run <label> -- <command> [args...]") }
        let invocation = try self.runInvocation(args, context: context)
        return try self.execute(invocation, context: context)
    }

    private static func runInvocation(_ args: [String], context: SSHContext) throws -> SSHInvocation {
        guard let separator = args.firstIndex(of: "--"), separator == 1 else {
            throw CLIError.invalidArguments(message: "Usage: macop ssh run <label> -- <command> [args...]")
        }
        let label = args[0]; let command = Array(args.dropFirst(separator + 1))
        guard !command.isEmpty
        else { throw CLIError.invalidArguments(message: "ssh run requires a command after \"--\".") }
        try self.validate(label: label)
        _ = try self.identity(label, context: context)
        // Git shell-interprets GIT_SSH_COMMAND. This value remains safe because
        // every token is a fixed internal constant and no user input is interpolated.
        guard command[0] == "git" || command[0] == "/usr/bin/git" else {
            throw CLIError.unsupportedCommand(
                command: "ssh run",
                reason: "This wrapper accepts only `git` or Apple's `/usr/bin/git` entry point; "
                    + "it never shells out or exports a private key."
            )
        }
        var childEnv = context.env
        childEnv["GIT_SSH_COMMAND"] = ([self.ssh] + self.isolatedAgentSSHOptions()).joined(separator: " ")
        let executable = try self.resolveGitExecutable(command[0], context: context, environment: childEnv)
        return try self.trustedHelperInvocation(
            ["git", label, "--", executable] + Array(command.dropFirst()),
            context: SSHContext(env: childEnv, executor: context.executor)
        )
    }

    private static func testInvocation(_ args: [String], context: SSHContext) throws -> SSHInvocation {
        guard args.count <= 2, let label = args.first else {
            throw CLIError.invalidArguments(message: "Usage: macop ssh test <label> [destination]")
        }
        let destination = args.count == 2 ? args[1] : "git@github.com"
        try self.validate(label: label); try self.validateDestination(destination)
        _ = try self.identity(label, context: context)
        return try self.agentInvocation(
            ["shell", label, "--", self.ssh] + self.isolatedAgentSSHOptions() + ["-T", destination],
            context: context
        )
    }

    private static func testDestination(_ args: [String]) -> String {
        args.count >= 3 ? args[2] : "git@github.com"
    }

    private static func normalizedTestExitCode(_ raw: Int32, output: Data, destination: String) -> Int32 {
        guard raw == 1, self.isGitHub(destination: destination),
              let text = String(data: output, encoding: .utf8)?.lowercased(),
              text.contains("successfully authenticated"), text.contains("does not provide shell access")
        else { return raw }
        return 0
    }

    private static func isGitHub(destination: String) -> Bool {
        destination.split(separator: "@").last.map(String.init)?.lowercased() == "github.com"
    }

    private static func apple(
        _ executor: CommandExecutor,
        _ path: String,
        _ args: [String],
        _ env: CommandEnvironment
    ) throws -> CommandResult {
        guard FileManager.default.isExecutableFile(atPath: path) || !(executor is SystemCommandExecutor)
        else { throw CLIError.providerUnavailable(
            provider: "apple-ssh",
            reason: "Required Apple executable is unavailable: \(path)"
        ) }
        return try executor.execute(path: path, arguments: args, environment: env)
    }

    private static func requireSuccess(_ result: CommandResult, provider: String, operation: String) throws {
        guard result.exitCode == 0 else { throw CLIError.providerUnavailable(
            provider: provider,
            reason: "Apple tooling failed to \(operation) (exit \(result.exitCode))."
        ) }
    }

    private static func identity(_ label: String, context: SSHContext) throws -> Identity {
        try self.validate(label: label)
        let matches = try self.identities(context: context)
            .filter { $0.label == label && self.isSHA1Hash($0.hash ?? "") }
        guard matches.count == 1,
              let found = matches.first
        else {
            throw matches.isEmpty ? CLIError.notFound(message: "No CTK identity named \"\(label)\".") : CLIError
                .providerUnavailable(
                    provider: "CryptoTokenKit",
                    reason: "CTK identity label \"\(label)\" is ambiguous."
                )
        }
        return found
    }

    private static func identities(context: SSHContext) throws -> [Identity] {
        let result = try apple(
            context.executor,
            self.scAuth,
            ["list-ctk-identities", "-t", "sha1", "-e", "hex"],
            context.env
        )
        try self.requireSuccess(result, provider: "CryptoTokenKit", operation: "list identities")
        return try self.parseIdentities(result.stdout)
    }

    private static func parseIdentities(_ text: String) throws -> [Identity] {
        if let header = text.split(whereSeparator: \.isNewline).first(where: { $0.contains("Public Key Hash") }) {
            let layout = try TableLayout(header: String(header))
            var identities = [Identity]()
            for row in text.split(whereSeparator: \.isNewline).drop(while: { $0 != header }).dropFirst() {
                guard !row.trimmingCharacters(in: .whitespaces).isEmpty, !self.isTableSeparator(row) else { continue }
                guard let identity = try self.parseTableRow(row, layout: layout) else {
                    throw CLIError.providerUnavailable(
                        provider: "CryptoTokenKit",
                        reason: "sc_auth identity table contains an unparseable data row."
                    )
                }
                identities.append(identity)
            }
            return identities.sorted { $0.label < $1.label }
        }
        throw CLIError.providerUnavailable(
            provider: "CryptoTokenKit",
            reason: "sc_auth did not return a recognizable CTK identity table."
        )
    }

    private static func parseTableRow(_ row: Substring, layout: TableLayout) throws -> Identity? {
        let line = String(row)
        guard line.count > layout.publicKeyHash else { return nil }
        let publicStart = line.index(line.startIndex, offsetBy: layout.publicKeyHash)
        guard let range = line[publicStart...]
            .range(of: #"^[[:space:]]*([0-9A-Fa-f]+)"#, options: .regularExpression)
        else {
            return nil
        }
        let hash = String(line[range]).trimmingCharacters(in: .whitespaces).uppercased()
        guard self.isSHA1Hash(hash) else { return nil }
        let hashEnd = line.distance(from: line.startIndex, to: range.upperBound)
        let shift = max(0, hashEnd - layout.protocolColumn)
        let labelStart = layout.label + shift
        let commonNameStart = layout.commonName + shift
        guard line.count > labelStart else { return nil }
        let labelEnd = min(line.count, commonNameStart)
        let label = String(line[
            line.index(line.startIndex, offsetBy: labelStart) ..< line.index(line.startIndex, offsetBy: labelEnd)
        ]).trimmingCharacters(in: .whitespaces)
        guard !label.isEmpty else { return nil }
        return Identity(label: label, hash: hash)
    }

    private static func isTableSeparator(_ row: Substring) -> Bool {
        row.allSatisfy { $0 == "-" || $0 == " " || $0 == "\t" }
    }

    private static func validate(label: String) throws {
        guard !label.isEmpty,
              label == label.trimmingCharacters(in: .whitespacesAndNewlines),
              label.utf8.count <= 128,
              !label.unicodeScalars.contains(where: {
                  $0.value == 0 || CharacterSet.controlCharacters.contains($0)
                      || CharacterSet.newlines.contains($0) || $0.properties.generalCategory == .format
              })
        else {
            throw CLIError
                .invalidArguments(
                    message: "SSH identity label must be printable, trimmed, and at most 128 UTF-8 bytes."
                )
        }
    }

    private static func validateDestination(_ value: String) throws {
        guard !value.hasPrefix("-"), value.range(
            of: "^[A-Za-z0-9._@:-]+$",
            options: .regularExpression
        ) != nil else { throw CLIError.invalidArguments(message: "SSH destination is invalid.") }
    }

    private static func isSHA1Hash(_ value: String) -> Bool {
        value.range(of: "^[0-9A-Fa-f]{40}$", options: .regularExpression) != nil
    }

    private static func selectedPublicIdentity(
        label: String,
        context: SSHContext
    ) throws -> VerifiedSessionIdentity {
        try self.publicIdentity(self.identity(label, context: context), context: context)
    }

    private static func publicIdentity(
        _ identity: Identity,
        context: SSHContext
    ) throws -> VerifiedSessionIdentity {
        guard let publicKeyHash = identity.hash else {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "Selected identity has no SHA-1 public-key hash."
            )
        }
        let fixture = context.executor as? any CTKPublicKeyResolving
        let resolver: @Sendable (String, String) throws -> Data = if let fixture {
            { try fixture.publicKeyBlob(identityLabel: $0, publicKeyHash: $1) }
        } else {
            { try CTKIdentitySigner.publicKeyBlob(identityLabel: $0, publicKeyHash: $1) }
        }
        let blob: Data
        do {
            blob = try resolver(identity.label, publicKeyHash)
        } catch {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "Could not resolve exactly one Security identity for the selected CTK label."
            )
        }
        return VerifiedSessionIdentity(
            fingerprint: sshFingerprint(for: blob), label: identity.label, publicKeyBlob: blob
        )
    }

    private static func resolveExecutable(_ command: String, environment: CommandEnvironment) throws -> String {
        guard !command.isEmpty, !command.contains("\0") else {
            throw CLIError.invalidArguments(message: "SSH run command is invalid.")
        }
        if command.contains("/") {
            guard FileManager.default.isExecutableFile(atPath: command) else {
                throw CLIError.providerUnavailable(provider: "ssh-run", reason: "Command is not executable: \(command)")
            }
            return command
        }
        let path = environment["PATH"] ?? ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin"
        for directory in path.split(separator: ":", omittingEmptySubsequences: false) {
            let base = directory.isEmpty ? "." : String(directory)
            let candidate = URL(fileURLWithPath: base).appendingPathComponent(command).path
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        throw CLIError.notFound(message: "Command not found in PATH: \(command)")
    }

    private static func resolveGitExecutable(
        _ command: String,
        context: SSHContext,
        environment: CommandEnvironment
    ) throws -> String {
        guard command == "git" || command == "/usr/bin/git" else {
            throw CLIError.unsupportedCommand(
                command: "ssh run",
                reason: "Only the active Apple developer-tool Git image is supported."
            )
        }
        guard context.executor is SystemCommandExecutor || context.executor is any AppleGitTrustValidating else {
            return try self.resolveExecutable(command, environment: environment)
        }
        var lookupEnvironment = context.env
        for key in ["DEVELOPER_DIR", "SDKROOT", "TOOLCHAINS", "xcrun_log", "xcrun_nocache", "xcrun_verbose"] {
            lookupEnvironment.removeValue(forKey: key)
        }
        let resolved = try self.apple(
            context.executor, "/usr/bin/xcrun", ["--no-cache", "--find", "git"], lookupEnvironment
        )
        try self.requireSuccess(resolved, provider: "xcode-select", operation: "resolve the Git executable")
        let path = resolved.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard URL(fileURLWithPath: path).lastPathComponent == "git",
              FileManager.default.isExecutableFile(atPath: path), path.hasPrefix("/")
        else {
            throw CLIError.providerUnavailable(
                provider: "xcode-select",
                reason: "xcrun did not return an executable Git path."
            )
        }
        do {
            if let fixture = context.executor as? any AppleGitTrustValidating {
                try fixture.validateAppleGitExecutable(path: path)
            } else {
                _ = try LiveCodeIdentityInspector.inspectExpectedAppleGitStatic(path: path)
            }
        } catch {
            throw CLIError.providerUnavailable(
                provider: "apple-git",
                reason: "xcrun did not resolve an Apple-signed, library-validated Git image."
            )
        }
        return path
    }

    private static func render(_ identities: [Identity], action: String?, _ options: GlobalOptions) -> CommandResult {
        if options.format == .json {
            return self.json(SSHIdentitiesResponse(
                action: action,
                identities: identities.map(SSHIdentityResponse.init)
            ))
        }
        let prefix = action.map { "\($0) " } ?? ""; return CommandResult(
            exitCode: 0,
            stdout: identities.map { "\(prefix)\($0.label)\($0.hash.map { " \($0)" } ?? "")" }
                .joined(separator: "\n") + (identities.isEmpty ? "" : "\n")
        )
    }

    private static func json(_ response: some Encodable, exitCode: Int32 = 0) -> CommandResult {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        do {
            return try CommandResult(
                exitCode: exitCode,
                stdout: (String(bytes: encoder.encode(response), encoding: .utf8) ?? "") + "\n"
            )
        } catch {
            return ErrorRenderer.render(
                error: .runtimeError(message: "Unable to encode SSH response."), format: .json
            )
        }
    }

    struct Identity { let label: String; let hash: String? }
}

private struct SSHInvocation {
    let path: String
    let arguments: [String]
    let environment: CommandEnvironment
    let trustedAgentPolicy: TrustedAgentLaunchPolicy?

    init(
        path: String,
        arguments: [String],
        environment: CommandEnvironment,
        trustedAgentPolicy: TrustedAgentLaunchPolicy? = nil
    ) {
        self.path = path
        self.arguments = arguments
        self.environment = environment
        self.trustedAgentPolicy = trustedAgentPolicy
    }
}

private struct SSHIdentityResponse: Encodable {
    let label: String
    let publicKeyHash: String?
    enum CodingKeys: String, CodingKey { case label; case publicKeyHash = "public_key_hash" }
    init(_ identity: SSHCommand.Identity) {
        self.label = identity.label; self.publicKeyHash = identity.hash
    }
}

private struct SSHIdentitiesResponse: Encodable {
    let schemaVersion = 1
    let action: String?
    let identities: [SSHIdentityResponse]
    enum CodingKeys: String, CodingKey { case schemaVersion = "schema_version", action, identities }
}

private struct SSHPublicKeyResponse: Encodable {
    let schemaVersion = 1
    let label: String
    let publicKey: String
    let provider = "security-framework"
    enum CodingKeys: String,
        CodingKey { case schemaVersion = "schema_version", label; case publicKey = "public_key"; case provider }
}

private struct SSHTestResponse: Encodable {
    let schemaVersion = 1
    let destination: String
    let status: String
    let rawExitCode: Int32
    let exitCode: Int32
    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case destination, status
        case rawExitCode = "raw_exit_code"
        case exitCode = "exit_code"
    }
}

private struct TableLayout {
    let publicKeyHash: Int
    let protocolColumn: Int
    let label: Int
    let commonName: Int

    init(header: String) throws {
        func start(_ name: String) -> Int? {
            header.range(of: name).map { header.distance(from: header.startIndex, to: $0.lowerBound) }
        }
        guard let publicKeyHash = start("Public Key Hash"), let protocolColumn = start("Prot"),
              let label = start("Label"), let commonName = start("Common Name"),
              publicKeyHash < protocolColumn, protocolColumn < label, label < commonName
        else {
            throw CLIError.providerUnavailable(
                provider: "CryptoTokenKit", reason: "sc_auth identity table header is ambiguous."
            )
        }
        self.publicKeyHash = publicKeyHash
        self.protocolColumn = protocolColumn
        self.label = label
        self.commonName = commonName
    }
}

private struct SSHContext {
    let env: CommandEnvironment
    let executor: CommandExecutor
}
