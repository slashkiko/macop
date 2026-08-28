// swiftlint:disable file_length
import Darwin
import Dispatch
import Foundation
import MacopPTY

public enum RunCommand {
    /// Shared bounded pipe relay for wrappers which must preserve argv and the
    /// exact child environment without accumulating unbounded output in memory.
    public static func relay(
        argv: [String], environment: [String: String],
        stdout: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32 {
        try ProcessRunner.executeStreaming(
            argv: argv, environment: environment, stdin: nil,
            stdoutRedactor: nil, stderrRedactor: nil, stdout: stdout, stderr: stderr
        )
    }

    public static func relayTrustedAgent(
        argv: [String], environment: [String: String], policy: TrustedAgentLaunchPolicy,
        stdout: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32 {
        try ProcessRunner.executeStreaming(
            argv: argv, environment: environment, stdin: nil,
            stdoutRedactor: nil, stderrRedactor: nil, stdout: stdout, stderr: stderr,
            suspendedPolicy: policy
        )
    }

    public static func captureTrustedAgent(
        argv: [String], environment: [String: String], policy: TrustedAgentLaunchPolicy, limit: Int
    ) throws -> CommandResult {
        try ProcessRunner.execute(
            argv: argv, environment: environment, stdin: nil,
            stdoutRedactor: nil, stderrRedactor: nil, captureLimit: limit,
            suspendedPolicy: policy
        )
    }

    public static func runTrustedAgentInteractively(
        argv: [String], environment: [String: String], policy: TrustedAgentLaunchPolicy
    ) throws -> Int32 {
        try SuspendedTerminalProcess.execute(
            argv: argv,
            environment: environment,
            validate: { try policy.validateRunningProcess($0) }
        )
    }

    /// Process-level fixture seam for PTY/job-control coverage. Production
    /// trusted-agent dispatch always uses `runTrustedAgentInteractively`.
    public static func runSuspendedInteractiveFixture(
        argv: [String], environment: [String: String],
        validate: @escaping @Sendable (Int32) throws -> Void
    ) throws -> Int32 {
        try SuspendedTerminalProcess.execute(argv: argv, environment: environment, validate: validate)
    }

    /// Process-level fixture seam for the non-interactive suspended launch.
    /// Production trusted-agent dispatch always supplies a code-identity policy.
    public static func captureSuspendedFixture(
        argv: [String], environment: [String: String], limit: Int,
        validate: @escaping @Sendable (Int32) throws -> Void
    ) throws -> CommandResult {
        try ProcessRunner.execute(
            argv: argv, environment: environment, stdin: nil,
            stdoutRedactor: nil, stderrRedactor: nil, captureLimit: limit,
            suspendedValidator: validate
        )
    }

    public static func capture(
        argv: [String], environment: [String: String], limit: Int
    ) throws -> CommandResult {
        try ProcessRunner.execute(
            argv: argv, environment: environment, stdin: nil,
            stdoutRedactor: nil, stderrRedactor: nil, captureLimit: limit
        )
    }

    public static func relayInteractively(
        argv: [String], environment: [String: String], observer: (@Sendable (Data) -> Void)? = nil
    ) throws -> Int32 {
        try TerminalRelay.execute(
            argv: argv, environment: environment, initialInput: nil, redactor: nil, observer: observer
        )
    }

    /// The terminal relay owns the pty master and deliberately keeps child output
    /// separate from the CLI's normal buffered-command contract.
    public static func isInteractiveTerminal() -> Bool {
        self.isInteractiveTerminal(stdin: STDIN_FILENO, stdout: STDOUT_FILENO)
    }

    /// Kept parameterized so terminal selection is deterministic to test.
    public static func isInteractiveTerminal(stdin: Int32, stdout: Int32) -> Bool {
        isatty(stdin) == 1 && isatty(stdout) == 1
    }

    public static func requestsInjectedStdin(_ args: [String]) throws -> Bool {
        try self.parseArgs(args).stdinReference != nil
    }

    public static func run(
        args: [String], options: GlobalOptions, env: [String: String], client: any KeychainClient
    ) throws -> CommandResult {
        let context = try prepare(args: args, options: options, env: env, client: client)
        return try ProcessRunner.execute(
            argv: context.command,
            environment: context.environment,
            stdin: context.stdin,
            stdoutRedactor: context.noMasking ? nil : SecretRedactor(secrets: context.secrets),
            stderrRedactor: context.noMasking ? nil : SecretRedactor(secrets: context.secrets)
        )
    }

    // swiftlint:disable function_parameter_count
    /// Streams a non-interactive child directly to caller-owned sinks. This is
    /// used by MacopCLI so an unbounded child output cannot become CLI memory.
    public static func runStreaming(
        args: [String], options: GlobalOptions, env: [String: String], client: any KeychainClient,
        stdout: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32 {
        let context = try prepare(args: args, options: options, env: env, client: client)
        return try ProcessRunner.executeStreaming(
            argv: context.command,
            environment: context.environment,
            stdin: context.stdin,
            stdoutRedactor: context.noMasking ? nil : SecretRedactor(secrets: context.secrets),
            stderrRedactor: context.noMasking ? nil : SecretRedactor(secrets: context.secrets),
            stdout: stdout,
            stderr: stderr
        )
    }

    // swiftlint:enable function_parameter_count

    /// Runs a command through a PTY. This is intentionally separate from the
    /// buffered API above: a terminal program must observe a real terminal and
    /// its output must be relayed as it is produced.
    public static func runInteractively(
        args: [String], options: GlobalOptions, env: [String: String], client: any KeychainClient
    ) throws -> Int32 {
        let context = try prepare(args: args, options: options, env: env, client: client)
        return try TerminalRelay.execute(
            argv: context.command,
            environment: context.environment,
            initialInput: context.stdin,
            redactor: context.noMasking ? nil : SecretRedactor(secrets: context.secrets),
            observer: nil
        )
    }

    private static func prepare(
        args: [String], options: GlobalOptions, env: [String: String], client: any KeychainClient
    ) throws -> PreparedRun {
        let parsed = try parseArgs(args)
        var childEnvironment = ProcessInfo.processInfo.environment
        childEnvironment.merge(env) { _, supplied in supplied }
        var secrets = [String]()

        var dotenv = [String: String]()
        for path in parsed.envFiles {
            try dotenv.merge(Dotenv.load(path: path)) { _, later in later }
        }
        childEnvironment.merge(dotenv) { _, supplied in supplied }
        // Resolve only after all raw sources have been merged. A provider value
        // is opaque even when its secret text happens to look like another URI.
        for (key, value) in childEnvironment where SecretMaterial.containsReference(value) {
            let resolved = try SecretMaterial.resolveReferences(
                in: value,
                options: options,
                env: childEnvironment,
                client: client
            )
            childEnvironment[key] = resolved.output
            secrets.append(contentsOf: resolved.secrets)
        }
        let stdin = try parsed.stdinReference.map {
            try Data(SecretMaterial.resolveSingleReference($0, options: options, env: childEnvironment, client: client)
                .utf8)
        }
        if let stdin, let text = String(bytes: stdin, encoding: .utf8) {
            secrets.append(text)
        }
        return PreparedRun(
            command: parsed.command,
            environment: childEnvironment,
            stdin: stdin,
            secrets: secrets,
            noMasking: parsed.noMasking
        )
    }

    private static func parseArgs(_ args: [String]) throws -> ParsedRunArguments {
        var envFiles = [String](); var stdinReference: String?; var noMasking = false; var command =
            [String](); var index = 0
        while index < args.count {
            let arg = args[index]
            if arg == "--" {
                command = Array(args.dropFirst(index + 1)); break
            }
            switch arg {
            case "--env-file":
                guard index + 1 < args.count
                else { throw CLIError.invalidArguments(message: "Flag --env-file requires a path.") }
                envFiles.append(args[index + 1]); index += 1
            case let value where value.hasPrefix("--env-file="):
                let path = String(value.dropFirst("--env-file=".count)); guard !path.isEmpty
                else { throw CLIError.invalidArguments(message: "Flag --env-file requires a path.") }; envFiles
                    .append(path)
            case "--stdin":
                guard index + 1 < args.count
                else { throw CLIError.invalidArguments(message: "Flag --stdin requires a secret reference.") }
                guard stdinReference == nil
                else { throw CLIError.invalidArguments(message: "Flag --stdin may be specified once.") }
                stdinReference = args[index + 1]; index += 1
            case let value where value.hasPrefix("--stdin="):
                guard stdinReference == nil
                else { throw CLIError.invalidArguments(message: "Flag --stdin may be specified once.") }
                stdinReference = String(value.dropFirst("--stdin=".count))
            case "--no-masking": noMasking = true
            case "--environment":
                throw CLIError.unsupportedFlag(
                    flag: "--environment",
                    reason: "1Password Environments are not supported by macop."
                )
            case let value where value.hasPrefix("--environment="):
                throw CLIError.unsupportedFlag(
                    flag: "--environment",
                    reason: "1Password Environments are not supported by macop."
                )
            default: throw CLIError.invalidArguments(message: "run requires \"--\" before the command.")
            }
            index += 1
        }
        guard !command.isEmpty else { throw CLIError.invalidArguments(message: "run requires a command after \"--\".") }
        return ParsedRunArguments(
            envFiles: envFiles,
            stdinReference: stdinReference,
            noMasking: noMasking,
            command: command
        )
    }
}

private enum Dotenv {
    static func load(path: String) throws -> [String: String] {
        let text: String
        do { text = try String(contentsOfFile: path, encoding: .utf8) } catch {
            throw CLIError.runtimeError(message: "Unable to read env file.")
        }
        var result = [String: String]()
        for (lineNumber, original) in text.split(whereSeparator: \.isNewline).enumerated() {
            let line = original.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") {
                continue
            }
            let body = line.hasPrefix("export ") ? String(line.dropFirst(7)) : String(line)
            guard let equals = body.firstIndex(of: "=")
            else { throw CLIError.invalidArguments(message: "Invalid dotenv line \(lineNumber + 1).") }
            let key = String(body[..<equals]).trimmingCharacters(in: .whitespaces)
            guard key.range(of: #"^[A-Za-z_][A-Za-z0-9_]*$"#, options: .regularExpression) != nil
            else { throw CLIError.invalidArguments(message: "Invalid dotenv key on line \(lineNumber + 1).") }
            var value = String(body[body.index(after: equals)...]).trimmingCharacters(in: .whitespaces)
            if let first = value.first, first == "\"" || first == "'" {
                guard value.count >= 2, value.last == first else {
                    throw CLIError.invalidArguments(message: "Unterminated dotenv quote on line \(lineNumber + 1).")
                }
                value.removeFirst(); value.removeLast()
                if first == "\"" {
                    try self.rejectVariableExpansion(value, lineNumber: lineNumber + 1)
                    value = try self.decodeDoubleQuoted(value, lineNumber: lineNumber + 1)
                }
            } else if let comment = value.range(of: #"\s+#"#, options: .regularExpression) {
                value = String(value[..<comment.lowerBound]).trimmingCharacters(in: .whitespaces)
                try self.rejectVariableExpansion(value, lineNumber: lineNumber + 1)
            } else {
                try self.rejectVariableExpansion(value, lineNumber: lineNumber + 1)
            }
            result[key] = value
        }
        return result
    }

    private static func decodeDoubleQuoted(_ value: String, lineNumber: Int) throws -> String {
        var output = ""
        var iterator = value.makeIterator()
        while let character = iterator.next() {
            guard character == "\\" else { output.append(character); continue }
            guard let escaped = iterator.next() else {
                throw CLIError.invalidArguments(message: "Invalid dotenv escape on line \(lineNumber).")
            }
            switch escaped {
            case "n": output.append("\n")
            case "r": output.append("\r")
            case "t": output.append("\t")
            case "\\": output.append("\\")
            case "\"": output.append("\"")
            case "$": output.append("$")
            default:
                // dotenv parsers conventionally retain unknown escapes verbatim.
                output.append("\\"); output.append(escaped)
            }
        }
        return output
    }

    private static func rejectVariableExpansion(_ value: String, lineNumber: Int) throws {
        let referenceRanges = SecretMaterial.referenceRanges(in: value)
        var index = value.startIndex
        while index < value.endIndex {
            guard value[index] == "$" else { index = value.index(after: index); continue }
            var slashCount = 0
            var previous = index
            while previous > value.startIndex {
                previous = value.index(before: previous)
                guard value[previous] == "\\" else { break }
                slashCount += 1
            }
            let escaped = slashCount % 2 == 1
            let inReference = referenceRanges.contains { $0.contains(index) }
            let next = value.index(after: index)
            let startsVariable = next < value.endIndex
                && (value[next] == "{" || value[next] == "_" || value[next].isLetter)
            if !escaped, !inReference, startsVariable {
                throw CLIError.unsupportedFlag(
                    flag: "dotenv variable expansion",
                    reason: "Unescaped variable expansion on line \(lineNumber) is not supported by macop."
                )
            }
            index = next
        }
    }
}

enum SecretMaterial {
    struct Resolution {
        let output: String
        let secrets: [String]
    }

    static func containsReference(_ text: String) -> Bool {
        text.contains("op://") || text.contains("keychain://") || text.contains("secure-enclave://") || text
            .contains("apple-passwords://")
    }

    static func resolveSingleReference(
        _ text: String,
        options: GlobalOptions,
        env: [String: String],
        client: any KeychainClient
    ) throws -> String {
        let reference = try ReferenceResolver.parse(text, env: env)
        return try self.read(reference, options: options, client: client)
    }

    static func resolveReferences(
        in text: String,
        options: GlobalOptions,
        env: [String: String],
        client: any KeychainClient
    ) throws -> Resolution {
        var output = text
        var secrets = [String]()
        for range in self.referenceRanges(in: text).reversed() {
            let secret = try self.resolveSingleReference(
                String(output[range]), options: options, env: env, client: client
            )
            secrets.append(secret)
            output.replaceSubrange(range, with: secret)
        }
        return Resolution(output: output, secrets: secrets.reversed())
    }

    /// Finds URIs without making punctuation part of a reference and without
    /// consuming an immediately adjacent URI. ReferenceResolver remains the
    /// sole grammar authority for the URI itself.
    static func referenceRanges(in text: String) -> [Range<String.Index>] {
        let schemes = ["op://", "keychain://", "secure-enclave://", "apple-passwords://"]
        var ranges = [Range<String.Index>](); var cursor = text.startIndex
        while cursor < text.endIndex {
            guard let start = schemes.compactMap({ text.range(of: $0, range: cursor ..< text.endIndex)?.lowerBound })
                .min()
            else { break }
            let afterStart = text.index(start, offsetBy: schemes.first { text[start...].hasPrefix($0) }!.count)
            var end = afterStart
            while end < text.endIndex {
                if schemes.contains(where: { text[end...].hasPrefix($0) }) {
                    break
                }
                let character = text[end]
                if character.isWhitespace || "\"';,)}]".contains(character) {
                    break
                }
                end = text.index(after: end)
            }
            while end > afterStart, ".:!?".contains(text[text.index(before: end)]) {
                end = text.index(before: end)
            }
            if end > afterStart {
                ranges.append(start ..< end)
            }
            cursor = max(end, text.index(after: start))
        }
        return ranges
    }

    private static func read(
        _ reference: SecretReference,
        options: GlobalOptions,
        client: any KeychainClient
    ) throws -> String {
        switch reference {
        case let .keychainGeneric(service, account): return try KeychainProvider.readText(
                .generic(service: service, account: account),
                client: client
            )
        case let .keychainInternet(server, account): return try KeychainProvider.readText(
                .internet(server: server, account: account),
                client: client
            )
        case let .opReference(namespace, item, section, field):
            let item = try ConfigStore.resolveItem(
                namespace: namespace,
                item: item,
                configDirectory: options.configDirectory
            )
            let requested = section.map { "\($0)/\(field)" } ?? field
            if let fields = item.fields, !fields.isEmpty, !fields.contains(requested) {
                throw CLIError.notFound(message: "Field is not configured for this item.")
            }
            if item.provider == "keychain-generic", let service = item.service, let account = item.account {
                return try KeychainProvider.readText(
                    .generic(service: service, account: account),
                    client: client
                )
            }
            if item.provider == "keychain-managed", let service = item.service, let account = item.account {
                return try KeychainProvider.readText(
                    .managed(
                        service: service,
                        account: account,
                        synchronizable: item.managedKeychainSynchronizable
                    ),
                    client: client
                )
            }
            if item.provider == "keychain-internet", let server = item.server, let account = item.account {
                return try KeychainProvider.readText(
                    .internet(server: server, account: account),
                    client: client
                )
            }
            throw CLIError.unsupportedProvider(
                provider: item.provider,
                reason: "This provider cannot supply secret text."
            )
        case .secureEnclave: throw CLIError.unsupportedProvider(
                provider: "secure-enclave",
                reason: "Reading Secure Enclave identities as secrets is not supported."
            )
        }
    }
}

private enum ExecutableResolver {
    static func resolve(_ command: String, environment: [String: String]) throws -> String {
        if command.contains("/") {
            guard access(command, X_OK) == 0 else {
                throw CLIError.runtimeError(message: "Unable to start command: \(command).")
            }
            return command
        }
        let path = environment["PATH"] ?? "/usr/bin:/bin"
        for directory in path.split(separator: ":", omittingEmptySubsequences: false) {
            let candidate = (directory.isEmpty ? "." : String(directory)) + "/" + command
            if access(candidate, X_OK) == 0 {
                return candidate
            }
        }
        throw CLIError.runtimeError(message: "Unable to start command: \(command).")
    }
}

private enum ProcessRunner {
    // swiftlint:disable:next function_parameter_count
    static func executeStreaming(
        argv: [String], environment: [String: String], stdin: Data?, stdoutRedactor: SecretRedactor?,
        stderrRedactor: SecretRedactor?, stdout: @escaping @Sendable (Data) -> Void,
        stderr: @escaping @Sendable (Data) -> Void,
        suspendedPolicy: TrustedAgentLaunchPolicy? = nil
    ) throws -> Int32 {
        let result = try self.execute(
            argv: argv,
            environment: environment,
            stdin: stdin,
            stdoutRedactor: stdoutRedactor,
            stderrRedactor: stderrRedactor,
            stdoutSink: stdout,
            stderrSink: stderr,
            captureLimit: 0,
            suspendedPolicy: suspendedPolicy
        )
        return result.exitCode
    }

    static func execute(
        argv: [String], environment: [String: String], stdin: Data?, stdoutRedactor: SecretRedactor?,
        stderrRedactor: SecretRedactor?, stdoutSink: (@Sendable (Data) -> Void)? = nil,
        stderrSink: (@Sendable (Data) -> Void)? = nil, captureLimit: Int = .max,
        suspendedPolicy: TrustedAgentLaunchPolicy? = nil,
        suspendedValidator: (@Sendable (Int32) throws -> Void)? = nil
    ) throws -> CommandResult {
        let executable = try ExecutableResolver.resolve(argv[0], environment: environment)
        let validator = suspendedValidator ?? suspendedPolicy.map { policy in
            { try policy.validateRunningProcess($0) }
        }
        let signalGate = try validator.map { _ in try SuspendedSignalGate() }
        defer { signalGate?.finish() }
        var input = [Int32](repeating: -1, count: 2); var output = input; var errors = input
        defer { for descriptor in input + output + errors where descriptor >= 0 {
            _ = close(descriptor)
        } }
        guard pipe(&input) == 0, pipe(&output) == 0, pipe(&errors) == 0 else {
            throw CLIError.runtimeError(message: "Unable to create process pipes.")
        }
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw CLIError.runtimeError(message: "Unable to configure process pipes.")
        }
        defer {
            posix_spawn_file_actions_destroy(&actions)
        }
        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw CLIError.runtimeError(message: "Unable to configure process descriptors.")
        }
        defer { posix_spawnattr_destroy(&attributes) }
        var spawnFlags: Int16 = 0
        let requestedFlags = Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)
            | (validator == nil ? 0 : Int16(POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSIGMASK))
        var childSignalMask = sigset_t()
        sigemptyset(&childSignalMask)
        guard posix_spawnattr_getflags(&attributes, &spawnFlags) == 0,
              posix_spawnattr_setflags(&attributes, spawnFlags | requestedFlags) == 0,
              validator == nil || posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0
        else {
            throw CLIError.runtimeError(message: "Unable to isolate process descriptors.")
        }
        posix_spawn_file_actions_adddup2(&actions, input[0], STDIN_FILENO); posix_spawn_file_actions_adddup2(
            &actions,
            output[1],
            STDOUT_FILENO
        ); posix_spawn_file_actions_adddup2(&actions, errors[1], STDERR_FILENO)
        for descriptor in input + output + errors {
            posix_spawn_file_actions_addclose(&actions, descriptor)
        }
        var argvPointers = argv.map { strdup($0) } + [nil]; var envPointers = environment
            .map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            argvPointers.compactMap(\.self).forEach { free($0) }
            envPointers.compactMap(\.self).forEach { free($0) }
        }
        var pid: pid_t = 0
        let status = executable.withCString { executablePointer in
            argvPointers.withUnsafeMutableBufferPointer { argvBuffer in
                envPointers.withUnsafeMutableBufferPointer { envBuffer in
                    posix_spawn(
                        &pid,
                        executablePointer,
                        &actions,
                        &attributes,
                        argvBuffer.baseAddress,
                        envBuffer.baseAddress
                    )
                }
            }
        }
        guard status == 0 else { throw CLIError.runtimeError(message: "Unable to start command: \(argv[0]).") }
        var childReaped = false
        var childResumed = validator == nil
        defer {
            if !childReaped {
                _ = kill(pid, childResumed ? SIGTERM : SIGKILL)
                var ignoredStatus: Int32 = 0
                while waitpid(pid, &ignoredStatus, 0) == -1, errno == EINTR {}
            }
        }
        if let validator, let signalGate {
            do {
                try validator(pid)
            } catch {
                _ = kill(pid, SIGKILL)
                var ignoredStatus: Int32 = 0
                while waitpid(pid, &ignoredStatus, 0) == -1, errno == EINTR {}
                childReaped = true
                throw CLIError.denied(message: "The launched macop-agent image did not match the trusted helper.")
            }
            if let signalNumber = signalGate.pendingCancellation() {
                _ = kill(pid, SIGKILL)
                var ignoredStatus: Int32 = 0
                while waitpid(pid, &ignoredStatus, 0) == -1, errno == EINTR {}
                childReaped = true
                return CommandResult(exitCode: 128 + signalNumber, stdout: "", stderr: "")
            }
            guard kill(pid, SIGCONT) == 0 else {
                throw CLIError.runtimeError(message: "Unable to resume trusted macop-agent.")
            }
            childResumed = true
            // The ordinary streaming wait keeps the caller's prior signal
            // behavior. The gate exists only across the trusted pre-exec check.
            signalGate.finishBeforeWait()
        }
        _ = close(input[0]); input[0] = -1; _ = close(output[1]); output[1] = -1; _ = close(errors[1]); errors[1] = -1
        let outputRead = output[0]
        let errorRead = errors[0]
        let group = DispatchGroup(); let results = ProcessOutput()
        group.enter(); DispatchQueue.global().async {
            results.stdout = self.drain(
                outputRead,
                redactor: stdoutRedactor,
                sink: stdoutSink,
                captureLimit: captureLimit
            ); group.leave()
        }
        group.enter(); DispatchQueue.global().async {
            results.stderr = self.drain(
                errorRead,
                redactor: stderrRedactor,
                sink: stderrSink,
                captureLimit: captureLimit
            ); group.leave()
        }
        if let stdin {
            // macOS supports per-descriptor suppression. Do not mutate the
            // process-wide SIGPIPE disposition while a CLI is relaying input.
            guard fcntl(input[1], F_SETNOSIGPIPE, 1) == 0 else {
                throw CLIError.runtimeError(message: "Unable to configure command standard input.")
            }
            try self.writeAll(stdin, to: input[1])
        }
        _ = close(input[1]); input[1] = -1
        var childStatus: Int32 = 0
        while waitpid(pid, &childStatus, 0) == -1, errno == EINTR {}
        childReaped = true
        group.wait()
        let code = self.exitCode(for: childStatus)
        return CommandResult(
            exitCode: code,
            stdout: String(bytes: results.stdout, encoding: .utf8) ?? "",
            stderr: String(bytes: results.stderr, encoding: .utf8) ?? ""
        )
    }

    private static func drain(
        _ descriptor: Int32, redactor: SecretRedactor?, sink: (@Sendable (Data) -> Void)?, captureLimit: Int
    ) -> Data {
        var output = Data(); var bytes = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = read(descriptor, &bytes, bytes.count)
            if count < 0, errno == EINTR {
                continue
            }
            guard count > 0 else { break }
            let chunk = Data(bytes.prefix(Int(count)))
            let redacted = redactor?.process(chunk) ?? chunk
            sink?(redacted)
            self.append(redacted, to: &output, limit: captureLimit)
        }
        let tail = redactor?.process(Data(), final: true) ?? Data()
        sink?(tail)
        self.append(tail, to: &output, limit: captureLimit)
        return output
    }

    private static func append(_ data: Data, to output: inout Data, limit: Int) {
        guard output.count < limit else { return }
        output.append(data.prefix(limit - output.count))
    }

    private static func exitCode(for status: Int32) -> Int32 {
        if status & 0x7F != 0 {
            return 128 + (status & 0x7F)
        }
        return (status >> 8) & 0xFF
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { buffer in
                write(descriptor, buffer.baseAddress!.advanced(by: offset), data.count - offset)
            }
            if count < 0, errno == EINTR {
                continue
            }
            if count < 0, errno == EPIPE {
                return
            }
            guard count > 0 else { throw CLIError.runtimeError(message: "Unable to relay command standard input.") }
            offset += count
        }
    }
}

private struct ParsedRunArguments {
    let envFiles: [String]
    let stdinReference: String?
    let noMasking: Bool
    let command: [String]
}

private struct PreparedRun {
    let command: [String]
    let environment: [String: String]
    let stdin: Data?
    let secrets: [String]
    let noMasking: Bool
}

/// Holds INT/TERM while a suspended image is being authenticated. A signal
/// observed before the resume boundary is consumed and returned to the caller;
/// it can never be delivered by first running an unapproved child image.
private final class SuspendedSignalGate {
    let descriptor: Int32
    private var previousMask = sigset_t()
    private var maskBlocked = false
    private var bridgeInstalled = false

    init() throws {
        self.descriptor = macop_signal_pipe_install()
        guard self.descriptor >= 0 else {
            throw CLIError.runtimeError(message: "Unable to monitor helper signals.")
        }
        self.bridgeInstalled = true
        var mask = sigset_t()
        sigemptyset(&mask)
        sigaddset(&mask, SIGINT)
        sigaddset(&mask, SIGTERM)
        guard pthread_sigmask(SIG_BLOCK, &mask, &self.previousMask) == 0 else {
            macop_signal_pipe_restore()
            self.bridgeInstalled = false
            throw CLIError.runtimeError(message: "Unable to isolate helper validation signals.")
        }
        self.maskBlocked = true
    }

    func pendingCancellation() -> Int32? {
        var observed = self.drainSignals()
        var pending = sigset_t()
        guard sigpending(&pending) == 0 else { return observed.first }
        for signalNumber in [SIGINT, SIGTERM] where sigismember(&pending, signalNumber) == 1 {
            var singleSignal = sigset_t()
            sigemptyset(&singleSignal)
            sigaddset(&singleSignal, signalNumber)
            var consumed: Int32 = 0
            if sigwait(&singleSignal, &consumed) == 0 {
                observed.append(consumed)
            }
        }
        return observed.first { $0 == SIGINT || $0 == SIGTERM }
    }

    /// Restore the original handlers while cancellation remains blocked, then
    /// unmask. This avoids swallowing signals during the ordinary child wait.
    func finishBeforeWait() {
        self.restoreBridge()
        self.restoreMask()
    }

    /// Interactive callers keep the bridge after unmasking so later signals can
    /// be forwarded to the already authenticated child.
    func unblockForForwarding() {
        self.restoreMask()
    }

    func finish() {
        self.restoreMask()
        self.restoreBridge()
    }

    private func drainSignals() -> [Int32] {
        var result = [Int32]()
        var buffer = [UInt8](repeating: 0, count: 16)
        while true {
            let count = read(self.descriptor, &buffer, buffer.count)
            if count < 0, errno == EINTR {
                continue
            }
            guard count > 0 else { return result }
            result.append(contentsOf: buffer.prefix(Int(count)).map(Int32.init))
        }
    }

    private func restoreMask() {
        guard self.maskBlocked else { return }
        _ = pthread_sigmask(SIG_SETMASK, &self.previousMask, nil)
        self.maskBlocked = false
    }

    private func restoreBridge() {
        guard self.bridgeInstalled else { return }
        macop_signal_pipe_restore()
        self.bridgeInstalled = false
    }
}

/// The trusted helper already owns the caller's terminal and launches the
/// requested root itself. A new pseudo-terminal would obscure foreground-job
/// semantics, so start the exact helper suspended in the wrapper's existing
/// foreground process group, validate its live SecCode, then resume it.
private enum SuspendedTerminalProcess {
    static func execute(
        argv: [String], environment: [String: String],
        validate: @escaping @Sendable (Int32) throws -> Void
    ) throws -> Int32 {
        guard !argv.isEmpty, isatty(STDIN_FILENO) == 1, isatty(STDOUT_FILENO) == 1 else {
            throw CLIError.runtimeError(message: "Unable to configure trusted helper terminal.")
        }
        var arguments = argv.map { strdup($0) } + [nil]
        var variables = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            arguments.compactMap(\.self).forEach { free($0) }
            variables.compactMap(\.self).forEach { free($0) }
        }
        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw CLIError.runtimeError(message: "Unable to configure trusted helper.")
        }
        defer { posix_spawnattr_destroy(&attributes) }
        let signalGate = try SuspendedSignalGate()
        defer { signalGate.finish() }
        let flags = Int16(
            POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSIGMASK
        )
        var childSignalMask = sigset_t()
        sigemptyset(&childSignalMask)
        guard posix_spawnattr_setflags(&attributes, flags) == 0,
              posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0
        else { throw CLIError.runtimeError(message: "Unable to isolate trusted helper.") }
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw CLIError.runtimeError(message: "Unable to configure trusted helper terminal.")
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawn_file_actions_addinherit_np(&actions, STDIN_FILENO) == 0,
              posix_spawn_file_actions_addinherit_np(&actions, STDOUT_FILENO) == 0,
              posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO) == 0
        else { throw CLIError.runtimeError(message: "Unable to inherit trusted helper terminal.") }
        var pid: pid_t = 0
        let spawnStatus = arguments.withUnsafeMutableBufferPointer { argumentBuffer in
            variables.withUnsafeMutableBufferPointer { environmentBuffer in
                posix_spawn(
                    &pid, argv[0], &actions, &attributes,
                    argumentBuffer.baseAddress, environmentBuffer.baseAddress
                )
            }
        }
        guard spawnStatus == 0 else { throw CLIError.runtimeError(message: "Unable to start macop-agent.") }
        var reaped = false
        defer {
            if !reaped {
                _ = kill(pid, SIGKILL)
                var ignored: Int32 = 0
                while waitpid(pid, &ignored, 0) == -1, errno == EINTR {}
            }
        }
        do {
            try validate(pid)
        } catch {
            throw CLIError.denied(message: "The launched macop-agent image did not match the trusted helper.")
        }
        guard getpgid(pid) == getpgrp() else {
            throw CLIError.runtimeError(message: "Unable to resume trusted macop-agent.")
        }
        if let signalNumber = signalGate.pendingCancellation() {
            _ = kill(pid, SIGKILL)
            var ignored: Int32 = 0
            while waitpid(pid, &ignored, 0) == -1, errno == EINTR {}
            reaped = true
            return 128 + signalNumber
        }
        guard kill(pid, SIGCONT) == 0 else {
            throw CLIError.runtimeError(message: "Unable to resume trusted macop-agent.")
        }
        signalGate.unblockForForwarding()
        var status: Int32 = 0
        var forwardedSignal: Int32?
        var forcedDeadline: UInt64?
        while true {
            let waited = waitpid(pid, &status, WNOHANG)
            if waited == pid {
                reaped = true
                return self.exitCode(for: status)
            }
            if waited == -1, errno != EINTR {
                throw CLIError.runtimeError(message: "Unable to wait for trusted macop-agent.")
            }
            for signalNumber in self.drainSignals(signalGate.descriptor) {
                if signalNumber == SIGINT || signalNumber == SIGTERM {
                    forwardedSignal = forwardedSignal ?? signalNumber
                    forcedDeadline = forcedDeadline ?? DispatchTime.now().uptimeNanoseconds + 5_000_000_000
                    _ = kill(pid, signalNumber)
                }
            }
            if let deadline = forcedDeadline, DispatchTime.now().uptimeNanoseconds >= deadline {
                _ = kill(pid, SIGKILL)
                while waitpid(pid, &status, 0) == -1, errno == EINTR {}
                reaped = true
                return forwardedSignal.map { 128 + $0 } ?? ExitCode.denied.rawValue
            }
            var descriptor = pollfd(fd: signalGate.descriptor, events: Int16(POLLIN), revents: 0)
            _ = poll(&descriptor, 1, 50)
        }
    }

    private static func drainSignals(_ descriptor: Int32) -> [Int32] {
        var result = [Int32]()
        var buffer = [UInt8](repeating: 0, count: 16)
        while true {
            let count = read(descriptor, &buffer, buffer.count)
            if count < 0, errno == EINTR {
                continue
            }
            guard count > 0 else { return result }
            result.append(contentsOf: buffer.prefix(Int(count)).map(Int32.init))
        }
    }

    private static func exitCode(for status: Int32) -> Int32 {
        status & 0x7F != 0 ? 128 + (status & 0x7F) : (status >> 8) & 0xFF
    }
}

/// A synchronous relay used only when the CLI itself owns an interactive
/// terminal. Keeping it here (rather than in MacopCLI) makes the process and
/// secret-handling boundary identical for all executable entry points.
private enum TerminalRelay {
    static func execute(
        argv: [String], environment: [String: String], initialInput: Data?, redactor: SecretRedactor?,
        observer: (@Sendable (Data) -> Void)?
    ) throws -> Int32 {
        var size = winsize()
        guard ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 else {
            throw CLIError.runtimeError(message: "Unable to read terminal size.")
        }
        let executable = try ExecutableResolver.resolve(argv[0], environment: environment)
        var ptyController: Int32 = -1; var pid: pid_t = 0
        // execve receives the resolved path separately; argv[0] remains exactly
        // what the caller supplied, matching execvp's public contract.
        var arguments = argv.map { strdup($0) } + [nil]
        var variables = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            arguments.compactMap(\.self).forEach { free($0) }
            variables.compactMap(\.self).forEach { free($0) }
        }
        let forkStatus = arguments.withUnsafeMutableBufferPointer { argumentBuffer in
            variables.withUnsafeMutableBufferPointer { environmentBuffer in
                macop_forkpty_exec(
                    executable,
                    argumentBuffer.baseAddress,
                    environmentBuffer.baseAddress,
                    &size,
                    &ptyController,
                    &pid
                )
            }
        }
        guard forkStatus == 0 else { throw CLIError.runtimeError(message: "Unable to create terminal relay.") }
        defer {
            if ptyController >= 0 {
                _ = close(ptyController)
            }
        }

        var childStatus: Int32 = 0
        var childReaped = false
        var savedTerminal: termios?
        var signals: SignalForwarder?
        defer {
            signals?.stop()
            if var savedTerminal {
                _ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &savedTerminal)
            }
            if !childReaped {
                _ = kill(-pid, SIGTERM)
                while waitpid(pid, &childStatus, 0) == -1, errno == EINTR {}
                childReaped = true
            }
        }

        var originalTerminal = termios()
        guard tcgetattr(STDIN_FILENO, &originalTerminal) == 0 else {
            throw CLIError.runtimeError(message: "Unable to configure terminal relay.")
        }
        savedTerminal = originalTerminal
        var rawTerminal = originalTerminal
        cfmakeraw(&rawTerminal)
        guard tcsetattr(STDIN_FILENO, TCSAFLUSH, &rawTerminal) == 0 else {
            throw CLIError.runtimeError(message: "Unable to configure terminal relay.")
        }

        let signalForwarder = SignalForwarder(pid: pid, ptyController: ptyController)
        signals = signalForwarder
        signalForwarder.start()
        if let initialInput {
            try self.writeAll(initialInput, to: ptyController)
        }

        var status: Int32 = 0; var exited = false
        var descriptors = [
            pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0),
            pollfd(fd: ptyController, events: Int16(POLLIN), revents: 0)
        ]
        while true {
            _ = poll(&descriptors, 2, 50)
            if descriptors[0].revents & Int16(POLLIN) != 0 {
                try self.relayInput(from: STDIN_FILENO, to: ptyController)
            }
            if descriptors[1].revents & Int16(POLLIN) != 0 || descriptors[1].revents & Int16(POLLHUP) != 0 {
                let relayed = self.relayOutput(
                    from: ptyController, redactor: redactor, final: false, observer: observer
                )
                if !relayed, exited {
                    break
                }
            }
            if !exited, waitpid(pid, &status, WNOHANG) == pid {
                exited = true
                childReaped = true
            }
            if exited {
                while self.relayOutput(from: ptyController, redactor: redactor, final: false, observer: observer) {}
                let tail = redactor?.process(Data(), final: true) ?? Data()
                try self.writeAll(tail, to: STDOUT_FILENO)
                break
            }
            descriptors[0].revents = 0; descriptors[1].revents = 0
        }
        return self.exitCode(for: status)
    }

    private static func relayInput(from source: Int32, to destination: Int32) throws {
        var buffer = [UInt8](repeating: 0, count: 4096)
        let count = read(source, &buffer, buffer.count)
        if count > 0 {
            try self.writeAll(Data(buffer.prefix(Int(count))), to: destination)
        }
    }

    @discardableResult private static func relayOutput(
        from descriptor: Int32, redactor: SecretRedactor?, final: Bool,
        observer: (@Sendable (Data) -> Void)?
    ) -> Bool {
        var buffer = [UInt8](repeating: 0, count: 4096)
        let count = read(descriptor, &buffer, buffer.count)
        guard count > 0 else { return false }
        let output = redactor?.process(Data(buffer.prefix(Int(count))), final: final) ?? Data(buffer.prefix(Int(count)))
        observer?(output)
        try? self.writeAll(output, to: STDOUT_FILENO)
        return true
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { write(
                descriptor,
                $0.baseAddress!.advanced(by: offset),
                data.count - offset
            ) }
            guard count > 0 else { throw CLIError.runtimeError(message: "Unable to relay terminal data.") }
            offset += count
        }
    }

    private static func exitCode(for status: Int32) -> Int32 {
        if status & 0x7F != 0 {
            return 128 + (status & 0x7F)
        }
        return (status >> 8) & 0xFF
    }
}

private final class SignalForwarder: @unchecked Sendable {
    private let pid: pid_t; private let ptyController: Int32
    private var sources = [DispatchSourceSignal](); private var previous = [(
        Int32,
        (@convention(c) (Int32) -> Void)?
    )]()
    init(pid: pid_t, ptyController: Int32) {
        self.pid = pid; self.ptyController = ptyController
    }

    func start() {
        for signalNumber in [SIGINT, SIGTERM, SIGWINCH] {
            let old = signal(signalNumber, SIG_IGN); previous.append((signalNumber, old))
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .global())
            source.setEventHandler { [pid, ptyController] in
                if signalNumber == SIGWINCH {
                    var size = winsize(); if ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 {
                        _ = ioctl(
                            ptyController,
                            TIOCSWINSZ,
                            &size
                        )
                    }
                } else {
                    _ = kill(-pid, signalNumber)
                }
            }
            source.resume(); self.sources.append(source)
        }
    }

    func stop() {
        self.sources.forEach { $0.cancel() }; for (number, old) in self.previous {
            _ = signal(number, old)
        }
    }
}

private final class ProcessOutput: @unchecked Sendable {
    var stdout = Data()
    var stderr = Data()
}
