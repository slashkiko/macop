import Foundation

private func agentHelperEnvironment(_ environment: [String: String], options: GlobalOptions) -> [String: String] {
    var value = environment
    value["MACOP_AGENT_FORMAT"] = options.format == .json ? "json" : "human"
    value["MACOP_AGENT_DEBUG"] = options.debug ? "1" : "0"
    return value
}

/// Child argv begins at `--`; only the preceding macop grammar can select an
/// error format or debug output when command validation fails.
private func rawGlobalPrefix(argv: [String]) -> [String] {
    let arguments = argv.dropFirst()
    guard let boundary = arguments.firstIndex(of: "--") else { return Array(arguments) }
    return Array(arguments[..<boundary])
}

private func extractFormatHint(argv: [String], env: [String: String]) -> OutputFormat {
    var format: OutputFormat?
    let tokens = rawGlobalPrefix(argv: argv)
    var index = 0
    while index < tokens.count {
        let token = tokens[index]
        if token == "--format" {
            if index + 1 < tokens.count, let parsed = OutputFormat(rawValue: tokens[index + 1]) {
                format = parsed
                index += 1
            }
        } else if token.hasPrefix("--format=") {
            let value = String(token.dropFirst("--format=".count))
            if let parsed = OutputFormat(rawValue: value) {
                format = parsed
            }
        }
        index += 1
    }
    if let format {
        return format
    }
    return env["OP_FORMAT"] == OutputFormat.json.rawValue ? .json : .humanReadable
}

private func rawDebugEnabled(argv: [String], env: [String: String]) -> Bool {
    rawGlobalPrefix(argv: argv).contains("--debug")
        || env["OP_DEBUG"].map { ["1", "true", "yes", "on"].contains($0.lowercased()) } == true
}

public struct MacopApp {
    private let keychainClient: any KeychainClient
    private let commandExecutor: CommandExecutor
    private let biometricChecker: any BiometricAvailabilityChecking
    private let managedKeychainImporter: any ManagedKeychainImporting

    public init(
        keychainClient: any KeychainClient = DefaultKeychainClient(),
        commandExecutor: CommandExecutor = SystemCommandExecutor(),
        biometricChecker: any BiometricAvailabilityChecking = SystemBiometricAvailabilityChecker(),
        managedKeychainImporter: any ManagedKeychainImporting = CompanionManagedKeychainImporter()
    ) {
        self.keychainClient = keychainClient
        self.commandExecutor = commandExecutor
        self.biometricChecker = biometricChecker
        self.managedKeychainImporter = managedKeychainImporter
    }

    public func run(argv: [String], env: [String: String], input: Data = Data()) -> CommandResult {
        do {
            let parsed = try ArgumentParser.parse(argv: argv, env: env)
            let result = try self.execute(parsed, env: env, input: input)
            return self.withSafeDebug(
                result,
                enabled: parsed.options.debug && !(parsed.command == .ssh && parsed.commandArgs.first == "agent"),
                context: "command=\(parsed.command.rawValue)"
            )
        } catch let error as CLIError {
            let format = extractFormatHint(argv: argv, env: env)
            return self.withSafeDebug(
                ErrorRenderer.render(error: error, format: format),
                enabled: rawDebugEnabled(argv: argv, env: env),
                context: self.debugContext(error)
            )
        } catch {
            return self.withSafeDebug(
                ErrorRenderer.render(
                    error: .runtimeError(message: "Unexpected runtime error."),
                    format: extractFormatHint(argv: argv, env: env)
                ),
                enabled: rawDebugEnabled(argv: argv, env: env),
                context: nil
            )
        }
    }

    /// Returns a result only when the regular buffered CLI path should be used.
    /// A successful interactive `run` writes directly to the user's terminal.
    public func runInteractivelyIfNeeded(argv: [String], env: [String: String]) -> CommandResult? {
        guard RunCommand.isInteractiveTerminal() else { return nil }
        do {
            let parsed = try ArgumentParser.parse(argv: argv, env: env)
            if parsed.command == .ssh {
                if parsed.options.format == .json, parsed.commandArgs.first == "test" {
                    return nil
                }
                if let code = try SSHCommand.runInteractively(
                    args: parsed.commandArgs, env: agentHelperEnvironment(env, options: parsed.options),
                    executor: self.commandExecutor
                ) {
                    return self.withSafeDebug(
                        CommandResult(exitCode: code),
                        enabled: parsed.options.debug && parsed.commandArgs.first != "agent",
                        context: "command=ssh"
                    )
                }
            }
            guard parsed.command == .run else { return nil }
            guard try !RunCommand.requestsInjectedStdin(parsed.commandArgs) else { return nil }
            let code = try RunCommand.runInteractively(
                args: parsed.commandArgs, options: parsed.options, env: env, client: self.keychainClient
            )
            return self.withSafeDebug(
                CommandResult(exitCode: code), enabled: parsed.options.debug, context: "command=run"
            )
        } catch let error as CLIError {
            return self.renderCLIError(error, argv: argv, env: env)
        } catch {
            return self.renderUnexpectedCLIError(argv: argv, env: env)
        }
    }

    /// Streams a piped `run` directly to the caller. Other commands retain the
    /// buffered result contract, which is important for structured CLI errors.
    public func runStreamingIfNeeded(
        argv: [String], env: [String: String], stdout: @escaping @Sendable (Data) -> Void,
        stderr: @escaping @Sendable (Data) -> Void
    ) -> CommandResult? {
        do {
            let parsed = try ArgumentParser.parse(argv: argv, env: env)
            if parsed.command == .ssh {
                if parsed.options.format == .json, parsed.commandArgs.first == "test" {
                    return nil
                }
                if let code = try SSHCommand.runStreaming(
                    args: parsed.commandArgs, env: agentHelperEnvironment(env, options: parsed.options),
                    executor: self.commandExecutor, stdout: stdout, stderr: stderr
                ) {
                    return self.withSafeDebug(
                        CommandResult(exitCode: code),
                        enabled: parsed.options.debug && parsed.commandArgs.first != "agent",
                        context: "command=ssh"
                    )
                }
            }
            guard parsed.command == .run else { return nil }
            guard try !RunCommand.isInteractiveTerminal()
                || (RunCommand.requestsInjectedStdin(parsed.commandArgs))
            else { return nil }
            let code = try RunCommand.runStreaming(
                args: parsed.commandArgs,
                options: parsed.options,
                env: env,
                client: self.keychainClient,
                stdout: stdout,
                stderr: stderr
            )
            return self.withSafeDebug(
                CommandResult(exitCode: code), enabled: parsed.options.debug, context: "command=run"
            )
        } catch let error as CLIError {
            return self.renderCLIError(error, argv: argv, env: env)
        } catch {
            return self.renderUnexpectedCLIError(argv: argv, env: env)
        }
    }

    private func execute(_ parsed: ParsedCommand, env: [String: String], input: Data) throws -> CommandResult {
        switch parsed.command {
        case .help:
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: HelpText.main + "\n")
        case .version:
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: "macop 0.1.0\n")
        case .compatibility:
            guard parsed.commandArgs.isEmpty else {
                throw CLIError.invalidArguments(message: "compatibility does not accept arguments.")
            }
            return CompatibilityCommand.render(format: parsed.options.format)
        case .completion:
            guard parsed.commandArgs.count <= 1 else {
                throw CLIError.invalidArguments(message: "completion accepts at most one shell argument.")
            }
            let shell = parsed.commandArgs.first ?? "zsh"
            if shell == "zsh" || shell == "bash" || shell == "fish" {
                return CommandResult(exitCode: ExitCode.success.rawValue, stdout: CompletionText.render(shell: shell))
            }
            if shell == "powershell" {
                throw CLIError.unsupportedCommand(
                    command: "completion powershell",
                    reason: "PowerShell completion is not generated by macop."
                )
            }
            throw CLIError.invalidArguments(message: "Unknown shell for completion: \(shell)")
        case .read:
            return try ReadCommand.run(
                args: parsed.commandArgs,
                options: parsed.options,
                env: env,
                client: self.keychainClient
            )
        case .item:
            return try ItemCommand.run(
                args: parsed.commandArgs,
                options: parsed.options,
                input: input,
                client: self.keychainClient,
                importer: self.managedKeychainImporter
            )
        case .config:
            return try ConfigCommand.run(args: parsed.commandArgs, options: parsed.options)
        case .run:
            return try RunCommand.run(
                args: parsed.commandArgs,
                options: parsed.options,
                env: env,
                client: self.keychainClient
            )
        case .inject:
            return try InjectCommand.run(
                args: parsed.commandArgs,
                options: parsed.options,
                env: env,
                input: input,
                client: self.keychainClient
            )
        case .ssh:
            return try SSHCommand.run(
                args: parsed.commandArgs,
                options: parsed.options,
                env: agentHelperEnvironment(env, options: parsed.options),
                executor: self.commandExecutor,
                biometricChecker: self.biometricChecker
            )
        // macop-agent owns debug rendering so its JSON error stream stays
        // one object even when this command is relayed by macop.
        case .doctor:
            guard parsed.commandArgs.isEmpty
            else { throw CLIError.invalidArguments(message: "doctor does not accept arguments.") }
            return try DoctorCommand.run(
                options: parsed.options,
                context: DoctorContext(env: env, executor: self.commandExecutor)
            )
        }
    }

    private func renderedCommandName(_ parsed: ParsedCommand) -> String {
        if parsed.command == .item, let sub = parsed.commandArgs.first {
            return "item \(sub)"
        }
        return parsed.command.rawValue
    }

    private func renderCLIError(_ error: CLIError, argv: [String], env: [String: String]) -> CommandResult {
        self.withSafeDebug(
            ErrorRenderer.render(error: error, format: extractFormatHint(argv: argv, env: env)),
            enabled: rawDebugEnabled(argv: argv, env: env),
            context: self.debugContext(error)
        )
    }

    private func renderUnexpectedCLIError(argv: [String], env: [String: String]) -> CommandResult {
        self.withSafeDebug(
            ErrorRenderer.render(
                error: .runtimeError(message: "Unexpected runtime error."),
                format: extractFormatHint(argv: argv, env: env)
            ),
            enabled: rawDebugEnabled(argv: argv, env: env),
            context: nil
        )
    }

    private func withSafeDebug(_ result: CommandResult, enabled: Bool, context: String?) -> CommandResult {
        guard enabled else { return result }
        let jsonError = result.stderr.data(using: .utf8).flatMap { try? JSONSerialization.jsonObject(with: $0) }
        if var payload = jsonError as? [String: Any], var error = payload["error"] as? [String: Any] {
            var debug: [String: Any] = ["exit_code": result.exitCode]
            if let context {
                debug["context"] = context
            }
            error["debug"] = debug
            payload["error"] = error
            let rendered = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
            if let rendered, let stderr = String(data: rendered, encoding: .utf8) {
                return CommandResult(exitCode: result.exitCode, stdout: result.stdout, stderr: stderr + "\n")
            }
        }
        return CommandResult(
            exitCode: result.exitCode,
            stdout: result.stdout,
            stderr: result.stderr + "macop: debug exit_code=\(result.exitCode)\(context.map { " \($0)" } ?? "")\n"
        )
    }

    private func debugContext(_ error: CLIError) -> String? {
        switch error {
        case let .unsupportedCommand(command, _):
            "command=\(command.split(separator: " ").first ?? "unknown")"
        case let .unsupportedProvider(provider, _), let .providerUnavailable(provider, _):
            "provider=\(provider)"
        default:
            nil
        }
    }
}
