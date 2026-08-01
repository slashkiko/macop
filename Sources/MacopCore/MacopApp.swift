import Foundation

public struct MacopApp {
    public init() {}

    public func run(argv: [String], env: [String: String]) -> CommandResult {
        do {
            let parsed = try ArgumentParser.parse(argv: argv, env: env)
            return try self.execute(parsed, env: env)
        } catch let error as CLIError {
            let format = extractFormatHint(argv: argv, env: env)
            return ErrorRenderer.render(error: error, format: format)
        } catch {
            return CommandResult(
                exitCode: ExitCode.runtimeError.rawValue,
                stderr: "macop: unexpected runtime error\n"
            )
        }
    }

    private func execute(_ parsed: ParsedCommand, env: [String: String]) throws -> CommandResult {
        switch parsed.command {
        case .help:
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: HelpText.main + "\n")
        case .version:
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: "macop 0.1.0\n")
        case .compatibility:
            return CompatibilityCommand.render(format: parsed.options.format)
        case .completion:
            let shell = parsed.commandArgs.first ?? "zsh"
            if shell == "zsh" || shell == "bash" || shell == "fish" {
                return CommandResult(exitCode: ExitCode.success.rawValue, stdout: CompletionText.render(shell: shell))
            }
            throw CLIError.invalidArguments(message: "Unsupported shell for completion: \(shell)")
        case .read:
            return try ReadCommand.run(args: parsed.commandArgs, options: parsed.options, env: env)
        case .config:
            return try ConfigCommand.run(args: parsed.commandArgs, options: parsed.options)
        case .run, .inject, .item, .ssh, .doctor:
            throw CLIError.unsupportedCommand(
                command: self.renderedCommandName(parsed),
                reason: "Command scaffold exists, but implementation has not started yet."
            )
        }
    }

    private func renderedCommandName(_ parsed: ParsedCommand) -> String {
        if parsed.command == .item, let sub = parsed.commandArgs.first {
            return "item \(sub)"
        }
        return parsed.command.rawValue
    }

    private func extractFormatHint(argv: [String], env: [String: String]) -> OutputFormat {
        if argv.contains("json"), argv.contains("--format") {
            return .json
        }
        if env["OP_FORMAT"] == OutputFormat.json.rawValue {
            return .json
        }
        return .humanReadable
    }
}
