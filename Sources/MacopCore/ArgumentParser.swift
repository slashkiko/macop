import Foundation

public enum ArgumentParser {
    public static func parse(argv: [String], env: [String: String]) throws -> ParsedCommand {
        var options = GlobalOptions()
        if let envFormat = env["OP_FORMAT"], !envFormat.isEmpty {
            guard let parsedFormat = OutputFormat(rawValue: envFormat) else {
                throw CLIError.invalidArguments(message: "Invalid OP_FORMAT value: \(envFormat)")
            }
            options.format = parsedFormat
        }
        if let envDebug = env["OP_DEBUG"], isTruthy(envDebug) {
            options.debug = true
        }

        let args = Array(argv.dropFirst())
        var command: TopLevelCommand?
        var commandArgs: [String] = []
        var unsupportedCommandParts: [String] = []

        var index = 0
        while index < args.count {
            let token = args[index]

            switch token {
            case "--":
                if command != nil {
                    if command == .run {
                        commandArgs.append("--")
                    }
                    commandArgs.append(contentsOf: args[(index + 1)...])
                    index = args.count
                    continue
                }
                throw CLIError.invalidArguments(message: "Missing command before \"--\".")
            case "--help", "-h":
                options.requestedHelp = true
            case "--version", "-v":
                options.requestedVersion = true
            case "--no-color":
                options.noColor = true
            case "--debug":
                options.debug = true
            case "--format":
                guard index + 1 < args.count else {
                    throw CLIError.invalidArguments(message: "Flag --format requires a value.")
                }
                let value = args[index + 1]
                guard let parsedFormat = OutputFormat(rawValue: value) else {
                    throw CLIError.invalidArguments(message: "Invalid format: \(value)")
                }
                options.format = parsedFormat
                index += 1
            case let value where value.hasPrefix("--format="):
                let formatValue = String(value.dropFirst("--format=".count))
                guard let parsedFormat = OutputFormat(rawValue: formatValue) else {
                    throw CLIError.invalidArguments(message: "Invalid format: \(formatValue)")
                }
                options.format = parsedFormat
            case "--config":
                guard index + 1 < args.count else {
                    throw CLIError.invalidArguments(message: "Flag --config requires a value.")
                }
                options.configDirectory = args[index + 1]
                index += 1
            case let value where value.hasPrefix("--config="):
                let directory = String(value.dropFirst("--config=".count))
                guard !directory.isEmpty else {
                    throw CLIError.invalidArguments(message: "Flag --config requires a value.")
                }
                options.configDirectory = directory
            case "--encoding":
                guard index + 1 < args.count else {
                    throw CLIError.invalidArguments(message: "Flag --encoding requires a value.")
                }
                let encoding = args[index + 1]
                guard encoding.lowercased() == "utf-8" else {
                    throw CLIError.unsupportedFlag(
                        flag: "--encoding",
                        reason: "Only UTF-8 encoding is supported by macop."
                    )
                }
                index += 1
            case let value where value.hasPrefix("--encoding="):
                let encoding = String(value.dropFirst("--encoding=".count))
                guard encoding.lowercased() == "utf-8" else {
                    throw CLIError.unsupportedFlag(
                        flag: "--encoding",
                        reason: "Only UTF-8 encoding is supported by macop."
                    )
                }
            case let flag
                where Self.unsupportedGlobalFlags.contains(flag) || Self.unsupportedGlobalFlags
                .contains(Self.flagName(flag)):
                throw CLIError.unsupportedFlag(
                    flag: Self.flagName(flag),
                    reason: "This 1Password global flag is not supported by macop."
                )
            default:
                if token.hasPrefix("-"), token != "-" {
                    if command == nil {
                        throw CLIError.invalidArguments(message: "Unknown flag: \(token)")
                    }
                    commandArgs.append(token)
                } else if command == nil {
                    guard let parsedCommand = TopLevelCommand(rawValue: token) else {
                        unsupportedCommandParts.append(token)
                        index += 1
                        while index < args.count {
                            let next = args[index]
                            if next == "--format" || next == "--config" {
                                break
                            }
                            if next.hasPrefix("--format=") || next.hasPrefix("--config=") {
                                break
                            }
                            if next.hasPrefix("-") {
                                break
                            }
                            unsupportedCommandParts.append(next)
                            index += 1
                        }
                        throw CLIError.unsupportedCommand(
                            command: unsupportedCommandParts.joined(separator: " "),
                            reason: "macop does not provide this 1Password command or cloud backend."
                        )
                    }
                    command = parsedCommand
                } else {
                    commandArgs.append(token)
                }
            }

            index += 1
        }

        if options.requestedVersion {
            return ParsedCommand(command: .version, commandArgs: commandArgs, options: options)
        }
        if options.requestedHelp || command == nil {
            return ParsedCommand(command: .help, commandArgs: commandArgs, options: options)
        }
        return ParsedCommand(command: command!, commandArgs: commandArgs, options: options)
    }

    private static func isTruthy(_ value: String) -> Bool {
        switch value.lowercased() {
        case "1", "true", "yes", "on":
            true
        default:
            false
        }
    }

    private static let unsupportedGlobalFlags: Set<String> = [
        "--account", "--session", "--cache", "--iso-timestamps"
    ]

    private static func flagName(_ token: String) -> String {
        String(token.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
    }
}
