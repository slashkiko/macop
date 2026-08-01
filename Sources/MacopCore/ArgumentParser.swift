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

        var index = 0
        while index < args.count {
            let token = args[index]

            switch token {
            case "--":
                if command != nil {
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
            case "--config":
                guard index + 1 < args.count else {
                    throw CLIError.invalidArguments(message: "Flag --config requires a value.")
                }
                options.configDirectory = args[index + 1]
                index += 1
            default:
                if token.hasPrefix("-"), token != "-" {
                    if command == nil {
                        throw CLIError.invalidArguments(message: "Unknown flag: \(token)")
                    }
                    commandArgs.append(token)
                } else if command == nil {
                    guard let parsedCommand = TopLevelCommand(rawValue: token) else {
                        throw CLIError.unsupportedCommand(
                            command: token,
                            reason: "Command is not available in this build."
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
}
