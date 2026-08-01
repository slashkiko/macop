import Foundation

public enum ConfigCommand {
    public static func run(args: [String], options: GlobalOptions) throws -> CommandResult {
        guard let subcommand = args.first else {
            throw CLIError.invalidArguments(message: "config requires subcommand: init or validate")
        }

        switch subcommand {
        case "init":
            guard args.count == 1 else {
                throw CLIError.invalidArguments(message: "config init does not accept extra arguments.")
            }
            let fileURL = try ConfigStore.initialize(configDirectory: options.configDirectory)
            return self.renderSuccess(
                message: "Initialized config at \(fileURL.path)",
                payload: ["path": fileURL.path],
                format: options.format
            )
        case "validate":
            guard args.count == 1 else {
                throw CLIError.invalidArguments(message: "config validate does not accept extra arguments.")
            }
            let fileURL = try ConfigStore.validate(configDirectory: options.configDirectory)
            return self.renderSuccess(
                message: "Config is valid: \(fileURL.path)",
                payload: ["path": fileURL.path, "valid": true],
                format: options.format
            )
        default:
            throw CLIError.invalidArguments(message: "Unknown config subcommand: \(subcommand)")
        }
    }

    private static func renderSuccess(message: String, payload: [String: Any], format: OutputFormat) -> CommandResult {
        switch format {
        case .humanReadable:
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: message + "\n")
        case .json:
            let object: [String: Any] = ["result": payload]
            let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
            let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? "{\"result\":{}}"
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: text + "\n")
        }
    }
}
