import Foundation

public enum InjectCommand {
    public static func requiresStandardInput(args: [String]) throws -> Bool {
        try self.parseArgs(args) == nil
    }

    public static func run(
        args: [String],
        options: GlobalOptions,
        env: [String: String],
        input: Data,
        client: any KeychainClient,
        otpClient: any KeychainClient = CompanionManagedKeychainClient()
    ) throws -> CommandResult {
        let inputURL = try parseArgs(args)
        let template: Data
        if let inputURL {
            do {
                template = try Data(contentsOf: URL(fileURLWithPath: inputURL))
            } catch {
                throw CLIError.runtimeError(message: "Unable to read inject input file.")
            }
        } else {
            template = input
        }
        guard let text = String(data: template, encoding: .utf8) else {
            throw CLIError.invalidArguments(message: "inject input must be UTF-8 text.")
        }
        return try CommandResult(
            exitCode: 0,
            stdout: SecretMaterial.resolveReferences(
                in: text, options: options, env: env, client: client, otpClient: otpClient
            ).output
        )
    }

    private static func parseArgs(_ args: [String]) throws -> String? {
        var inputFile: String?
        var index = 0
        while index < args.count {
            let arg = args[index]
            switch arg {
            case "-i", "--in-file":
                guard index + 1 < args.count else {
                    throw CLIError.invalidArguments(message: "Flag \(arg) requires a path.")
                }
                guard inputFile == nil else {
                    throw CLIError.invalidArguments(message: "inject accepts only one input file.")
                }
                inputFile = args[index + 1]
                index += 1
            case let value where value.hasPrefix("--in-file="):
                guard inputFile == nil else {
                    throw CLIError.invalidArguments(message: "inject accepts only one input file.")
                }
                let path = String(value.dropFirst("--in-file=".count))
                guard !path.isEmpty else { throw CLIError.invalidArguments(message: "Flag --in-file requires a path.") }
                inputFile = path
            case "--out-file", "--file-mode", "--force":
                throw self.persistentOutputError(arg)
            case let value
                where value.hasPrefix("--out-file=") || value.hasPrefix("--file-mode=") || value.hasPrefix("--force="):
                throw self.persistentOutputError(String(value.split(separator: "=", maxSplits: 1)[0]))
            default:
                throw CLIError.invalidArguments(message: "Unknown inject argument: \(arg)")
            }
            index += 1
        }
        return inputFile
    }

    private static func persistentOutputError(_ flag: String) -> CLIError {
        .unsupportedFlag(
            flag: flag,
            reason: "Writing secrets to persistent files is disabled by the macop security policy."
        )
    }
}
