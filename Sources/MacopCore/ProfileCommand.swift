import Darwin
import Foundation

public struct ProfileOutputSinks: Sendable {
    public let stdout: @Sendable (Data) -> Void
    public let stderr: @Sendable (Data) -> Void

    public init(stdout: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void) {
        self.stdout = stdout
        self.stderr = stderr
    }
}

public enum ProfileShellArgumentEncoder {
    public static func quote(_ value: String, shell: String) throws -> String {
        switch shell {
        case "zsh", "bash":
            self.posixSingleQuoted(value)
        case "fish":
            self.fishSingleQuoted(value)
        default:
            throw CLIError.invalidArguments(message: "Unsupported profile shell: \(shell)")
        }
    }

    private static func posixSingleQuoted(_ value: String) -> String {
        var encoded = "'"
        for scalar in value.unicodeScalars {
            if scalar.value == 0x27 {
                encoded += "'\\''"
            } else {
                encoded.unicodeScalars.append(scalar)
            }
        }
        encoded.append("'")
        return encoded
    }

    private static func fishSingleQuoted(_ value: String) -> String {
        var encoded = "'"
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x5C: encoded += "\\\\"
            case 0x27: encoded += "\\'"
            default: encoded.unicodeScalars.append(scalar)
            }
        }
        encoded.append("'")
        return encoded
    }
}

public enum ProfileCommand {
    private struct PreparedProfile {
        let runArguments: [String]
        let environment: [String: String]
    }

    public static func run(
        args: [String], options: GlobalOptions, env: [String: String], client: any KeychainClient,
        otpClient: any KeychainClient = CompanionManagedKeychainClient()
    ) throws -> CommandResult {
        guard let subcommand = args.first else {
            throw CLIError.invalidArguments(message: "profile requires run or shell-init.")
        }
        switch subcommand {
        case "run": return try Self.runProfile(
                Array(args.dropFirst()), options: options, env: env, client: client, otpClient: otpClient
            )
        case "shell-init": return try Self.shellInit(Array(args.dropFirst()), options: options)
        default: throw CLIError.invalidArguments(message: "Unknown profile subcommand: \(subcommand)")
        }
    }

    private static func runProfile(
        _ args: [String], options: GlobalOptions, env: [String: String], client: any KeychainClient,
        otpClient: any KeychainClient
    ) throws -> CommandResult {
        let prepared = try Self.prepareRun(args, options: options, env: env)
        return try RunCommand.run(
            args: prepared.runArguments, options: options, env: prepared.environment,
            client: client, otpClient: otpClient
        )
    }

    public static func runStreaming(
        args: [String], options: GlobalOptions, env: [String: String], client: any KeychainClient,
        otpClient: any KeychainClient = CompanionManagedKeychainClient(),
        sinks: ProfileOutputSinks
    ) throws -> Int32? {
        guard args.first == "run" else { return nil }
        let prepared = try Self.prepareRun(Array(args.dropFirst()), options: options, env: env)
        return try RunCommand.runStreaming(
            args: prepared.runArguments, options: options, env: prepared.environment,
            client: client, otpClient: otpClient,
            stdout: sinks.stdout, stderr: sinks.stderr
        )
    }

    public static func runInteractively(
        args: [String], options: GlobalOptions, env: [String: String], client: any KeychainClient,
        otpClient: any KeychainClient = CompanionManagedKeychainClient()
    ) throws -> Int32? {
        guard args.first == "run" else { return nil }
        let prepared = try Self.prepareRun(Array(args.dropFirst()), options: options, env: env)
        return try RunCommand.runInteractively(
            args: prepared.runArguments, options: options, env: prepared.environment,
            client: client, otpClient: otpClient
        )
    }

    private static func prepareRun(
        _ args: [String], options: GlobalOptions, env: [String: String]
    ) throws -> PreparedProfile {
        guard let boundary = args.firstIndex(of: "--"), boundary == 1,
              let name = args.first, args.count > 2
        else {
            throw CLIError
                .invalidArguments(message: "profile run requires <name> -- <absolute-command> [arguments...].")
        }
        let document = try ConfigStore.load(configDirectory: options.configDirectory)
        guard let profile = document.profiles?[name] else {
            throw CLIError.notFound(message: "Credential profile was not found.")
        }
        let command = Array(args.dropFirst(boundary + 1))
        guard let requested = command.first, requested.hasPrefix("/") else {
            throw CLIError.denied(message: "Profile executable does not exactly match the configured executable.")
        }
        let requestedCanonical = try Self.canonical(requested)
        let configuredCanonical = try Self.canonical(profile.executable)
        guard requestedCanonical == configuredCanonical, configuredCanonical == profile.executable,
              requested == profile.executable
        else { throw CLIError.denied(message: "Profile executable does not exactly match the configured executable.") }
        guard !env.contains(where: { key, value in
            profile.environment[key] == nil && SecretMaterial.containsReference(value)
        }) else {
            throw CLIError.denied(message: "Profile environment contains an undeclared secret reference.")
        }
        var profileEnvironment = env
        for (key, reference) in profile.environment {
            profileEnvironment[key] = reference
        }
        return PreparedProfile(runArguments: ["--"] + command, environment: profileEnvironment)
    }

    private static func shellInit(_ args: [String], options: GlobalOptions) throws -> CommandResult {
        guard args.count == 2, let name = args.first, let shell = args.last,
              ["zsh", "bash", "fish"].contains(shell)
        else { throw CLIError.invalidArguments(message: "profile shell-init requires <name> <zsh|bash|fish>.") }
        let document = try ConfigStore.load(configDirectory: options.configDirectory)
        guard let profile = document.profiles?[name] else {
            throw CLIError.notFound(message: "Credential profile was not found.")
        }
        let function = "macop_" + name.map { $0.isLetter || $0.isNumber ? $0 : "_" }
        // Config schema constrains the function name. Every other static value
        // crosses the shell boundary through the shell-specific encoder below;
        // runtime arguments stay in the shell's native argument array.
        let quote: (String) throws -> String = {
            try ProfileShellArgumentEncoder.quote($0, shell: shell)
        }
        let configArgument: String
        if options.configDirectory != nil {
            let directory = try ConfigStore.configFilePath(configDirectory: options.configDirectory)
                .deletingLastPathComponent().standardizedFileURL.path
            configArgument = try " --config \(quote(directory))"
        } else {
            configArgument = ""
        }
        let output = if shell == "fish" {
            try "function \(function)\n  command macop\(configArgument) profile run \(quote(name)) -- \(quote(profile.executable)) $argv\nend\n"
        } else {
            try "\(function)() { command macop\(configArgument) profile run \(quote(name)) -- \(quote(profile.executable)) \"$@\"; }\n"
        }
        return CommandResult(exitCode: 0, stdout: output)
    }

    private static func canonical(_ path: String) throws -> String {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard realpath(path, &buffer) != nil,
              let value = String(bytes: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, encoding: .utf8)
        else { throw CLIError.notFound(message: "Profile executable was not found.") }
        return value
    }
}
