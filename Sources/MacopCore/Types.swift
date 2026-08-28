import Foundation

public struct CommandResult {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public init(exitCode: Int32, stdout: String = "", stderr: String = "") {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

public enum ExitCode: Int32 {
    case success = 0
    case runtimeError = 1
    case invalidArguments = 2
    case unsupported = 3
    case providerUnavailable = 4
    case denied = 5
    case notFound = 6
}

public enum OutputFormat: String {
    case humanReadable = "human-readable"
    case json
}

public struct GlobalOptions {
    public var format: OutputFormat
    public var noColor: Bool
    public var debug: Bool
    public var configDirectory: String?
    public var requestedHelp: Bool
    public var requestedVersion: Bool

    public init(
        format: OutputFormat = .humanReadable,
        noColor: Bool = false,
        debug: Bool = false,
        configDirectory: String? = nil,
        requestedHelp: Bool = false,
        requestedVersion: Bool = false
    ) {
        self.format = format
        self.noColor = noColor
        self.debug = debug
        self.configDirectory = configDirectory
        self.requestedHelp = requestedHelp
        self.requestedVersion = requestedVersion
    }
}

public enum TopLevelCommand: String {
    case help
    case version
    case compatibility
    case completion
    case read
    case run
    case inject
    case generate
    case profile
    case item
    case ssh
    case config
    case doctor
}

public struct ParsedCommand {
    public let command: TopLevelCommand
    public let commandArgs: [String]
    public let options: GlobalOptions
}
