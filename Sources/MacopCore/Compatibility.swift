import Foundation

public struct CompatibilityEntry: Codable, Sendable {
    public let command: String
    public let status: String
    public let reason: String?
    public let alternative: String?
}

public struct CompatibilityResponse: Codable, Sendable {
    public let schemaVersion: Int
    public let entries: [CompatibilityEntry]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case entries
    }
}

public enum CompatibilityCommand {
    public static let entries: [CompatibilityEntry] = [
        .init(command: "read", status: "partial", reason: "Reference parsing and config lookup implemented. Provider wiring is pending.", alternative: nil),
        .init(command: "run", status: "partial", reason: "Scaffolded but not yet implemented.", alternative: nil),
        .init(command: "inject", status: "partial", reason: "Scaffolded but not yet implemented.", alternative: nil),
        .init(command: "item list", status: "partial", reason: "Scaffolded but not yet implemented.", alternative: nil),
        .init(command: "item get", status: "partial", reason: "Scaffolded but not yet implemented.", alternative: nil),
        .init(command: "completion", status: "supported", reason: nil, alternative: nil),
        .init(command: "compatibility", status: "supported", reason: nil, alternative: nil),
        .init(command: "ssh", status: "partial", reason: "Scaffolded but not yet implemented.", alternative: nil),
        .init(command: "config", status: "partial", reason: "init and validate are implemented.", alternative: nil),
        .init(command: "doctor", status: "partial", reason: "Scaffolded but not yet implemented.", alternative: nil),
        .init(
            command: "vault",
            status: "unsupported",
            reason: "macop does not provide a vault or cloud account backend.",
            alternative: "macop compatibility"
        )
    ]

    public static func render(format: OutputFormat) -> CommandResult {
        switch format {
        case .humanReadable:
            let header = """
            Supported op-compatible commands: read, run, inject, item list, item get, completion
            macop extensions: ssh, config, doctor, compatibility
            Run "macop compatibility --format json" for machine-readable output.
            """
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: header)
        case .json:
            let response = CompatibilityResponse(schemaVersion: 1, entries: entries)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = (try? encoder.encode(response)) ?? Data("{\"schema_version\":1,\"entries\":[]}".utf8)
            let text = String(data: data, encoding: .utf8) ?? "{\"schema_version\":1,\"entries\":[]}"
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: text + "\n")
        }
    }
}
