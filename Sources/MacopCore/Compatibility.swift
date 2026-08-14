import Foundation

public struct CompatibilityEntry: Codable, Sendable {
    public let id: String
    public let command: String
    public let kind: String
    public let status: String
    public let reason: String?
    public let alternative: String?

    public init(
        id: String? = nil,
        command: String,
        kind: String,
        status: String,
        reason: String? = nil,
        alternative: String? = nil
    ) {
        self.id = id ?? command
        self.command = command
        self.kind = kind
        self.status = status
        self.reason = reason
        self.alternative = alternative
    }
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
    private static let pending = "Implementation has not started yet."
    private static let cloudUnavailable = "macop has no cloud account backend."
    private static let filePolicy = "Writing secrets to persistent files is disabled by policy."

    public static let entries: [CompatibilityEntry] = [
        .init(command: "read", kind: "command", status: "supported"),
        .init(command: "read --no-newline", kind: "flag", status: "supported"),
        .init(command: "read --out-file", kind: "flag", status: "unsupported", reason: filePolicy),
        .init(command: "read --file-mode", kind: "flag", status: "unsupported", reason: filePolicy),
        .init(command: "read --force", kind: "flag", status: "unsupported", reason: filePolicy),
        .init(command: "run", kind: "command", status: "supported"),
        .init(command: "run --env-file", kind: "flag", status: "supported"),
        .init(command: "run --stdin", kind: "flag", status: "supported"),
        .init(command: "run --no-masking", kind: "flag", status: "supported"),
        .init(
            command: "run --environment",
            kind: "flag",
            status: "unsupported",
            reason: "macop has no Environments backend."
        ),
        .init(command: "inject", kind: "command", status: "supported"),
        .init(command: "inject -i", kind: "flag", status: "supported"),
        .init(command: "inject --in-file", kind: "flag", status: "supported"),
        .init(command: "inject --out-file", kind: "flag", status: "unsupported", reason: filePolicy),
        .init(command: "inject --file-mode", kind: "flag", status: "unsupported", reason: filePolicy),
        .init(command: "inject --force", kind: "flag", status: "unsupported", reason: filePolicy),
        .init(
            command: "item list",
            kind: "subcommand",
            status: "partial",
            reason: "Only config-registered items; macop-specific metadata schema."
        ),
        .init(command: "item list --long", kind: "flag", status: "supported"),
        .init(command: "item list --format", kind: "flag", status: "supported"),
        .init(
            command: "item get",
            kind: "subcommand",
            status: "partial",
            reason: "Only config-registered items; macop-specific metadata schema."
        ),
        .init(command: "item get --fields", kind: "flag", status: "supported"),
        .init(command: "item get --reveal", kind: "flag", status: "supported"),
        .init(command: "item get --format", kind: "flag", status: "supported"),
        .init(
            command: "item get --vault",
            kind: "flag",
            status: "unsupported",
            reason: "macop has no vault data model."
        ),
        .init(
            command: "item get --categories",
            kind: "flag",
            status: "unsupported",
            reason: "macop has no category data model."
        ),
        .init(command: "item get --tags", kind: "flag", status: "unsupported", reason: "macop has no tag data model."),
        .init(
            command: "item get --favorite",
            kind: "flag",
            status: "unsupported",
            reason: "macop has no favorite data model."
        ),
        .init(
            command: "item get --include-archive",
            kind: "flag",
            status: "unsupported",
            reason: "macop has no archive data model."
        ),
        .init(
            command: "item get --otp",
            kind: "flag",
            status: "unsupported",
            reason: "OTP retrieval is outside the MVP."
        ),
        .init(
            command: "item get --share-link",
            kind: "flag",
            status: "unsupported",
            reason: "Share links are outside the MVP."
        ),
        .init(
            command: "item create",
            kind: "subcommand",
            status: "unsupported",
            reason: "Keychain CRUD is outside the MVP."
        ),
        .init(
            command: "item edit",
            kind: "subcommand",
            status: "unsupported",
            reason: "Keychain CRUD is outside the MVP."
        ),
        .init(
            command: "item delete",
            kind: "subcommand",
            status: "unsupported",
            reason: "Keychain CRUD is outside the MVP."
        ),
        .init(
            command: "item move",
            kind: "subcommand",
            status: "unsupported",
            reason: "macop has no vault data model."
        ),
        .init(
            command: "item share",
            kind: "subcommand",
            status: "unsupported",
            reason: "Share links are outside the MVP."
        ),
        .init(
            command: "item template",
            kind: "subcommand",
            status: "unsupported",
            reason: "Item templates are outside the MVP."
        ),
        .init(command: "completion", kind: "command", status: "supported"),
        .init(command: "help", kind: "command", status: "supported"),
        .init(command: "version", kind: "command", status: "supported"),
        .init(
            command: "whoami",
            kind: "command",
            status: "unsupported",
            reason: "macop does not model a 1Password account."
        ),
        .init(command: "signin", kind: "command", status: "unsupported", reason: cloudUnavailable),
        .init(command: "signout", kind: "command", status: "unsupported", reason: cloudUnavailable),
        .init(command: "update", kind: "command", status: "unsupported", reason: "macop does not self-update."),
        .init(command: "vault", kind: "command", status: "unsupported", reason: cloudUnavailable),
        .init(command: "account", kind: "command", status: "unsupported", reason: cloudUnavailable),
        .init(command: "user", kind: "command", status: "unsupported", reason: cloudUnavailable),
        .init(command: "group", kind: "command", status: "unsupported", reason: cloudUnavailable),
        .init(command: "service-account", kind: "command", status: "unsupported", reason: cloudUnavailable),
        .init(command: "connect", kind: "command", status: "unsupported", reason: cloudUnavailable),
        .init(command: "events-api", kind: "command", status: "unsupported", reason: cloudUnavailable),
        .init(command: "document", kind: "command", status: "unsupported", reason: "macop has no document backend."),
        .init(
            command: "environment",
            kind: "command",
            status: "unsupported",
            reason: "macop has no Environments backend."
        ),
        .init(command: "plugin", kind: "command", status: "unsupported", reason: "macop has no plugin backend."),
        .init(command: "compatibility", kind: "extension", status: "supported"),
        .init(command: "config init", kind: "extension", status: "supported"),
        .init(command: "config validate", kind: "extension", status: "supported"),
        .init(command: "doctor", kind: "extension", status: "unsupported", reason: pending),
        .init(command: "ssh", kind: "extension", status: "unsupported", reason: pending),
        .init(command: "--help", kind: "flag", status: "supported"),
        .init(command: "--version", kind: "flag", status: "supported"),
        .init(command: "--format", kind: "flag", status: "supported"),
        .init(command: "--config", kind: "flag", status: "supported"),
        .init(command: "--no-color", kind: "flag", status: "supported"),
        .init(command: "--debug", kind: "flag", status: "supported"),
        .init(command: "--encoding=utf-8", kind: "flag", status: "supported"),
        .init(
            command: "--account",
            kind: "flag",
            status: "unsupported",
            reason: "This global 1Password state is not modeled by macop."
        ),
        .init(
            command: "--session",
            kind: "flag",
            status: "unsupported",
            reason: "This global 1Password state is not modeled by macop."
        ),
        .init(
            command: "--cache",
            kind: "flag",
            status: "unsupported",
            reason: "This global 1Password state is not modeled by macop."
        ),
        .init(
            command: "--iso-timestamps",
            kind: "flag",
            status: "unsupported",
            reason: "This global 1Password state is not modeled by macop."
        ),
        .init(
            command: "--encoding=<non-UTF-8>",
            kind: "flag",
            status: "unsupported",
            reason: "macop only accepts UTF-8 text secrets."
        )
    ]

    public static func render(format: OutputFormat) -> CommandResult {
        switch format {
        case .humanReadable:
            let opCommands = self.entries.filter { $0.kind == "command" || $0.kind == "subcommand" }
            let supported = self.names(opCommands.filter { $0.status == "supported" || $0.status == "partial" })
            let extensions = self.names(self.entries.filter { $0.kind == "extension" && $0.status != "unsupported" })
            let unsupported = self.names(self.entries.filter { $0.status == "unsupported" })
            let flags = self.names(self.entries.filter { $0.kind == "flag" })
            let text = """
            Supported or partial op commands: \(supported)
            Macop extensions: \(extensions)
            Unsupported operations: \(unsupported)
            Flags: \(flags)
            Run "macop compatibility --format json" for machine-readable output.
            """
            return CommandResult(
                exitCode: ExitCode.success.rawValue,
                stdout: text
            )
        case .json:
            let response = CompatibilityResponse(schemaVersion: 3, entries: entries)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = (try? encoder.encode(response)) ?? Data("{\"schema_version\":3,\"entries\":[]}".utf8)
            let text = String(data: data, encoding: .utf8) ?? "{\"schema_version\":3,\"entries\":[]}"
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: text + "\n")
        }
    }

    private static func names(_ entries: [CompatibilityEntry]) -> String {
        entries.map(\.command).joined(separator: ", ")
    }
}
