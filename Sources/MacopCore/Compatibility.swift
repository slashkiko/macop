// swiftlint:disable file_length
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

private let compatibilityItemListEntries: [CompatibilityEntry] = [
    "--vault", "--categories", "--tags", "--favorite", "--include-archive", "--otp", "--share-link"
].map {
    .init(
        command: "item list \($0)",
        kind: "flag",
        status: "unsupported",
        reason: "This item list operation is not supported by macop."
    )
}

private let compatibilitySSHEntries: [CompatibilityEntry] = [
    .init(command: "ssh create", kind: "subcommand", status: "supported"),
    .init(command: "ssh create --touch-id", kind: "flag", status: "supported"),
    .init(command: "ssh list", kind: "subcommand", status: "supported"),
    .init(command: "ssh public-key", kind: "subcommand", status: "supported"),
    .init(
        command: "ssh test", kind: "subcommand", status: "supported",
        reason: "First-party macop shell/test CTK and Touch ID end-to-end acceptance is complete."
    ),
    .init(
        command: "ssh run",
        kind: "subcommand",
        status: "partial",
        reason: "Only Git child commands are accepted; first-party CTK/Touch ID E2E is complete and macop never exports a private key."
    ),
    .init(command: "ssh delete", kind: "subcommand", status: "supported"),
    .init(
        command: "ssh agent",
        kind: "subcommand",
        status: "partial",
        reason: "Verified sessions are limited to a newly launched cooperative root. "
            + "First-party shell/test/run CTK and Touch ID E2E is complete; third-party application E2E is not claimed."
    ),
    .init(
        command: "ssh agent shell",
        kind: "subcommand",
        status: "partial",
        reason: "Requires `-- <program> [arguments...]`, a cooperative newly launched root, and a local CTK identity."
    ),
    .init(
        command: "ssh agent application",
        kind: "subcommand",
        status: "partial",
        reason: "Requires a newly launched cooperative application; existing applications and external relays are rejected."
    ),
    .init(
        command: "ssh shell-init",
        kind: "extension",
        status: "supported",
        reason: "Generate per-tab zsh, bash, or fish verified-session integration; real Terminal tab lifecycle acceptance remains pending."
    ),
    .init(
        command: "ssh git-signing-config",
        kind: "extension",
        status: "supported",
        reason: "Generate repository-local Git SSH signing configuration for a CTK identity."
    ),
    .init(
        command: "ssh git-client",
        kind: "extension",
        status: "supported",
        reason: "Explicitly pins non-Apple Git selector paths to an exact machine-local identifier and cdhash."
    ),
    .init(command: "ssh git-client trust", kind: "subcommand", status: "supported"),
    .init(command: "ssh git-client list", kind: "subcommand", status: "supported"),
    .init(command: "ssh git-client remove", kind: "subcommand", status: "supported"),
    .init(command: "ssh git-client migrate", kind: "subcommand", status: "supported"),
    .init(command: "ssh git-client reset", kind: "subcommand", status: "supported"),
    .init(
        command: "ssh connect",
        kind: "extension",
        status: "supported",
        reason: "Launch Apple OpenSSH for a configured alias with exactly one short-lived Secure Enclave identity; "
            + "real host-routing acceptance remains pending."
    ),
    .init(
        command: "ssh host-config",
        kind: "extension",
        status: "supported",
        reason: "Render public SSH host metadata; credentials and agent sockets are never persisted."
    )
]

private let compatibilityReferenceQueryEntries: [CompatibilityEntry] = [
    .init(
        command: "reference ?attribute=otp",
        kind: "query",
        status: "supported",
        reason: "Resolves a separately stored macop-managed OTP seed."
    ),
    .init(
        command: "reference ?ssh-format=openssh",
        kind: "query",
        status: "unsupported",
        reason: "Exporting SSH private keys is disabled by policy."
    )
]

private let compatibilityCloudUnavailable = "macop has no cloud account backend."
private let compatibilityFilePolicy = "Writing secrets to persistent files is disabled by policy."

public enum CompatibilityCommand {}

public extension CompatibilityCommand {
    static let entries: [CompatibilityEntry] = (
        [
            .init(command: "read", kind: "command", status: "supported"),
            .init(command: "read --no-newline", kind: "flag", status: "supported"),
            .init(
                command: "read --otp",
                kind: "flag",
                status: "unsupported",
                reason: "The 1Password --otp flag syntax is not implemented; configured OTP retrieval is supported.",
                alternative: "Use read 'op://<namespace>/<item>/password?attribute=otp'."
            ),
            .init(
                command: "read --ssh-format",
                kind: "flag",
                status: "unsupported",
                reason: "Exporting SSH private keys is disabled by policy."
            ),
            .init(command: "read --out-file", kind: "flag", status: "unsupported", reason: compatibilityFilePolicy),
            .init(command: "read --file-mode", kind: "flag", status: "unsupported", reason: compatibilityFilePolicy),
            .init(command: "read --force", kind: "flag", status: "unsupported", reason: compatibilityFilePolicy),
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
            .init(command: "inject --out-file", kind: "flag", status: "unsupported", reason: compatibilityFilePolicy),
            .init(command: "inject --file-mode", kind: "flag", status: "unsupported", reason: compatibilityFilePolicy),
            .init(command: "inject --force", kind: "flag", status: "unsupported", reason: compatibilityFilePolicy),
            .init(command: "generate password", kind: "extension", status: "supported"),
            .init(command: "item generate", kind: "extension", status: "supported"),
            .init(command: "item generate --replace", kind: "extension", status: "supported"),
            .init(command: "item otp", kind: "extension", status: "supported"),
            .init(command: "item otp import", kind: "extension", status: "supported"),
            .init(command: "item otp edit", kind: "extension", status: "supported"),
            .init(command: "item otp delete", kind: "extension", status: "supported"),
            .init(command: "profile run", kind: "extension", status: "supported"),
            .init(command: "profile shell-init", kind: "extension", status: "supported"),
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
                command: "item import",
                kind: "extension",
                status: "supported",
                reason: "Create-only stdin import for configured keychain-managed items."
            ),
            .init(
                command: "item acquire",
                kind: "extension",
                status: "supported",
                reason: "Return a managed credential, with an explicit Apple Passwords refresh option."
            ),
            .init(
                command: "item acquire --from-passwords",
                kind: "flag",
                status: "supported",
                reason: "Open the user-initiated system AutoFill chooser and bypass a cached managed item."
            ),
            .init(
                command: "passwords direct-provider",
                kind: "provider",
                status: "unsupported",
                reason: "macOS exposes no public API for silently enumerating or querying the Passwords database.",
                alternative: "Use item acquire --from-passwords and the system AutoFill chooser."
            ),
            .init(
                command: "item get --id",
                kind: "flag",
                status: "unsupported",
                reason: "macop has no 1Password item ID data model."
            ),
            .init(
                command: "item get --stdin",
                kind: "flag",
                status: "unsupported",
                reason: "Reading an item selector from standard input is outside the MVP."
            ),
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
            .init(
                command: "item get --tags",
                kind: "flag",
                status: "unsupported",
                reason: "macop has no tag data model."
            ),
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
                reason: "The 1Password item-get OTP flag syntax is not implemented; configured OTP is supported.",
                alternative: "Use item otp <name>."
            ),
            .init(
                command: "item get --share-link",
                kind: "flag",
                status: "unsupported",
                reason: "Share links are outside the MVP."
            ),
            .init(
                command: "item create",
                kind: "extension",
                status: "supported",
                reason: "Create one configured generic or internet password from secret stdin."
            ),
            .init(
                command: "item edit",
                kind: "extension",
                status: "supported",
                reason: "Update exactly one configured generic or internet password from secret stdin."
            ),
            .init(
                command: "item delete",
                kind: "extension",
                status: "supported",
                reason: "Delete one configured Keychain item or all items in macop's private access group."
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
            .init(command: "completion bash", kind: "subcommand", status: "supported"),
            .init(command: "completion zsh", kind: "subcommand", status: "supported"),
            .init(command: "completion fish", kind: "subcommand", status: "supported"),
            .init(
                command: "completion powershell",
                kind: "subcommand",
                status: "unsupported",
                reason: "PowerShell completion is not generated by macop."
            ),
            .init(command: "help", kind: "command", status: "supported"),
            .init(command: "version", kind: "command", status: "supported"),
            .init(
                command: "whoami",
                kind: "command",
                status: "unsupported",
                reason: "macop does not model a 1Password account."
            ),
            .init(command: "signin", kind: "command", status: "unsupported", reason: compatibilityCloudUnavailable),
            .init(command: "signout", kind: "command", status: "unsupported", reason: compatibilityCloudUnavailable),
            .init(command: "update", kind: "command", status: "unsupported", reason: "macop does not self-update."),
            .init(command: "vault", kind: "command", status: "unsupported", reason: compatibilityCloudUnavailable),
            .init(
                command: "vault list",
                kind: "subcommand",
                status: "unsupported",
                reason: compatibilityCloudUnavailable
            ),
            .init(command: "account", kind: "command", status: "unsupported", reason: compatibilityCloudUnavailable),
            .init(command: "user", kind: "command", status: "unsupported", reason: compatibilityCloudUnavailable),
            .init(command: "group", kind: "command", status: "unsupported", reason: compatibilityCloudUnavailable),
            .init(
                command: "service-account",
                kind: "command",
                status: "unsupported",
                reason: compatibilityCloudUnavailable
            ),
            .init(command: "connect", kind: "command", status: "unsupported", reason: compatibilityCloudUnavailable),
            .init(command: "events-api", kind: "command", status: "unsupported", reason: compatibilityCloudUnavailable),
            .init(
                command: "document",
                kind: "command",
                status: "unsupported",
                reason: "macop has no document backend."
            ),
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
            .init(command: "doctor", kind: "extension", status: "supported"),
            .init(
                command: "ssh",
                kind: "extension",
                status: "partial",
                reason: "Secure Enclave operations use verified one-shot agents and require a newly launched "
                    + "cooperative root; third-party application integration remains limited."
            ),
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
        ] + compatibilityItemListEntries + compatibilitySSHEntries + compatibilityReferenceQueryEntries
    )
}

public extension CompatibilityCommand {
    static func render(format: OutputFormat) -> CommandResult {
        switch format {
        case .humanReadable:
            let opCommands = self.entries.filter { $0.kind == "command" || $0.kind == "subcommand" }
            let supported = self.names(opCommands.filter { $0.status == "supported" || $0.status == "partial" })
            let extensions = self.names(self.entries.filter { $0.kind == "extension" && $0.status != "unsupported" })
            let unsupported = self.names(self.entries.filter { $0.status == "unsupported" })
            let flags = self.names(self.entries.filter { $0.kind == "flag" })
            let queries = self.names(self.entries.filter { $0.kind == "query" })
            let text = """
            Supported or partial op commands: \(supported)
            Macop extensions: \(extensions)
            Unsupported operations: \(unsupported)
            Flags: \(flags)
            Reference query modes: \(queries)
            Run "macop compatibility --format json" for machine-readable output.
            """
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: text)
        case .json:
            let response = CompatibilityResponse(schemaVersion: 3, entries: entries)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = (try? encoder.encode(response)) ?? Data("{\"schema_version\":3,\"entries\":[]}".utf8)
            let text = String(data: data, encoding: .utf8) ?? "{\"schema_version\":3,\"entries\":[]}"
            return CommandResult(exitCode: ExitCode.success.rawValue, stdout: text + "\n")
        }
    }

    /// Only names published by the compatibility matrix are unsupported; arbitrary tokens are syntax errors.
    static func unsupportedRootReason(for command: String) -> String? {
        self.entries.first {
            $0.kind == "command" && $0.status == "unsupported" && $0.command == command
        }?.reason
    }

    /// Returns only documented unsupported command identities; trailing arguments never enter an error response.
    static func unsupportedCommand(root: String, next: String?) -> (command: String, reason: String)? {
        if let next {
            let path = "\(root) \(next)"
            if let entry = self.entries.first(where: {
                $0.kind == "subcommand" && $0.status == "unsupported" && $0.command == path
            }), let reason = entry.reason {
                return (entry.command, reason)
            }
        }
        guard let reason = self.unsupportedRootReason(for: root) else { return nil }
        return (root, reason)
    }

    static func humanSupportGuidance() -> [String] {
        let opCommands = self.entries.filter { $0.kind == "command" || $0.kind == "subcommand" }
        let supported = self.names(opCommands.filter { $0.status == "supported" || $0.status == "partial" })
        let extensions = self.names(self.entries.filter { $0.kind == "extension" && $0.status != "unsupported" })
        return [
            "Supported op-compatible commands: \(supported)",
            "macop extensions: \(extensions)",
            "Run \"macop compatibility\" for the complete support matrix."
        ]
    }

    private static func names(_ entries: [CompatibilityEntry]) -> String {
        entries.map(\.command).joined(separator: ", ")
    }
}
