import Foundation

private struct GitClientTrustResponse: Encodable {
    let schemaVersion = 2
    let action: String?
    let clients: [GitClientTrustEntry]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case action
        case clients
    }
}

public enum GitClientTrustCommand {
    public static func run(
        args: [String],
        options: GlobalOptions,
        versionProbe: any GitClientVersionProbing = SystemGitClientVersionProbe(),
        registry: GitClientTrustRegistry = GitClientTrustRegistry()
    ) throws -> CommandResult {
        guard let action = args.first else {
            throw CLIError
                .invalidArguments(
                    message: "Usage: macop ssh git-client <trust|list|remove|migrate|reset> [absolute-selector-path]"
                )
        }
        switch action {
        case "list":
            guard args.count == 1
            else { throw CLIError.invalidArguments(message: "ssh git-client list does not accept arguments.") }
            return try self.render(registry.list(), options: options)
        case "trust":
            guard args.count == 2
            else {
                throw CLIError.invalidArguments(message: "Usage: macop ssh git-client trust <absolute-selector-path>")
            }
            let selector = try GitClientPathPolicy.validateSelector(args[1])
            let entry = try registry.trust(selectorPath: selector) { versionProbe.version(executablePath: $0) }
            return try self.render([entry], action: "trusted", options: options)
        case "remove":
            guard args.count == 2
            else {
                throw CLIError.invalidArguments(message: "Usage: macop ssh git-client remove <absolute-selector-path>")
            }
            let entry = try registry.remove(selectorPath: args[1])
            return try self.render([entry], action: "removed", options: options)
        case "migrate":
            guard args.count == 1
            else { throw CLIError.invalidArguments(message: "ssh git-client migrate does not accept arguments.") }
            return try self.render(
                registry.migrateLegacy { versionProbe.version(executablePath: $0) },
                action: "migrated",
                options: options
            )
        case "reset":
            guard args.count == 1
            else { throw CLIError.invalidArguments(message: "ssh git-client reset does not accept arguments.") }
            try registry.reset()
            return try self.render([], action: "reset", options: options)
        default:
            throw CLIError.invalidArguments(message: "Unknown ssh git-client action: \(action)")
        }
    }

    private static func render(
        _ clients: [GitClientTrustEntry], action: String? = nil, options: GlobalOptions
    ) throws -> CommandResult {
        if options.format == .json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(GitClientTrustResponse(action: action, clients: clients))
            guard let text = String(data: data, encoding: .utf8) else {
                throw CLIError.runtimeError(message: "Failed to encode Git client trust response.")
            }
            return CommandResult(exitCode: 0, stdout: text + "\n")
        }
        let rows = clients.map { entry in
            [
                action.map { "\($0): \(entry.selectorPath)" } ?? entry.selectorPath,
                "  resolved: \(entry.resolvedPath)",
                "  signature: \(entry.signatureKind)",
                "  identifier: \(entry.identifier)",
                "  cdhash: \(entry.cdHash)",
                "  version: \(entry.version)"
            ].joined(separator: "\n")
        }
        return CommandResult(exitCode: 0, stdout: rows.joined(separator: "\n") + (rows.isEmpty ? "" : "\n"))
    }
}
