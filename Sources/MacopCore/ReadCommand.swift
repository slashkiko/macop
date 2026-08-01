import Foundation

public enum ReadCommand {
    public static func run(args: [String], options: GlobalOptions, env: [String: String]) throws -> CommandResult {
        let parsed = try parseArgs(args)
        _ = parsed.noNewline
        let reference = try ReferenceResolver.parse(parsed.reference, env: env)

        switch reference {
        case let .opReference(namespace, item, section, field):
            let configItem = try ConfigStore.resolveItem(
                namespace: namespace,
                item: item,
                configDirectory: options.configDirectory
            )
            try self.validateFieldAccess(configItem: configItem, section: section, field: field)
            let providerKind = try ConfigStore.providerKind(for: configItem)
            throw self.providerNotImplemented(for: providerKind)
        case .keychainGeneric, .keychainInternet:
            throw self.providerNotImplemented(for: .keychainGeneric)
        case .secureEnclave:
            throw self.providerNotImplemented(for: .secureEnclave)
        }
    }

    private static func parseArgs(_ args: [String]) throws -> (noNewline: Bool, reference: String) {
        var noNewline = false
        var reference: String?

        for arg in args {
            switch arg {
            case "--no-newline":
                noNewline = true
            case "--out-file", "--file-mode", "--force":
                throw CLIError.unsupportedFlag(
                    flag: arg,
                    reason: "Writing secrets to persistent files is disabled by the macop security policy."
                )
            default:
                if arg.hasPrefix("-") {
                    throw CLIError.invalidArguments(message: "Unknown read flag: \(arg)")
                }
                if reference != nil {
                    throw CLIError.invalidArguments(message: "read accepts exactly one reference.")
                }
                reference = arg
            }
        }

        guard let reference else {
            throw CLIError.invalidArguments(message: "read requires a secret reference argument.")
        }
        return (noNewline: noNewline, reference: reference)
    }

    private static func validateFieldAccess(configItem: ConfigItem, section: String?, field: String) throws {
        guard let allowedFields = configItem.fields, !allowedFields.isEmpty else {
            return
        }
        let requested = section.map { "\($0)/\(field)" } ?? field
        guard allowedFields.contains(requested) else {
            throw CLIError.notFound(message: "Field \"\(requested)\" is not configured for this item.")
        }
    }

    private static func providerNotImplemented(for provider: ConfigProviderKind) -> CLIError {
        switch provider {
        case .keychainGeneric, .keychainInternet:
            .providerUnavailable(
                provider: "keychain",
                reason: "keychain provider wiring is not implemented yet."
            )
        case .secureEnclave:
            .providerUnavailable(
                provider: "secure-enclave",
                reason: "secure-enclave read is not implemented yet."
            )
        }
    }
}
