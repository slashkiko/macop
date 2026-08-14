import Foundation

public enum ReadCommand {
    public static func run(
        args: [String],
        options: GlobalOptions,
        env: [String: String],
        client: any KeychainClient = SystemKeychainClient()
    ) throws -> CommandResult {
        let parsed = try parseArgs(args)
        let reference = try ReferenceResolver.parse(parsed.reference, env: env)

        switch reference {
        case let .opReference(namespace, item, section, field):
            let configItem = try ConfigStore.resolveItem(
                namespace: namespace,
                item: item,
                configDirectory: options.configDirectory
            )
            try self.validateFieldAccess(configItem: configItem, section: section, field: field)
            let text = try KeychainProvider.readText(self.query(for: configItem), client: client)
            return CommandResult(exitCode: 0, stdout: text + (parsed.noNewline ? "" : "\n"))
        case let .keychainGeneric(service, account):
            return try self.output(
                KeychainProvider.readText(.generic(service: service, account: account), client: client),
                noNewline: parsed.noNewline
            )
        case let .keychainInternet(server, account):
            return try self.output(
                KeychainProvider.readText(.internet(server: server, account: account), client: client),
                noNewline: parsed.noNewline
            )
        case .secureEnclave:
            throw CLIError.unsupportedProvider(
                provider: "secure-enclave",
                reason: "Reading Secure Enclave identities as secrets is not supported."
            )
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
            case "--otp":
                throw CLIError.unsupportedFlag(flag: arg, reason: "OTP retrieval is not supported by macop.")
            case "--ssh-format":
                throw CLIError.unsupportedFlag(
                    flag: arg,
                    reason: "Exporting SSH private keys is not supported by macop."
                )
            default:
                let persistentFlag = ["--out-file", "--file-mode", "--force"]
                    .first { arg.hasPrefix("\($0)=") }
                if let persistentFlag {
                    throw CLIError.unsupportedFlag(
                        flag: persistentFlag,
                        reason: "Writing secrets to persistent files is disabled by the macop security policy."
                    )
                }
                if arg.hasPrefix("--otp=") {
                    throw CLIError.unsupportedFlag(
                        flag: "--otp",
                        reason: "OTP retrieval is not supported by macop."
                    )
                }
                if arg.hasPrefix("--ssh-format=") {
                    throw CLIError.unsupportedFlag(
                        flag: "--ssh-format",
                        reason: "Exporting SSH private keys is not supported by macop."
                    )
                }
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

    private static func query(for item: ConfigItem) throws -> KeychainQuery {
        if item.provider == "keychain-internet", let server = item.server, let account = item.account {
            return .internet(server: server, account: account)
        }
        if item.provider == "keychain-generic", let service = item.service, let account = item.account {
            return .generic(service: service, account: account)
        }
        throw CLIError.unsupportedProvider(provider: item.provider, reason: "This provider cannot supply secret text.")
    }

    private static func output(_ text: String, noNewline: Bool) throws -> CommandResult {
        CommandResult(exitCode: 0, stdout: text + (noNewline ? "" : "\n"))
    }
}
