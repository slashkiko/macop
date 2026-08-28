import Foundation

enum ManagedKeychainDeleteCommand {
    static func run(
        _ args: [String],
        options: GlobalOptions,
        deleter: any ManagedKeychainDeleting,
        mutator: any KeychainMutating
    ) throws -> CommandResult {
        if args == ["--all-managed"] {
            try deleter.deleteAll()
            if options.format == .json {
                return CommandResult(
                    exitCode: 0,
                    stdout: "{\"schema_version\":1,\"status\":\"deleted_all_managed\"}\n"
                )
            }
            return CommandResult(exitCode: 0, stdout: "Deleted all macop-managed Keychain items.\n")
        }
        guard args.count == 1, let name = args.first, !name.hasPrefix("-") else {
            throw CLIError.invalidArguments(
                message: "item delete requires one configured Keychain item name or --all-managed."
            )
        }
        let item = try ConfiguredKeychainItemLocator.item(named: name, options: options)
        if item.value.provider == "keychain-managed" {
            try deleter.delete(
                service: item.value.service!,
                account: item.value.account!,
                synchronizable: item.value.managedKeychainSynchronizable
            )
        } else {
            try mutator.delete(query: ConfiguredKeychainItemLocator.query(for: item.value))
        }
        if options.format == .json {
            return CommandResult(exitCode: 0, stdout: "{\"schema_version\":1,\"status\":\"deleted\"}\n")
        }
        return CommandResult(exitCode: 0, stdout: "Deleted \(item.key) from Keychain.\n")
    }
}
