import Foundation

enum ManagedKeychainDeleteCommand {
    static func run(
        _ args: [String],
        options: GlobalOptions,
        deleter: any ManagedKeychainDeleting
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
                message: "item delete requires one configured managed item name or --all-managed."
            )
        }
        let item = try ManagedItemLocator.item(named: name, options: options)
        try deleter.delete(service: item.value.service!, account: item.value.account!)
        if options.format == .json {
            return CommandResult(exitCode: 0, stdout: "{\"schema_version\":1,\"status\":\"deleted\"}\n")
        }
        return CommandResult(exitCode: 0, stdout: "Deleted \(item.key) from the managed Keychain.\n")
    }
}
