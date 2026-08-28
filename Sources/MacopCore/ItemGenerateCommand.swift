import Foundation

enum ItemGenerateCommand {
    static func run(
        _ args: [String], options: GlobalOptions,
        importer: any ManagedKeychainImporting, mutator: any KeychainMutating
    ) throws -> CommandResult {
        var arguments = args
        let replace = arguments.first == "--replace"
        if replace {
            arguments.removeFirst()
        }
        guard let name = arguments.first, !name.hasPrefix("-") else {
            throw CLIError.invalidArguments(message: "item generate [--replace] requires one configured item name.")
        }
        let generation = try PasswordGenerationArguments.parse(Array(arguments.dropFirst()))
        let item = try ConfiguredKeychainItemLocator.item(
            named: name, options: options,
            providers: ["keychain-generic", "keychain-internet", "keychain-managed"]
        )
        var generated = try PasswordGenerator.generate(generation)
        defer { generated.removeAll(keepingCapacity: false) }
        let secret = Data(generated.utf8)
        if item.value.provider == "keychain-managed" {
            do {
                if replace {
                    try importer.updateSecret(
                        secret, service: item.value.service!, account: item.value.account!,
                        synchronizable: item.value.managedKeychainSynchronizable
                    )
                } else {
                    try importer.generateSecret(
                        secret, service: item.value.service!, account: item.value.account!,
                        synchronizable: item.value.managedKeychainSynchronizable
                    )
                }
            } catch let failure as ManagedKeychainMutationFailure {
                let guidance = replace
                    ? "Retry item generate --replace for the same configured item; a successful retry establishes a new completed rotation."
                    : "Reconcile the configured selector before retrying create; the generated item may already exist."
                throw CLIError.runtimeError(
                    message: "Managed password \(replace ? "rotation" : "creation") is indeterminate. "
                        + "\(failure.diagnostic) \(guidance) No generated password is printed or "
                        + "required for reconciliation."
                )
            }
        } else {
            if replace {
                try mutator.edit(secret, query: ConfiguredKeychainItemLocator.query(for: item.value))
            } else {
                try mutator.create(secret, query: ConfiguredKeychainItemLocator.query(for: item.value))
            }
        }
        let status = options.format == .json
            ? "{\"schema_version\":1,\"status\":\"\(replace ? "rotated" : "generated")\"}\n"
            : "Generated and \(replace ? "rotated" : "saved") a password for \(item.key).\n"
        return CommandResult(exitCode: 0, stdout: status)
    }
}
