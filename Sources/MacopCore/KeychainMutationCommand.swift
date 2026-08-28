import Foundation

enum KeychainMutationCommand {
    static func run(
        _ operation: String,
        args: [String],
        options: GlobalOptions,
        input: Data,
        mutator: any KeychainMutating
    ) throws -> CommandResult {
        guard args.count == 1, let name = args.first, !name.hasPrefix("-") else {
            throw CLIError.invalidArguments(
                message: "item \(operation) requires one configured generic or internet item name and secret stdin."
            )
        }
        try self.validateSecret(input, operation: operation)
        let item = try ConfiguredKeychainItemLocator.item(
            named: name,
            options: options,
            providers: ["keychain-generic", "keychain-internet"]
        )
        let query = try ConfiguredKeychainItemLocator.query(for: item.value)
        if operation == "create" {
            try mutator.create(input, query: query)
        } else {
            try mutator.edit(input, query: query)
        }
        let status = operation == "create" ? "created" : "updated"
        if options.format == .json {
            return CommandResult(exitCode: 0, stdout: "{\"schema_version\":1,\"status\":\"\(status)\"}\n")
        }
        let action = operation == "create" ? "Created" : "Updated"
        return CommandResult(exitCode: 0, stdout: "\(action) \(item.key) in Keychain.\n")
    }

    private static func validateSecret(_ input: Data, operation: String) throws {
        guard !input.isEmpty, input.count <= ManagedKeychainStore.maximumSecretLength,
              let text = String(data: input, encoding: .utf8), !text.contains("\0")
        else {
            throw CLIError.invalidArguments(
                message: "item \(operation) requires 1 to 65536 bytes of UTF-8 secret stdin."
            )
        }
    }
}
