import Foundation

enum OTPCommand {
    // swiftlint:disable:next function_parameter_count
    static func run(
        _ args: [String], options: GlobalOptions, input: Data,
        client: any KeychainClient, importer: any ManagedKeychainImporting,
        deleter: any ManagedKeychainDeleting
    ) throws -> CommandResult {
        if args.first == "import" {
            return try self.importSeed(
                Array(args.dropFirst()), options: options, input: input, importer: importer, updating: false
            )
        }
        if args.first == "edit" {
            return try self.importSeed(
                Array(args.dropFirst()), options: options, input: input, importer: importer, updating: true
            )
        }
        if args.first == "delete" {
            guard args.count == 2 else {
                throw CLIError.invalidArguments(message: "item otp delete requires one item name.")
            }
            let item = try Self.locate(name: args[1], options: options)
            let otp = item.value.otp!
            do {
                try deleter.delete(
                    service: otp.service, account: otp.account, synchronizable: otp.synchronizable,
                    purpose: .otpSeed
                )
            } catch is ManagedKeychainDeletionFailure {
                throw CLIError.runtimeError(
                    message: "OTP seed deletion is indeterminate because its broker response was not confirmed. "
                        + "Retry item otp delete for the same configured item; success or not-found confirms "
                        + "the seed is absent. No seed value is needed."
                )
            }
            return CommandResult(
                exitCode: 0,
                stdout: options.format == .json
                    ? "{\"schema_version\":1,\"status\":\"deleted\"}\n"
                    : "Deleted OTP seed for \(item.key) from the managed Keychain.\n"
            )
        }
        guard args.count == 1, let name = args.first, !name.hasPrefix("-") else {
            throw CLIError.invalidArguments(
                message: "item otp requires one item name, or: item otp <import|edit|delete> <name>."
            )
        }
        let item = try Self.locate(name: name, options: options)
        let code = try CredentialFieldResolver.otp(item: item.value, client: client)
        if options.format == .json {
            let data = try JSONSerialization.data(withJSONObject: ["schema_version": 1, "otp": code])
            guard let output = String(bytes: data, encoding: .utf8) else {
                throw CLIError.runtimeError(message: "Unable to render OTP response.")
            }
            return CommandResult(exitCode: 0, stdout: output + "\n")
        }
        return CommandResult(exitCode: 0, stdout: code + "\n")
    }

    private static func importSeed(
        _ args: [String], options: GlobalOptions, input: Data,
        importer: any ManagedKeychainImporting, updating: Bool
    ) throws -> CommandResult {
        guard args.count == 1, let name = args.first,
              !input.isEmpty, input.count <= ManagedKeychainStore.maximumSecretLength,
              let text = String(data: input, encoding: .utf8), !text.contains("\0")
        else {
            throw CLIError
                .invalidArguments(
                    message: "item otp \(updating ? "edit" : "import") requires an item name and Base32 or otpauth URI stdin."
                )
        }
        let item = try Self.locate(name: name, options: options)
        guard let otp = item.value.otp else { throw CLIError.notFound(message: "OTP is not configured for this item.") }
        let parsed = try TOTPGenerator.parse(text)
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let metadataMismatch = parsed.algorithm.uppercased() != otp.algorithm.uppercased()
            || parsed.digits != otp.digits || parsed.period != otp.period
            || parsed.label != otp.label || parsed.issuer != otp.issuer
        if trimmed.lowercased().hasPrefix("otpauth://"), metadataMismatch {
            throw CLIError.invalidArguments(message: "OTP URI parameters do not match the configured OTP metadata.")
        }
        do {
            if updating {
                try importer.updateOTPSeed(
                    parsed.seed, service: otp.service, account: otp.account, synchronizable: otp.synchronizable
                )
            } else {
                try importer.importOTPSeed(
                    parsed.seed, service: otp.service, account: otp.account, synchronizable: otp.synchronizable
                )
            }
        } catch let failure as ManagedKeychainMutationFailure {
            let guidance = updating
                ? "Retry item otp edit for the same configured item with the same stdin; "
                + "the exact update is safe to repeat."
                : "Retry item otp import for the same configured item with the same stdin: "
                + "success means the retry created it, while already-exists means the original create completed."
            throw CLIError.runtimeError(
                message: "OTP seed \(updating ? "update" : "creation") is indeterminate. "
                    + "\(failure.diagnostic) \(guidance) Never put the seed in command arguments."
            )
        }
        return CommandResult(
            exitCode: 0,
            stdout: options.format == .json
                ? "{\"schema_version\":1,\"status\":\"\(updating ? "updated" : "imported")\"}\n"
                : "\(updating ? "Updated" : "Imported") OTP seed for \(item.key) \(updating ? "in" : "into") the managed Keychain.\n"
        )
    }

    private static func locate(name: String, options: GlobalOptions) throws -> (key: String, value: ConfigItem) {
        let item = try ConfiguredKeychainItemLocator.item(named: name, options: options)
        guard item.value.otp != nil else {
            throw CLIError.notFound(message: "OTP is not configured for item \"\(item.key)\".")
        }
        return item
    }
}
