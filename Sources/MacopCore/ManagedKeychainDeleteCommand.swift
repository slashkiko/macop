import Foundation

enum ManagedKeychainDeleteCommand {
    static func run(
        _ args: [String],
        options: GlobalOptions,
        deleter: any ManagedKeychainDeleting,
        mutator: any KeychainMutating
    ) throws -> CommandResult {
        if args == ["--all-managed"] {
            do {
                try deleter.deleteAll()
            } catch is ManagedKeychainDeletionFailure {
                throw CLIError.runtimeError(
                    message: "Managed Keychain bulk deletion is indeterminate because its broker response was "
                        + "not confirmed. Retry item delete --all-managed; success confirms cleanup, and an "
                        + "already-empty managed Keychain is also the desired state. No secret value is needed."
                )
            }
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
            do {
                try deleter.delete(
                    service: item.value.service!,
                    account: item.value.account!,
                    synchronizable: item.value.managedKeychainSynchronizable,
                    purpose: .item
                )
            } catch is ManagedKeychainDeletionFailure {
                throw CLIError.runtimeError(
                    message: "The primary managed Keychain deletion result is indeterminate because its broker "
                        + "response was not confirmed. The associated OTP seed was not touched by this command. "
                        + "Reconcile the primary item first, then run item otp delete for the same configured item."
                )
            } catch let error as CLIError {
                throw error
            } catch {
                throw CLIError.runtimeError(
                    message: "The primary managed Keychain deletion result is indeterminate. The associated OTP "
                        + "seed was not touched by this command. Reconcile the primary item first, then run item "
                        + "otp delete for the same configured item."
                )
            }
        } else {
            // Exact-one selection, authentication, and primary deletion happen
            // before touching the independent OTP seed. A missing, ambiguous,
            // cancelled, or failed primary operation therefore preserves OTP.
            try mutator.delete(query: ConfiguredKeychainItemLocator.query(for: item.value))
        }
        if let otp = item.value.otp {
            do {
                try deleter.delete(
                    service: otp.service, account: otp.account, synchronizable: otp.synchronizable,
                    purpose: .otpSeed
                )
            } catch let error as CLIError {
                if case .notFound = error {
                    // An already-missing associated seed is the desired final state.
                } else {
                    throw CLIError.runtimeError(
                        message: "The primary Keychain item was deleted, but its OTP seed remains. "
                            + "Run item otp delete for the same configured item to reconcile."
                    )
                }
            } catch {
                throw CLIError.runtimeError(
                    message: "The primary Keychain item was deleted, but OTP seed deletion could not be "
                        + "confirmed and the seed may remain. Run item otp delete for the same configured item "
                        + "to reconcile."
                )
            }
        }
        if options.format == .json {
            return CommandResult(exitCode: 0, stdout: "{\"schema_version\":1,\"status\":\"deleted\"}\n")
        }
        return CommandResult(exitCode: 0, stdout: "Deleted \(item.key) from Keychain.\n")
    }
}
