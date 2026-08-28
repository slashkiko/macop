import Foundation
import Security

enum ManagedItemLocator {
    static func item(
        named name: String,
        options: GlobalOptions
    ) throws -> (key: String, value: ConfigItem) {
        let matches = try ConfigStore.items(configDirectory: options.configDirectory)
            .filter {
                $0.value.provider == "keychain-managed"
                    && $0.key.split(separator: "/").last == Substring(name)
            }
        guard matches.count == 1, let item = matches.first,
              item.value.service != nil, item.value.account != nil
        else { throw CLIError.notFound(message: "Configured managed item \"\(name)\" was not found.") }
        return item
    }
}

enum CredentialAcquireCommand {
    static func run(
        _ args: [String],
        options: GlobalOptions,
        client: any KeychainClient,
        passwordAutoFillProvider: any PasswordAutoFillProviding
    ) throws -> CommandResult {
        var name: String?
        var forcePasswords = false
        for arg in args {
            if arg == "--from-passwords" {
                forcePasswords = true
            } else if arg.hasPrefix("-") {
                throw CLIError.invalidArguments(message: "Unknown item acquire flag: \(arg)")
            } else if name == nil {
                name = arg
            } else {
                throw CLIError.invalidArguments(message: "item acquire accepts one item name.")
            }
        }
        guard let name else {
            throw CLIError.invalidArguments(
                message: "item acquire requires one configured managed item name."
            )
        }
        let item = try ManagedItemLocator.item(named: name, options: options)
        let service = item.value.service!
        let account = item.value.account!
        if !forcePasswords {
            switch client.read(.managed(
                service: service,
                account: account,
                synchronizable: item.value.managedKeychainSynchronizable
            )) {
            case let .success(secret):
                guard !secret.isEmpty, secret.count <= ManagedKeychainStore.maximumSecretLength else {
                    throw CLIError.runtimeError(message: "Managed Keychain returned an invalid credential.")
                }
                return try self.render(secret, options: options)
            case let .failure(failure) where failure.status == errSecItemNotFound:
                break
            case let .failure(failure):
                throw self.keychainError(failure)
            }
        }
        let credential = try passwordAutoFillProvider.acquire(
            service: service,
            account: account,
            synchronizable: item.value.managedKeychainSynchronizable,
            command: forcePasswords ? "macop item acquire --from-passwords" : "macop item acquire"
        )
        return try self.render(credential.secret, options: options)
    }

    private static func keychainError(_ failure: KeychainFailure) -> CLIError {
        if failure.isAmbiguous {
            return .invalidArguments(
                message: "Keychain selector is ambiguous; configure a unique item before reading it."
            )
        }
        switch failure.status {
        case errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed:
            return .denied(message: "Keychain access was denied or cancelled.")
        case errSecNotAvailable:
            return .providerUnavailable(provider: "keychain", reason: "Keychain is not available.")
        default:
            return .runtimeError(message: "Keychain provider failed (OSStatus \(failure.status)).")
        }
    }

    private static func render(_ secret: Data, options _: GlobalOptions) throws -> CommandResult {
        let text = try KeychainProvider.text(from: secret)
        return CommandResult(exitCode: 0, stdout: text + "\n")
    }
}
