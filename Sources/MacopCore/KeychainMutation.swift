import Foundation
import LocalAuthentication
import Security

public protocol KeychainMutating: Sendable {
    func create(_ secret: Data, query: KeychainQuery) throws
    func edit(_ secret: Data, query: KeychainQuery) throws
    func delete(query: KeychainQuery) throws
}

public struct SystemKeychainMutator: KeychainMutating {
    private let securityAccess: any KeychainSecurityAccess

    public init(securityAccess: any KeychainSecurityAccess = SystemKeychainSecurityAccess()) {
        self.securityAccess = securityAccess
    }

    public func create(_ secret: Data, query: KeychainQuery) throws {
        var attributes = try self.selector(for: query)
        attributes[kSecValueData] = secret
        let status = SecItemAdd(attributes as CFDictionary, nil)
        try self.check(status, operation: "creation")
    }

    public func edit(_ secret: Data, query: KeychainQuery) throws {
        let context = self.authenticationContext(reason: "Edit the selected Keychain item for macop.")
        defer { context.invalidate() }
        let reference = try self.exactReference(for: query, authenticationContext: context)
        let status = SecItemUpdate(
            [
                kSecValuePersistentRef: reference,
                kSecUseAuthenticationContext: context
            ] as CFDictionary,
            [kSecValueData: secret] as CFDictionary
        )
        try self.check(status, operation: "update")
    }

    public func delete(query: KeychainQuery) throws {
        let context = self.authenticationContext(reason: "Delete the selected Keychain item for macop.")
        defer { context.invalidate() }
        let reference = try self.exactReference(for: query, authenticationContext: context)
        let status = SecItemDelete([
            kSecValuePersistentRef: reference,
            kSecUseAuthenticationContext: context
        ] as CFDictionary)
        try self.check(status, operation: "deletion")
    }

    private func selector(for query: KeychainQuery) throws -> [CFString: Any] {
        switch query {
        case let .generic(service, account):
            return [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: account,
                kSecAttrLabel: "macop: \(service)"
            ]
        case let .internet(server, account):
            return [
                kSecClass: kSecClassInternetPassword,
                kSecAttrServer: server,
                kSecAttrAccount: account,
                kSecAttrLabel: "macop: \(server)"
            ]
        case .managed:
            throw CLIError.invalidArguments(
                message: "Managed Keychain items must use the native authorization path."
            )
        }
    }

    private func exactReference(
        for query: KeychainQuery,
        authenticationContext: LAContext
    ) throws -> Data {
        let result = self.securityAccess.persistentReferences(
            for: query,
            authenticationContext: authenticationContext
        )
        guard result.status == errSecSuccess, let value = result.result else {
            throw self.error(for: result.status, operation: "selection")
        }
        let references: [Data]
        if let reference = value as? Data {
            references = [reference]
        } else if let array = value as? NSArray {
            let values = array.compactMap { $0 as? Data }
            guard values.count == array.count else {
                throw CLIError.runtimeError(message: "Keychain selection returned invalid metadata.")
            }
            references = values
        } else {
            throw CLIError.runtimeError(message: "Keychain selection returned invalid metadata.")
        }
        guard references.count == 1, let reference = references.first else {
            throw CLIError.invalidArguments(
                message: "Keychain selector is ambiguous; configure a unique item before modifying it."
            )
        }
        return reference
    }

    private func authenticationContext(reason: String) -> LAContext {
        let context = LAContext()
        context.localizedReason = reason
        return context
    }

    private func check(_ status: OSStatus, operation: String) throws {
        guard status != errSecSuccess else { return }
        throw self.error(for: status, operation: operation)
    }

    private func error(for status: OSStatus, operation: String) -> CLIError {
        switch status {
        case errSecItemNotFound:
            .notFound(message: "Keychain item was not found.")
        case errSecDuplicateItem:
            .invalidArguments(message: "Keychain item already exists; use item edit to replace its value.")
        case errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed:
            .denied(message: "Keychain \(operation) was denied or cancelled.")
        case errSecNotAvailable:
            .providerUnavailable(provider: "keychain", reason: "Keychain is not available.")
        default:
            .runtimeError(message: "Keychain \(operation) failed (OSStatus \(status)).")
        }
    }
}

enum ConfiguredKeychainItemLocator {
    static func item(
        named name: String,
        options: GlobalOptions,
        providers: Set<String> = ["keychain-generic", "keychain-internet", "keychain-managed"]
    ) throws -> (key: String, value: ConfigItem) {
        let matches = try ConfigStore.items(configDirectory: options.configDirectory)
            .filter {
                providers.contains($0.value.provider)
                    && $0.key.split(separator: "/").last == Substring(name)
            }
        guard matches.count == 1, let item = matches.first else {
            throw CLIError.notFound(message: "Configured Keychain item \"\(name)\" was not found.")
        }
        return item
    }

    static func query(for item: ConfigItem) throws -> KeychainQuery {
        if item.provider == "keychain-generic", let service = item.service, let account = item.account {
            return .generic(service: service, account: account)
        }
        if item.provider == "keychain-internet", let server = item.server, let account = item.account {
            return .internet(server: server, account: account)
        }
        if item.provider == "keychain-managed", let service = item.service, let account = item.account {
            return .managed(
                service: service,
                account: account,
                synchronizable: item.managedKeychainSynchronizable
            )
        }
        throw CLIError.unsupportedProvider(provider: item.provider, reason: "Item is not backed by Keychain.")
    }
}
