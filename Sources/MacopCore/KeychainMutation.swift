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
        let context = self.authenticationContext(reason: "Check that the Keychain selector is unused for macop.")
        defer { context.invalidate() }
        try self.requireNoMatches(for: query, authenticationContext: context)
        var attributes = try self.selector(for: query)
        attributes[kSecValueData] = secret
        let creation = self.securityAccess.add(
            attributes: attributes,
            authenticationContext: context
        )
        try self.check(creation.status, operation: "creation")
        guard let createdReference = creation.result as? Data else {
            throw CLIError.runtimeError(
                message: "Keychain creation succeeded but returned no persistent reference, so its outcome is "
                    + "indeterminate and a newly created item may remain. No broad deletion was attempted. "
                    + "Inspect the configured selector in Keychain settings before retrying create."
            )
        }

        let verification = self.securityAccess.persistentReferences(
            for: query, authenticationContext: context
        )
        let verifiedReferences = verification.status == errSecSuccess
            ? try? self.references(from: verification.result)
            : nil
        let creationIsUnique = verifiedReferences?.count == 1
            && verifiedReferences?.first.map { constantTimeEqual($0, createdReference) } == true
        if creationIsUnique {
            return
        }

        // A concurrent add can make a broad internet-password selector
        // ambiguous between preflight and SecItemAdd. Roll back only the item
        // returned by our add, never every item matching the broad selector.
        let rollback = self.securityAccess.delete(
            persistentReference: createdReference,
            authenticationContext: context
        )
        guard rollback == errSecSuccess || rollback == errSecItemNotFound else {
            throw CLIError.runtimeError(
                message: "Keychain creation verification failed and targeted rollback could not be confirmed "
                    + "(OSStatus \(rollback)); the newly created item may remain. No broad deletion was attempted. "
                    + "Inspect the configured selector in Keychain settings before retrying create."
            )
        }
        if verification.status == errSecSuccess {
            throw CLIError.invalidArguments(
                message: "Keychain selector became ambiguous during creation; the newly created item was rolled back."
            )
        }
        throw self.error(for: verification.status, operation: "creation verification")
    }

    private func requireNoMatches(
        for query: KeychainQuery,
        authenticationContext: LAContext
    ) throws {
        let result = self.securityAccess.persistentReferences(
            for: query, authenticationContext: authenticationContext
        )
        switch result.status {
        case errSecItemNotFound:
            return
        case errSecSuccess:
            throw CLIError.invalidArguments(
                message: "Keychain selector already matches an item; create requires zero matches."
            )
        default:
            throw self.error(for: result.status, operation: "creation preflight")
        }
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
        let references = try self.references(from: value)
        guard references.count == 1, let reference = references.first else {
            throw CLIError.invalidArguments(
                message: "Keychain selector is ambiguous; configure a unique item before modifying it."
            )
        }
        return reference
    }

    private func references(from value: CFTypeRef?) throws -> [Data] {
        if let reference = value as? Data {
            return [reference]
        } else if let array = value as? NSArray {
            let values = array.compactMap { $0 as? Data }
            guard values.count == array.count else {
                throw CLIError.runtimeError(message: "Keychain selection returned invalid metadata.")
            }
            return values
        } else {
            throw CLIError.runtimeError(message: "Keychain selection returned invalid metadata.")
        }
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
