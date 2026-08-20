import Foundation
import Security

public enum KeychainQuery: Sendable, Equatable {
    case generic(service: String, account: String)
    case internet(server: String, account: String)
}

public struct KeychainFailure: Error, Sendable {
    public let status: OSStatus
    public let isAmbiguous: Bool

    public init(_ status: OSStatus, isAmbiguous: Bool = false) {
        self.status = status
        self.isAmbiguous = isAmbiguous
    }

    public static let ambiguousItem = KeychainFailure(errSecDuplicateItem, isAmbiguous: true)
    public static let ambiguousInternetItem = Self.ambiguousItem
}

public protocol KeychainClient: Sendable {
    func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure>
}

public struct SystemKeychainClient: KeychainClient {
    public init() {}

    public func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        var attributes: [CFString: Any] = [:]
        switch query {
        case let .generic(service, account):
            attributes[kSecClass] = kSecClassGenericPassword
            attributes[kSecAttrService] = service
            attributes[kSecAttrAccount] = account
        case let .internet(server, account):
            attributes[kSecClass] = kSecClassInternetPassword
            attributes[kSecAttrServer] = server
            attributes[kSecAttrAccount] = account
        }
        return self.readExactlyOne(attributes: attributes)
    }

    private func readExactlyOne(attributes: [CFString: Any]) -> Result<Data, KeychainFailure> {
        // Both generic and internet selectors can match more than one item in
        // an accessible search list. Enumerate opaque persistent references,
        // then dereference exactly one item only after the count is known.
        var referenceQuery = attributes
        referenceQuery[kSecReturnPersistentRef] = true
        referenceQuery[kSecMatchLimit] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(referenceQuery as CFDictionary, &result)
        guard status == errSecSuccess, let result else { return .failure(KeychainFailure(status)) }
        let references: [Data]
        if let reference = result as? Data {
            references = [reference]
        } else if let array = result as? NSArray {
            let persistentReferences = array.compactMap { $0 as? Data }
            guard persistentReferences.count == array.count else { return .failure(KeychainFailure(errSecDecode)) }
            references = persistentReferences
        } else {
            return .failure(KeychainFailure(errSecDecode))
        }
        guard references.count == 1, let reference = references.first else { return .failure(.ambiguousItem) }

        let valueQuery: [CFString: Any] = [
            kSecValuePersistentRef: reference,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var valueResult: CFTypeRef?
        let valueStatus = SecItemCopyMatching(valueQuery as CFDictionary, &valueResult)
        guard valueStatus == errSecSuccess, let value = valueResult as? Data else {
            return .failure(KeychainFailure(valueStatus))
        }
        return .success(value)
    }
}

public enum KeychainProvider {
    public static func readText(_ query: KeychainQuery, client: any KeychainClient) throws -> String {
        switch client.read(query) {
        case let .success(data):
            guard let text = String(data: data, encoding: .utf8), !text.contains("\0") else {
                throw CLIError.runtimeError(message: "Keychain secret must be UTF-8 text without NUL bytes.")
            }
            return text
        case let .failure(failure):
            if failure.isAmbiguous {
                throw CLIError.invalidArguments(
                    message: "Keychain selector is ambiguous; configure a unique item before reading it."
                )
            }
            throw self.mapStatus(failure.status)
        }
    }

    private static func mapStatus(_ status: OSStatus) -> CLIError {
        switch status {
        case errSecItemNotFound: .notFound(message: "Keychain item was not found.")
        case errSecAuthFailed, errSecUserCanceled,
             errSecInteractionNotAllowed: .denied(message: "Keychain access was denied or cancelled.")
        case errSecNotAvailable: .providerUnavailable(provider: "keychain", reason: "Keychain is not available.")
        case errSecDuplicateItem: .invalidArguments(
                message: "Keychain selector is ambiguous; configure a unique item before reading it."
            )
        default: .runtimeError(message: "Keychain provider failed (OSStatus \(status)).")
        }
    }
}
