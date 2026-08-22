import Foundation
import LocalAuthentication
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

public struct KeychainSecurityResult: @unchecked Sendable {
    public let status: OSStatus
    public let result: CFTypeRef?

    public init(status: OSStatus, result: CFTypeRef? = nil) {
        self.status = status
        self.result = result
    }
}

/// Injectable boundary around the two Security.framework queries needed for
/// exact-one reads. Both calls receive the same authentication context.
public protocol KeychainSecurityAccess: Sendable {
    func persistentReferences(
        for query: KeychainQuery,
        authenticationContext: LAContext
    ) -> KeychainSecurityResult

    func value(
        for persistentReference: Data,
        authenticationContext: LAContext
    ) -> KeychainSecurityResult
}

public struct SystemKeychainSecurityAccess: KeychainSecurityAccess {
    public init() {}

    public func persistentReferences(
        for query: KeychainQuery,
        authenticationContext: LAContext
    ) -> KeychainSecurityResult {
        var securityQuery: [CFString: Any] = [:]
        switch query {
        case let .generic(service, account):
            securityQuery[kSecClass] = kSecClassGenericPassword
            securityQuery[kSecAttrService] = service
            securityQuery[kSecAttrAccount] = account
        case let .internet(server, account):
            securityQuery[kSecClass] = kSecClassInternetPassword
            securityQuery[kSecAttrServer] = server
            securityQuery[kSecAttrAccount] = account
        }
        securityQuery[kSecReturnPersistentRef] = true
        securityQuery[kSecMatchLimit] = kSecMatchLimitAll
        securityQuery[kSecUseAuthenticationContext] = authenticationContext
        var result: CFTypeRef?
        let status = SecItemCopyMatching(securityQuery as CFDictionary, &result)
        return KeychainSecurityResult(status: status, result: result)
    }

    public func value(
        for persistentReference: Data,
        authenticationContext: LAContext
    ) -> KeychainSecurityResult {
        let securityQuery: [CFString: Any] = [
            kSecValuePersistentRef: persistentReference,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: authenticationContext
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(securityQuery as CFDictionary, &result)
        return KeychainSecurityResult(status: status, result: result)
    }
}

public struct SystemKeychainClient: KeychainClient {
    private let securityAccess: any KeychainSecurityAccess

    public init(securityAccess: any KeychainSecurityAccess = SystemKeychainSecurityAccess()) {
        self.securityAccess = securityAccess
    }

    public func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        let authenticationContext = LAContext()
        authenticationContext.localizedReason = "Read the selected Keychain item for macop."
        defer { authenticationContext.invalidate() }
        return self.readExactlyOne(query: query, authenticationContext: authenticationContext)
    }

    private func readExactlyOne(
        query: KeychainQuery,
        authenticationContext: LAContext
    ) -> Result<Data, KeychainFailure> {
        // Both generic and internet selectors can match more than one item in
        // an accessible search list. Enumerate opaque persistent references,
        // then dereference exactly one item only after the count is known. The
        // second query is the only secret-data read. A shared LAContext can
        // reuse Data Protection Keychain authentication, but legacy login
        // Keychain ACL dialogs are managed independently by macOS.
        let referenceResult = self.securityAccess.persistentReferences(
            for: query,
            authenticationContext: authenticationContext
        )
        let status = referenceResult.status
        let result = referenceResult.result
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

        let valueResult = self.securityAccess.value(
            for: reference,
            authenticationContext: authenticationContext
        )
        guard valueResult.status == errSecSuccess, let value = valueResult.result as? Data else {
            return .failure(KeychainFailure(valueResult.status))
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
