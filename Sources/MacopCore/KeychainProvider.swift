import Foundation
import Security

public enum KeychainQuery: Sendable, Equatable {
    case generic(service: String, account: String)
    case internet(server: String, account: String)
}

public struct KeychainFailure: Error, Sendable {
    public let status: OSStatus
    public init(_ status: OSStatus) {
        self.status = status
    }
}

public protocol KeychainClient: Sendable {
    func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure>
}

public struct SystemKeychainClient: KeychainClient {
    public init() {}

    public func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        var attributes: [CFString: Any] = [
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
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
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return .failure(KeychainFailure(status)) }
        return .success(data)
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
            throw self.mapStatus(failure.status)
        }
    }

    private static func mapStatus(_ status: OSStatus) -> CLIError {
        switch status {
        case errSecItemNotFound: .notFound(message: "Keychain item was not found.")
        case errSecAuthFailed, errSecUserCanceled,
             errSecInteractionNotAllowed: .denied(message: "Keychain access was denied or cancelled.")
        case errSecNotAvailable: .providerUnavailable(provider: "keychain", reason: "Keychain is not available.")
        default: .runtimeError(message: "Keychain provider failed (OSStatus \(status)).")
        }
    }
}
