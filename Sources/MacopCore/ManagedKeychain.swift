import Foundation
import LocalAuthentication
import Security

public enum ManagedKeychainStore {
    public static let maximumSecretLength = 64 * 1024

    public static func read(
        service: String,
        account: String,
        authenticationContext: LAContext
    ) -> Result<Data, KeychainFailure> {
        guard self.validSelector(service), self.validSelector(account) else {
            return .failure(KeychainFailure(errSecParam))
        }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
            kSecUseAuthenticationContext: authenticationContext,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return .failure(KeychainFailure(status == errSecSuccess ? errSecDecode : status))
        }
        guard data.count <= self.maximumSecretLength else {
            return .failure(KeychainFailure(errSecDecode))
        }
        return .success(data)
    }

    public static func importSecret(
        _ secret: Data,
        service: String,
        account: String,
        authenticationContext: LAContext
    ) -> OSStatus {
        guard !secret.isEmpty, secret.count <= self.maximumSecretLength,
              self.validSelector(service), self.validSelector(account)
        else { return errSecParam }
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error
        ) else { return errSecParam }
        let attributes: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrLabel: "macop managed: \(service)",
            kSecAttrAccessControl: accessControl,
            kSecUseDataProtectionKeychain: true,
            kSecUseAuthenticationContext: authenticationContext,
            kSecValueData: secret
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { return status }
        switch self.read(service: service, account: account, authenticationContext: authenticationContext) {
        case let .success(readback):
            return constantTimeEqual(secret, readback) ? errSecSuccess : errSecDecode
        case let .failure(failure):
            return failure.status
        }
    }

    private static func validSelector(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= AuthBrokerWire.maximumMetadataLength
            && !value.contains("\0")
    }
}

public struct CompanionManagedKeychainClient: KeychainClient {
    public init() {}

    public func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        guard case let .managed(service, account) = query else {
            return .failure(KeychainFailure(errSecParam))
        }
        do {
            let connection = try AuthBrokerClientConnection.launchAndConnect(
                requiredCapabilities: AuthBrokerCapability.managedKeychain.rawValue
            )
            let request = try AuthBrokerRequester.approvalRequest(
                operation: .managedKeychainRead,
                command: "macop read",
                credentialLabel: account,
                service: service,
                account: account
            )
            guard case let .approvalResponse(response) = try connection.send(.approvalRequest(request)),
                  response.requestID == request.requestID
            else { return .failure(KeychainFailure(errSecDecode)) }
            guard response.status == .approved else {
                return .failure(KeychainFailure(
                    response.status == .cancelled ? errSecUserCanceled : errSecAuthFailed
                ))
            }
            guard response.resultStatus == errSecSuccess else {
                return .failure(KeychainFailure(response.resultStatus))
            }
            return .success(response.resultData)
        } catch {
            return .failure(KeychainFailure(errSecInteractionNotAllowed))
        }
    }
}

public protocol ManagedKeychainImporting: Sendable {
    func importSecret(_ secret: Data, service: String, account: String) throws
}

public struct CompanionManagedKeychainImporter: ManagedKeychainImporting {
    public init() {}

    public func importSecret(_ secret: Data, service: String, account: String) throws {
        guard !secret.isEmpty, secret.count <= ManagedKeychainStore.maximumSecretLength else {
            throw CLIError.invalidArguments(message: "Managed Keychain secret must be 1 to 65536 bytes.")
        }
        let connection = try AuthBrokerClientConnection.launchAndConnect(
            requiredCapabilities: AuthBrokerCapability.managedKeychain.rawValue
        )
        let request = try AuthBrokerRequester.approvalRequest(
            operation: .managedKeychainImport,
            command: "macop item import",
            credentialLabel: account,
            service: service,
            account: account
        )
        guard case let .approvalResponse(approval) = try connection.send(.approvalRequest(request)),
              approval.requestID == request.requestID else { throw CLIError.denied(message: "Import was denied.") }
        guard approval.status == .approved else {
            throw CLIError.denied(message: "Import was denied or cancelled.")
        }
        let message = AuthBrokerManagedKeychainImportRequest(
            authorizationID: request.requestID,
            secret: secret
        )
        guard case let .managedKeychainImportResponse(response) = try connection.send(
            .managedKeychainImportRequest(message)
        ), response.authorizationID == request.requestID else {
            throw CLIError.runtimeError(message: "Managed Keychain import returned an invalid response.")
        }
        switch response.status {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            throw CLIError
                .invalidArguments(message: "Managed Keychain item already exists; import does not overwrite it.")
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
            throw CLIError.denied(message: "Managed Keychain import was denied or cancelled.")
        default:
            throw CLIError.runtimeError(message: "Managed Keychain import failed (OSStatus \(response.status)).")
        }
    }
}

public enum AuthBrokerRequester {
    public static func approvalRequest(
        operation: AuthBrokerOperation,
        command: String,
        credentialLabel: String,
        service: String,
        account: String
    ) throws -> AuthBrokerApprovalRequest {
        let executable = try RunningExecutable.path()
        let inspection = try LiveCodeIdentityInspector.inspect(pid: getpid(), expectedPath: executable)
        guard inspection.identity.hasTrustedPublisher,
              let snapshot = SystemRequesterInspector().snapshot(of: getpid())
        else { throw AgentProtocolError.denied }
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        return AuthBrokerApprovalRequest(
            requestID: UUID(),
            issuedAtMilliseconds: now,
            expiresAtMilliseconds: now + 120_000,
            operation: operation,
            rootPID: getpid(),
            rootStartTime: snapshot.startTime,
            rootIdentifier: inspection.identity.identifier,
            rootCodeRequirement: inspection.codeRequirement,
            rootExecutablePath: inspection.identity.canonicalPath,
            command: command,
            credentialLabel: credentialLabel,
            credentialFingerprint: "",
            host: "",
            keychainService: service,
            keychainAccount: account
        )
    }
}
