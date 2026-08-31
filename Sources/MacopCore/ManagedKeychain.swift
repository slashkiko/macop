// swiftlint:disable file_length
import Darwin
import Foundation
import LocalAuthentication
import Security

public enum ManagedKeychainMutationOutcome: Sendable, Equatable {
    case committed
    case failed(OSStatus)
    case indeterminate

    public var brokerOutcome: AuthBrokerMutationOutcome {
        switch self {
        case .committed: .committed
        case .failed: .failed
        case .indeterminate: .indeterminate
        }
    }

    public var status: OSStatus {
        switch self {
        case .committed: errSecSuccess
        case let .failed(status): status
        case .indeterminate: errSecSuccess
        }
    }
}

public protocol ManagedKeychainStoreAccess: Sendable {
    func read(
        service: String, account: String, synchronizable: Bool,
        authenticationContext: LAContext
    ) -> Result<Data, KeychainFailure>
    func add(
        _ secret: Data, service: String, account: String, synchronizable: Bool,
        authenticationContext: LAContext
    ) -> OSStatus
    func update(
        _ secret: Data, service: String, account: String, synchronizable: Bool,
        authenticationContext: LAContext
    ) -> OSStatus
}

public struct SystemManagedKeychainStoreAccess: ManagedKeychainStoreAccess {
    public init() {}

    public func read(
        service: String, account: String, synchronizable: Bool,
        authenticationContext: LAContext
    ) -> Result<Data, KeychainFailure> {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: synchronizable,
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
        return .success(data)
    }

    public func add(
        _ secret: Data, service: String, account: String, synchronizable: Bool,
        authenticationContext: LAContext
    ) -> OSStatus {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            synchronizable ? kSecAttrAccessibleWhenUnlocked : kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error
        ) else { return errSecParam }
        let attributes: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: synchronizable,
            kSecAttrLabel: "macop managed: \(service)",
            kSecAttrAccessControl: accessControl,
            kSecUseDataProtectionKeychain: true,
            kSecUseAuthenticationContext: authenticationContext,
            kSecValueData: secret
        ]
        return SecItemAdd(attributes as CFDictionary, nil)
    }

    public func update(
        _ secret: Data, service: String, account: String, synchronizable: Bool,
        authenticationContext: LAContext
    ) -> OSStatus {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: synchronizable,
            kSecUseDataProtectionKeychain: true,
            kSecUseAuthenticationContext: authenticationContext
        ]
        return SecItemUpdate(query as CFDictionary, [kSecValueData: secret] as CFDictionary)
    }
}

public enum ManagedKeychainStore {
    public static let maximumSecretLength = 64 * 1024

    public static func read(
        service: String,
        account: String,
        synchronizable: Bool,
        authenticationContext: LAContext,
        access: any ManagedKeychainStoreAccess = SystemManagedKeychainStoreAccess()
    ) -> Result<Data, KeychainFailure> {
        guard self.validSelector(service), self.validSelector(account) else {
            return .failure(KeychainFailure(errSecParam))
        }
        let result = access.read(
            service: service, account: account, synchronizable: synchronizable,
            authenticationContext: authenticationContext
        )
        guard case let .success(data) = result else { return result }
        guard data.count <= self.maximumSecretLength else {
            return .failure(KeychainFailure(errSecDecode))
        }
        return .success(data)
    }

    public static func importSecret(
        _ secret: Data,
        service: String,
        account: String,
        synchronizable: Bool,
        authenticationContext: LAContext,
        access: any ManagedKeychainStoreAccess = SystemManagedKeychainStoreAccess()
    ) -> ManagedKeychainMutationOutcome {
        guard !secret.isEmpty, secret.count <= self.maximumSecretLength,
              self.validSelector(service), self.validSelector(account)
        else { return .failed(errSecParam) }
        let status = access.add(
            secret, service: service, account: account, synchronizable: synchronizable,
            authenticationContext: authenticationContext
        )
        guard status == errSecSuccess else { return .failed(status) }
        return self.verifyMutation(
            secret,
            service: service,
            account: account,
            synchronizable: synchronizable,
            authenticationContext: authenticationContext,
            access: access
        )
    }

    public static func upsertSecret(
        _ secret: Data,
        service: String,
        account: String,
        synchronizable: Bool,
        authenticationContext: LAContext,
        access: any ManagedKeychainStoreAccess = SystemManagedKeychainStoreAccess()
    ) -> ManagedKeychainMutationOutcome {
        guard !secret.isEmpty, secret.count <= self.maximumSecretLength,
              self.validSelector(service), self.validSelector(account)
        else { return .failed(errSecParam) }
        let status = access.update(
            secret, service: service, account: account, synchronizable: synchronizable,
            authenticationContext: authenticationContext
        )
        if status == errSecItemNotFound {
            return self.importSecret(
                secret,
                service: service,
                account: account,
                synchronizable: synchronizable,
                authenticationContext: authenticationContext,
                access: access
            )
        }
        guard status == errSecSuccess else { return .failed(status) }
        return self.verifyMutation(
            secret,
            service: service,
            account: account,
            synchronizable: synchronizable,
            authenticationContext: authenticationContext,
            access: access
        )
    }

    public static func updateSecret(
        _ secret: Data,
        service: String,
        account: String,
        synchronizable: Bool,
        authenticationContext: LAContext,
        access: any ManagedKeychainStoreAccess = SystemManagedKeychainStoreAccess()
    ) -> ManagedKeychainMutationOutcome {
        guard !secret.isEmpty, secret.count <= self.maximumSecretLength,
              self.validSelector(service), self.validSelector(account)
        else { return .failed(errSecParam) }
        let status = access.update(
            secret, service: service, account: account, synchronizable: synchronizable,
            authenticationContext: authenticationContext
        )
        guard status == errSecSuccess else { return .failed(status) }
        return self.verifyMutation(
            secret,
            service: service,
            account: account,
            synchronizable: synchronizable,
            authenticationContext: authenticationContext,
            access: access
        )
    }

    public static func delete(
        service: String,
        account: String,
        synchronizable: Bool,
        authenticationContext: LAContext
    ) -> OSStatus {
        guard self.validSelector(service), self.validSelector(account) else { return errSecParam }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: synchronizable,
            kSecUseDataProtectionKeychain: true,
            kSecUseAuthenticationContext: authenticationContext
        ]
        return SecItemDelete(query as CFDictionary)
    }

    public static func deleteAll(authenticationContext: LAContext) -> OSStatus {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrSynchronizable: kSecAttrSynchronizableAny,
            kSecUseDataProtectionKeychain: true,
            kSecUseAuthenticationContext: authenticationContext
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecItemNotFound ? errSecSuccess : status
    }

    // swiftlint:disable:next function_parameter_count
    private static func verifyMutation(
        _ secret: Data,
        service: String,
        account: String,
        synchronizable: Bool,
        authenticationContext: LAContext,
        access: any ManagedKeychainStoreAccess
    ) -> ManagedKeychainMutationOutcome {
        switch self.read(
            service: service, account: account, synchronizable: synchronizable,
            authenticationContext: authenticationContext, access: access
        ) {
        case let .success(readback):
            constantTimeEqual(secret, readback) ? .committed : .indeterminate
        case .failure:
            .indeterminate
        }
    }

    public static func validSelector(_ value: String) -> Bool {
        !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && value.utf8.count <= AuthBrokerWire.maximumMetadataLength
            && value.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0) && !CharacterSet.newlines.contains($0)
                    && !$0.properties.isBidiControl && $0.value != 0x1B
            }
    }
}

public enum ManagedKeychainReadPresentation: Sendable, Equatable {
    case readPassword
    case runPassword
    case injectPassword
    case profilePassword
    case itemGetPassword
    case itemAcquirePassword
    case readOTP
    case runOTP
    case injectOTP
    case profileOTP
    case itemOTP

    public var brokerPurpose: AuthBrokerPurpose {
        switch self {
        case .readPassword: .managedKeychainRead
        case .runPassword: .passwordRun
        case .injectPassword: .passwordInject
        case .profilePassword: .passwordProfile
        case .itemGetPassword: .passwordItemGet
        case .itemAcquirePassword: .passwordItemAcquire
        case .readOTP: .otpRead
        case .runOTP: .otpRun
        case .injectOTP: .otpInject
        case .profileOTP: .otpProfile
        case .itemOTP: .otpItem
        }
    }
}

public struct CompanionManagedKeychainClient: KeychainClient {
    private let presentation: ManagedKeychainReadPresentation

    public init(presentation: ManagedKeychainReadPresentation = .readPassword) {
        self.presentation = presentation
    }

    public func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        guard case let .managed(service, account, synchronizable) = query else {
            return .failure(KeychainFailure(errSecParam))
        }
        do {
            let connection = try AuthBrokerClientConnection.launchAndConnect(
                requiredCapabilities: AuthBrokerCapability.managedKeychain.rawValue
            )
            let request = try AuthBrokerRequester.approvalRequest(
                operation: .managedKeychainRead,
                purpose: self.presentation.brokerPurpose,
                credentialLabel: account,
                service: service,
                account: account,
                keychainSynchronizable: synchronizable
            )
            guard case let .approvalResponse(response) = try connection.send(.approvalRequest(request)),
                  response.requestID == request.requestID
            else { return .failure(KeychainFailure(brokerFailure: AuthBrokerFailure(.protocolMismatch))) }
            if let failureCategory = response.status.failureCategory {
                return .failure(KeychainFailure(brokerFailure: AuthBrokerFailure(failureCategory)))
            }
            guard response.status == .approved else {
                return .failure(KeychainFailure(brokerFailure: AuthBrokerFailure(.protocolMismatch)))
            }
            guard response.resultStatus == errSecSuccess else {
                return .failure(KeychainFailure(response.resultStatus))
            }
            return .success(response.resultData)
        } catch let failure as AuthBrokerFailure {
            return .failure(KeychainFailure(brokerFailure: failure))
        } catch {
            return .failure(KeychainFailure(brokerFailure: AuthBrokerFailure(.transportFailure)))
        }
    }
}

public protocol ManagedKeychainImporting: Sendable {
    func importSecret(_ secret: Data, service: String, account: String, synchronizable: Bool) throws
    func generateSecret(_ secret: Data, service: String, account: String, synchronizable: Bool) throws
    func importOTPSeed(_ seed: Data, service: String, account: String, synchronizable: Bool) throws
    func updateSecret(_ secret: Data, service: String, account: String, synchronizable: Bool) throws
    func updateOTPSeed(_ seed: Data, service: String, account: String, synchronizable: Bool) throws
}

/// The companion may commit an import or update before its response is lost.
/// Callers must present operation-specific reconciliation guidance rather than
/// retrying blindly or claiming the original mutation failed.
public enum ManagedKeychainMutationFailure: Error, Sendable, Equatable {
    case serverIndeterminate
    case responseLost

    public var diagnostic: String {
        switch self {
        case .serverIndeterminate:
            "The companion returned an indeterminate post-write verification result."
        case .responseLost:
            "The broker response was lost after the mutation request may have been delivered."
        }
    }
}

public extension ManagedKeychainImporting {
    func generateSecret(_ secret: Data, service: String, account: String, synchronizable: Bool) throws {
        try self.importSecret(secret, service: service, account: account, synchronizable: synchronizable)
    }

    func importOTPSeed(_ seed: Data, service: String, account: String, synchronizable: Bool) throws {
        try self.importSecret(seed, service: service, account: account, synchronizable: synchronizable)
    }

    func updateSecret(_ secret: Data, service: String, account: String, synchronizable: Bool) throws {
        try self.importSecret(secret, service: service, account: account, synchronizable: synchronizable)
    }

    func updateOTPSeed(_ seed: Data, service: String, account: String, synchronizable: Bool) throws {
        try self.updateSecret(seed, service: service, account: account, synchronizable: synchronizable)
    }
}

public protocol ManagedKeychainDeleting: Sendable {
    func delete(
        service: String, account: String, synchronizable: Bool,
        purpose: ManagedKeychainDeletePurpose
    ) throws
    func deleteAll() throws
}

/// The broker may complete a deletion before its response is lost. Callers
/// must reconcile instead of treating this transport state as either success
/// or a guarantee that the item was preserved.
public enum ManagedKeychainDeletionFailure: Error, Sendable, Equatable {
    case indeterminate
}

public enum ManagedKeychainDeletePurpose: Sendable, Equatable {
    case item
    case otpSeed

    public var brokerPurpose: AuthBrokerPurpose {
        switch self {
        case .item: .managedKeychainDelete
        case .otpSeed: .otpDelete
        }
    }

    fileprivate func credentialLabel(account: String) -> String {
        self == .otpSeed ? ManagedKeychainPresentationLabel.otpSeed : account
    }
}

public enum ManagedKeychainPresentationLabel {
    /// The account is displayed separately in the native UI. Keeping the
    /// purpose label constant avoids exceeding the broker metadata bound when
    /// a valid selector itself is at that bound.
    public static let otpSeed = "OTP seed"
}

public extension ManagedKeychainDeleting {
    func delete(service: String, account: String, synchronizable: Bool) throws {
        try self.delete(
            service: service, account: account, synchronizable: synchronizable, purpose: .item
        )
    }
}

public struct CompanionManagedKeychainDeleter: ManagedKeychainDeleting {
    public init() {}

    public func delete(
        service: String, account: String, synchronizable: Bool,
        purpose: ManagedKeychainDeletePurpose
    ) throws {
        try self.deleteRequest(
            service: service, account: account, synchronizable: synchronizable, all: false,
            purpose: purpose
        )
    }

    public func deleteAll() throws {
        try self.deleteRequest(
            service: "", account: "", synchronizable: false, all: true, purpose: .item
        )
    }

    private func deleteRequest(
        service: String, account: String, synchronizable: Bool, all: Bool,
        purpose: ManagedKeychainDeletePurpose
    ) throws {
        guard all || (ManagedKeychainStore.validSelector(service) && ManagedKeychainStore.validSelector(account)) else {
            throw CLIError.invalidArguments(message: "Managed Keychain selector metadata is invalid.")
        }
        let connection = try AuthBrokerClientConnection.launchAndConnect(
            requiredCapabilities: AuthBrokerCapability.managedKeychain.rawValue
        )
        let request = try AuthBrokerRequester.approvalRequest(
            operation: .managedKeychainDelete,
            purpose: all ? .managedKeychainDeleteAll : purpose.brokerPurpose,
            credentialLabel: all ? "all managed items" : purpose.credentialLabel(account: account),
            service: service,
            account: account,
            keychainSynchronizable: synchronizable
        )
        // Complete deterministic protocol validation before entering the
        // region where a write followed by a lost response is indeterminate.
        _ = try AuthBrokerWire.frame(.approvalRequest(request))
        let responseMessage: AuthBrokerMessage
        do {
            responseMessage = try connection.send(.approvalRequest(request))
        } catch {
            throw ManagedKeychainDeletionFailure.indeterminate
        }
        guard case let .approvalResponse(response) = responseMessage,
              response.requestID == request.requestID
        else { throw AuthBrokerFailure(.protocolMismatch).cliError }
        if let failureCategory = response.status.failureCategory {
            throw AuthBrokerFailure(failureCategory).cliError
        }
        switch response.resultStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            throw CLIError.notFound(message: "Managed Keychain item was not found.")
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
            throw AuthBrokerFailure(.userDenied).cliError
        default:
            throw CLIError.runtimeError(
                message: "Managed Keychain deletion failed (OSStatus \(response.resultStatus))."
            )
        }
    }
}

public enum PasswordAutoFillSaveStatus: String, Sendable {
    case saved
    case notRequested = "not_requested"
    case failed = "save_failed"
    case indeterminate = "save_indeterminate"

    public init(mutationOutcome: ManagedKeychainMutationOutcome) {
        self = switch mutationOutcome {
        case .committed: .saved
        case .failed: .failed
        case .indeterminate: .indeterminate
        }
    }
}

public enum PasswordAutoFillResponseDelivery: Sendable, Equatable {
    case delivered
    case unknown
}

public struct PasswordAutoFillCompletionPresentation: Sendable, Equatable {
    public let message: String
    public let isSuccess: Bool

    public init(
        saveStatus: PasswordAutoFillSaveStatus,
        delivery: PasswordAutoFillResponseDelivery
    ) {
        self.isSuccess = delivery == .delivered
            && (saveStatus == .saved || saveStatus == .notRequested)
        self.message = switch (saveStatus, delivery) {
        case (.saved, .delivered):
            "Keychainに保存し、要求元へ資格情報を渡しました"
        case (.notRequested, .delivered):
            "Keychainには保存せず、要求元へ資格情報を渡しました"
        case (.failed, .delivered):
            "Keychainへの保存に失敗しました。要求元は資格情報を使用しません"
        case (.indeterminate, .delivered):
            "Keychainへの保存結果を確認できません。要求元は資格情報を使用しません"
        case (.saved, .unknown):
            "Keychainに保存しました。要求元への資格情報の受け渡しは確認できません"
        case (.notRequested, .unknown):
            "Keychainには保存していません。要求元への資格情報の受け渡しは確認できません"
        case (.failed, .unknown):
            "Keychainへの保存に失敗しました。要求元への結果通知は確認できません"
        case (.indeterminate, .unknown):
            "Keychainへの保存結果と、要求元への結果通知を確認できません"
        }
    }
}

public struct PasswordAutoFillRejectionPresentation: Sendable, Equatable {
    public let message: String
    public let isSuccess = false

    public init(status: AuthBrokerApprovalStatus, delivery: PasswordAutoFillResponseDelivery) {
        let decision = switch status {
        case .cancelled: "キャンセルしました"
        case .denied: "承認しませんでした"
        case .approved: "承認結果を確認できません"
        }
        self.message = delivery == .delivered
            ? decision
            : decision + "。要求元への結果通知は確認できません"
    }
}

public enum PasswordAutoFillFailure: Error, Sendable, Equatable {
    case responseLost
    case invalidResponse
    case saveIndeterminate
    case saveFailed(OSStatus)

    public var cliError: CLIError {
        switch self {
        case .responseLost:
            .runtimeError(
                message: "Password AutoFill response was lost after the request may have been delivered. "
                    + "Credential selection or managed Keychain save may have completed; reconcile the configured "
                    + "item before retrying."
            )
        case .invalidResponse:
            .runtimeError(
                message: "Password AutoFill returned an invalid response after the request may have been "
                    + "delivered. Credential selection or managed Keychain save may have completed; reconcile the "
                    + "configured item before retrying."
            )
        case .saveIndeterminate:
            .runtimeError(
                message: "Password AutoFill selected a credential, but managed Keychain save verification was "
                    + "indeterminate. Reconcile the configured item before retrying."
            )
        case let .saveFailed(status):
            .runtimeError(
                message: "Password AutoFill selected a credential, but managed Keychain save failed "
                    + "(OSStatus \(status)); the credential was not used."
            )
        }
    }
}

public enum PasswordAutoFillResponseClassifier {
    /// Classifies only responses received after the approval request entered
    /// the transport. Any malformed or contradictory response is therefore an
    /// indeterminate post-send state, never an ordinary validation failure.
    public static func classify(
        _ message: AuthBrokerMessage,
        requestID: UUID,
        expectedUsername: String
    ) throws -> PasswordAutoFillCredential {
        guard case let .approvalResponse(response) = message,
              response.requestID == requestID
        else { throw PasswordAutoFillFailure.invalidResponse }
        switch response.status {
        case .cancelled, .denied:
            guard response.message.isEmpty,
                  response.resultStatus == errSecAuthFailed,
                  response.resultData.isEmpty,
                  response.verifiedUsername.isEmpty
            else { throw PasswordAutoFillFailure.invalidResponse }
            throw AuthBrokerFailure(.userDenied).cliError
        case .approved:
            guard !response.resultData.isEmpty,
                  response.resultData.count <= ManagedKeychainStore.maximumSecretLength,
                  String(data: response.resultData, encoding: .utf8) != nil,
                  !response.resultData.contains(0),
                  response.verifiedUsername == expectedUsername,
                  let saveStatus = PasswordAutoFillSaveStatus(rawValue: response.message),
                  self.valid(saveStatus: saveStatus, resultStatus: response.resultStatus)
            else { throw PasswordAutoFillFailure.invalidResponse }
            return PasswordAutoFillCredential(
                username: response.verifiedUsername,
                secret: response.resultData,
                saveStatus: saveStatus,
                saveResultStatus: response.resultStatus
            )
        }
    }

    private static func valid(
        saveStatus: PasswordAutoFillSaveStatus,
        resultStatus: OSStatus
    ) -> Bool {
        switch saveStatus {
        case .saved, .notRequested, .indeterminate:
            resultStatus == errSecSuccess
        case .failed:
            resultStatus != errSecSuccess
        }
    }
}

public enum PasswordAutoFillPurpose: Sendable, Equatable {
    case read
    case run
    case inject
    case profile
    case itemAcquire

    public var brokerPurpose: AuthBrokerPurpose {
        switch self {
        case .read: .passwordAutoFillRead
        case .run: .passwordAutoFillRun
        case .inject: .passwordAutoFillInject
        case .profile: .passwordAutoFillProfile
        case .itemAcquire: .passwordAutoFillItemAcquire
        }
    }
}

public struct PasswordAutoFillCredential: Sendable {
    public let username: String
    public let secret: Data
    public let saveStatus: PasswordAutoFillSaveStatus
    public let saveResultStatus: OSStatus

    public init(
        username: String = "", secret: Data, saveStatus: PasswordAutoFillSaveStatus,
        saveResultStatus: OSStatus = errSecSuccess
    ) {
        self.username = username
        self.secret = secret
        self.saveStatus = saveStatus
        self.saveResultStatus = saveResultStatus
    }

    public var saveFailure: PasswordAutoFillFailure? {
        switch self.saveStatus {
        case .saved, .notRequested: nil
        case .indeterminate: .saveIndeterminate
        case .failed: .saveFailed(self.saveResultStatus)
        }
    }
}

public protocol PasswordAutoFillProviding: Sendable {
    func acquire(
        service: String,
        account: String,
        synchronizable: Bool,
        purpose: PasswordAutoFillPurpose
    ) throws -> PasswordAutoFillCredential
}

public struct CompanionPasswordAutoFillProvider: PasswordAutoFillProviding {
    public init() {}

    public func acquire(
        service: String,
        account: String,
        synchronizable: Bool,
        purpose: PasswordAutoFillPurpose
    ) throws -> PasswordAutoFillCredential {
        let required = AuthBrokerCapability.managedKeychain.rawValue
            | AuthBrokerCapability.passwordAutoFill.rawValue
            | AuthBrokerCapability.passwordAutoFillUsername.rawValue
        let connection = try AuthBrokerClientConnection.launchAndConnect(requiredCapabilities: required)
        let request = try AuthBrokerRequester.approvalRequest(
            operation: .passwordAutoFill,
            purpose: purpose.brokerPurpose,
            credentialLabel: account,
            service: service,
            account: account,
            keychainSynchronizable: synchronizable
        )
        let message = AuthBrokerMessage.approvalRequest(request)
        // Complete deterministic validation before entering the region where
        // request delivery followed by response loss is indeterminate.
        _ = try AuthBrokerWire.frame(message)
        let responseMessage: AuthBrokerMessage
        do {
            responseMessage = try connection.send(message, timeout: 600)
        } catch {
            throw PasswordAutoFillFailure.responseLost
        }
        return try PasswordAutoFillResponseClassifier.classify(
            responseMessage,
            requestID: request.requestID,
            expectedUsername: account
        )
    }
}

public struct CompanionManagedKeychainImporter: ManagedKeychainImporting {
    public init() {}

    public func importSecret(
        _ secret: Data,
        service: String,
        account: String,
        synchronizable: Bool
    ) throws {
        try self.importValue(
            secret, service: service, account: account, synchronizable: synchronizable,
            presentation: (.managedKeychainImport, account)
        )
    }

    public func generateSecret(
        _ secret: Data,
        service: String,
        account: String,
        synchronizable: Bool
    ) throws {
        try self.importValue(
            secret, service: service, account: account, synchronizable: synchronizable,
            presentation: (.managedKeychainGenerate, account)
        )
    }

    public func importOTPSeed(
        _ seed: Data, service: String, account: String, synchronizable: Bool
    ) throws {
        try self.importValue(
            seed, service: service, account: account, synchronizable: synchronizable,
            presentation: (.otpImport, ManagedKeychainPresentationLabel.otpSeed)
        )
    }

    public func updateSecret(
        _ secret: Data, service: String, account: String, synchronizable: Bool
    ) throws {
        try self.importValue(
            secret, service: service, account: account, synchronizable: synchronizable,
            operation: .managedKeychainUpdate,
            presentation: (.managedKeychainUpdate, account)
        )
    }

    public func updateOTPSeed(
        _ seed: Data, service: String, account: String, synchronizable: Bool
    ) throws {
        try self.importValue(
            seed, service: service, account: account, synchronizable: synchronizable,
            operation: .managedKeychainUpdate,
            presentation: (.otpUpdate, ManagedKeychainPresentationLabel.otpSeed)
        )
    }

    private func importValue(
        _ secret: Data, service: String, account: String, synchronizable: Bool,
        operation: AuthBrokerOperation = .managedKeychainImport,
        presentation: (purpose: AuthBrokerPurpose, label: String)
    ) throws {
        guard !secret.isEmpty, secret.count <= ManagedKeychainStore.maximumSecretLength else {
            throw CLIError.invalidArguments(message: "Managed Keychain secret must be 1 to 65536 bytes.")
        }
        let connection = try AuthBrokerClientConnection.launchAndConnect(
            requiredCapabilities: AuthBrokerCapability.managedKeychain.rawValue
        )
        let request = try AuthBrokerRequester.approvalRequest(
            operation: operation,
            purpose: presentation.purpose,
            credentialLabel: presentation.label,
            service: service,
            account: account,
            keychainSynchronizable: synchronizable
        )
        guard case let .approvalResponse(approval) = try connection.send(.approvalRequest(request)),
              approval.requestID == request.requestID
        else { throw AuthBrokerFailure(.protocolMismatch).cliError }
        if let failureCategory = approval.status.failureCategory {
            throw AuthBrokerFailure(failureCategory).cliError
        }
        let message = AuthBrokerManagedKeychainImportRequest(
            authorizationID: request.requestID,
            secret: secret
        )
        let brokerMessage = AuthBrokerMessage.managedKeychainImportRequest(message)
        _ = try AuthBrokerWire.frame(brokerMessage)
        let responseMessage: AuthBrokerMessage
        do {
            responseMessage = try connection.send(brokerMessage)
        } catch {
            throw ManagedKeychainMutationFailure.responseLost
        }
        guard case let .managedKeychainImportResponse(response) = responseMessage,
              response.authorizationID == request.requestID
        else { throw ManagedKeychainMutationFailure.responseLost }
        switch response.outcome {
        case .indeterminate:
            throw ManagedKeychainMutationFailure.serverIndeterminate
        case .committed:
            guard response.status == errSecSuccess else {
                throw ManagedKeychainMutationFailure.responseLost
            }
            return
        case .failed:
            break
        }
        switch response.status {
        case errSecSuccess:
            throw ManagedKeychainMutationFailure.responseLost
        case errSecDuplicateItem:
            throw CLIError
                .invalidArguments(message: "Managed Keychain item already exists; import does not overwrite it.")
        case errSecItemNotFound:
            throw CLIError.notFound(message: "Managed Keychain item was not found; update does not create it.")
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
            throw AuthBrokerFailure(.userDenied).cliError
        default:
            throw CLIError.runtimeError(message: "Managed Keychain import failed (OSStatus \(response.status)).")
        }
    }
}
