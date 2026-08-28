import Foundation
import LocalAuthentication
import MacopCore
import Security

@inline(__always)
func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() {
        throw SelftestFailure(message: message)
    }
}

struct FakeKeychainClient: KeychainClient {
    let response: Result<Data, KeychainFailure>

    func read(_: KeychainQuery) -> Result<Data, KeychainFailure> {
        self.response
    }
}

final class RecordingKeychainClient: KeychainClient, @unchecked Sendable {
    var queries: [KeychainQuery] = []
    let response: Result<Data, KeychainFailure>

    init(_ response: Result<Data, KeychainFailure>) {
        self.response = response
    }

    func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        self.queries.append(query)
        return self.response
    }
}

final class RecordingKeychainSecurityAccess: KeychainSecurityAccess, @unchecked Sendable {
    var referenceResponses: [KeychainSecurityResult]
    var valueResponses: [KeychainSecurityResult]
    private(set) var queries = [KeychainQuery]()
    private(set) var referenceContexts = [LAContext]()
    private(set) var valueContexts = [LAContext]()

    init(
        referenceResponses: [KeychainSecurityResult],
        valueResponses: [KeychainSecurityResult] = []
    ) {
        self.referenceResponses = referenceResponses
        self.valueResponses = valueResponses
    }

    func persistentReferences(
        for query: KeychainQuery,
        authenticationContext: LAContext
    ) -> KeychainSecurityResult {
        self.queries.append(query)
        self.referenceContexts.append(authenticationContext)
        return self.referenceResponses.removeFirst()
    }

    func value(
        for _: Data,
        authenticationContext: LAContext
    ) -> KeychainSecurityResult {
        self.valueContexts.append(authenticationContext)
        return self.valueResponses.removeFirst()
    }
}

final class QuerySensitiveKeychainClient: KeychainClient, @unchecked Sendable {
    var queries = [KeychainQuery]()

    func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        self.queries.append(query)
        switch query {
        case .generic(service: "service", account: "account"):
            return .success(Data("keychain://generic/other/account".utf8))
        default:
            return .success(Data("unexpected-second-resolution".utf8))
        }
    }
}

final class RecordingManagedKeychainImporter: ManagedKeychainImporting, @unchecked Sendable {
    private(set) var imports = [(secret: Data, service: String, account: String)]()

    func importSecret(_ secret: Data, service: String, account: String) throws {
        self.imports.append((secret, service, account))
    }
}

final class RecordingManagedKeychainDeleter: ManagedKeychainDeleting, @unchecked Sendable {
    private(set) var deletes = [(service: String, account: String)]()
    private(set) var deleteAllCount = 0

    func delete(service: String, account: String) throws {
        self.deletes.append((service, account))
    }

    func deleteAll() throws {
        self.deleteAllCount += 1
    }
}

final class RecordingPasswordAutoFillProvider: PasswordAutoFillProviding, @unchecked Sendable {
    private(set) var requests = [(service: String, account: String, command: String)]()
    let credential: PasswordAutoFillCredential

    init(
        secret: Data = Data("passwords-secret".utf8),
        saveStatus: PasswordAutoFillSaveStatus = .saved
    ) {
        self.credential = PasswordAutoFillCredential(secret: secret, saveStatus: saveStatus)
    }

    func acquire(service: String, account: String, command: String) throws -> PasswordAutoFillCredential {
        self.requests.append((service, account, command))
        return self.credential
    }
}

struct DenyingPasswordAutoFillProvider: PasswordAutoFillProviding {
    func acquire(service _: String, account _: String, command _: String) throws -> PasswordAutoFillCredential {
        throw CLIError.denied(message: "Password AutoFill was denied for this fixture.")
    }
}
