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

final class RecordingPurposeClient: KeychainClient, ManagedKeychainReadPresentationBinding, @unchecked Sendable {
    private(set) var presentations = [ManagedKeychainReadPresentation]()
    private(set) var queries = [KeychainQuery]()
    let response: Result<Data, KeychainFailure>

    init(_ response: Result<Data, KeychainFailure>) {
        self.response = response
    }

    func binding(_ presentation: ManagedKeychainReadPresentation) -> any KeychainClient {
        self.presentations.append(presentation)
        return self
    }

    func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        self.queries.append(query)
        return self.response
    }
}

final class RecordingKeychainSecurityAccess: KeychainSecurityAccess, @unchecked Sendable {
    var referenceResponses: [KeychainSecurityResult]
    var valueResponses: [KeychainSecurityResult]
    var addResponses: [KeychainSecurityResult]
    var deleteResponses: [OSStatus]
    private(set) var queries = [KeychainQuery]()
    private(set) var referenceContexts = [LAContext]()
    private(set) var valueContexts = [LAContext]()
    private(set) var addedAttributes = [[CFString: Any]]()
    private(set) var addedContexts = [LAContext]()
    private(set) var deletedReferences = [Data]()
    private(set) var deletedContexts = [LAContext]()

    init(
        referenceResponses: [KeychainSecurityResult],
        valueResponses: [KeychainSecurityResult] = [],
        addResponses: [KeychainSecurityResult] = [],
        deleteResponses: [OSStatus] = []
    ) {
        self.referenceResponses = referenceResponses
        self.valueResponses = valueResponses
        self.addResponses = addResponses
        self.deleteResponses = deleteResponses
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

    func add(
        attributes: [CFString: Any],
        authenticationContext: LAContext
    ) -> KeychainSecurityResult {
        self.addedAttributes.append(attributes)
        self.addedContexts.append(authenticationContext)
        return self.addResponses.removeFirst()
    }

    func delete(
        persistentReference: Data,
        authenticationContext: LAContext
    ) -> OSStatus {
        self.deletedReferences.append(persistentReference)
        self.deletedContexts.append(authenticationContext)
        return self.deleteResponses.removeFirst()
    }
}

final class FaultingManagedKeychainStoreAccess: ManagedKeychainStoreAccess, @unchecked Sendable {
    let addStatus: OSStatus
    let updateStatus: OSStatus
    let readResult: Result<Data, KeychainFailure>
    private(set) var addCount = 0
    private(set) var updateCount = 0
    private(set) var readCount = 0

    init(
        addStatus: OSStatus = errSecSuccess,
        updateStatus: OSStatus = errSecSuccess,
        readResult: Result<Data, KeychainFailure>
    ) {
        self.addStatus = addStatus
        self.updateStatus = updateStatus
        self.readResult = readResult
    }

    func read(
        service _: String, account _: String, synchronizable _: Bool,
        authenticationContext _: LAContext
    ) -> Result<Data, KeychainFailure> {
        self.readCount += 1
        return self.readResult
    }

    func add(
        _: Data, service _: String, account _: String, synchronizable _: Bool,
        authenticationContext _: LAContext
    ) -> OSStatus {
        self.addCount += 1
        return self.addStatus
    }

    func update(
        _: Data, service _: String, account _: String, synchronizable _: Bool,
        authenticationContext _: LAContext
    ) -> OSStatus {
        self.updateCount += 1
        return self.updateStatus
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
    private(set) var imports = [(secret: Data, service: String, account: String, synchronizable: Bool)]()
    private(set) var generatedImports = [(secret: Data, service: String, account: String, synchronizable: Bool)]()
    private(set) var updates = [(secret: Data, service: String, account: String, synchronizable: Bool)]()
    private let importFailure: (any Error)?
    private let updateFailure: (any Error)?

    init(importFailure: (any Error)? = nil, updateFailure: (any Error)? = nil) {
        self.importFailure = importFailure
        self.updateFailure = updateFailure
    }

    func importSecret(_ secret: Data, service: String, account: String, synchronizable: Bool) throws {
        self.imports.append((secret, service, account, synchronizable))
        if let importFailure {
            throw importFailure
        }
    }

    func generateSecret(_ secret: Data, service: String, account: String, synchronizable: Bool) throws {
        self.generatedImports.append((secret, service, account, synchronizable))
        if let importFailure {
            throw importFailure
        }
    }

    func updateSecret(_ secret: Data, service: String, account: String, synchronizable: Bool) throws {
        self.updates.append((secret, service, account, synchronizable))
        if let updateFailure {
            throw updateFailure
        }
    }
}

final class RecordingManagedKeychainDeleter: ManagedKeychainDeleting, @unchecked Sendable {
    private(set) var deletes = [(
        service: String, account: String, synchronizable: Bool, purpose: ManagedKeychainDeletePurpose
    )]()
    private(set) var deleteAllCount = 0
    private var deleteFailures: [(any Error)?]
    private let deleteAllFailure: (any Error)?

    init(deleteFailures: [(any Error)?] = [], deleteAllFailure: (any Error)? = nil) {
        self.deleteFailures = deleteFailures
        self.deleteAllFailure = deleteAllFailure
    }

    func delete(
        service: String, account: String, synchronizable: Bool,
        purpose: ManagedKeychainDeletePurpose
    ) throws {
        self.deletes.append((service, account, synchronizable, purpose))
        if !self.deleteFailures.isEmpty, let failure = self.deleteFailures.removeFirst() {
            throw failure
        }
    }

    func deleteAll() throws {
        self.deleteAllCount += 1
        if let deleteAllFailure {
            throw deleteAllFailure
        }
    }
}

struct FixtureTransportFailure: Error {}

final class RecordingKeychainMutator: KeychainMutating, @unchecked Sendable {
    private(set) var creates = [(secret: Data, query: KeychainQuery)]()
    private(set) var edits = [(secret: Data, query: KeychainQuery)]()
    private(set) var deletes = [KeychainQuery]()
    private let deleteFailure: CLIError?

    init(deleteFailure: CLIError? = nil) {
        self.deleteFailure = deleteFailure
    }

    func create(_ secret: Data, query: KeychainQuery) throws {
        self.creates.append((secret, query))
    }

    func edit(_ secret: Data, query: KeychainQuery) throws {
        self.edits.append((secret, query))
    }

    func delete(query: KeychainQuery) throws {
        self.deletes.append(query)
        if let deleteFailure {
            throw deleteFailure
        }
    }
}

final class RecordingPasswordAutoFillProvider: PasswordAutoFillProviding, @unchecked Sendable {
    private(set) var requests = [(
        service: String, account: String, synchronizable: Bool, purpose: PasswordAutoFillPurpose
    )]()
    let secret: Data
    let saveStatus: PasswordAutoFillSaveStatus
    let saveResultStatus: OSStatus

    init(
        secret: Data = Data("passwords-secret".utf8),
        saveStatus: PasswordAutoFillSaveStatus = .saved,
        saveResultStatus: OSStatus = errSecSuccess
    ) {
        self.secret = secret
        self.saveStatus = saveStatus
        self.saveResultStatus = saveResultStatus
    }

    func acquire(
        service: String,
        account: String,
        synchronizable: Bool,
        purpose: PasswordAutoFillPurpose
    ) throws -> PasswordAutoFillCredential {
        self.requests.append((service, account, synchronizable, purpose))
        return PasswordAutoFillCredential(
            username: account,
            secret: self.secret,
            saveStatus: self.saveStatus,
            saveResultStatus: self.saveResultStatus
        )
    }
}

struct DenyingPasswordAutoFillProvider: PasswordAutoFillProviding {
    func acquire(
        service _: String,
        account _: String,
        synchronizable _: Bool,
        purpose _: PasswordAutoFillPurpose
    ) throws -> PasswordAutoFillCredential {
        throw CLIError.denied(message: "Password AutoFill was denied for this fixture.")
    }
}

struct FailingPasswordAutoFillProvider: PasswordAutoFillProviding {
    let failure: PasswordAutoFillFailure

    func acquire(
        service _: String,
        account _: String,
        synchronizable _: Bool,
        purpose _: PasswordAutoFillPurpose
    ) throws -> PasswordAutoFillCredential {
        throw self.failure
    }
}

struct ClassifyingPasswordAutoFillProvider: PasswordAutoFillProviding {
    let secret: Data

    func acquire(
        service _: String,
        account: String,
        synchronizable _: Bool,
        purpose _: PasswordAutoFillPurpose
    ) throws -> PasswordAutoFillCredential {
        let requestID = UUID()
        return try PasswordAutoFillResponseClassifier.classify(
            .approvalResponse(AuthBrokerApprovalResponse(
                requestID: requestID,
                status: .approved,
                message: "not_requested",
                resultStatus: errSecSuccess,
                resultData: self.secret,
                verifiedUsername: account
            )),
            requestID: requestID,
            expectedUsername: account
        )
    }
}
