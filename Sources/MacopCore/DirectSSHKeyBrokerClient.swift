import Foundation

public enum DirectSSHKeyBrokerClientError: Error, Equatable, Sendable {
    case protocolMismatch
    case userDenied
    case notFound
    case duplicate
    case denied
    case unavailable
    case failed
    case indeterminate
    case generationConflict
}

public protocol DirectSSHKeyBrokerProviding: Sendable {
    func list() throws -> [AuthBrokerDirectSSHKeyRecord]
    func identity(label: String) throws -> SSHCommand.VerifiedSessionIdentity
    func migrationCandidateIdentity(label: String) throws -> SSHCommand.VerifiedSessionIdentity
    func identity(matchingPublicKeyBlob expected: Data) throws -> SSHCommand.VerifiedSessionIdentity
    func migrationDocument() throws -> SSHKeyMigrationDocument
    func transition(
        label: String,
        expectedGeneration: UInt64,
        transition: SSHKeyMigrationTransition
    ) throws -> SSHKeyMigrationDocument
    func create(label: String, legacyFingerprint: String) throws -> AuthBrokerDirectSSHKeyRecord
    func delete(_ record: AuthBrokerDirectSSHKeyRecord) throws
}

protocol AuthBrokerMessageSending: AnyObject, Sendable {
    func send(_ message: AuthBrokerMessage, timeout: TimeInterval) throws -> AuthBrokerMessage
}

extension AuthBrokerClientConnection: AuthBrokerMessageSending {}

/// Secret-free client for the MacopAuth-owned direct Secure Enclave key
/// store. The connection owns peer and code-identity verification; this layer
/// binds every response to the request ID and operation before returning it.
public struct DirectSSHKeyBrokerClient: DirectSSHKeyBrokerProviding, Sendable {
    struct Dependencies: Sendable {
        let connect: @Sendable () throws -> any AuthBrokerMessageSending
        let approvalRequest: @Sendable (
            _ operation: AuthBrokerOperation,
            _ purpose: AuthBrokerPurpose,
            _ label: String,
            _ fingerprint: String
        ) throws -> AuthBrokerApprovalRequest

        static let live = Self(
            connect: {
                try AuthBrokerClientConnection.launchAndConnect(
                    requiredCapabilities: AuthBrokerCapability.directSSHKeyManagement.rawValue
                )
            },
            approvalRequest: { operation, purpose, label, fingerprint in
                try AuthBrokerRequester.approvalRequest(
                    operation: operation,
                    purpose: purpose,
                    credentialLabel: label,
                    service: "",
                    account: "",
                    credentialFingerprint: fingerprint,
                    sshKeyBackend: .directSecureEnclaveV1
                )
            }
        )
    }

    private let dependencies: Dependencies

    public init() {
        self.dependencies = .live
    }

    init(dependencies: Dependencies) {
        self.dependencies = dependencies
    }

    public func list() throws -> [AuthBrokerDirectSSHKeyRecord] {
        let connection = try self.dependencies.connect()
        let request = AuthBrokerDirectSSHKeyRequest(
            authorizationID: UUID(),
            operation: .list
        )
        return try self.send(request, over: connection)
    }

    public func identity(label: String) throws -> SSHCommand.VerifiedSessionIdentity {
        try SSHIdentityLabelValidator.validate(label)
        let document = try self.migrationDocument()
        guard let selected = document.entries.first(where: { $0.label == label }),
              selected.selectedBackend == .directSecureEnclaveV1
        else { throw DirectSSHKeyBrokerClientError.notFound }
        return try self.identity(for: selected)
    }

    /// Resolves the exact protected direct key only while it is registered
    /// externally but has not become the default backend. This is the narrow
    /// pre-activation proof path used by `ssh test --migration-candidate`.
    public func migrationCandidateIdentity(label: String) throws -> SSHCommand.VerifiedSessionIdentity {
        try SSHIdentityLabelValidator.validate(label)
        let document = try self.migrationDocument()
        guard let selected = document.entries.first(where: { $0.label == label }),
              selected.phase == .externallyRegistered
        else { throw DirectSSHKeyBrokerClientError.notFound }
        return try self.identity(for: selected)
    }

    private func identity(for selected: SSHKeyMigrationEntry) throws -> SSHCommand.VerifiedSessionIdentity {
        let matches = try self.list().filter {
            $0.id == selected.directKeyID
                && $0.label == selected.label
                && constantTimeEqual($0.publicKeyBlob, selected.directPublicKeyBlob)
        }
        guard matches.count == 1, let record = matches.first else {
            throw matches.isEmpty ? DirectSSHKeyBrokerClientError.notFound : .unavailable
        }
        return SSHCommand.VerifiedSessionIdentity(
            fingerprint: sshFingerprint(for: record.publicKeyBlob),
            label: record.label,
            publicKeyBlob: record.publicKeyBlob,
            backend: .directSecureEnclaveV1
        )
    }

    public func identity(matchingPublicKeyBlob expected: Data) throws -> SSHCommand.VerifiedSessionIdentity {
        let document = try self.migrationDocument()
        let selectedEntries = document.entries.filter {
            $0.selectedBackend == .directSecureEnclaveV1
                && constantTimeEqual($0.directPublicKeyBlob, expected)
        }
        guard selectedEntries.count == 1, let selected = selectedEntries.first else {
            throw selectedEntries.isEmpty ? DirectSSHKeyBrokerClientError.notFound : .unavailable
        }
        let matches = try self.list().filter {
            $0.id == selected.directKeyID
                && $0.label == selected.label
                && constantTimeEqual($0.publicKeyBlob, selected.directPublicKeyBlob)
        }
        guard matches.count == 1, let record = matches.first else {
            throw matches.isEmpty ? DirectSSHKeyBrokerClientError.notFound : .unavailable
        }
        return SSHCommand.VerifiedSessionIdentity(
            fingerprint: sshFingerprint(for: record.publicKeyBlob),
            label: record.label,
            publicKeyBlob: record.publicKeyBlob,
            backend: .directSecureEnclaveV1
        )
    }

    public func migrationDocument() throws -> SSHKeyMigrationDocument {
        let connection = try self.dependencies.connect()
        let request = AuthBrokerSSHMigrationRequest(requestID: UUID(), action: .list)
        return try self.sendMigration(request, over: connection)
    }

    public func transition(
        label: String,
        expectedGeneration: UInt64,
        transition: SSHKeyMigrationTransition
    ) throws -> SSHKeyMigrationDocument {
        try SSHIdentityLabelValidator.validate(label)
        let current = try self.migrationDocument()
        guard current.generation == expectedGeneration,
              let entry = current.entries.first(where: { $0.label == label })
        else { throw DirectSSHKeyBrokerClientError.generationConflict }
        let connection = try self.dependencies.connect()
        let purpose = Self.purpose(for: transition)
        let approval = try self.dependencies.approvalRequest(
            .sshMigrationTransition,
            purpose,
            label,
            entry.directFingerprint
        )
        try self.approve(approval, over: connection)
        return try self.sendMigration(AuthBrokerSSHMigrationRequest(
            requestID: approval.requestID,
            action: .transition,
            label: label,
            expectedGeneration: expectedGeneration,
            transition: transition
        ), over: connection)
    }

    public func create(label: String, legacyFingerprint: String) throws -> AuthBrokerDirectSSHKeyRecord {
        try SSHIdentityLabelValidator.validate(label)
        guard !legacyFingerprint.isEmpty else { throw DirectSSHKeyBrokerClientError.protocolMismatch }
        let current = try self.migrationDocument()
        guard current.entries.allSatisfy({ $0.label != label }) else {
            throw DirectSSHKeyBrokerClientError.duplicate
        }
        let connection = try self.dependencies.connect()
        let approval = try self.dependencies.approvalRequest(
            .directSSHKeyCreate,
            .directSSHKeyCreate,
            label,
            legacyFingerprint
        )
        try self.approve(approval, over: connection)
        let records = try self.send(AuthBrokerDirectSSHKeyRequest(
            authorizationID: approval.requestID,
            operation: .create,
            label: label,
            expectedGeneration: current.generation,
            legacyFingerprint: legacyFingerprint
        ), over: connection)
        guard records.count == 1, let record = records.first else {
            throw DirectSSHKeyBrokerClientError.protocolMismatch
        }
        return record
    }

    public func delete(_ record: AuthBrokerDirectSSHKeyRecord) throws {
        try SSHIdentityLabelValidator.validate(record.label)
        guard !record.publicKeyBlob.isEmpty else { throw DirectSSHKeyBrokerClientError.protocolMismatch }
        let connection = try self.dependencies.connect()
        let approval = try self.dependencies.approvalRequest(
            .directSSHKeyDelete,
            .directSSHKeyDelete,
            record.label,
            sshFingerprint(for: record.publicKeyBlob)
        )
        try self.approve(approval, over: connection)
        let records = try self.send(AuthBrokerDirectSSHKeyRequest(
            authorizationID: approval.requestID,
            operation: .delete,
            id: record.id,
            label: record.label,
            expectedPublicKeyBlob: record.publicKeyBlob
        ), over: connection)
        guard records.isEmpty else { throw DirectSSHKeyBrokerClientError.protocolMismatch }
    }

    private func approve(
        _ request: AuthBrokerApprovalRequest,
        over connection: any AuthBrokerMessageSending
    ) throws {
        guard case let .approvalResponse(response) = try connection.send(.approvalRequest(request), timeout: 120),
              response.requestID == request.requestID
        else { throw DirectSSHKeyBrokerClientError.protocolMismatch }
        guard response.status == .approved else { throw DirectSSHKeyBrokerClientError.userDenied }
        guard response.resultStatus == 0, response.resultData.isEmpty else {
            throw DirectSSHKeyBrokerClientError.protocolMismatch
        }
    }

    private func send(
        _ request: AuthBrokerDirectSSHKeyRequest,
        over connection: any AuthBrokerMessageSending
    ) throws -> [AuthBrokerDirectSSHKeyRecord] {
        guard case let .directSSHKeyResponse(response) = try connection.send(
            .directSSHKeyRequest(request),
            timeout: 120
        ), response.authorizationID == request.authorizationID,
        response.operation == request.operation
        else { throw DirectSSHKeyBrokerClientError.protocolMismatch }
        guard response.status == .success else { throw Self.error(for: response.status) }
        return response.records
    }

    private static func error(for status: AuthBrokerDirectSSHKeyStatus) -> DirectSSHKeyBrokerClientError {
        switch status {
        case .success: .protocolMismatch
        case .notFound: .notFound
        case .duplicate: .duplicate
        case .denied: .denied
        case .unavailable: .unavailable
        case .failed: .failed
        case .indeterminate: .indeterminate
        case .generationConflict: .generationConflict
        }
    }

    private func sendMigration(
        _ request: AuthBrokerSSHMigrationRequest,
        over connection: any AuthBrokerMessageSending
    ) throws -> SSHKeyMigrationDocument {
        guard case let .sshMigrationResponse(response) = try connection.send(
            .sshMigrationRequest(request),
            timeout: 120
        ), response.requestID == request.requestID,
        response.action == request.action
        else { throw DirectSSHKeyBrokerClientError.protocolMismatch }
        guard response.status == .success else {
            throw Self.error(for: response.status)
        }
        return try SSHKeyMigrationDocument(generation: response.generation, entries: response.entries)
    }

    private static func error(for status: AuthBrokerSSHMigrationStatus) -> DirectSSHKeyBrokerClientError {
        switch status {
        case .success: .protocolMismatch
        case .notFound: .notFound
        case .generationConflict: .generationConflict
        case .denied: .denied
        case .unavailable: .unavailable
        case .failed: .failed
        }
    }

    private static func purpose(for transition: SSHKeyMigrationTransition) -> AuthBrokerPurpose {
        switch transition {
        case .confirmExternalRegistration: .sshMigrationConfirmExternal
        case .activateDirectBackend: .sshMigrationActivate
        case .beginLegacyRetirement: .sshMigrationBeginRetirement
        case .confirmLegacyRetired: .sshMigrationConfirmRetired
        case .returnToPreparation, .returnToExternalRegistration, .returnToActive:
            .sshMigrationRollback
        case .confirmDirectKeyDeleted: .sshMigrationDeletePrepared
        }
    }
}
