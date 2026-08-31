import Foundation
@testable import MacopCore
import XCTest

final class DirectSSHKeyBrokerClientTests: XCTestCase {
    func testCreateBindsApprovedIDAndReturnsExactRecord() throws {
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased()))
        let record = AuthBrokerDirectSSHKeyRecord(id: id, label: "github", publicKeyBlob: Data([1, 2]))
        let listSender = StubSender { messages in
            guard case let .sshMigrationRequest(request) = messages[0] else {
                throw DirectSSHKeyBrokerClientError.protocolMismatch
            }
            return .sshMigrationResponse(AuthBrokerSSHMigrationResponse(
                requestID: request.requestID,
                action: .list,
                status: .success,
                generation: 2
            ))
        }
        let createSender = StubSender { messages in
            guard messages.count == 2,
                  case .approvalRequest = messages[0],
                  case let .directSSHKeyRequest(request) = messages[1]
            else { throw DirectSSHKeyBrokerClientError.protocolMismatch }
            return .directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
                authorizationID: request.authorizationID,
                operation: .create,
                status: .success,
                records: [record]
            ))
        }
        let requestID = UUID()
        createSender.firstResponse = .approvalResponse(AuthBrokerApprovalResponse(
            requestID: requestID,
            status: .approved
        ))
        let senders = StubSenderQueue([listSender, createSender])
        let client = DirectSSHKeyBrokerClient(dependencies: .init(
            connect: { try senders.next() },
            approvalRequest: { operation, purpose, label, fingerprint in
                XCTAssertEqual(operation, .directSSHKeyCreate)
                XCTAssertEqual(purpose, .directSSHKeyCreate)
                XCTAssertEqual(label, "github")
                XCTAssertEqual(fingerprint, "SHA256:legacy")
                return Self.approvalRequest(
                    requestID: requestID,
                    operation: operation,
                    purpose: purpose,
                    label: label,
                    fingerprint: fingerprint
                )
            }
        ))

        XCTAssertEqual(
            try client.create(label: "github", legacyFingerprint: "SHA256:legacy"),
            record
        )
        guard case let .directSSHKeyRequest(request) = createSender.messages[1] else {
            return XCTFail("missing direct key request")
        }
        XCTAssertEqual(request.authorizationID, requestID)
        XCTAssertEqual(request.operation, .create)
        XCTAssertEqual(request.label, "github")
        XCTAssertEqual(request.expectedGeneration, 2)
        XCTAssertEqual(request.legacyFingerprint, "SHA256:legacy")
    }

    func testDeleteCarriesImmutableIDAndExpectedPublicKey() throws {
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased()))
        let record = AuthBrokerDirectSSHKeyRecord(id: id, label: "github", publicKeyBlob: Data([3, 4]))
        let requestID = UUID()
        let sender = StubSender { messages in
            guard case let .directSSHKeyRequest(request) = messages[1] else {
                throw DirectSSHKeyBrokerClientError.protocolMismatch
            }
            return .directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
                authorizationID: request.authorizationID,
                operation: .delete,
                status: .success
            ))
        }
        sender.firstResponse = .approvalResponse(AuthBrokerApprovalResponse(
            requestID: requestID,
            status: .approved
        ))

        try self.client(sender: sender, requestID: requestID).delete(record)
        guard case let .directSSHKeyRequest(request) = sender.messages[1] else {
            return XCTFail("missing direct key request")
        }
        XCTAssertEqual(request.id, id)
        XCTAssertEqual(request.expectedPublicKeyBlob, record.publicKeyBlob)
    }

    func testRejectsMismatchedResponseIdentity() throws {
        let sender = StubSender { _ in
            .directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
                authorizationID: UUID(),
                operation: .list,
                status: .success
            ))
        }
        let client = self.client(sender: sender, requestID: UUID())
        XCTAssertThrowsError(try client.list()) { error in
            XCTAssertEqual(error as? DirectSSHKeyBrokerClientError, .protocolMismatch)
        }
    }

    func testMigrationTransitionUsesFreshProtectedGenerationAndFingerprint() throws {
        let requestID = UUID()
        let entry = try SSHKeyMigrationEntry(
            label: "github",
            legacyFingerprint: "SHA256:legacy",
            directKeyID: XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased())),
            directPublicKeyBlob: Data([7, 8]),
            phase: .externallyRegistered
        )
        let listSender = StubSender { messages in
            guard case let .sshMigrationRequest(request) = messages[0] else {
                throw DirectSSHKeyBrokerClientError.protocolMismatch
            }
            return .sshMigrationResponse(AuthBrokerSSHMigrationResponse(
                requestID: request.requestID,
                action: .list,
                status: .success,
                generation: 2,
                entries: [entry]
            ))
        }
        let transitionSender = StubSender { messages in
            guard case let .sshMigrationRequest(request) = messages[1] else {
                throw DirectSSHKeyBrokerClientError.protocolMismatch
            }
            let active = try XCTUnwrap(entry.applying(.activateDirectBackend))
            return .sshMigrationResponse(AuthBrokerSSHMigrationResponse(
                requestID: request.requestID,
                action: .transition,
                status: .success,
                generation: 3,
                entries: [active]
            ))
        }
        transitionSender.firstResponse = .approvalResponse(AuthBrokerApprovalResponse(
            requestID: requestID,
            status: .approved
        ))
        let senders = StubSenderQueue([listSender, transitionSender])
        let client = DirectSSHKeyBrokerClient(dependencies: .init(
            connect: { try senders.next() },
            approvalRequest: { operation, purpose, label, fingerprint in
                XCTAssertEqual(operation, .sshMigrationTransition)
                XCTAssertEqual(purpose, .sshMigrationActivate)
                XCTAssertEqual(fingerprint, entry.directFingerprint)
                return AuthBrokerApprovalRequest(
                    requestID: requestID,
                    issuedAtMilliseconds: 1,
                    expiresAtMilliseconds: 2,
                    operation: operation,
                    rootPID: 1,
                    rootStartTime: 1,
                    rootIdentifier: "macop",
                    rootCodeRequirement: "requirement",
                    rootExecutablePath: "/macop",
                    presentation: .requesterOnly,
                    purpose: purpose,
                    credentialLabel: label,
                    credentialFingerprint: fingerprint,
                    host: "",
                    sshKeyBackend: .directSecureEnclaveV1
                )
            }
        ))

        let document = try client.transition(
            label: "github",
            expectedGeneration: 2,
            transition: .activateDirectBackend
        )
        XCTAssertEqual(document.generation, 3)
        XCTAssertEqual(document.entries.first?.phase, .active)
    }

    private func client(sender: StubSender, requestID: UUID) -> DirectSSHKeyBrokerClient {
        DirectSSHKeyBrokerClient(dependencies: .init(
            connect: { sender },
            approvalRequest: { operation, purpose, label, fingerprint in
                Self.approvalRequest(
                    requestID: requestID,
                    operation: operation,
                    purpose: purpose,
                    label: label,
                    fingerprint: fingerprint
                )
            }
        ))
    }

    private static func approvalRequest(
        requestID: UUID,
        operation: AuthBrokerOperation,
        purpose: AuthBrokerPurpose,
        label: String,
        fingerprint: String
    ) -> AuthBrokerApprovalRequest {
        AuthBrokerApprovalRequest(
            requestID: requestID,
            issuedAtMilliseconds: 1,
            expiresAtMilliseconds: 2,
            operation: operation,
            rootPID: 1,
            rootStartTime: 1,
            rootIdentifier: "macop",
            rootCodeRequirement: "requirement",
            rootExecutablePath: "/macop",
            presentation: .requesterOnly,
            purpose: purpose,
            credentialLabel: label,
            credentialFingerprint: fingerprint,
            host: "",
            sshKeyBackend: .directSecureEnclaveV1
        )
    }
}

final class MigrationCandidateClientTests: XCTestCase {
    func testIdentityIsBoundToExternallyRegisteredRecord() throws {
        let entry = try SSHKeyMigrationEntry(
            label: "github",
            legacyFingerprint: "SHA256:legacy",
            directKeyID: XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased())),
            directPublicKeyBlob: Data([4, 5, 6]),
            phase: .externallyRegistered
        )
        let migrationSender = StubSender { messages in
            guard case let .sshMigrationRequest(request) = messages[0] else {
                throw DirectSSHKeyBrokerClientError.protocolMismatch
            }
            return .sshMigrationResponse(AuthBrokerSSHMigrationResponse(
                requestID: request.requestID,
                action: .list,
                status: .success,
                generation: 3,
                entries: [entry]
            ))
        }
        let listSender = StubSender { messages in
            guard case let .directSSHKeyRequest(request) = messages[0] else {
                throw DirectSSHKeyBrokerClientError.protocolMismatch
            }
            return .directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
                authorizationID: request.authorizationID,
                operation: .list,
                status: .success,
                records: [AuthBrokerDirectSSHKeyRecord(
                    id: entry.directKeyID,
                    label: entry.label,
                    publicKeyBlob: entry.directPublicKeyBlob
                )]
            ))
        }
        let senders = StubSenderQueue([migrationSender, listSender])
        let client = DirectSSHKeyBrokerClient(dependencies: .init(
            connect: { try senders.next() },
            approvalRequest: { _, _, _, _ in
                throw DirectSSHKeyBrokerClientError.denied
            }
        ))

        let identity = try client.migrationCandidateIdentity(label: "github")

        XCTAssertEqual(identity.backend, .directSecureEnclaveV1)
        XCTAssertEqual(identity.publicKeyBlob, entry.directPublicKeyBlob)
        XCTAssertEqual(identity.fingerprint, entry.directFingerprint)
    }
}

private final class StubSenderQueue: @unchecked Sendable {
    private let lock = NSLock()
    private var senders: [StubSender]

    init(_ senders: [StubSender]) {
        self.senders = senders
    }

    func next() throws -> StubSender {
        self.lock.lock(); defer { self.lock.unlock() }
        guard !self.senders.isEmpty else { throw DirectSSHKeyBrokerClientError.protocolMismatch }
        return self.senders.removeFirst()
    }
}

private final class StubSender: AuthBrokerMessageSending, @unchecked Sendable {
    var firstResponse: AuthBrokerMessage?
    private let finalResponse: ([AuthBrokerMessage]) throws -> AuthBrokerMessage
    private(set) var messages: [AuthBrokerMessage] = []

    init(finalResponse: @escaping ([AuthBrokerMessage]) throws -> AuthBrokerMessage) {
        self.finalResponse = finalResponse
    }

    func send(_ message: AuthBrokerMessage, timeout _: TimeInterval) throws -> AuthBrokerMessage {
        self.messages.append(message)
        if self.messages.count == 1, let firstResponse {
            return firstResponse
        }
        return try self.finalResponse(self.messages)
    }
}
