import Foundation
@testable import MacopCore
import XCTest

final class SSHBackendSelectionTests: XCTestCase {
    func testActiveMigrationSelectsDirectIdentityWithoutConsultingCTK() throws {
        let fixture = try SelectionFixture(phase: .active)
        let selected = try SSHCommand.verifiedSessionIdentity(
            label: fixture.entry.label,
            executor: RejectingCommandExecutor(),
            directSSHKeys: fixture.broker
        )

        XCTAssertEqual(selected.backend, .directSecureEnclaveV1)
        XCTAssertEqual(selected.publicKeyBlob, fixture.entry.directPublicKeyBlob)
    }

    func testActiveMigrationRejectsConfiguredLegacyGitKey() throws {
        let legacyBlob = Data([9, 8, 7])
        let fixture = try SelectionFixture(
            phase: .active,
            legacyFingerprint: sshFingerprint(for: legacyBlob)
        )

        XCTAssertThrowsError(try SSHCommand.verifiedSessionIdentity(
            matchingPublicKeyBlob: legacyBlob,
            executor: RejectingCommandExecutor(),
            directSSHKeys: fixture.broker
        )) { error in
            guard case CLIError.denied = error else {
                return XCTFail("expected a fail-closed backend rejection, got \(error)")
            }
        }
    }

    func testDirectGitKeyMustMatchProtectedIDAndBlob() throws {
        let fixture = try SelectionFixture(phase: .retired)
        let selected = try SSHCommand.verifiedSessionIdentity(
            matchingPublicKeyBlob: fixture.entry.directPublicKeyBlob,
            executor: RejectingCommandExecutor(),
            directSSHKeys: fixture.broker
        )

        XCTAssertEqual(selected.backend, .directSecureEnclaveV1)
        XCTAssertEqual(selected.label, fixture.entry.label)
    }

    func testExternallyRegisteredMigrationCandidateSelectsDirectIdentity() throws {
        let fixture = try SelectionFixture(phase: .externallyRegistered)
        let selected = try SSHCommand.verifiedSessionIdentity(
            label: fixture.entry.label,
            executor: RejectingCommandExecutor(),
            directSSHKeys: fixture.broker,
            selection: .externallyRegisteredMigrationCandidate
        )

        XCTAssertEqual(selected.backend, .directSecureEnclaveV1)
        XCTAssertEqual(selected.publicKeyBlob, fixture.entry.directPublicKeyBlob)
    }

    func testPreparedKeyCannotBeUsedAsMigrationCandidate() throws {
        let fixture = try SelectionFixture(phase: .prepared)

        XCTAssertThrowsError(try SSHCommand.verifiedSessionIdentity(
            label: fixture.entry.label,
            executor: RejectingCommandExecutor(),
            directSSHKeys: fixture.broker,
            selection: .externallyRegisteredMigrationCandidate
        )) { error in
            XCTAssertEqual(error as? DirectSSHKeyBrokerClientError, .notFound)
        }
    }
}

private struct SelectionFixture {
    let entry: SSHKeyMigrationEntry
    let broker: SelectionBroker

    init(
        phase: SSHKeyMigrationPhase,
        legacyFingerprint: String = "SHA256:legacy"
    ) throws {
        let entry = try SSHKeyMigrationEntry(
            label: "github",
            legacyFingerprint: legacyFingerprint,
            directKeyID: XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased())),
            directPublicKeyBlob: Data([1, 2, 3]),
            phase: phase
        )
        self.entry = entry
        self.broker = try SelectionBroker(entry: entry)
    }
}

private struct SelectionBroker: DirectSSHKeyBrokerProviding {
    let entry: SSHKeyMigrationEntry
    let document: SSHKeyMigrationDocument

    init(entry: SSHKeyMigrationEntry) throws {
        self.entry = entry
        self.document = try SSHKeyMigrationDocument(generation: 4, entries: [entry])
    }

    func list() throws -> [AuthBrokerDirectSSHKeyRecord] {
        [AuthBrokerDirectSSHKeyRecord(
            id: self.entry.directKeyID,
            label: self.entry.label,
            publicKeyBlob: self.entry.directPublicKeyBlob
        )]
    }

    func identity(label: String) throws -> SSHCommand.VerifiedSessionIdentity {
        guard label == self.entry.label else { throw DirectSSHKeyBrokerClientError.notFound }
        return self.directIdentity
    }

    func migrationCandidateIdentity(label: String) throws -> SSHCommand.VerifiedSessionIdentity {
        guard label == self.entry.label, self.entry.phase == .externallyRegistered else {
            throw DirectSSHKeyBrokerClientError.notFound
        }
        return self.directIdentity
    }

    func identity(matchingPublicKeyBlob expected: Data) throws -> SSHCommand.VerifiedSessionIdentity {
        guard constantTimeEqual(expected, self.entry.directPublicKeyBlob) else {
            throw DirectSSHKeyBrokerClientError.notFound
        }
        return self.directIdentity
    }

    func migrationDocument() throws -> SSHKeyMigrationDocument {
        self.document
    }

    func transition(
        label _: String,
        expectedGeneration _: UInt64,
        transition _: SSHKeyMigrationTransition
    ) throws -> SSHKeyMigrationDocument {
        throw DirectSSHKeyBrokerClientError.denied
    }

    func create(label _: String, legacyFingerprint _: String) throws -> AuthBrokerDirectSSHKeyRecord {
        throw DirectSSHKeyBrokerClientError.denied
    }

    func delete(_: AuthBrokerDirectSSHKeyRecord) throws {
        throw DirectSSHKeyBrokerClientError.denied
    }

    private var directIdentity: SSHCommand.VerifiedSessionIdentity {
        SSHCommand.VerifiedSessionIdentity(
            fingerprint: self.entry.directFingerprint,
            label: self.entry.label,
            publicKeyBlob: self.entry.directPublicKeyBlob,
            backend: .directSecureEnclaveV1
        )
    }
}

private struct RejectingCommandExecutor: CommandExecuting {
    func execute(path _: String, arguments _: [String], environment _: CommandEnvironment) throws -> CommandResult {
        throw AgentProtocolError.denied
    }
}
