import Foundation
@testable import MacopCore
import Security
import XCTest

final class SSHKeyMigrationStateTests: XCTestCase {
    func testDirectSigningBecomesAvailableForCandidateWithoutSelectingIt() throws {
        let prepared = try self.entry(phase: .prepared)
        let registered = try self.entry(phase: .externallyRegistered)

        XCTAssertFalse(prepared.permitsDirectSigning)
        XCTAssertEqual(prepared.selectedBackend, .legacyCTK)
        XCTAssertTrue(registered.permitsDirectSigning)
        XCTAssertEqual(registered.selectedBackend, .legacyCTK)
    }

    func testForwardPathSwitchesBackendOnlyAtActive() throws {
        var entry = try self.entry()
        XCTAssertEqual(entry.selectedBackend, .legacyCTK)
        entry = try XCTUnwrap(entry.applying(.confirmExternalRegistration))
        XCTAssertEqual(entry.selectedBackend, .legacyCTK)
        entry = try XCTUnwrap(entry.applying(.activateDirectBackend))
        XCTAssertEqual(entry.selectedBackend, .directSecureEnclaveV1)
        entry = try XCTUnwrap(entry.applying(.beginLegacyRetirement))
        entry = try XCTUnwrap(entry.applying(.confirmLegacyRetired))
        XCTAssertEqual(entry.phase, .retired)
        XCTAssertEqual(entry.selectedBackend, .directSecureEnclaveV1)
    }

    func testRollbackNeverDeletesAnActiveDirectKey() throws {
        var entry = try self.entry()
        entry = try XCTUnwrap(entry.applying(.confirmExternalRegistration))
        entry = try XCTUnwrap(entry.applying(.activateDirectBackend))
        XCTAssertThrowsError(try entry.applying(.confirmDirectKeyDeleted))
        entry = try XCTUnwrap(entry.applying(.returnToExternalRegistration))
        entry = try XCTUnwrap(entry.applying(.returnToPreparation))
        XCTAssertThrowsError(try entry.applying(.confirmDirectKeyDeleted))
        entry = try entry.changingPhase(to: .deleting)
        XCTAssertNil(try entry.applying(.confirmDirectKeyDeleted))
    }

    func testRejectsSkippingExternalRegistration() throws {
        XCTAssertThrowsError(try self.entry().applying(.activateDirectBackend))
    }

    func testRecordCarriesImmutableDirectIdentityAcrossTransitions() throws {
        let initial = try self.entry()
        let active = try XCTUnwrap(
            initial.applying(.confirmExternalRegistration)?.applying(.activateDirectBackend)
        )
        XCTAssertEqual(active.directKeyID, initial.directKeyID)
        XCTAssertEqual(active.directPublicKeyBlob, initial.directPublicKeyBlob)
        XCTAssertEqual(active.directFingerprint, initial.directFingerprint)
    }

    func testDocumentEncodingIsCanonicalAndRejectsUnknownKeys() throws {
        let document = try SSHKeyMigrationDocument(generation: 1, entries: [self.entry()])
        let encoded = try document.encoded()
        XCTAssertEqual(try SSHKeyMigrationDocument.decode(encoded), document)

        let text = try XCTUnwrap(String(bytes: encoded, encoding: .utf8))
        let tampered = Data(text
            .replacingOccurrences(of: "{\"entries\"", with: "{\"unknown\":1,\"entries\"").utf8)
        XCTAssertThrowsError(try SSHKeyMigrationDocument.decode(tampered))
    }

    func testDocumentCASRejectsStaleGeneration() throws {
        let one = try SSHKeyMigrationDocument(generation: 1, entries: [self.entry()])
        let two = try SSHKeyMigrationDocument(generation: 2, entries: [self.entry()])
        let store = InMemorySSHKeyMigrationStateStore()
        XCTAssertTrue(try store.compareAndSwap(expectedGeneration: nil, next: one))
        XCTAssertFalse(try store.compareAndSwap(expectedGeneration: nil, next: two))
        XCTAssertFalse(try store.compareAndSwap(expectedGeneration: 0, next: two))
        XCTAssertTrue(try store.compareAndSwap(expectedGeneration: 1, next: two))
    }

    func testKeychainQueryPinsPrivateGroupAndGeneration() throws {
        let builder = try SSHKeyMigrationKeychainQueryBuilder(accessGroup: "TEAM.io.github.macop.auth.ssh")
        let generation = Data([0, 1])
        let read = builder.read()
        XCTAssertEqual(read[kSecAttrAccessGroup] as? String, builder.accessGroup)
        XCTAssertEqual(read[kSecUseDataProtectionKeychain] as? Bool, true)
        XCTAssertEqual(read[kSecAttrAccessible] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        XCTAssertEqual(builder.update(generation: generation)[kSecAttrGeneric] as? Data, generation)
    }

    private func entry(phase: SSHKeyMigrationPhase = .prepared) throws -> SSHKeyMigrationEntry {
        try SSHKeyMigrationEntry(
            label: "github",
            legacyFingerprint: "SHA256:legacy",
            directKeyID: XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased())),
            directPublicKeyBlob: Data([1, 2, 3]),
            phase: phase
        )
    }
}
