import Foundation
@testable import MacopCore
import XCTest

final class AuthBrokerDirectSSHKeyProtocolTests: XCTestCase {
    func testRoundTripsListCreateAndDelete() throws {
        let requestID = UUID()
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased()))
        let record = AuthBrokerDirectSSHKeyRecord(id: id, label: "github", publicKeyBlob: Data([1, 2, 3]))
        let messages: [AuthBrokerMessage] = [
            .directSSHKeyRequest(AuthBrokerDirectSSHKeyRequest(
                authorizationID: requestID,
                operation: .list
            )),
            .directSSHKeyRequest(AuthBrokerDirectSSHKeyRequest(
                authorizationID: requestID,
                operation: .create,
                label: "github",
                expectedGeneration: 2,
                legacyFingerprint: "SHA256:legacy"
            )),
            .directSSHKeyRequest(AuthBrokerDirectSSHKeyRequest(
                authorizationID: requestID,
                operation: .delete,
                id: id,
                label: "github",
                expectedPublicKeyBlob: record.publicKeyBlob
            )),
            .directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
                authorizationID: requestID,
                operation: .list,
                status: .success,
                records: [record]
            )),
            .directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
                authorizationID: requestID,
                operation: .create,
                status: .success,
                records: [record]
            )),
            .directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
                authorizationID: requestID,
                operation: .delete,
                status: .success
            ))
        ]

        for message in messages {
            var frame = try AuthBrokerWire.frame(message)
            XCTAssertEqual(try AuthBrokerWire.takeFrame(from: &frame), message)
            XCTAssertTrue(frame.isEmpty)
        }
    }

    func testRejectsSelectorsThatDoNotMatchOperation() throws {
        let requestID = UUID()
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased()))
        XCTAssertThrowsError(try AuthBrokerWire.frame(.directSSHKeyRequest(AuthBrokerDirectSSHKeyRequest(
            authorizationID: requestID,
            operation: .list,
            id: id
        ))))
        XCTAssertThrowsError(try AuthBrokerWire.frame(.directSSHKeyRequest(AuthBrokerDirectSSHKeyRequest(
            authorizationID: requestID,
            operation: .create,
            label: ""
        ))))
        XCTAssertThrowsError(try AuthBrokerWire.frame(.directSSHKeyRequest(AuthBrokerDirectSSHKeyRequest(
            authorizationID: requestID,
            operation: .delete,
            id: id,
            label: "github"
        ))))
    }

    func testRejectsResponseShapeThatCouldClaimWrongMutation() throws {
        let requestID = UUID()
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased()))
        let record = AuthBrokerDirectSSHKeyRecord(id: id, label: "github", publicKeyBlob: Data([1]))
        XCTAssertThrowsError(try AuthBrokerWire.frame(.directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
            authorizationID: requestID,
            operation: .create,
            status: .success
        ))))
        XCTAssertThrowsError(try AuthBrokerWire.frame(.directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
            authorizationID: requestID,
            operation: .delete,
            status: .success,
            records: [record]
        ))))
        XCTAssertThrowsError(try AuthBrokerWire.frame(.directSSHKeyResponse(AuthBrokerDirectSSHKeyResponse(
            authorizationID: requestID,
            operation: .list,
            status: .failed,
            records: [record]
        ))))
    }

    func testMigrationQueryAndTransitionRoundTrip() throws {
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: UUID().uuidString.lowercased()))
        let entry = try SSHKeyMigrationEntry(
            label: "github",
            legacyFingerprint: "SHA256:legacy",
            directKeyID: id,
            directPublicKeyBlob: Data([1, 2, 3]),
            phase: .externallyRegistered
        )
        let messages: [AuthBrokerMessage] = [
            .sshMigrationRequest(AuthBrokerSSHMigrationRequest(requestID: UUID(), action: .list)),
            .sshMigrationRequest(AuthBrokerSSHMigrationRequest(
                requestID: UUID(),
                action: .transition,
                label: "github",
                expectedGeneration: 2,
                transition: .activateDirectBackend
            )),
            .sshMigrationResponse(AuthBrokerSSHMigrationResponse(
                requestID: UUID(),
                action: .list,
                status: .success,
                generation: 2,
                entries: [entry]
            ))
        ]
        for message in messages {
            var frame = try AuthBrokerWire.frame(message)
            XCTAssertEqual(try AuthBrokerWire.takeFrame(from: &frame), message)
        }
    }
}
