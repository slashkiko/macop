@testable import MacopCore
import XCTest

final class AuthBrokerApprovalPresentationTests: XCTestCase {
    func testSSHSessionTargetPresentationRoundTrips() throws {
        let request = self.request(presentation: .sshSessionTarget(
            application: "/bin/zsh",
            signingAuthority: "certificate-backed; Developer ID Application: Example",
            cdHash: "0123456789abcdef",
            verification: "live image pinned before approval"
        ))

        var frame = try AuthBrokerWire.frame(.approvalRequest(request))

        XCTAssertEqual(try AuthBrokerWire.takeFrame(from: &frame), .approvalRequest(request))
    }

    func testTargetPresentationRejectsNonSessionOperation() {
        let request = self.request(
            operation: .gitSSHSign,
            purpose: .gitSSHSign,
            presentation: .sshSessionTarget(
                application: "/usr/bin/git",
                signingAuthority: "certificate-backed; Apple",
                cdHash: "0123456789abcdef",
                verification: "live image pinned before approval"
            )
        )

        XCTAssertThrowsError(try AuthBrokerWire.frame(.approvalRequest(request)))
    }

    func testSSHSessionRejectsMissingTargetPresentation() {
        let request = self.request(presentation: .requesterOnly)

        XCTAssertThrowsError(try AuthBrokerWire.frame(.approvalRequest(request)))
    }

    func testTargetPresentationRejectsUnsafeDisplayText() {
        let request = self.request(presentation: .sshSessionTarget(
            application: "/bin/zsh\nforged",
            signingAuthority: "certificate-backed; Example",
            cdHash: "0123456789abcdef",
            verification: "live image pinned before approval"
        ))

        XCTAssertThrowsError(try AuthBrokerWire.frame(.approvalRequest(request)))
    }

    private func request(
        operation: AuthBrokerOperation = .sshSession,
        purpose: AuthBrokerPurpose = .sshSession,
        presentation: AuthBrokerApprovalPresentation
    ) -> AuthBrokerApprovalRequest {
        AuthBrokerApprovalRequest(
            requestID: UUID(),
            issuedAtMilliseconds: 1,
            expiresAtMilliseconds: 2,
            operation: operation,
            rootPID: 42,
            rootStartTime: 1,
            rootIdentifier: "io.github.slashkiko.macop.agent",
            rootCodeRequirement: "identifier io.github.slashkiko.macop.agent",
            rootExecutablePath: "/usr/local/bin/macop-agent",
            presentation: presentation,
            purpose: purpose,
            credentialLabel: "fixture",
            credentialFingerprint: "SHA256:fixture",
            host: ""
        )
    }
}
