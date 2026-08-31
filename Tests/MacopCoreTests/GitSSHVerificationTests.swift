@testable import MacopCore
import XCTest

private struct UnreachableBrokerRequesterValidator: GitSSHSigningRequesterValidating {
    func validateRequester() throws -> Int32 {
        throw AuthBrokerFailure(.transportFailure)
    }
}

private final class UnusedGitVerificationExecutor: GitSSHVerificationExecuting, @unchecked Sendable {
    private(set) var wasCalled = false

    func execute(arguments _: [String]) throws -> Int32 {
        self.wasCalled = true
        return 0
    }
}

final class GitSSHVerificationTests: XCTestCase {
    func testBrokerFailureIsNotMisreportedAsSignatureFailure() {
        let executor = UnusedGitVerificationExecutor()
        let result = GitSSHVerificationCommand.run(
            argv: [
                "macop", "-Y", "check-novalidate", "-n", "git",
                "-s", "/private/tmp/signature", "-Overify-time=20260830220000"
            ],
            executor: executor,
            requesterValidator: UnreachableBrokerRequesterValidator()
        )

        XCTAssertFalse(executor.wasCalled)
        XCTAssertTrue(result.stderr.contains("MacopAuth could not be reached"))
        XCTAssertFalse(result.stderr.contains("Git SSH verification failed"))
    }
}
