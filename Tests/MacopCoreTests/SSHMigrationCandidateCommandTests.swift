import Foundation
@testable import MacopCore
import XCTest

final class SSHMigrationCandidateCommandTests: XCTestCase {
    func testCandidateFlagUsesDedicatedAgentMode() throws {
        let executor = RecordingCommandExecutor()

        let result = try SSHCommand.run(
            args: ["test", "github", "git@github.com", "--migration-candidate"],
            options: GlobalOptions(),
            env: [:],
            executor: executor
        )

        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(executor.path, "macop-agent")
        XCTAssertEqual(Array(executor.arguments.prefix(3)), ["migration-test", "github", "--"])
        XCTAssertEqual(executor.arguments.suffix(2), ["-T", "git@github.com"])
    }

    func testCandidateFlagCannotReplaceTheIdentityLabel() {
        XCTAssertThrowsError(try SSHCommand.run(
            args: ["test", "--migration-candidate"],
            options: GlobalOptions(),
            env: [:],
            executor: RecordingCommandExecutor()
        )) { error in
            guard case CLIError.invalidArguments = error else {
                return XCTFail("expected invalid arguments, got \(error)")
            }
        }
    }
}

private final class RecordingCommandExecutor: CommandExecuting, @unchecked Sendable {
    private(set) var path = ""
    private(set) var arguments = [String]()

    func execute(path: String, arguments: [String], environment _: CommandEnvironment) throws -> CommandResult {
        self.path = path
        self.arguments = arguments
        return CommandResult(
            exitCode: 1,
            stderr: "Hi fixture! You've successfully authenticated, but GitHub does not provide shell access.\n"
        )
    }
}
