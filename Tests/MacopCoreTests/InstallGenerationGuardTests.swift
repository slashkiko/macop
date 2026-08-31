import Darwin
@testable import MacopCore
import XCTest

final class InstallGenerationGuardTests: XCTestCase {
    private struct Identity {
        let device: Int64
        let inode: UInt64
    }

    private struct Fixture {
        let root: URL
        let state: URL
        let journal: URL
        let macop: URL
        let auth: URL
        let capability: URL
        let descriptor: Int32

        func environment(mode: String, descriptor: Int32? = nil) -> [String: String] {
            [
                "MACOP_INSTALL_VERIFY_MODE": mode,
                "MACOP_INSTALL_VERIFY_FD": String(descriptor ?? self.descriptor)
            ]
        }
    }

    func testPendingGenerationBlocksNormalCLIAndAgentAndAuth() throws {
        let fixture = try self.makeFixture()
        defer { self.destroy(fixture) }

        XCTAssertFalse(self.permits(["macop", "item", "list"], executable: fixture.macop, fixture: fixture))
        XCTAssertFalse(self.permits(["macop-agent", "shell"], executable: fixture.macop, fixture: fixture))
        XCTAssertFalse(self.permits(
            ["MacopAuth", "--socket", "/tmp/auth.sock"], executable: fixture.auth, fixture: fixture
        ))
    }

    func testBlockedDecisionDistinguishesActiveUpdateFromRequiredRecovery() throws {
        let fixture = try self.makeFixture()
        defer { self.destroy(fixture) }

        XCTAssertEqual(
            self.decision(["macop", "doctor"], executable: fixture.macop, fixture: fixture),
            .blocked(.recoveryRequired)
        )
        XCTAssertTrue(InstallGenerationGuard.InvocationBlockReason.recoveryRequired.diagnostic
            .contains("rerun the macop installer"))

        let lock = fixture.state.appendingPathComponent("lock")
        try FileManager.default.createDirectory(at: lock, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: lock.path)
        let owner = lock.appendingPathComponent("pid")
        try "\(getpid())\n".write(to: owner, atomically: false, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: owner.path)

        XCTAssertEqual(
            self.decision(["macop", "doctor"], executable: fixture.macop, fixture: fixture),
            .blocked(.updateInProgress)
        )
    }

    func testOnlyExactDoctorAndAuthProbeCanUseActiveCapability() throws {
        let fixture = try self.makeFixture()
        defer { self.destroy(fixture) }

        XCTAssertTrue(self.permits(
            ["macop", "doctor"], executable: fixture.macop, fixture: fixture,
            environment: fixture.environment(mode: "generation")
        ))
        XCTAssertTrue(self.permits(
            ["macop", "doctor"], executable: fixture.macop, fixture: fixture,
            environment: fixture.environment(mode: "broker")
        ))
        XCTAssertTrue(self.permits(
            ["MacopAuth", "--socket", "/tmp/auth.sock", "--probe"], executable: fixture.auth, fixture: fixture,
            environment: fixture.environment(mode: "auth-probe")
        ))
        XCTAssertFalse(self.permits(
            ["macop", "doctor", "--json"], executable: fixture.macop, fixture: fixture,
            environment: fixture.environment(mode: "generation")
        ))
        XCTAssertFalse(self.permits(
            ["MacopAuth", "--probe"], executable: fixture.auth, fixture: fixture,
            environment: fixture.environment(mode: "auth-probe")
        ))
        XCTAssertFalse(self.permits(
            ["MacopAuth", "--socket", "/tmp/auth.sock", "--probe"], executable: fixture.auth, fixture: fixture,
            environment: fixture.environment(mode: "generation")
        ))
    }

    func testDescriptorMustBeTheActiveJournalCapabilityAndMatchPendingNonce() throws {
        let fixture = try self.makeFixture()
        defer { self.destroy(fixture) }
        let copied = fixture.root.appendingPathComponent("copied-capability")
        try FileManager.default.copyItem(at: fixture.capability, to: copied)
        let copiedFD = open(copied.path, O_RDONLY)
        XCTAssertGreaterThanOrEqual(copiedFD, 0)
        defer { _ = close(copiedFD) }

        XCTAssertFalse(self.permits(
            ["macop", "doctor"], executable: fixture.macop, fixture: fixture,
            environment: fixture.environment(mode: "generation", descriptor: copiedFD)
        ))

        let pending = fixture.state.appendingPathComponent("pending")
        let original = try String(contentsOf: pending, encoding: .utf8)
        try original.replacingOccurrences(of: "nonce=12345678-1234-1234-1234-123456789abc", with: "nonce=bad")
            .write(to: pending, atomically: true, encoding: .utf8)
        XCTAssertFalse(self.permits(
            ["macop", "doctor"], executable: fixture.macop, fixture: fixture,
            environment: fixture.environment(mode: "generation")
        ))
    }

    func testBrokerProbeLaunchPermissionRequiresExactBrokerCapability() throws {
        let fixture = try self.makeFixture()
        defer { self.destroy(fixture) }

        XCTAssertEqual(
            InstallGenerationGuard.brokerProbeLaunchPermission(
                argv: ["macop", "doctor"],
                environment: fixture.environment(mode: "broker"),
                executablePath: fixture.macop.path,
                stateDirectory: fixture.state
            ),
            .authorized(descriptor: fixture.descriptor)
        )
        XCTAssertEqual(
            InstallGenerationGuard.brokerProbeLaunchPermission(
                argv: ["macop", "doctor"],
                environment: fixture.environment(mode: "generation"),
                executablePath: fixture.macop.path,
                stateDirectory: fixture.state
            ),
            .denied
        )
        XCTAssertEqual(
            InstallGenerationGuard.brokerProbeLaunchPermission(
                argv: ["macop", "doctor", "--json"],
                environment: fixture.environment(mode: "broker"),
                executablePath: fixture.macop.path,
                stateDirectory: fixture.state
            ),
            .denied
        )
    }

    func testStateDirectorySubstitutionFailsClosed() throws {
        let fixture = try self.makeFixture()
        defer { self.destroy(fixture) }
        let replacement = fixture.root.appendingPathComponent("replacement-state")
        try FileManager.default.moveItem(at: fixture.state, to: replacement)
        try FileManager.default.createDirectory(at: fixture.state, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.state.path)
        try "pending\n".write(to: fixture.state.appendingPathComponent("pending"), atomically: true, encoding: .utf8)

        XCTAssertFalse(self.permits(
            ["macop", "doctor"], executable: fixture.macop, fixture: fixture,
            environment: fixture.environment(mode: "generation")
        ))
    }

    private func permits(
        _ argv: [String], executable: URL, fixture: Fixture, environment: [String: String] = [:]
    ) -> Bool {
        InstallGenerationGuard.permitsInvocation(
            argv: argv,
            environment: environment,
            executablePath: executable.path,
            stateDirectory: fixture.state
        )
    }

    private func decision(
        _ argv: [String], executable: URL, fixture: Fixture, environment: [String: String] = [:]
    ) -> InstallGenerationGuard.InvocationDecision {
        InstallGenerationGuard.invocationDecision(
            argv: argv,
            environment: environment,
            executablePath: executable.path,
            stateDirectory: fixture.state
        )
    }

    private func makeFixture() throws -> Fixture {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("macop-install-guard-\(UUID().uuidString)")
            .standardizedFileURL
            .resolvingSymlinksInPath()
        let state = root.appendingPathComponent("install-state")
        let journal = state.appendingPathComponent("journal.fixture")
        let macop = root.appendingPathComponent("macop")
        let auth = root.appendingPathComponent("MacopAuth")
        try FileManager.default.createDirectory(at: journal, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: state.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: journal.path)
        try Data().write(to: macop)
        try Data().write(to: auth)
        let nonce = "12345678-1234-1234-1234-123456789abc"
        let stateIdentity = try self.identity(state)
        let journalIdentity = try self.identity(journal)
        let capability = journal.appendingPathComponent("INSTALLER_CAPABILITY")
        let record = """
        schema=1
        state=\(state.path)
        state_device=\(stateIdentity.device)
        state_inode=\(stateIdentity.inode)
        journal=\(journal.path)
        journal_device=\(journalIdentity.device)
        journal_inode=\(journalIdentity.inode)
        nonce=\(nonce)
        operations=generation,broker,auth-probe
        macop_executable=\(macop.path)
        auth_executable=\(auth.path)
        """
        try (record + "\n").write(to: capability, atomically: true, encoding: .utf8)
        try "pending\n".write(to: journal.appendingPathComponent("PENDING"), atomically: true, encoding: .utf8)
        let pending = """
        schema=1
        nonce=\(nonce)
        journal=\(journal.path)
        state_device=\(stateIdentity.device)
        state_inode=\(stateIdentity.inode)
        """
        try (pending + "\n").write(to: state.appendingPathComponent("pending"), atomically: true, encoding: .utf8)
        let descriptor = open(capability.path, O_RDONLY)
        guard descriptor >= 0 else { throw POSIXError(.EBADF) }
        return Fixture(
            root: root, state: state, journal: journal, macop: macop, auth: auth,
            capability: capability, descriptor: descriptor
        )
    }

    private func destroy(_ fixture: Fixture) {
        _ = close(fixture.descriptor)
        try? FileManager.default.removeItem(at: fixture.root)
    }

    private func identity(_ url: URL) throws -> Identity {
        var value = stat()
        guard lstat(url.path, &value) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        return Identity(device: Int64(value.st_dev), inode: UInt64(value.st_ino))
    }
}
