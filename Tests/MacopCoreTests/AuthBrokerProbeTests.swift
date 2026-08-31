// swiftlint:disable file_length
import Darwin
import Foundation
@testable import MacopCore
import XCTest

// swiftlint:disable:next type_body_length
final class AuthBrokerProbeTests: XCTestCase {
    private let required = AuthBrokerCapability.approvalUI.rawValue | AuthBrokerCapability.sshSigning.rawValue
    private let appPath = "/Applications/MacopAuth.app/Contents/MacOS/MacopAuth"

    func testInstalledProbeUsesSelectedAppAndAcceptsV8WireReply() throws {
        var launchRequest: AuthBrokerClientConnection.LaunchRequest?
        let connection = try self.connectToProbeServer { descriptor in
            try self.reply(to: descriptor, message: self.welcome())
        } launch: { request in
            launchRequest = request
            return .none
        }
        withExtendedLifetime(connection) {}
        XCTAssertEqual(launchRequest?.executableURL.path, "/usr/bin/open")
        XCTAssertEqual(Array(launchRequest?.arguments.prefix(3) ?? []), ["-g", "-n", "/Applications/MacopAuth.app"])
        XCTAssertNil(launchRequest?.inheritedDescriptor)
    }

    func testInstalledProbeRejectsV4AndV5WireReplies() {
        for version: UInt16 in [4, 5] {
            self.assertBrokerFailure(.protocolMismatch) {
                try self.connectToProbeServer { descriptor in
                    try self.reply(to: descriptor, rawFrame: self.frameWithVersion(version))
                }
            }
        }
    }

    func testInstalledProbeRejectsWrongTeamAndIdentifier() {
        self.assertBrokerFailure(.identityInvalid) {
            try self.connectToProbeServer(
                peerIdentity: self.identity(teamID: "OTHER"),
                server: { _ in }
            )
        }
        let wrongIdentifier = LiveCodeIdentity(
            canonicalPath: self.appPath,
            identifier: "io.github.slashkiko.other",
            teamID: "TEAM",
            signingAuthority: "Developer ID",
            cdHash: nil,
            hasTrustedPublisher: true
        )
        self.assertBrokerFailure(.identityInvalid) {
            try self.connectToProbeServer(
                peerIdentity: wrongIdentifier,
                server: { _ in }
            )
        }
    }

    func testInstalledProbeClassifiesMissingCapabilityAsProtocolMismatch() {
        self.assertBrokerFailure(.protocolMismatch) {
            try self.connectToProbeServer { descriptor in
                try self.reply(to: descriptor, message: self.welcome(
                    capabilities: AuthBrokerCapability.approvalUI.rawValue
                ))
            }
        }
    }

    func testInstalledProbeRejectsConnectFailureAndClosedConnection() {
        let dependencies = self.dependencies(
            connect: { _, _ in throw AgentProtocolError.denied },
            launch: { _ in .none }
        )
        self.assertBrokerFailure(.transportFailure) {
            try AuthBrokerClientConnection.launchAndConnect(
                timeout: 0.1,
                requiredCapabilities: self.required,
                probe: true,
                dependencies: dependencies
            )
        }
        self.assertBrokerFailure(.transportFailure) {
            try self.connectToProbeServer { descriptor in
                _ = try AuthBrokerSocketIO.readMessage(from: descriptor, timeout: 1)
            }
        }
    }

    func testInstalledProbeClassifiesMissingCompanion() {
        let dependencies = self.dependencies(
            connect: { _, _ in throw AgentProtocolError.denied },
            resolveCompanion: { throw AgentProtocolError.denied },
            launch: { _ in .none }
        )
        self.assertBrokerFailure(.companionUnavailable) {
            try AuthBrokerClientConnection.launchAndConnect(
                timeout: 0.1,
                requiredCapabilities: self.required,
                probe: true,
                dependencies: dependencies
            )
        }
    }

    func testUserCancellationAndDenialRemainUserDecisionCategory() {
        for status in [AuthBrokerApprovalStatus.cancelled, .denied] {
            XCTAssertEqual(status.failureCategory, .userDenied)
        }
        XCTAssertNil(AuthBrokerApprovalStatus.approved.failureCategory)
    }

    func testBrokerFailurePresentationIsCategorizedAndSecretFree() {
        let secret = "stage4-secret-payload"
        let request = "request-id=4E5B"
        let path = "/private/var/folders/macop-auth.sock"
        for category in [
            AuthBrokerFailureCategory.companionUnavailable,
            .identityInvalid,
            .protocolMismatch,
            .transportFailure,
            .userDenied
        ] {
            let rendered = ErrorRenderer.render(
                error: AuthBrokerFailure(category).cliError,
                format: .json
            )
            XCTAssertTrue(rendered.stderr.contains(category.rawValue))
            XCTAssertTrue(rendered.stderr.contains("MacopAuth"))
            XCTAssertFalse(rendered.stderr.contains(secret))
            XCTAssertFalse(rendered.stderr.contains(request))
            XCTAssertFalse(rendered.stderr.contains(path))
        }
    }

    func testBrokerBoundariesClassifyInjectedRawErrorsWithoutRenderingThem() {
        let secret = "stage4-secret-from-boundary"
        let requestID = "request-id=DEADBEEF"
        let socketPath = "/private/tmp/macop-auth-sensitive.sock"
        let leaked = LeakyBoundaryError(secret: secret, requestID: requestID, socketPath: socketPath)

        let resolver = self.dependencies(
            connect: { _, _ in throw leaked },
            resolveCompanion: { throw leaked },
            launch: { _ in .none }
        )
        self.assertBrokerFailure(.companionUnavailable) {
            try AuthBrokerClientConnection.launchAndConnect(
                timeout: 0.1, requiredCapabilities: self.required, probe: true, dependencies: resolver
            )
        }
        self.assertSafePresentation(
            .companionUnavailable, secret: secret, requestID: requestID, socketPath: socketPath
        )

        let launcher = self.dependencies(
            connect: { _, _ in throw leaked },
            launch: { _ in throw leaked }
        )
        self.assertBrokerFailure(.companionUnavailable) {
            try AuthBrokerClientConnection.launchAndConnect(
                timeout: 0.1, requiredCapabilities: self.required, probe: true, dependencies: launcher
            )
        }
        self.assertSafePresentation(
            .companionUnavailable, secret: secret, requestID: requestID, socketPath: socketPath
        )

        let connector = self.dependencies(
            connect: { _, _ in throw leaked },
            launch: { _ in .none }
        )
        self.assertBrokerFailure(.transportFailure) {
            try AuthBrokerClientConnection.launchAndConnect(
                timeout: 0.1, requiredCapabilities: self.required, probe: true, dependencies: connector
            )
        }
        self.assertSafePresentation(
            .transportFailure, secret: secret, requestID: requestID, socketPath: socketPath
        )

        var pair = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { close(pair[1]) }
        let reader = self.dependencies(
            connect: { _, _ in pair[0] },
            launch: { _ in .none }
        )
        let readFailure = AuthBrokerClientConnection.Dependencies(
            resolveCompanion: reader.resolveCompanion,
            reserveEndpoint: reader.reserveEndpoint,
            brokerProbePermission: reader.brokerProbePermission,
            launch: reader.launch,
            connect: reader.connect,
            readPeer: { _ in throw leaked },
            verifyPeer: reader.verifyPeer,
            validatesBoundSocket: reader.validatesBoundSocket
        )
        self.assertBrokerFailure(.identityInvalid) {
            try AuthBrokerClientConnection.launchAndConnect(
                timeout: 0.1, requiredCapabilities: self.required, probe: true, dependencies: readFailure
            )
        }
        self.assertSafePresentation(
            .identityInvalid, secret: secret, requestID: requestID, socketPath: socketPath
        )
    }

    func testDirectInstallerLauncherConnectsBeforeItsBlockingHelperIsReaped() throws {
        let signal = Pipe()
        var helper: Process?
        let connection = try self.connectToProbeServer(
            server: { descriptor in
                try self.reply(to: descriptor, message: self.welcome())
            },
            launch: { _ in
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/bin/sh")
                process.arguments = ["-c", "read -r connected"]
                process.standardInput = signal.fileHandleForReading
                try process.run()
                helper = process
                return AuthBrokerLaunch(process: process)
            },
            onConnect: {
                try? signal.fileHandleForWriting.write(contentsOf: Data("connected\n".utf8))
            }
        )
        withExtendedLifetime(connection) {}
        XCTAssertNotNil(helper)
        XCTAssertFalse(helper?.isRunning ?? true)
    }

    func testPendingProbeDirectlyLaunchesAuthWithInheritedCapability() throws {
        var launchRequest: AuthBrokerClientConnection.LaunchRequest?
        let dependencies = self.dependencies(
            connect: { _, _ in throw AgentProtocolError.denied },
            permission: .authorized(descriptor: 42),
            launch: { request in
                launchRequest = request
                return .none
            }
        )
        XCTAssertThrowsError(try AuthBrokerClientConnection.launchAndConnect(
            timeout: 0.1,
            requiredCapabilities: self.required,
            probe: true,
            dependencies: dependencies
        ))
        XCTAssertEqual(launchRequest?.executableURL.path, self.appPath)
        XCTAssertEqual(launchRequest?.arguments.count, 3)
        XCTAssertEqual(launchRequest?.arguments.first, "--socket")
        XCTAssertFalse(launchRequest?.arguments[1].isEmpty ?? true)
        XCTAssertEqual(launchRequest?.arguments.last, "--probe")
        XCTAssertEqual(launchRequest?.environment?["MACOP_INSTALL_VERIFY_MODE"], "auth-probe")
        XCTAssertNil(launchRequest?.environment?["MACOP_INSTALL_VERIFY_FD"])
        XCTAssertEqual(launchRequest?.inheritedDescriptor, 42)
    }

    func testProductionDirectProbeMapsCapabilityToDedicatedChildDescriptorAndHandshakes() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("macop-direct-probe-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let helper = root.appendingPathComponent("MacopAuth")
        let marker = root.appendingPathComponent("capability")
        let errorMarker = root.appendingPathComponent("capability-error")
        try self.writeDirectProbeHelper(
            at: helper,
            capabilityMarker: marker,
            errorMarker: errorMarker
        )
        let capability = root.appendingPathComponent("INSTALLER_CAPABILITY")
        try Data("broker-capability\n".utf8).write(to: capability)
        let descriptor = open(capability.path, O_RDONLY)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { close(descriptor) }

        let companion = AuthBrokerCompanionIdentity(
            appURL: root,
            executablePath: helper.path,
            teamID: "TEAM"
        )
        let dependencies = self.dependencies(
            connect: { path, timeout in
                try AuthBrokerSocketIO.connect(path: path, timeout: timeout)
            },
            peerIdentity: self.identity(path: helper.path),
            permission: .authorized(descriptor: descriptor),
            resolveCompanion: { companion },
            launch: { request in try AuthBrokerClientConnection.run(request) }
        )
        let reservationDirectory: URL
        do {
            let connection = try AuthBrokerClientConnection.launchAndConnect(
                timeout: 1,
                requiredCapabilities: self.required,
                probe: true,
                dependencies: dependencies
            )
            reservationDirectory = connection.reservation.directory
            XCTAssertEqual(
                try String(contentsOf: marker, encoding: .utf8),
                "\(AuthBrokerClientConnection.capabilityChildDescriptor):broker-capability\n"
            )
        } catch {
            let helperError = (try? String(contentsOf: errorMarker, encoding: .utf8)) ?? "none"
            XCTFail("production helper did not reach its socket lifecycle: \(helperError)")
            return
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: reservationDirectory.path))
        XCTAssertNotEqual(descriptor, AuthBrokerClientConnection.capabilityChildDescriptor)
    }

    func testProductionDirectProbeRejectsMissingCapabilityDescriptorBeforeExec() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("macop-direct-probe-missing-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let marker = root.appendingPathComponent("executed")
        let helper = root.appendingPathComponent("MacopAuth")
        try "#!/bin/sh\ntouch '\(marker.path)'\n".write(to: helper, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        let closedDescriptor = open("/dev/null", O_RDONLY)
        XCTAssertGreaterThanOrEqual(closedDescriptor, 0)
        close(closedDescriptor)

        XCTAssertThrowsError(try AuthBrokerClientConnection.run(.init(
            executableURL: helper,
            arguments: [],
            environment: ["MACOP_INSTALL_VERIFY_MODE": "auth-probe"],
            inheritedDescriptor: closedDescriptor
        ))) { error in
            XCTAssertEqual((error as? AuthBrokerFailure)?.category, .identityInvalid)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testProductionDirectProbeClassifiesCapabilityDescriptorLimitAsTransportFailure() throws {
        let descriptor = open("/dev/null", O_RDONLY)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { close(descriptor) }

        var original = rlimit()
        XCTAssertEqual(getrlimit(RLIMIT_NOFILE, &original), 0)
        guard original.rlim_max >= rlim_t(AuthBrokerClientConnection.capabilityChildDescriptor) else {
            throw XCTSkip("the process limit cannot exercise a child descriptor limit")
        }
        var limited = original
        limited.rlim_cur = rlim_t(AuthBrokerClientConnection.capabilityChildDescriptor)
        XCTAssertEqual(setrlimit(RLIMIT_NOFILE, &limited), 0)
        defer { XCTAssertEqual(setrlimit(RLIMIT_NOFILE, &original), 0) }

        XCTAssertThrowsError(try AuthBrokerClientConnection.run(.init(
            executableURL: URL(fileURLWithPath: "/usr/bin/true"),
            arguments: [],
            environment: nil,
            inheritedDescriptor: descriptor
        ))) { error in
            XCTAssertEqual((error as? AuthBrokerFailure)?.category, .transportFailure)
        }
    }

    func testPendingProbeClassifiesInvalidInstallerCapabilityBeforeLaunch() {
        var didLaunch = false
        let dependencies = self.dependencies(
            connect: { _, _ in throw AgentProtocolError.denied },
            permission: .denied,
            launch: { _ in
                didLaunch = true
                return .none
            }
        )
        self.assertBrokerFailure(.identityInvalid) {
            try AuthBrokerClientConnection.launchAndConnect(
                timeout: 0.1,
                requiredCapabilities: self.required,
                probe: true,
                dependencies: dependencies
            )
        }
        XCTAssertFalse(didLaunch)
    }

    private func connectToProbeServer(
        peerIdentity: LiveCodeIdentity? = nil,
        server: @escaping (Int32) throws -> Void,
        launch: @escaping (AuthBrokerClientConnection.LaunchRequest) throws -> AuthBrokerLaunch = { _ in .none },
        onConnect: @escaping () -> Void = {}
    ) throws -> AuthBrokerClientConnection {
        var pair = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        let serverDescriptor = pair[1]
        let serverAction = ProbeServerAction(server)
        DispatchQueue.global().async {
            defer { close(serverDescriptor) }
            try? serverAction.body(serverDescriptor)
        }
        let clientDescriptor = pair[0]
        let dependencies = self.dependencies(
            connect: { _, _ in
                onConnect()
                return clientDescriptor
            },
            peerIdentity: peerIdentity ?? self.identity(),
            launch: launch
        )
        return try AuthBrokerClientConnection.launchAndConnect(
            timeout: 1,
            requiredCapabilities: self.required,
            probe: true,
            dependencies: dependencies
        )
    }

    private func dependencies(
        connect: @escaping (String, TimeInterval) throws -> Int32,
        peerIdentity: LiveCodeIdentity? = nil,
        permission: InstallGenerationGuard.BrokerProbeLaunchPermission = .notPending,
        resolveCompanion: (() throws -> AuthBrokerCompanionIdentity)? = nil,
        launch: @escaping (AuthBrokerClientConnection.LaunchRequest) throws -> AuthBrokerLaunch
    ) -> AuthBrokerClientConnection.Dependencies {
        let companion = AuthBrokerCompanionIdentity(
            appURL: URL(fileURLWithPath: "/Applications/MacopAuth.app", isDirectory: true),
            executablePath: self.appPath,
            teamID: "TEAM"
        )
        let actualPeerIdentity = peerIdentity ?? self.identity()
        return .init(
            resolveCompanion: resolveCompanion ?? { companion },
            reserveEndpoint: { try AuthBrokerEndpointReservation() },
            brokerProbePermission: { permission },
            launch: launch,
            connect: connect,
            readPeer: { _ in RequesterPeer(pid: 42, uid: Int32(getuid())) },
            verifyPeer: { peer, target in
                try AuthBrokerPeerVerifier(
                    expectedTeamID: target.teamID,
                    allowedIdentifiers: [AuthBrokerCompanionResolver.appIdentifier]
                ).verify(
                    peer: peer,
                    inspector: StaticRequesterInspector(),
                    identityInspector: { _ in actualPeerIdentity }
                )
            },
            validatesBoundSocket: { _ in true }
        )
    }

    private func welcome(capabilities: UInt32? = nil) -> AuthBrokerMessage {
        .helloReply(AuthBrokerHelloReply(
            selectedVersion: AuthBrokerWire.currentVersion,
            capabilities: capabilities ?? self.required,
            nonce: Data(repeating: 7, count: 32)
        ))
    }

    private func reply(to descriptor: Int32, message: AuthBrokerMessage) throws {
        _ = try AuthBrokerSocketIO.readMessage(from: descriptor, timeout: 1)
        try AuthBrokerSocketIO.writeMessage(message, to: descriptor, timeout: 1)
    }

    private func reply(to descriptor: Int32, rawFrame: Data) throws {
        _ = try AuthBrokerSocketIO.readMessage(from: descriptor, timeout: 1)
        let result = rawFrame.withUnsafeBytes { write(descriptor, $0.baseAddress, rawFrame.count) }
        guard result == rawFrame.count else { throw AgentProtocolError.denied }
    }

    private func frameWithVersion(_ version: UInt16) throws -> Data {
        var frame = try AuthBrokerWire.frame(self.welcome())
        frame[8] = UInt8(version >> 8)
        frame[9] = UInt8(version & 0xFF)
        return frame
    }

    private func identity(path: String? = nil, teamID: String = "TEAM") -> LiveCodeIdentity {
        LiveCodeIdentity(
            canonicalPath: path ?? self.appPath,
            identifier: AuthBrokerCompanionResolver.appIdentifier,
            teamID: teamID,
            signingAuthority: "Developer ID",
            cdHash: nil,
            hasTrustedPublisher: true
        )
    }

    private func assertBrokerFailure(
        _ expected: AuthBrokerFailureCategory,
        operation: () throws -> Any
    ) {
        XCTAssertThrowsError(try operation()) { error in
            XCTAssertEqual((error as? AuthBrokerFailure)?.category, expected)
        }
    }

    private func assertSafePresentation(
        _ category: AuthBrokerFailureCategory,
        secret: String,
        requestID: String,
        socketPath: String
    ) {
        for format in [OutputFormat.humanReadable, .json] {
            let rendered = ErrorRenderer.render(error: AuthBrokerFailure(category).cliError, format: format)
            XCTAssertTrue(rendered.stderr.contains(category.rawValue))
            XCTAssertFalse(rendered.stderr.contains(secret))
            XCTAssertFalse(rendered.stderr.contains(requestID))
            XCTAssertFalse(rendered.stderr.contains(socketPath))
        }

        let debugResult = MacopApp(keychainClient: BrokerFailureKeychainClient(category: category)).run(
            argv: ["macop", "--debug", "--format", "json", "read", "keychain://generic/service/account"],
            env: [:]
        )
        XCTAssertTrue(debugResult.stderr.contains(category.rawValue))
        XCTAssertTrue(debugResult.stderr.contains("broker_category=\(category.rawValue)"))
        XCTAssertFalse(debugResult.stderr.contains(secret))
        XCTAssertFalse(debugResult.stderr.contains(requestID))
        XCTAssertFalse(debugResult.stderr.contains(socketPath))
    }

    private func writeDirectProbeHelper(
        at helper: URL,
        capabilityMarker: URL,
        errorMarker: URL
    ) throws {
        let script = #"""
        #!/usr/bin/python3
        import os
        import socket
        import struct
        import sys

        path = sys.argv[2]
        try:
            descriptor = int(os.environ["MACOP_INSTALL_VERIFY_FD"])
            os.fstat(descriptor)
            capability = os.read(descriptor, 4096)
            if capability != b"broker-capability\n":
                sys.exit(31)
            with open("\#(capabilityMarker.path)", "wb") as marker:
                marker.write(str(descriptor).encode("ascii") + b":" + capability)
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(path)
            os.chmod(path, 0o600)
            server.listen(1)
            client, _ = server.accept()
            with client:
                def receive_exact(size):
                    value = b""
                    while len(value) < size:
                        chunk = client.recv(size - len(value))
                        if not chunk:
                            raise RuntimeError("client closed")
                        value += chunk
                    return value

                length = struct.unpack(">I", receive_exact(4))[0]
                hello = receive_exact(length)
                if hello[:7] != b"MCAU\x00\x08\x01":
                    sys.exit(32)
                payload = (
                    b"MCAU" + struct.pack(">H", 8) + b"\x02" + struct.pack(">H", 8)
                    + struct.pack(">I", 5) + struct.pack(">I", 32) + (b"\x07" * 32)
                )
                client.sendall(struct.pack(">I", len(payload)) + payload)
            server.close()
        except BaseException as error:
            with open("\#(errorMarker.path)", "w") as marker:
                marker.write(repr(error))
            raise
        """#
        try script.write(to: helper, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
    }
}

private struct LeakyBoundaryError: Error, LocalizedError {
    let secret: String
    let requestID: String
    let socketPath: String

    var errorDescription: String? {
        "secret=\(self.secret) request=\(self.requestID) socket=\(self.socketPath)"
    }
}

private struct BrokerFailureKeychainClient: KeychainClient {
    let category: AuthBrokerFailureCategory

    func read(_: KeychainQuery) -> Result<Data, KeychainFailure> {
        .failure(KeychainFailure(brokerFailure: AuthBrokerFailure(self.category)))
    }
}

private struct StaticRequesterInspector: RequesterInspecting {
    func snapshot(of pid: Int32) -> ProcessSnapshot? {
        pid == 42 ? ProcessSnapshot(pid: pid, parentPID: 1, startTime: 1) : nil
    }

    func validatedCodeIdentity(pid _: Int32, requirement _: String) throws -> String {
        ""
    }
}

private final class ProbeServerAction: @unchecked Sendable {
    let body: (Int32) throws -> Void

    init(_ body: @escaping (Int32) throws -> Void) {
        self.body = body
    }
}

// swiftlint:enable file_length
