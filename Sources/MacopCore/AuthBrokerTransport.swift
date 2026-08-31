import AppKit

// swiftlint:disable file_length
import Darwin
import Foundation
import Security

/// A closed, presentation-safe description of why the local MacopAuth
/// boundary could not be used.  It intentionally carries no path, request,
/// response, or underlying error because this value can cross into CLI output.
public enum AuthBrokerFailureCategory: String, Error, Sendable, Equatable {
    case companionUnavailable = "companion_unavailable"
    case identityInvalid = "identity_invalid"
    case protocolMismatch = "protocol_mismatch"
    case transportFailure = "transport_failure"
    case userDenied = "user_denied"
}

public struct AuthBrokerFailure: Error, Sendable, Equatable {
    public let category: AuthBrokerFailureCategory

    public init(_ category: AuthBrokerFailureCategory) {
        self.category = category
    }
}

/// Valid, attested Git-client-trust business outcomes.  These are not broker
/// transport or identity failures and therefore must not be rendered as one.
public enum GitClientTrustFailure: Error, Sendable, Equatable {
    case stateMismatch
    case stateUnavailable
    case generationConflict

    var cliError: CLIError {
        switch self {
        case .stateMismatch:
            .runtimeError(
                message: "Git client trust state does not match the local registry. Review it, then run the authenticated migration or reset."
            )
        case .stateUnavailable:
            .providerUnavailable(
                provider: "MacopAuth",
                reason: "Authenticated Git client trust state is unavailable. Run the authenticated reset after reviewing the registry."
            )
        case .generationConflict:
            .runtimeError(
                message: "Git client trust state changed concurrently. Reload the registry and retry the reviewed operation."
            )
        }
    }
}

/// Owns the short-lived launcher process until the authenticated socket
/// connection is established.  The installer probe launches MacopAuth
/// directly, and that process waits in `accept`; waiting synchronously at
/// spawn time would therefore deadlock the client before it can connect.
final class AuthBrokerLaunch: @unchecked Sendable {
    private let process: Process?
    private let pid: pid_t?
    private var childStatus: Int32?

    static let none = AuthBrokerLaunch(process: nil, pid: nil)

    init(process: Process?, pid: pid_t? = nil) {
        self.process = process
        self.pid = pid
    }

    convenience init(pid: pid_t) {
        self.init(process: nil, pid: pid)
    }

    func reap(timeout: TimeInterval) throws {
        guard self.process != nil || self.pid != nil else { return }
        guard let status = self.waitForExit(timeout: timeout) else {
            self.terminate()
            throw AgentProtocolError.denied
        }
        guard status == 0 else { throw AgentProtocolError.denied }
    }

    func terminate() {
        guard self.pollExit() == nil else { return }
        if let process {
            process.terminate()
        } else if let pid {
            _ = kill(pid, SIGTERM)
        }
        guard self.waitForExit(timeout: 0.5) == nil else { return }
        if let process {
            _ = kill(process.processIdentifier, SIGKILL)
        } else if let pid {
            _ = kill(pid, SIGKILL)
        }
        _ = self.waitForExit(timeout: 0.5)
    }

    private func waitForExit(timeout: TimeInterval) -> Int32? {
        let deadline = DispatchTime.now().uptimeNanoseconds
            + UInt64(max(0, timeout) * 1_000_000_000)
        repeat {
            if let status = self.pollExit() {
                return status
            }
            usleep(10000)
        } while DispatchTime.now().uptimeNanoseconds < deadline
        return self.pollExit()
    }

    private func pollExit() -> Int32? {
        if let childStatus {
            return childStatus
        }
        if let process {
            guard !process.isRunning else { return nil }
            self.childStatus = process.terminationStatus
            return self.childStatus
        }
        if let pid {
            var status: Int32 = 0
            while true {
                let result = waitpid(pid, &status, WNOHANG)
                if result == pid {
                    self.childStatus = status
                    return status
                }
                if result == 0 {
                    return nil
                }
                if errno == EINTR {
                    continue
                }
                if errno == ECHILD {
                    self.childStatus = 1
                    return self.childStatus
                }
                return nil
            }
        }
        return 0
    }
}

public final class AuthBrokerEndpointReservation: @unchecked Sendable {
    public let directory: URL
    public let socketPath: URL
    private let directoryFD: Int32

    public init(root: URL? = nil) throws {
        let suffix = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16)
        let directory = root ?? URL(
            fileURLWithPath: "/tmp/macop-auth-\(getuid())-\(suffix)",
            isDirectory: true
        )
        guard directory.path != "/",
              directory.path.utf8.count + 10 < MemoryLayout.size(ofValue: sockaddr_un().sun_path),
              mkdir(directory.path, 0o700) == 0
        else { throw AgentProtocolError.denied }
        let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            _ = rmdir(directory.path)
            throw AgentProtocolError.denied
        }
        do {
            try Self.validateDirectory(descriptor)
        } catch {
            close(descriptor)
            _ = rmdir(directory.path)
            throw error
        }
        self.directory = directory
        self.socketPath = directory.appendingPathComponent("auth.sock")
        self.directoryFD = descriptor
    }

    deinit {
        _ = unlinkat(self.directoryFD, "auth.sock", 0)
        close(self.directoryFD)
        _ = rmdir(self.directory.path)
    }

    public func validateVisibleDirectory() -> Bool {
        var retained = stat()
        var visible = stat()
        return fstat(self.directoryFD, &retained) == 0
            && lstat(self.directory.path, &visible) == 0
            && retained.st_dev == visible.st_dev && retained.st_ino == visible.st_ino
            && visible.st_mode & S_IFMT == S_IFDIR && visible.st_uid == getuid()
            && visible.st_mode & 0o077 == 0
    }

    public func validateBoundSocket() -> Bool {
        guard self.validateVisibleDirectory() else { return false }
        var value = stat()
        return fstatat(self.directoryFD, "auth.sock", &value, AT_SYMLINK_NOFOLLOW) == 0
            && value.st_mode & S_IFMT == S_IFSOCK && value.st_uid == getuid()
            && value.st_mode & 0o077 == 0
    }

    private static func validateDirectory(_ descriptor: Int32) throws {
        var value = stat()
        guard fstat(descriptor, &value) == 0, value.st_mode & S_IFMT == S_IFDIR,
              value.st_uid == getuid(), value.st_mode & 0o077 == 0
        else { throw AgentProtocolError.denied }
    }
}

public enum AuthBrokerSocketIO {
    public static func openListener(path: String) throws -> Int32 {
        guard path.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
            throw AgentProtocolError.denied
        }
        var existing = stat()
        guard lstat(path, &existing) != 0, errno == ENOENT else { throw AgentProtocolError.denied }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw AgentProtocolError.denied }
        do {
            try self.setCloseOnExec(descriptor)
            var address = try self.address(path: path)
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard result == 0, chmod(path, 0o600) == 0, listen(descriptor, 8) == 0 else {
                throw AgentProtocolError.denied
            }
            return descriptor
        } catch {
            close(descriptor)
            _ = unlink(path)
            throw error
        }
    }

    public static func accept(listener: Int32, timeout: TimeInterval) throws -> Int32 {
        guard self.wait(descriptor: listener, events: Int16(POLLIN), deadline: self.deadline(after: timeout)) else {
            throw AgentProtocolError.denied
        }
        let client = Darwin.accept(listener, nil, nil)
        guard client >= 0 else { throw AgentProtocolError.denied }
        do {
            try self.setCloseOnExec(client)
            return client
        } catch {
            close(client)
            throw error
        }
    }

    public static func connect(path: String, timeout: TimeInterval) throws -> Int32 {
        let deadline = self.deadline(after: timeout)
        while self.remaining(until: deadline) > 0 {
            let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
            guard descriptor >= 0 else { throw AgentProtocolError.denied }
            do {
                try self.setCloseOnExec(descriptor)
                var address = try self.address(path: path)
                let result = withUnsafePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                    }
                }
                if result == 0 {
                    return descriptor
                }
            } catch {
                close(descriptor)
                throw error
            }
            close(descriptor)
            usleep(20000)
        }
        throw AgentProtocolError.denied
    }

    public static func readMessage(
        from descriptor: Int32,
        timeout: TimeInterval,
        nowMilliseconds: UInt64? = nil
    ) throws -> AuthBrokerMessage {
        let deadline = self.deadline(after: timeout)
        let header = try self.readExactly(4, from: descriptor, deadline: deadline)
        let length = Int(header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
        guard length <= AuthBrokerWire.maximumFrameLength else { throw AuthBrokerProtocolError.tooLarge }
        let payload = try self.readExactly(length, from: descriptor, deadline: deadline)
        var framed = header + payload
        guard let message = try AuthBrokerWire.takeFrame(from: &framed, nowMilliseconds: nowMilliseconds),
              framed.isEmpty else { throw AuthBrokerProtocolError.malformed }
        return message
    }

    public static func writeMessage(_ message: AuthBrokerMessage, to descriptor: Int32, timeout: TimeInterval) throws {
        let data = try AuthBrokerWire.frame(message)
        let deadline = self.deadline(after: timeout)
        var offset = 0
        while offset < data.count {
            guard self.wait(descriptor: descriptor, events: Int16(POLLOUT), deadline: deadline) else {
                throw AgentProtocolError.denied
            }
            let count = data.withUnsafeBytes { buffer in
                Darwin.write(descriptor, buffer.baseAddress!.advanced(by: offset), data.count - offset)
            }
            guard count > 0 else {
                if count < 0, errno == EINTR {
                    continue
                }
                throw AgentProtocolError.denied
            }
            offset += count
        }
    }

    public static func randomNonce() throws -> Data {
        var value = Data(repeating: 0, count: 32)
        let status = value.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else { throw AgentProtocolError.denied }
        return value
    }

    private static func readExactly(_ count: Int, from descriptor: Int32, deadline: UInt64) throws -> Data {
        var value = Data(repeating: 0, count: count)
        var offset = 0
        while offset < count {
            guard self.wait(descriptor: descriptor, events: Int16(POLLIN), deadline: deadline) else {
                throw AgentProtocolError.denied
            }
            let readCount = value.withUnsafeMutableBytes { buffer in
                Darwin.read(descriptor, buffer.baseAddress!.advanced(by: offset), count - offset)
            }
            guard readCount > 0 else {
                if readCount < 0, errno == EINTR {
                    continue
                }
                throw AgentProtocolError.denied
            }
            offset += readCount
        }
        return value
    }

    private static func wait(descriptor: Int32, events: Int16, deadline: UInt64) -> Bool {
        while true {
            let remaining = self.remaining(until: deadline)
            guard remaining > 0 else { return false }
            var value = pollfd(fd: descriptor, events: events, revents: 0)
            let milliseconds = Int32(min(remaining / 1_000_000, UInt64(Int32.max)))
            let result = poll(&value, 1, max(1, milliseconds))
            if result < 0, errno == EINTR {
                continue
            }
            return result > 0 && value.revents & events != 0
        }
    }

    private static func address(path: String) throws -> sockaddr_un {
        guard path.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
            throw AgentProtocolError.denied
        }
        var value = sockaddr_un()
        value.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        value.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &value.sun_path) { buffer in
            buffer.copyBytes(from: Array(path.utf8) + [0])
        }
        return value
    }

    private static func setCloseOnExec(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFD)
        guard flags >= 0, fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0 else {
            throw AgentProtocolError.denied
        }
    }

    private static func deadline(after timeout: TimeInterval) -> UInt64 {
        DispatchTime.now().uptimeNanoseconds + UInt64(max(0, timeout) * 1_000_000_000)
    }

    private static func remaining(until deadline: UInt64) -> UInt64 {
        let now = DispatchTime.now().uptimeNanoseconds
        return deadline > now ? deadline - now : 0
    }
}

public struct AuthBrokerCompanionIdentity: Sendable {
    public let appURL: URL
    public let executablePath: String
    public let teamID: String

    public init(appURL: URL, executablePath: String, teamID: String) {
        self.appURL = appURL
        self.executablePath = executablePath
        self.teamID = teamID
    }
}

public enum AuthBrokerCompanionResolver {
    public static let appIdentifier = "io.github.slashkiko.macop.auth"

    /// This is deliberately only an existence check for doctor.  Authorization
    /// always goes through `resolve`, which also validates both code identities.
    public static func companionIsPresent(currentExecutable: String? = nil) -> Bool {
        guard let executable = currentExecutable ?? (try? RunningExecutable.path()) else { return false }
        let appURL = URL(fileURLWithPath: executable).deletingLastPathComponent()
            .appendingPathComponent("MacopAuth.app", isDirectory: true)
        return Bundle(url: appURL)?.executableURL != nil
    }

    public static func resolve(currentExecutable: String? = nil) throws -> AuthBrokerCompanionIdentity {
        guard let executable = currentExecutable ?? (try? RunningExecutable.path()),
              let current = try? LiveCodeIdentityInspector.inspect(pid: getpid(), expectedPath: executable).identity
        else { throw AuthBrokerFailure(.identityInvalid) }
        guard ["macop", "macop-agent"].contains(current.identifier), current.hasTrustedPublisher,
              let teamID = current.teamID, !teamID.isEmpty else { throw AuthBrokerFailure(.identityInvalid) }
        let appURL = URL(fileURLWithPath: current.canonicalPath).deletingLastPathComponent()
            .appendingPathComponent("MacopAuth.app", isDirectory: true)
        guard let appExecutable = Bundle(url: appURL)?.executableURL else {
            throw AuthBrokerFailure(.companionUnavailable)
        }
        guard let app = try? LiveCodeIdentityInspector.inspectStatic(path: appExecutable.path) else {
            throw AuthBrokerFailure(.identityInvalid)
        }
        guard app.identifier == self.appIdentifier, app.hasTrustedPublisher, app.teamID == teamID else {
            throw AuthBrokerFailure(.identityInvalid)
        }
        return AuthBrokerCompanionIdentity(
            appURL: appURL,
            executablePath: app.canonicalPath,
            teamID: teamID
        )
    }
}

// swiftlint:disable:next type_body_length
public final class AuthBrokerClientConnection: @unchecked Sendable {
    /// A fixed child-only descriptor prevents the installed probe from
    /// accidentally relying on Foundation `Process` descriptor inheritance.
    /// The parent capability is duplicated above this number before spawn, so
    /// a caller-provided descriptor can never collide with the child target.
    static let capabilityChildDescriptor: Int32 = 198

    struct LaunchRequest {
        let executableURL: URL
        let arguments: [String]
        let environment: [String: String]?
        let inheritedDescriptor: Int32?
    }

    /// The installed-broker path is deliberately assembled from small seams so
    /// it can be exercised with a real local socket in tests.  The live value
    /// keeps all code-signing, peer-credential, and endpoint checks intact.
    struct Dependencies {
        let resolveCompanion: () throws -> AuthBrokerCompanionIdentity
        let reserveEndpoint: () throws -> AuthBrokerEndpointReservation
        let brokerProbePermission: () -> InstallGenerationGuard.BrokerProbeLaunchPermission
        let launch: (LaunchRequest) throws -> AuthBrokerLaunch
        let connect: (String, TimeInterval) throws -> Int32
        let readPeer: (Int32) throws -> RequesterPeer
        let verifyPeer: (RequesterPeer, AuthBrokerCompanionIdentity) throws -> AuthBrokerVerifiedPeer
        let validatesBoundSocket: (AuthBrokerEndpointReservation) -> Bool

        static func live() -> Self {
            Self(
                resolveCompanion: { try AuthBrokerCompanionResolver.resolve() },
                reserveEndpoint: { try AuthBrokerEndpointReservation() },
                brokerProbePermission: { InstallGenerationGuard.brokerProbeLaunchPermission() },
                launch: { try AuthBrokerClientConnection.run($0) },
                connect: { try AuthBrokerSocketIO.connect(path: $0, timeout: $1) },
                readPeer: { try SocketPeerEvidence.read(from: $0) },
                verifyPeer: { peer, companion in
                    try AuthBrokerPeerVerifier(
                        expectedTeamID: companion.teamID,
                        allowedIdentifiers: [AuthBrokerCompanionResolver.appIdentifier]
                    ).verify(peer: peer)
                },
                validatesBoundSocket: { $0.validateBoundSocket() }
            )
        }
    }

    public let descriptor: Int32
    public let reservation: AuthBrokerEndpointReservation
    public let companion: AuthBrokerCompanionIdentity
    private let lock = NSLock()

    private init(
        descriptor: Int32,
        reservation: AuthBrokerEndpointReservation,
        companion: AuthBrokerCompanionIdentity
    ) {
        self.descriptor = descriptor
        self.reservation = reservation
        self.companion = companion
    }

    deinit { close(self.descriptor) }

    public static func launchAndConnect(
        timeout: TimeInterval = 8,
        requiredCapabilities: UInt32,
        probe: Bool = false
    ) throws -> AuthBrokerClientConnection {
        try self.launchAndConnect(
            timeout: timeout,
            requiredCapabilities: requiredCapabilities,
            probe: probe,
            dependencies: .live()
        )
    }

    static func run(_ request: LaunchRequest) throws -> AuthBrokerLaunch {
        if let descriptor = request.inheritedDescriptor {
            return try self.runWithCapability(request, descriptor: descriptor)
        }
        let launcher = Process()
        launcher.executableURL = request.executableURL
        launcher.arguments = request.arguments
        launcher.environment = request.environment
        try launcher.run()
        return AuthBrokerLaunch(process: launcher)
    }

    private static func runWithCapability(_ request: LaunchRequest, descriptor: Int32) throws -> AuthBrokerLaunch {
        let duplicated = fcntl(descriptor, F_DUPFD_CLOEXEC, self.capabilityChildDescriptor + 1)
        guard duplicated >= 0 else {
            // EBADF proves the caller supplied an invalid capability. Limits
            // and unsupported duplication are local transport failures: they
            // say nothing about the capability's identity.
            throw AuthBrokerFailure(errno == EBADF ? .identityInvalid : .transportFailure)
        }
        defer { close(duplicated) }

        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw AuthBrokerFailure(.transportFailure) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawn_file_actions_addinherit_np(&actions, STDIN_FILENO) == 0,
              posix_spawn_file_actions_addinherit_np(&actions, STDOUT_FILENO) == 0,
              posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, duplicated, self.capabilityChildDescriptor) == 0,
              posix_spawn_file_actions_addclose(&actions, duplicated) == 0
        else { throw AuthBrokerFailure(.transportFailure) }

        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else { throw AuthBrokerFailure(.transportFailure) }
        defer { posix_spawnattr_destroy(&attributes) }
        var flags: Int16 = 0
        guard posix_spawnattr_getflags(&attributes, &flags) == 0,
              posix_spawnattr_setflags(&attributes, flags | Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0
        else { throw AuthBrokerFailure(.transportFailure) }

        var environment = request.environment ?? ProcessInfo.processInfo.environment
        environment["MACOP_INSTALL_VERIFY_FD"] = String(self.capabilityChildDescriptor)
        let argv = [request.executableURL.path] + request.arguments
        var envp = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { envp.compactMap(\.self).forEach { free($0) } }
        var argvPointers = argv.map { strdup($0) } + [nil]
        defer { argvPointers.compactMap(\.self).forEach { free($0) } }
        var pid: pid_t = 0
        let status = request.executableURL.path.withCString { executable in
            argvPointers.withUnsafeMutableBufferPointer { argvBuffer in
                envp.withUnsafeMutableBufferPointer { environmentBuffer in
                    posix_spawn(
                        &pid,
                        executable,
                        &actions,
                        &attributes,
                        argvBuffer.baseAddress,
                        environmentBuffer.baseAddress
                    )
                }
            }
        }
        guard status == 0 else { throw AuthBrokerFailure(.companionUnavailable) }
        return AuthBrokerLaunch(pid: pid)
    }

    private static func launchRequest(
        companion: AuthBrokerCompanionIdentity,
        reservation: AuthBrokerEndpointReservation,
        probe: Bool,
        permission: InstallGenerationGuard.BrokerProbeLaunchPermission
    ) throws -> LaunchRequest {
        if probe {
            switch permission {
            case let .authorized(descriptor):
                var environment = ProcessInfo.processInfo.environment
                environment["MACOP_INSTALL_VERIFY_MODE"] = "auth-probe"
                return LaunchRequest(
                    executableURL: URL(fileURLWithPath: companion.executablePath),
                    arguments: ["--socket", reservation.socketPath.path, "--probe"],
                    environment: environment,
                    inheritedDescriptor: descriptor
                )
            case .denied:
                throw AuthBrokerFailure(.identityInvalid)
            case .notPending:
                break
            }
        }
        var arguments = ["-g", "-n", companion.appURL.path, "--args", "--socket", reservation.socketPath.path]
        if probe {
            arguments.append("--probe")
        }
        return LaunchRequest(
            executableURL: URL(fileURLWithPath: "/usr/bin/open"),
            arguments: arguments,
            environment: nil,
            inheritedDescriptor: nil
        )
    }

    static func launchAndConnect(
        timeout: TimeInterval,
        requiredCapabilities: UInt32,
        probe: Bool,
        dependencies: Dependencies
    ) throws -> AuthBrokerClientConnection {
        let companion: AuthBrokerCompanionIdentity
        do {
            companion = try dependencies.resolveCompanion()
        } catch let failure as AuthBrokerFailure {
            throw failure
        } catch {
            throw AuthBrokerFailure(.companionUnavailable)
        }
        let reservation: AuthBrokerEndpointReservation
        do {
            reservation = try dependencies.reserveEndpoint()
        } catch {
            throw AuthBrokerFailure(.transportFailure)
        }
        let permission = probe ? dependencies.brokerProbePermission() : .notPending
        let launched: AuthBrokerLaunch
        do {
            launched = try dependencies.launch(Self.launchRequest(
                companion: companion,
                reservation: reservation,
                probe: probe,
                permission: permission
            ))
        } catch let failure as AuthBrokerFailure {
            throw failure
        } catch {
            throw AuthBrokerFailure(.companionUnavailable)
        }
        var completed = false
        defer {
            if !completed {
                launched.terminate()
            }
        }
        let descriptor: Int32
        do {
            descriptor = try dependencies.connect(reservation.socketPath.path, timeout)
        } catch {
            throw AuthBrokerFailure(.transportFailure)
        }
        do {
            let peer: RequesterPeer
            let verified: AuthBrokerVerifiedPeer
            do {
                peer = try dependencies.readPeer(descriptor)
                verified = try dependencies.verifyPeer(peer, companion)
                guard verified.peerIdentity.canonicalPath == companion.executablePath,
                      dependencies.validatesBoundSocket(reservation)
                else {
                    throw AuthBrokerFailure(.identityInvalid)
                }
            } catch let failure as AuthBrokerFailure {
                throw failure
            } catch {
                throw AuthBrokerFailure(.identityInvalid)
            }
            let connection = AuthBrokerClientConnection(
                descriptor: descriptor,
                reservation: reservation,
                companion: companion
            )
            do {
                try connection.handshake(requiredCapabilities: requiredCapabilities)
            } catch let failure as AuthBrokerFailure {
                throw failure
            } catch {
                throw AuthBrokerFailure(.protocolMismatch)
            }
            do {
                try launched.reap(timeout: min(max(timeout, 0.1), 2))
            } catch {
                throw AuthBrokerFailure(.transportFailure)
            }
            completed = true
            return connection
        } catch {
            close(descriptor)
            throw error
        }
    }

    /// Verifies only the installed companion boundary. This sends hello/welcome
    /// and closes immediately: it does not request a secret, protected trust
    /// state, mutation, or user approval.
    public static func verifyInstalledBroker() throws {
        _ = try self.launchAndConnect(
            requiredCapabilities: AuthBrokerCapability.approvalUI.rawValue
                | AuthBrokerCapability.sshSigning.rawValue
                | AuthBrokerCapability.directSSHKeyManagement.rawValue,
            probe: true
        )
    }

    public func send(_ message: AuthBrokerMessage, timeout: TimeInterval = 120) throws -> AuthBrokerMessage {
        self.lock.lock(); defer { self.lock.unlock() }
        do {
            try AuthBrokerSocketIO.writeMessage(message, to: self.descriptor, timeout: timeout)
            return try AuthBrokerSocketIO.readMessage(from: self.descriptor, timeout: timeout)
        } catch is AuthBrokerProtocolError {
            throw AuthBrokerFailure(.protocolMismatch)
        } catch {
            throw AuthBrokerFailure(.transportFailure)
        }
    }

    private func handshake(requiredCapabilities: UInt32) throws {
        let nonce: Data
        do {
            nonce = try AuthBrokerSocketIO.randomNonce()
        } catch {
            throw AuthBrokerFailure(.transportFailure)
        }
        let hello = AuthBrokerMessage.hello(AuthBrokerHello(
            minimumVersion: AuthBrokerWire.currentVersion,
            maximumVersion: AuthBrokerWire.currentVersion,
            capabilities: AuthBrokerCapability.approvalUI.rawValue
                | AuthBrokerCapability.managedKeychain.rawValue
                | AuthBrokerCapability.sshSigning.rawValue
                | AuthBrokerCapability.passwordAutoFill.rawValue
                | AuthBrokerCapability.passwordAutoFillUsername.rawValue
                | AuthBrokerCapability.gitClientTrust.rawValue
                | AuthBrokerCapability.directSSHKeyManagement.rawValue,
            nonce: nonce
        ))
        do {
            try AuthBrokerSocketIO.writeMessage(hello, to: self.descriptor, timeout: 5)
        } catch {
            throw AuthBrokerFailure(.transportFailure)
        }
        let reply: AuthBrokerMessage
        do {
            reply = try AuthBrokerSocketIO.readMessage(from: self.descriptor, timeout: 5)
        } catch is AuthBrokerProtocolError {
            throw AuthBrokerFailure(.protocolMismatch)
        } catch {
            throw AuthBrokerFailure(.transportFailure)
        }
        do {
            try Self.validateProbeHelloReply(reply, requiredCapabilities: requiredCapabilities)
        } catch {
            throw AuthBrokerFailure(.protocolMismatch)
        }
    }

    /// Narrow transport-independent seam used by the installed-broker probe
    /// tests. Production still obtains this message through the same socket
    /// decoder above; tests supply real encoded/decoded frames.
    static func validateProbeHelloReply(_ message: AuthBrokerMessage, requiredCapabilities: UInt32) throws {
        guard case let .helloReply(reply) = message,
              reply.selectedVersion == AuthBrokerWire.currentVersion,
              reply.capabilities & AuthBrokerCapability.approvalUI.rawValue != 0,
              reply.capabilities & requiredCapabilities == requiredCapabilities,
              reply.nonce.count == 32
        else { throw AgentProtocolError.denied }
    }
}

// The only production bridge from a registry file to its protected state.
// No state Keychain query is linked into macop or macop-agent.
// swiftformat:disable wrapMultilineStatementBraces
public struct AuthBrokerGitClientTrustVerifier: GitClientTrustDocumentVerifying, GitClientTrustDocumentMutating,
    GitClientTrustProtectedStateQuerying {
    public init() {}

    public func verify(document: GitClientTrustDocument, canonicalDocument: Data, digest: Data) throws {
        let requestID = UUID()
        let connection = try AuthBrokerClientConnection.launchAndConnect(
            requiredCapabilities: AuthBrokerCapability.gitClientTrust.rawValue
        )
        let reply = try connection.send(.gitClientTrustVerifyRequest(AuthBrokerGitClientTrustVerifyRequest(
            requestID: requestID, canonicalDocument: canonicalDocument, digest: digest
        )), timeout: 10)
        try Self.validateVerifyResponse(
            reply,
            requestID: requestID,
            digest: digest,
            generation: document.generation
        )
    }

    public func authorizeMutation(
        operation: GitClientTrustMutationOperation,
        expectedGeneration: UInt64,
        nextDocument: GitClientTrustDocument,
        canonicalDocument: Data,
        digest: Data
    ) throws {
        let authorizationID = UUID()
        let connection = try AuthBrokerClientConnection.launchAndConnect(
            requiredCapabilities: AuthBrokerCapability.gitClientTrust.rawValue
        )
        let reply = try connection.send(.gitClientTrustMutationRequest(AuthBrokerGitClientTrustMutationRequest(
            authorizationID: authorizationID, operation: operation, expectedGeneration: expectedGeneration,
            canonicalDocument: canonicalDocument, digest: digest
        )), timeout: 120)
        try Self.validateMutationResponse(
            reply,
            authorizationID: authorizationID,
            digest: digest,
            generation: nextDocument.generation
        )
    }

    public func protectedGeneration() throws -> UInt64? {
        let requestID = UUID()
        let connection = try AuthBrokerClientConnection.launchAndConnect(
            requiredCapabilities: AuthBrokerCapability.gitClientTrust.rawValue
        )
        let reply = try connection.send(.gitClientTrustStateRequest(AuthBrokerGitClientTrustStateRequest(
            requestID: requestID
        )), timeout: 10)
        return try Self.classifyProtectedStateResponse(reply, requestID: requestID)
    }

    static func validateVerifyResponse(
        _ reply: AuthBrokerMessage,
        requestID: UUID,
        digest: Data,
        generation: UInt64
    ) throws {
        guard case let .gitClientTrustVerifyResponse(response) = reply,
              response.requestID == requestID,
              constantTimeEqual(response.digest, digest),
              response.generation == generation
        else { throw AuthBrokerFailure(.protocolMismatch) }
        switch response.status {
        case .trusted: return
        case .mismatch: throw GitClientTrustFailure.stateMismatch
        case .unavailable: throw GitClientTrustFailure.stateUnavailable
        case .approved, .rejected, .generationConflict: throw AuthBrokerFailure(.protocolMismatch)
        }
    }

    static func validateMutationResponse(
        _ reply: AuthBrokerMessage,
        authorizationID: UUID,
        digest: Data,
        generation: UInt64
    ) throws {
        guard case let .gitClientTrustMutationResponse(response) = reply,
              response.authorizationID == authorizationID,
              constantTimeEqual(response.digest, digest),
              response.generation == generation
        else { throw AuthBrokerFailure(.protocolMismatch) }
        switch response.status {
        case .approved: return
        case .rejected: throw AuthBrokerFailure(.userDenied)
        case .generationConflict: throw GitClientTrustFailure.generationConflict
        case .trusted, .mismatch, .unavailable: throw AuthBrokerFailure(.protocolMismatch)
        }
    }

    static func classifyProtectedStateResponse(
        _ reply: AuthBrokerMessage,
        requestID: UUID
    ) throws -> UInt64? {
        guard case let .gitClientTrustStateResponse(response) = reply,
              response.requestID == requestID
        else { throw AuthBrokerFailure(.protocolMismatch) }
        switch response.status {
        case .trusted: return response.generation
        case .unavailable: return nil
        case .mismatch, .approved, .rejected, .generationConflict:
            throw AuthBrokerFailure(.protocolMismatch)
        }
    }
}
