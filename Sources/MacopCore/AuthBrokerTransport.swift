import AppKit
import Darwin
import Foundation
import Security

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

    public static func resolve(currentExecutable: String? = nil) throws -> AuthBrokerCompanionIdentity {
        let executable = try currentExecutable ?? RunningExecutable.path()
        let current = try LiveCodeIdentityInspector.inspect(pid: getpid(), expectedPath: executable).identity
        guard ["macop", "macop-agent"].contains(current.identifier), current.hasTrustedPublisher,
              let teamID = current.teamID, !teamID.isEmpty else { throw AgentProtocolError.denied }
        let appURL = URL(fileURLWithPath: current.canonicalPath).deletingLastPathComponent()
            .appendingPathComponent("MacopAuth.app", isDirectory: true)
        guard let appExecutable = Bundle(url: appURL)?.executableURL else { throw AgentProtocolError.denied }
        let app = try LiveCodeIdentityInspector.inspectStatic(path: appExecutable.path)
        guard app.identifier == self.appIdentifier, app.hasTrustedPublisher, app.teamID == teamID else {
            throw AgentProtocolError.denied
        }
        return AuthBrokerCompanionIdentity(
            appURL: appURL,
            executablePath: app.canonicalPath,
            teamID: teamID
        )
    }
}

public final class AuthBrokerClientConnection: @unchecked Sendable {
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
        requiredCapabilities: UInt32
    ) throws -> AuthBrokerClientConnection {
        let companion = try AuthBrokerCompanionResolver.resolve()
        let reservation = try AuthBrokerEndpointReservation()
        let launcher = Process()
        launcher.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        launcher.arguments = ["-n", companion.appURL.path, "--args", "--socket", reservation.socketPath.path]
        try launcher.run()
        launcher.waitUntilExit()
        guard launcher.terminationStatus == 0 else { throw AgentProtocolError.denied }
        let descriptor = try AuthBrokerSocketIO.connect(path: reservation.socketPath.path, timeout: timeout)
        do {
            let peer = try SocketPeerEvidence.read(from: descriptor)
            let verified = try AuthBrokerPeerVerifier(
                expectedTeamID: companion.teamID,
                allowedIdentifiers: [AuthBrokerCompanionResolver.appIdentifier]
            ).verify(peer: peer)
            guard verified.peerIdentity.canonicalPath == companion.executablePath,
                  reservation.validateBoundSocket() else { throw AgentProtocolError.denied }
            let connection = AuthBrokerClientConnection(
                descriptor: descriptor,
                reservation: reservation,
                companion: companion
            )
            try connection.handshake(requiredCapabilities: requiredCapabilities)
            return connection
        } catch {
            close(descriptor)
            throw error
        }
    }

    public func send(_ message: AuthBrokerMessage, timeout: TimeInterval = 120) throws -> AuthBrokerMessage {
        self.lock.lock(); defer { self.lock.unlock() }
        try AuthBrokerSocketIO.writeMessage(message, to: self.descriptor, timeout: timeout)
        return try AuthBrokerSocketIO.readMessage(from: self.descriptor, timeout: timeout)
    }

    private func handshake(requiredCapabilities: UInt32) throws {
        let nonce = try AuthBrokerSocketIO.randomNonce()
        try AuthBrokerSocketIO.writeMessage(.hello(AuthBrokerHello(
            minimumVersion: AuthBrokerWire.currentVersion,
            maximumVersion: AuthBrokerWire.currentVersion,
            capabilities: AuthBrokerCapability.approvalUI.rawValue
                | AuthBrokerCapability.managedKeychain.rawValue
                | AuthBrokerCapability.sshSigning.rawValue
                | AuthBrokerCapability.passwordAutoFill.rawValue
                | AuthBrokerCapability.passwordAutoFillUsername.rawValue,
            nonce: nonce
        )), to: self.descriptor, timeout: 5)
        guard case let .helloReply(reply) = try AuthBrokerSocketIO.readMessage(
            from: self.descriptor,
            timeout: 5
        ),
            reply.selectedVersion == AuthBrokerWire.currentVersion,
            reply.capabilities & AuthBrokerCapability.approvalUI.rawValue != 0,
            reply.capabilities & requiredCapabilities == requiredCapabilities,
            reply.nonce.count == 32
        else { throw AgentProtocolError.denied }
    }
}
