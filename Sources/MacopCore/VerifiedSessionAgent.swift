import Darwin
import Foundation

// swiftlint:disable file_length

/// Builds a fresh protocol state machine for each accepted Unix connection.
/// In particular, a session binding cannot leak from one socket to another.
public protocol AgentConnectionBuilding: Sendable {
    func makeConnection(for sessionID: UUID) throws -> AgentConnection
}

public struct DefaultAgentConnectionBuilder: AgentConnectionBuilding {
    public let requester: RequesterVerifier
    public let registry: SessionRegistry
    public let signer: any AgentKeySigning
    public let bindingVerifier: any SessionBindingVerifying

    public init(
        requester: RequesterVerifier,
        registry: SessionRegistry,
        signer: any AgentKeySigning,
        bindingVerifier: any SessionBindingVerifying = SecuritySessionBindingVerifier()
    ) {
        self.requester = requester
        self.registry = registry
        self.signer = signer
        self.bindingVerifier = bindingVerifier
    }

    public func makeConnection(for sessionID: UUID) throws -> AgentConnection {
        guard let session = self.registry.session(sessionID),
              constantTimeEqual(Data(session.keyFingerprint.utf8), Data(self.signer.fingerprint.utf8))
        else { throw AgentProtocolError.denied }
        return AgentConnection(
            requester: self.requester,
            registry: self.registry,
            sessionID: sessionID,
            signer: self.signer,
            bindingVerifier: self.bindingVerifier
        )
    }
}

// swiftlint:disable type_body_length
/// A short-lived OpenSSH-agent listener for exactly one verified session.
/// It deliberately owns no stable socket and accepts no session that is not in
/// the in-memory registry.  Transport errors close only their connection;
/// protocol errors are converted by `AgentConnection.reply`.
public final class VerifiedSessionAgent: @unchecked Sendable {
    private struct SocketPathIdentity {
        let device: dev_t
        let inode: ino_t
        let mode: mode_t
        let owner: uid_t
        let changeTime: timespec
    }

    private let registry: SessionRegistry
    private let sessionID: UUID
    private let connections: any AgentConnectionBuilding
    private let inspector: any RequesterInspecting
    private let queue: DispatchQueue
    private let frameReadTimeout: TimeInterval
    private let frameWriteTimeout: TimeInterval
    private let clientSendBuffer: Int32
    private let maximumClientOutput: Int
    private let maximumClients: Int
    private let maximumPendingClients: Int
    private let lock = NSLock()
    private let listening = NSCondition()
    private var listeningFD: Int32 = -1
    private var clients = Set<Int32>()
    private var pendingClients = Set<Int32>()
    private var socketPathIdentity: SocketPathIdentity?
    private var stopped = false

    public init(
        registry: SessionRegistry,
        sessionID: UUID,
        connections: any AgentConnectionBuilding,
        inspector: any RequesterInspecting = SystemRequesterInspector(),
        queue: DispatchQueue = .global(qos: .userInitiated),
        frameReadTimeout: TimeInterval = 5,
        frameWriteTimeout: TimeInterval = 5,
        clientSendBuffer: Int32 = 64 * 1024,
        maximumClientOutput: Int = 1 * 1024 * 1024,
        maximumClients: Int = 32,
        maximumPendingClients: Int = 4
    ) {
        self.registry = registry
        self.sessionID = sessionID
        self.connections = connections
        self.inspector = inspector
        self.queue = queue
        self.frameReadTimeout = frameReadTimeout
        self.frameWriteTimeout = frameWriteTimeout
        self.clientSendBuffer = max(1024, clientSendBuffer)
        self.maximumClientOutput = max(SSHWire.maxFrameLength, maximumClientOutput)
        self.maximumClients = max(1, maximumClients)
        self.maximumPendingClients = max(1, min(maximumPendingClients, self.maximumClients))
    }

    deinit { self.stop() }

    /// Runs until stopped, expired, revoked, or its registered root dies.
    /// A reserved socket is bound before activation so a just-launched client
    /// never races the listener.  Pending clients are retained but cannot send
    /// a request to a signer until their reservation becomes active.
    public func serve() throws {
        guard let reservation = self.registry.reservation(self.sessionID) else { throw AgentProtocolError.denied }
        // Cleanup is installed before any post-bind state transition.  This
        // also covers a stop racing immediately after `openListener`.
        let listenerFD: Int32
        do {
            listenerFD = try self.openListener(for: reservation)
        } catch {
            self.lock.lock(); self.stopped = true; self.lock.unlock()
            self.listening.lock(); self.listening.broadcast(); self.listening.unlock()
            self.registry.revoke(self.sessionID)
            throw error
        }
        defer { self.registry.removeSocket(for: self.sessionID) }
        self.lock.lock()
        guard !self.stopped else { self.lock.unlock(); close(listenerFD); self.registry.revoke(self.sessionID); return }
        self.listeningFD = listenerFD
        self.lock.unlock()
        self.listening.lock(); self.listening.broadcast(); self.listening.unlock()
        defer {
            self.lock.lock()
            if self.listeningFD == listenerFD {
                self.listeningFD = -1
            }
            self.lock.unlock()
            close(listenerFD)
            self.registry.revoke(self.sessionID)
        }

        while !self.shouldStop() {
            guard self.socketPathIsUnchanged() else { self.failClosedForSocketSubstitution(); break }
            self.registry.revokeDeadRoots(inspector: self.inspector)
            guard self.registry.reservation(self.sessionID) != nil else { break }
            var descriptor = pollfd(fd: listenerFD, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, 250)
            if ready < 0 {
                if errno == EINTR {
                    continue
                }
                throw AgentProtocolError.denied
            }
            guard ready > 0, descriptor.revents & Int16(POLLIN) != 0 else { continue }
            guard self.socketPathIsUnchanged() else { self.failClosedForSocketSubstitution(); break }
            let client = accept(listenerFD, nil, nil)
            if client < 0 {
                if errno == EINTR || errno == ECONNABORTED {
                    continue
                }
                throw AgentProtocolError.denied
            }
            guard self.socketPathIsUnchanged() else {
                close(client); self.failClosedForSocketSubstitution(); break
            }
            guard Self.setCloseOnExec(client) else { close(client); continue }
            guard Self.setSendBuffer(client, bytes: self.clientSendBuffer) else { close(client); continue }
            self.lock.lock()
            // A connection remains pending until activation, approval, and
            // signer installation have all completed. Keep those waiters in a
            // separate small budget so they cannot consume every client slot.
            guard self.clients.count < self.maximumClients,
                  self.pendingClients.count < self.maximumPendingClients
            else {
                self.lock.unlock()
                close(client)
                continue
            }
            self.clients.insert(client)
            self.pendingClients.insert(client)
            self.lock.unlock()
            self.queue.async { [self] in self.serveConnection(client) }
        }
    }

    public func stop() {
        self.lock.lock()
        self.stopped = true
        let listenerFD = self.listeningFD
        let clients = self.clients
        self.listeningFD = -1
        self.lock.unlock()
        // Revocation owns descriptor-relative unlink/rmdir, so callers do not
        // need to wait for the serving queue to observe shutdown.
        self.registry.revoke(self.sessionID)
        // `serve` owns the close.  Closing here could let the descriptor be
        // reused before its deferred cleanup runs.
        if listenerFD >= 0 {
            _ = shutdown(listenerFD, SHUT_RDWR)
        }
        for client in clients {
            _ = shutdown(client, SHUT_RDWR)
        }
        self.listening.lock(); self.listening.broadcast(); self.listening.unlock()
    }

    /// Waits for successful bind and listen, avoiding a pathname-exists race.
    public func waitUntilListening(timeout: TimeInterval) -> Bool {
        let deadline = Self.monotonicDeadline(after: timeout)
        self.listening.lock(); defer { self.listening.unlock() }
        while true {
            self.lock.lock(); let ready = self.listeningFD >= 0; let stopped = self.stopped; self.lock.unlock()
            if ready {
                return true
            }
            let remaining = Self.remainingNanoseconds(until: deadline)
            guard !stopped, remaining > 0 else {
                return false
            }
            // NSCondition exposes only a wall-clock wait API. This is merely
            // a bounded wake-up; the actual timeout decision is monotonic.
            _ = self.listening.wait(until: Date(timeIntervalSinceNow: min(Double(remaining) / 1_000_000_000, 0.05)))
        }
    }

    private func shouldStop() -> Bool {
        self.lock.lock(); defer { self.lock.unlock() }
        return self.stopped
    }

    /// The pathname is an ambient capability: once it no longer identifies the
    /// socket we bound, no further request may reach a signer.
    private func socketPathIsUnchanged() -> Bool {
        self.lock.lock()
        let identity = self.socketPathIdentity
        self.lock.unlock()
        guard let identity,
              let path = self.registry.pinnedSocketBindPath(for: self.sessionID)
        else { return false }
        var current = stat()
        return lstat(path, &current) == 0 && current.st_mode & S_IFMT == S_IFSOCK
            && current.st_uid == identity.owner && current.st_mode & 0o777 == identity.mode
            && current.st_dev == identity.device && current.st_ino == identity.inode
            && current.st_ctimespec.tv_sec == identity.changeTime.tv_sec
            && current.st_ctimespec.tv_nsec == identity.changeTime.tv_nsec
    }

    private func failClosedForSocketSubstitution() {
        self.lock.lock()
        self.stopped = true
        let listener = self.listeningFD
        let clients = self.clients
        self.lock.unlock()
        self.registry.revoke(self.sessionID)
        if listener >= 0 {
            _ = shutdown(listener, SHUT_RDWR)
        }
        for client in clients {
            _ = shutdown(client, SHUT_RDWR)
        }
        self.listening.lock(); self.listening.broadcast(); self.listening.unlock()
    }

    private func serveConnection(_ socket: Int32) {
        defer {
            self.lock.lock(); self.clients.remove(socket); self.pendingClients.remove(socket); self.lock.unlock()
            close(socket)
        }
        guard let peer = try? SocketPeerEvidence.read(from: socket) else { return }
        // Do not interpret a pending client's bytes.  In particular, this
        // avoids treating an unauthenticated pre-launch connection as a sign
        // request while still allowing OpenSSH to connect immediately after
        // exec.  A revoked/expired reservation is simply closed.
        var connection: AgentConnection?
        while connection == nil {
            guard self.socketPathIsUnchanged() else { self.failClosedForSocketSubstitution(); return }
            guard self.registry.reservation(self.sessionID) != nil else { return }
            connection = try? self.connections.makeConnection(for: self.sessionID)
            if connection == nil {
                usleep(10000)
            }
        }
        self.lock.lock(); self.pendingClients.remove(socket); self.lock.unlock()
        guard let session = self.registry.session(self.sessionID),
              connection!.requester.verify(peer: peer, session: session)
        else { return }
        var outputBytes = 0
        while self.registry.session(self.sessionID) != nil {
            guard self.socketPathIsUnchanged() else { self.failClosedForSocketSubstitution(); return }
            guard Self.waitForFrameStart(socket, shouldStop: {
                self.shouldStop() || self.registry.session(self.sessionID) == nil || !self.socketPathIsUnchanged()
            }) else {
                guard self.socketPathIsUnchanged() else { self.failClosedForSocketSubstitution(); return }
                return
            }
            guard let payload = try? Self.readFrame(socket, timeout: self.frameReadTimeout) else { return }
            guard self.socketPathIsUnchanged() else { self.failClosedForSocketSubstitution(); return }
            let reply = connection!.reply(peer: peer, payload: payload)
            guard let framed = try? SSHWire.frame(reply), framed.count <= self.maximumClientOutput - outputBytes,
                  Self.writeAll(framed, to: socket, timeout: self.frameWriteTimeout, shouldStop: {
                      self.shouldStop() || self.registry.reservation(self.sessionID) == nil
                  })
            else { return }
            outputBytes += framed.count
        }
    }

    private func openListener(for reservation: VerifiedSessionReservation) throws -> Int32 {
        guard let bindPath = self.registry.pinnedSocketBindPath(for: self.sessionID),
              bindPath.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path)
        else {
            throw AgentProtocolError.denied
        }
        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else { throw AgentProtocolError.denied }
        guard Self.setCloseOnExec(socketFD) else { close(socketFD); throw AgentProtocolError.denied }
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(bindPath.utf8) + [0]
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: pathBytes)
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0,
              let pinnedPath = self.registry.pinnedSocketBindPath(for: self.sessionID),
              pinnedPath == bindPath,
              self.registry.secureSocketPermissions(for: self.sessionID),
              self.registry.validateBoundSocket(for: self.sessionID),
              listen(socketFD, SOMAXCONN) == 0
        else {
            close(socketFD)
            self.registry.removeSocket(for: self.sessionID)
            throw AgentProtocolError.denied
        }
        var bound = stat()
        guard lstat(bindPath, &bound) == 0, bound.st_mode & S_IFMT == S_IFSOCK,
              bound.st_uid == getuid(), bound.st_mode & 0o077 == 0
        else {
            close(socketFD); self.registry.removeSocket(for: self.sessionID)
            throw AgentProtocolError.denied
        }
        self.lock.lock()
        self.socketPathIdentity = SocketPathIdentity(
            device: bound.st_dev, inode: bound.st_ino, mode: bound.st_mode & 0o777, owner: bound.st_uid,
            changeTime: bound.st_ctimespec
        )
        self.lock.unlock()
        return socketFD
    }

    private static func readFrame(_ socket: Int32, timeout: TimeInterval) throws -> Data {
        let deadline = self.monotonicDeadline(after: timeout)
        let header = try self.readExactly(4, from: socket, deadline: deadline)
        let length = try SSHWire.readU32(header)
        guard length <= UInt32(SSHWire.maxFrameLength) else { throw AgentProtocolError.tooLarge }
        return try self.readExactly(Int(length), from: socket, deadline: deadline)
    }

    private static func waitForFrameStart(_ socket: Int32, shouldStop: () -> Bool) -> Bool {
        while !shouldStop() {
            var descriptor = pollfd(fd: socket, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, 250)
            if ready < 0 {
                if errno == EINTR {
                    continue
                }
                return false
            }
            guard ready > 0 else { continue }
            if descriptor.revents & Int16(POLLIN) != 0 {
                return true
            }
            if descriptor.revents & Int16(POLLHUP | POLLERR | POLLNVAL) != 0 {
                return false
            }
        }
        return false
    }

    private static func readExactly(_ count: Int, from socket: Int32, deadline: UInt64) throws -> Data {
        var result = Data(repeating: 0, count: count)
        var offset = 0
        while offset < count {
            var descriptor = pollfd(fd: socket, events: Int16(POLLIN), revents: 0)
            // A client which connects before activation must not be able to
            // pin a worker indefinitely by slowly dribbling a frame.
            let remaining = self.remainingMilliseconds(until: deadline)
            guard remaining > 0, poll(&descriptor, 1, remaining) > 0
            else { throw AgentProtocolError.denied }
            let received = result.withUnsafeMutableBytes { buffer in
                recv(socket, buffer.baseAddress!.advanced(by: offset), count - offset, 0)
            }
            if received == 0 {
                throw AgentProtocolError.denied
            }
            if received < 0 {
                if errno == EINTR {
                    continue
                }
                throw AgentProtocolError.denied
            }
            offset += received
        }
        return result
    }

    // swiftlint:disable opening_brace
    private static func writeAll(_ data: Data, to socket: Int32, timeout: TimeInterval,
                                 shouldStop: () -> Bool) -> Bool
    {
        let deadline = self.monotonicDeadline(after: timeout)
        var offset = 0
        while offset < data.count {
            guard !shouldStop(), self.remainingNanoseconds(until: deadline) > 0 else { return false }
            let sent = data.withUnsafeBytes { buffer in
                send(socket, buffer.baseAddress!.advanced(by: offset), data.count - offset,
                     Int32(MSG_NOSIGNAL | MSG_DONTWAIT))
            }
            if sent > 0 {
                offset += sent; continue
            }
            if sent < 0 {
                if errno == EINTR {
                    continue
                }
                guard errno == EAGAIN || errno == EWOULDBLOCK else { return false }
            }
            var descriptor = pollfd(fd: socket, events: Int16(POLLOUT), revents: 0)
            let remaining = self.remainingMilliseconds(until: deadline)
            guard remaining > 0, poll(&descriptor, 1, remaining) > 0,
                  descriptor.revents & Int16(POLLOUT) != 0 else { return false }
        }
        return true
    }

    // swiftlint:enable opening_brace

    private static func monotonicDeadline(after timeout: TimeInterval) -> UInt64 {
        var now = timespec()
        clock_gettime(CLOCK_MONOTONIC, &now)
        return UInt64(now.tv_sec) * 1_000_000_000 + UInt64(now.tv_nsec)
            + UInt64(max(0, timeout) * 1_000_000_000)
    }

    private static func remainingMilliseconds(until deadline: UInt64) -> Int32 {
        let remaining = self.remainingNanoseconds(until: deadline)
        guard remaining > 0 else { return 0 }
        let milliseconds = (remaining + 999_999) / 1_000_000
        return Int32(min(milliseconds, UInt64(Int32.max)))
    }

    private static func remainingNanoseconds(until deadline: UInt64) -> UInt64 {
        var now = timespec()
        clock_gettime(CLOCK_MONOTONIC, &now)
        let current = UInt64(now.tv_sec) * 1_000_000_000 + UInt64(now.tv_nsec)
        return deadline > current ? deadline - current : 0
    }

    private static func setCloseOnExec(_ descriptor: Int32) -> Bool {
        let flags = fcntl(descriptor, F_GETFD)
        return flags >= 0 && fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0
    }

    private static func setSendBuffer(_ descriptor: Int32, bytes: Int32) -> Bool {
        var value = bytes
        return setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &value, socklen_t(MemoryLayout.size(ofValue: value))) == 0
    }
}

// swiftlint:enable type_body_length
