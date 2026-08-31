import Darwin
import Foundation
import Security

// SwiftFormat's multiline declaration style conflicts with SwiftLint's
// opening-brace rule for declarations that cannot fit on a single line.
// swiftlint:disable opening_brace
// swiftlint:disable identifier_name
// swiftlint:disable file_length

public struct VerifiedSession: Sendable, Equatable {
    public let id: UUID; public let nonce: String; public let directory: URL; public let socketPath: URL
    public let rootPID: Int32; public let rootStartTime: UInt64; public let bundleID: String; public let codeRequirement: String
    public let keyFingerprint: String; public let expiresAt: Date

    public init(id: UUID, nonce: String, directory: URL, socketPath: URL, rootPID: Int32, rootStartTime: UInt64,
                bundleID: String, codeRequirement: String, keyFingerprint: String, expiresAt: Date)
    {
        self.id = id; self.nonce = nonce; self.directory = directory; self.socketPath = socketPath
        self.rootPID = rootPID; self.rootStartTime = rootStartTime; self.bundleID = bundleID
        self.codeRequirement = codeRequirement; self.keyFingerprint = keyFingerprint; self.expiresAt = expiresAt
    }
}

public struct VerifiedSessionReservation: Sendable, Equatable {
    public let id: UUID; public let nonce: String; public let directory: URL; public let socketPath: URL
    public let keyFingerprint: String; public let expiresAt: Date

    public init(id: UUID, nonce: String, directory: URL, socketPath: URL, keyFingerprint: String, expiresAt: Date) {
        self.id = id; self.nonce = nonce; self.directory = directory; self.socketPath = socketPath
        self.keyFingerprint = keyFingerprint; self.expiresAt = expiresAt
    }
}

public struct ProcessSnapshot: Sendable, Equatable {
    public let pid: Int32; public let parentPID: Int32; public let startTime: UInt64
    public init(pid: Int32, parentPID: Int32, startTime: UInt64) {
        self.pid = pid; self.parentPID = parentPID; self.startTime = startTime
    }
}

public protocol RequesterInspecting: Sendable {
    func snapshot(of pid: Int32) -> ProcessSnapshot?
    func validatedCodeIdentity(pid: Int32, requirement: String) throws -> String
}

public final class SessionRegistry: @unchecked Sendable {
    fileprivate struct Storage {
        let reservation: VerifiedSessionReservation; let device: dev_t; let inode: ino_t; let directoryFD: Int32
    }

    fileprivate struct Stored {
        var session: VerifiedSession?
        let storage: Storage
    }

    private var sessions: [UUID: Stored] = [:]; private var grants = Set<UUID>()
    private let root: URL; private let fileManager: FileManager; private let rootFD: Int32; private let lock = NSLock()

    public init(root: URL, fileManager: FileManager = .default) throws {
        self.root = root; self.fileManager = fileManager
        try makeSecureDirectory(root, fileManager: fileManager)
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw AgentProtocolError.denied }
        do { let value = try directoryStat(fd); self.rootFD = fd; _ = value } catch { close(fd); throw error }
    }

    deinit {
        for stored in self.sessions.values {
            // Cleanup remains descriptor/inode-bound, so a substituted visible
            // path is never removed during registry teardown.
            try? cleanupOwned(stored.storage, rootFD: self.rootFD)
        }
        close(rootFD)
    }

    public func reserve(keyFingerprint: String, expiresAt: Date) throws -> VerifiedSessionReservation {
        guard expiresAt > .now, !keyFingerprint.isEmpty else { throw AgentProtocolError.denied }
        self.lock.lock(); defer { lock.unlock() }
        let id = UUID(); let directory = self.root.appendingPathComponent(id.uuidString, isDirectory: true)
        var directoryCreated = false; var fd: Int32 = -1
        defer {
            if fd >= 0 {
                close(fd)
            }
        }
        do {
            guard mkdirat(self.rootFD, id.uuidString, 0o700) == 0 else { throw AgentProtocolError.denied }
            directoryCreated = true
            fd = openat(self.rootFD, id.uuidString, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw AgentProtocolError.denied }
            let stat = try directoryStat(fd)
            let reservation = VerifiedSessionReservation(
                id: id,
                nonce: UUID().uuidString.replacingOccurrences(of: "-", with: ""),
                directory: directory,
                socketPath: directory.appendingPathComponent("agent.sock"),
                keyFingerprint: keyFingerprint,
                expiresAt: expiresAt
            )
            self.sessions[id] = Stored(
                session: nil,
                storage: Storage(reservation: reservation, device: stat.st_dev, inode: stat.st_ino, directoryFD: fd)
            )
            fd = -1
            return reservation
        } catch {
            if directoryCreated {
                _ = unlinkat(self.rootFD, id.uuidString, AT_REMOVEDIR)
            }
            throw error
        }
    }

    public func activate(
        reservation: VerifiedSessionReservation,
        rootPID: Int32,
        rootStartTime: UInt64,
        bundleID: String,
        codeRequirement: String,
        inspector: any RequesterInspecting = SystemRequesterInspector(),
        now: Date = .now
    ) throws -> VerifiedSession {
        guard rootPID > 0, rootStartTime > 0, !bundleID.isEmpty, !codeRequirement.isEmpty else {
            self.revoke(reservation.id)
            throw AgentProtocolError.denied
        }
        self.lock.lock(); defer { lock.unlock() }
        guard var stored = self.sessions[reservation.id] else {
            self.removeLocked(reservation.id)
            throw AgentProtocolError.denied
        }
        // A repeated activation must never tear down the already-valid live
        // session.  Only a malformed/stale *pending* capability is revoked.
        guard stored.session == nil else { throw AgentProtocolError.denied }
        guard stored.storage.reservation.expiresAt > now,
              constantTimeEqual(Data(reservation.nonce.utf8), Data(stored.storage.reservation.nonce.utf8)),
              inspector.snapshot(of: rootPID)?.startTime == rootStartTime,
              (try? inspector.validatedCodeIdentity(pid: rootPID, requirement: codeRequirement)) == bundleID
        else {
            self.removeLocked(reservation.id)
            throw AgentProtocolError.denied
        }
        let pending = stored.storage.reservation
        let session = VerifiedSession(
            id: pending.id,
            nonce: pending.nonce,
            directory: pending.directory,
            socketPath: pending.socketPath,
            rootPID: rootPID,
            rootStartTime: rootStartTime,
            bundleID: bundleID,
            codeRequirement: codeRequirement,
            keyFingerprint: pending.keyFingerprint,
            expiresAt: pending.expiresAt
        )
        stored.session = session
        self.sessions[reservation.id] = stored
        return session
    }

    // swiftlint:disable:next function_parameter_count
    public func create(rootPID: Int32, rootStartTime: UInt64, bundleID: String, codeRequirement: String,
                       keyFingerprint: String, expiresAt: Date,
                       inspector: any RequesterInspecting = SystemRequesterInspector()) throws -> VerifiedSession
    {
        let reservation = try self.reserve(keyFingerprint: keyFingerprint, expiresAt: expiresAt)
        return try self.activate(
            reservation: reservation,
            rootPID: rootPID,
            rootStartTime: rootStartTime,
            bundleID: bundleID,
            codeRequirement: codeRequirement,
            inspector: inspector
        )
    }

    public func authorize(_ id: UUID, now: Date = .now) -> Bool {
        self.lock.lock(); defer { lock.unlock() }
        guard let stored = activeLocked(id, now: now), let session = stored.session
        else { return false }; self.grants.insert(session.id); return true
    }

    public func session(_ id: UUID, now: Date = .now) -> VerifiedSession? {
        self.lock.lock(); defer { lock.unlock() }; return self.activeLocked(id, now: now)?.session
    }

    /// Returns metadata for a session which has reserved its private socket but
    /// has not necessarily been activated yet.  This is intentionally not an
    /// authorization decision: only `session(_:)` represents an active grant.
    public func reservation(_ id: UUID, now: Date = .now) -> VerifiedSessionReservation? {
        self.lock.lock(); defer { lock.unlock() }
        guard let stored = self.sessions[id], stored.storage.reservation.expiresAt > now else {
            return nil
        }
        return stored.storage.reservation
    }

    /// Returns the visible socket path only while it names the directory object
    /// retained by this registry. Darwin has no `bindat`; callers must repeat
    /// this check after `bind` and revoke on any substitution.
    public func pinnedSocketBindPath(for id: UUID, now: Date = .now) -> String? {
        self.lock.lock(); defer { self.lock.unlock() }
        guard let stored = self.sessions[id], stored.storage.reservation.expiresAt > now,
              let current = try? directoryStat(stored.storage.directoryFD),
              current.st_dev == stored.storage.device, current.st_ino == stored.storage.inode,
              visibleStorageMatches(stored.storage)
        else { return nil }
        return stored.storage.reservation.socketPath.path
    }

    /// Removes the private socket by directory descriptor. This remains safe
    /// if an attacker renames the visible session directory after reservation.
    public func removeSocket(for id: UUID) {
        self.lock.lock(); defer { self.lock.unlock() }
        guard let stored = self.sessions[id] else { return }
        _ = unlinkat(stored.storage.directoryFD, "agent.sock", 0)
    }

    public func secureSocketPermissions(for id: UUID) -> Bool {
        self.lock.lock(); defer { self.lock.unlock() }
        guard let stored = self.sessions[id],
              let current = try? directoryStat(stored.storage.directoryFD),
              current.st_dev == stored.storage.device, current.st_ino == stored.storage.inode
        else { return false }
        return fchmodat(stored.storage.directoryFD, "agent.sock", 0o600, 0) == 0
    }

    public func validateBoundSocket(for id: UUID) -> Bool {
        self.lock.lock(); defer { self.lock.unlock() }
        guard let stored = self.sessions[id], visibleStorageMatches(stored.storage) else { return false }
        var socket = stat()
        guard lstat(stored.storage.reservation.socketPath.path, &socket) == 0,
              socket.st_mode & S_IFMT == S_IFSOCK, socket.st_uid == getuid(), socket.st_mode & 0o077 == 0
        else { return false }
        return true
    }

    public func verifySign(sessionID: UUID, signerFingerprint: String, now: Date = .now) -> VerifiedSession? {
        self.lock.lock(); defer { lock.unlock() }
        guard let stored = activeLocked(sessionID, now: now), let session = stored.session, grants.contains(sessionID),
              constantTimeEqual(Data(session.keyFingerprint.utf8), Data(signerFingerprint.utf8))
        else { return nil }
        return session
    }

    public func revoke(_ id: UUID) {
        self.lock.lock(); defer { lock.unlock() }; self.removeLocked(id)
    }

    public func expire(now: Date = .now) {
        self.lock.lock(); defer { lock.unlock() }
        for id in Array(self.sessions.keys)
            where self.sessions[id]?.storage.reservation.expiresAt ?? .distantFuture <= now
        {
            self.removeLocked(id)
        }
    }

    public func revokeDeadRoots(inspector: any RequesterInspecting = SystemRequesterInspector()) {
        self.lock.lock(); defer { lock.unlock() }
        for (id, stored) in self.sessions
            where stored.session.map({ session in
                inspector.snapshot(of: session.rootPID)?.startTime != session.rootStartTime
            }) ?? false
        {
            removeLocked(id)
        }
    }

    private func activeLocked(_ id: UUID, now: Date) -> Stored? {
        guard let stored = sessions[id] else { return nil }
        guard stored.storage.reservation.expiresAt > now else { self.removeLocked(id); return nil }
        guard stored.session != nil else { return nil }
        return stored
    }

    private func removeLocked(_ id: UUID) {
        guard let stored = sessions.removeValue(forKey: id) else { return }; self.grants.remove(id)
        try? cleanupOwned(stored.storage, rootFD: self.rootFD)
    }
}

private func makeSecureDirectory(_ url: URL, fileManager: FileManager) throws {
    if !fileManager.fileExists(atPath: url.path) {
        try fileManager.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }
    _ = try ownedDirectoryStat(url)
}

private func ownedDirectoryStat(_ url: URL) throws -> stat {
    var value = stat()
    guard lstat(url.path, &value) == 0, value.st_mode & S_IFMT == S_IFDIR, value.st_uid == getuid(),
          value.st_mode & 0o077 == 0
    else { throw AgentProtocolError.denied }; return value
}

private func directoryStat(_ fd: Int32) throws -> stat {
    var value = stat(); guard fstat(fd, &value) == 0,
                              value.st_mode & S_IFMT == S_IFDIR,
                              value.st_uid == getuid(),
                              value.st_mode & 0o077 == 0
    else {
        throw AgentProtocolError.denied
    }; return value
}

private func removeNewDirectory(_ url: URL) throws {
    _ = try ownedDirectoryStat(url); guard rmdir(url.path) == 0 else { throw AgentProtocolError.denied }
}

private func cleanupOwned(_ storage: SessionRegistry.Storage, rootFD: Int32) throws {
    defer { close(storage.directoryFD) }
    let current = try directoryStat(storage.directoryFD)
    guard current.st_dev == storage.device, current.st_ino == storage.inode else { throw AgentProtocolError.denied }
    _ = unlinkat(storage.directoryFD, "agent.sock", 0)
    var named = stat(); let name = storage.reservation.id.uuidString
    guard fstatat(rootFD, name, &named, AT_SYMLINK_NOFOLLOW) == 0, named.st_dev == storage.device,
          named.st_ino == storage.inode,
          unlinkat(rootFD, name, AT_REMOVEDIR) == 0 else { throw AgentProtocolError.denied }
}

private func visibleStorageMatches(_ storage: SessionRegistry.Storage) -> Bool {
    var visible = stat()
    return lstat(storage.reservation.directory.path, &visible) == 0
        && visible.st_mode & S_IFMT == S_IFDIR
        && visible.st_uid == getuid()
        && visible.st_mode & 0o077 == 0
        && visible.st_dev == storage.device
        && visible.st_ino == storage.inode
}

public struct RequesterPeer: Sendable, Equatable { public let pid: Int32; public let uid: Int32
    public init(pid: Int32, uid: Int32) {
        self.pid = pid; self.uid = uid
    }
}

public enum SocketPeerEvidence {
    public static func read(from socket: Int32) throws -> RequesterPeer {
        var pid: pid_t = 0; var pidLength = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(socket, SOL_LOCAL, LOCAL_PEERPID, &pid, &pidLength) == 0
        else { throw AgentProtocolError.denied }
        var credentials = xucred(); var credentialLength = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(socket, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &credentialLength) == 0
        else { throw AgentProtocolError.denied }
        return try self.validate(
            pid: pid,
            pidLength: pidLength,
            credentials: credentials,
            credentialLength: credentialLength
        )
    }

    public static func validate(pid: pid_t, pidLength: socklen_t, credentials: xucred,
                                credentialLength: socklen_t) throws -> RequesterPeer
    {
        let minimumLength = MemoryLayout.offset(of: \xucred.cr_uid)! + MemoryLayout<uid_t>.size
        guard pidLength == socklen_t(MemoryLayout<pid_t>.size), pid > 0,
              credentialLength >= socklen_t(minimumLength), credentials.cr_version == XUCRED_VERSION,
              credentials.cr_uid != uid_t.max else { throw AgentProtocolError.denied }
        return RequesterPeer(pid: pid, uid: Int32(credentials.cr_uid))
    }
}

public struct RequesterVerifier: Sendable {
    public let inspector: any RequesterInspecting; public let currentUID: Int32; public let maxDepth: Int
    public init(
        inspector: any RequesterInspecting = SystemRequesterInspector(),
        currentUID: Int32 = Int32(getuid()),
        maxDepth: Int = 128
    ) {
        self.inspector = inspector; self.currentUID = currentUID; self.maxDepth = max(0, maxDepth)
    }

    public func verify(peer: RequesterPeer, session: VerifiedSession, now: Date = .now) -> Bool {
        guard peer.uid == self.currentUID, session.expiresAt > now, self.rootOK(session) else { return false }
        guard let first = inspector.snapshot(of: peer.pid),
              let chain = chain(from: first, root: session.rootPID) else { return false }
        guard chain.last?.startTime == session.rootStartTime,
              chain.allSatisfy({ self.inspector.snapshot(of: $0.pid) == $0 }) else { return false }
        return self.rootOK(session)
    }

    private func chain(from first: ProcessSnapshot, root: Int32) -> [ProcessSnapshot]? {
        var value = first; var seen = Set<Int32>(); var result = [ProcessSnapshot]()
        for _ in 0 ..< self.maxDepth {
            guard seen.insert(value.pid).inserted else { return nil }; result.append(value)
            if value.pid == root {
                return result
            }; guard value.parentPID > 0,
                     let next = inspector.snapshot(of: value.parentPID)
            else { return nil }; value = next
        }
        return nil
    }

    private func rootOK(_ session: VerifiedSession) -> Bool {
        guard let root = inspector.snapshot(of: session.rootPID), root.startTime == session.rootStartTime,
              let identity = try? inspector.validatedCodeIdentity(
                  pid: session.rootPID,
                  requirement: session.codeRequirement
              )
        else { return false }
        return identity == session.bundleID
    }
}

public struct SystemRequesterInspector: RequesterInspecting {
    public init() {}
    public func snapshot(of pid: Int32) -> ProcessSnapshot? {
        var info = proc_bsdinfo(); guard proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &info,
            Int32(MemoryLayout<proc_bsdinfo>.size)
        ) == MemoryLayout<proc_bsdinfo>.size else { return nil }; return ProcessSnapshot(
            pid: pid,
            parentPID: Int32(info.pbi_ppid),
            startTime: UInt64(info.pbi_start_tvsec) * 1_000_000 + UInt64(info.pbi_start_tvusec)
        )
    }

    public func validatedCodeIdentity(pid: Int32, requirement: String) throws -> String {
        guard pid > 0, !requirement.isEmpty else { throw AgentProtocolError.denied }
        var code: SecCode?; guard SecCodeCopyGuestWithAttributes(
            nil,
            [kSecGuestAttributePid: pid] as CFDictionary,
            [],
            &code
        ) == errSecSuccess, let code else { throw AgentProtocolError.denied }
        var expected: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &expected) == errSecSuccess,
              let expected else { throw AgentProtocolError.denied }
        guard SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), expected) == errSecSuccess
        else { throw AgentProtocolError.denied }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw AgentProtocolError.denied
        }
        var info: CFDictionary?; guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSRequirementInformation),
            &info
        ) == errSecSuccess, let values = info as? [CFString: Any], let id = values[
            kSecCodeInfoIdentifier
        ] as? String, !id.isEmpty else { throw AgentProtocolError.denied }
        return id
    }
}

public func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
    let maximum = max(
        left.count,
        right.count
    ); var difference = UInt(left.count ^ right.count); for index in 0 ..<
        maximum
    {
        difference |= UInt((index < left.count ? left[index] : 0) ^ (index < right.count ? right[index] : 0))
    }; return difference == 0
}

// swiftlint:enable opening_brace
// swiftlint:enable identifier_name
// swiftlint:enable file_length
