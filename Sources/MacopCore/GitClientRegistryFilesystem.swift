import Darwin
import Foundation

enum GitClientRegistryFilesystem {
    static func withExclusiveLock<T>(directoryURL: URL, _ action: () throws -> T) throws -> T {
        try self.ensureDirectory(directoryURL)
        let directoryFD = open(directoryURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else { throw CLIError.denied(message: "Git client registry directory is unsafe.") }
        defer { close(directoryFD) }
        try self.validate(fileDescriptor: directoryFD, type: S_IFDIR, mode: 0o700, label: "registry directory")
        var lockDescriptor = openat(directoryFD, ".git-clients.lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW)
        if lockDescriptor < 0, errno == ENOENT {
            lockDescriptor = openat(
                directoryFD, ".git-clients.lock", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600
            )
            if lockDescriptor < 0, errno == EEXIST {
                lockDescriptor = openat(directoryFD, ".git-clients.lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW)
            }
        }
        guard lockDescriptor >= 0 else { throw CLIError.denied(message: "Git client registry lock is unsafe.") }
        defer { close(lockDescriptor) }
        try self.validate(fileDescriptor: lockDescriptor, type: S_IFREG, mode: 0o600, label: "registry lock")
        guard flock(lockDescriptor, LOCK_EX) == 0 else {
            throw CLIError.providerUnavailable(provider: "git-client", reason: "Failed to lock trust registry.")
        }
        defer { _ = flock(lockDescriptor, LOCK_UN) }
        return try action()
    }

    static func read(fileURL: URL) throws -> Data {
        let directoryURL = fileURL.deletingLastPathComponent()
        let directoryFD = open(directoryURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else {
            throw CLIError.denied(message: "Git client registry directory is unavailable or unsafe.")
        }
        defer { close(directoryFD) }
        try self.validate(fileDescriptor: directoryFD, type: S_IFDIR, mode: 0o700, label: "registry directory")
        let fileDescriptor = openat(directoryFD, fileURL.lastPathComponent, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fileDescriptor >= 0 else {
            throw CLIError.denied(message: "Git client registry is unavailable or unsafe.")
        }
        defer { close(fileDescriptor) }
        try self.validate(fileDescriptor: fileDescriptor, type: S_IFREG, mode: 0o600, label: "registry file")
        var data = Data(); var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let bufferSize = buffer.count
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fileDescriptor, $0.baseAddress, bufferSize) }
            if count == 0 {
                return data
            }
            guard count > 0 else {
                if errno == EINTR {
                    continue
                }
                throw CLIError.providerUnavailable(provider: "git-client", reason: "Failed to read trust registry.")
            }
            guard data.count + count <= 1024 * 1024 else {
                throw CLIError.invalidArguments(message: "Git client trust registry is too large.")
            }
            data.append(buffer, count: count)
        }
    }

    static func write(_ document: GitClientTrustDocument, fileURL: URL) throws {
        let directory = fileURL.deletingLastPathComponent()
        try self.ensureDirectory(directory)
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else { throw CLIError.denied(message: "Git client registry directory is unsafe.") }
        defer { close(directoryFD) }
        try self.validate(fileDescriptor: directoryFD, type: S_IFDIR, mode: 0o700, label: "registry directory")
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(document)
        let temporary = ".git-clients.\(UUID().uuidString).tmp"
        let fileDescriptor = openat(
            directoryFD, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600
        )
        guard fileDescriptor >= 0 else {
            throw CLIError.providerUnavailable(provider: "git-client", reason: "Failed to create registry update.")
        }
        var shouldUnlink = true
        defer {
            close(fileDescriptor); if shouldUnlink {
                _ = unlinkat(directoryFD, temporary, 0)
            }
        }
        try self.validate(fileDescriptor: fileDescriptor, type: S_IFREG, mode: 0o600, label: "registry update")
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fileDescriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                guard count > 0 else {
                    throw CLIError.providerUnavailable(
                        provider: "git-client",
                        reason: "Failed to write registry update."
                    )
                }
                offset += count
            }
        }
        guard fsync(fileDescriptor) == 0,
              renameat(directoryFD, temporary, directoryFD, fileURL.lastPathComponent) == 0,
              fsync(directoryFD) == 0
        else {
            throw CLIError.providerUnavailable(
                provider: "git-client",
                reason: "Failed to commit registry update atomically."
            )
        }
        shouldUnlink = false
    }

    private static func validate(fileDescriptor: Int32, type: mode_t, mode: mode_t, label: String) throws {
        var details = stat()
        guard fstat(fileDescriptor, &details) == 0, details.st_mode & S_IFMT == type,
              details.st_uid == getuid(), details.st_mode & 0o777 == mode
        else {
            throw CLIError.denied(
                message: "Git client \(label) must be owned by the current user with mode \(String(format: "%04o", mode))."
            )
        }
        errno = 0
        guard let acl = acl_get_fd_np(fileDescriptor, ACL_TYPE_EXTENDED) else {
            guard errno == ENOENT || errno == ENOTSUP else {
                throw CLIError.denied(message: "Git client \(label) ACL could not be validated.")
            }
            return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        let result = acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry)
        guard result == -1, errno == EINVAL else {
            throw CLIError.denied(message: "Git client \(label) must not grant access through an extended ACL.")
        }
    }

    private static func ensureDirectory(_ directoryURL: URL) throws {
        if mkdir(directoryURL.path, 0o700) == 0 || errno == EEXIST {
            return
        }
        throw CLIError.providerUnavailable(
            provider: "git-client", reason: "Failed to create the machine-local registry directory."
        )
    }
}
