import Darwin
import Foundation

/// Filesystem boundary for the Git-client registry. A lock owns one opened,
/// validated directory capability; mutations must use that capability instead
/// of reopening a mutable pathname after the lock has been acquired.
enum GitClientRegistryFilesystem {
    static let registryFileName = "git-clients.json"
    private static let lockFileName = ".git-clients.lock"

    /// The configured leaf is validated once before any filesystem operation,
    /// then carried into the descriptor-scoped transaction. It never accepts a
    /// nested path or a name reserved for lock/temporary state.
    struct RegistryPath: Sendable {
        fileprivate let directoryURL: URL
        fileprivate let leafName: String
    }

    /// This value deliberately exposes registry operations only. It does not
    /// expose the raw descriptor or accept a caller-controlled pathname.
    struct LockedDirectory {
        private let directoryFD: Int32
        private let registryLeaf: String

        fileprivate init(directoryFD: Int32, registryLeaf: String) {
            self.directoryFD = directoryFD
            self.registryLeaf = registryLeaf
        }

        func readRegistry() throws -> Data {
            try GitClientRegistryFilesystem.readRegistry(directoryFD: self.directoryFD, leafName: self.registryLeaf)
        }

        func readRegistryIfPresent() throws -> Data? {
            try GitClientRegistryFilesystem
                .readRegistryIfPresent(directoryFD: self.directoryFD, leafName: self.registryLeaf)
        }

        func writeRegistry(_ document: GitClientTrustDocument) throws {
            try GitClientRegistryFilesystem
                .writeRegistry(document, directoryFD: self.directoryFD, registryLeaf: self.registryLeaf)
        }
    }

    static func withExclusiveLock<T>(
        registryPath: RegistryPath,
        _ action: (LockedDirectory) throws -> T
    ) throws -> T {
        try self.ensureDirectory(registryPath.directoryURL)
        let directoryFD = try self.openValidatedDirectory(registryPath.directoryURL)
        defer { close(directoryFD) }

        let lockDescriptor = try self.openLock(directoryFD: directoryFD)
        defer { close(lockDescriptor) }
        try self.validate(fileDescriptor: lockDescriptor, type: S_IFREG, mode: 0o600, label: "registry lock")
        guard flock(lockDescriptor, LOCK_EX) == 0 else {
            throw CLIError.providerUnavailable(provider: "git-client", reason: "Failed to lock trust registry.")
        }
        defer { _ = flock(lockDescriptor, LOCK_UN) }
        return try action(LockedDirectory(directoryFD: directoryFD, registryLeaf: registryPath.leafName))
    }

    /// Read-only callers keep the configured pathname entry point. Its leaf is
    /// validated before the directory is opened, and the same leaf is used for
    /// the descriptor-relative operation.
    static func read(fileURL: URL) throws -> Data {
        let registryPath = try self.validatedPath(for: fileURL)
        let directoryFD = try self.openValidatedDirectory(registryPath.directoryURL)
        defer { close(directoryFD) }
        return try self.readRegistry(directoryFD: directoryFD, leafName: registryPath.leafName)
    }

    static func readIfPresent(fileURL: URL) throws -> Data? {
        let registryPath = try self.validatedPath(for: fileURL)
        guard let directoryFD = try self.openValidatedDirectoryIfPresent(registryPath.directoryURL) else {
            return nil
        }
        defer { close(directoryFD) }
        return try self.readRegistryIfPresent(directoryFD: directoryFD, leafName: registryPath.leafName)
    }

    static func validatedPath(for fileURL: URL) throws -> RegistryPath {
        let standardized = fileURL.standardizedFileURL
        let leafName = fileURL.lastPathComponent
        guard fileURL.isFileURL, !fileURL.hasDirectoryPath, standardized.path == fileURL.path,
              Self.validRegistryLeaf(leafName)
        else {
            throw CLIError.invalidArguments(message: "Git client registry path is invalid.")
        }
        return RegistryPath(directoryURL: fileURL.deletingLastPathComponent(), leafName: leafName)
    }

    private static func readRegistry(directoryFD: Int32, leafName: String) throws -> Data {
        guard let data = try self.readRegistryIfPresent(directoryFD: directoryFD, leafName: leafName) else {
            throw CLIError.denied(message: "Git client registry is unavailable or unsafe.")
        }
        return data
    }

    private static func readRegistryIfPresent(directoryFD: Int32, leafName: String) throws -> Data? {
        let fileDescriptor = openat(
            directoryFD, leafName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW
        )
        guard fileDescriptor >= 0 else {
            if errno == ENOENT {
                return nil
            }
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

    private static func writeRegistry(
        _ document: GitClientTrustDocument,
        directoryFD: Int32,
        registryLeaf: String
    ) throws {
        let data = try document.canonicalBytes()
        // A fresh leaf prevents a failed write from blocking authenticated
        // recovery. We never unlink a pre-existing pathname after validating
        // an FD, so a same-UID rename cannot turn cleanup into deletion.
        let temporaryFileName = ".git-clients.\(UUID().uuidString).tmp"
        let fileDescriptor = openat(
            directoryFD, temporaryFileName, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600
        )
        guard fileDescriptor >= 0 else {
            throw CLIError.providerUnavailable(provider: "git-client", reason: "Failed to create registry update.")
        }
        defer { close(fileDescriptor) }
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
              renameat(directoryFD, temporaryFileName, directoryFD, registryLeaf) == 0,
              fsync(directoryFD) == 0
        else {
            throw CLIError.providerUnavailable(
                provider: "git-client",
                reason: "Failed to commit registry update atomically."
            )
        }
    }

    private static func openValidatedDirectory(_ directoryURL: URL) throws -> Int32 {
        let directoryFD = open(directoryURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else {
            throw CLIError.denied(message: "Git client registry directory is unavailable or unsafe.")
        }
        do {
            try self.validate(fileDescriptor: directoryFD, type: S_IFDIR, mode: 0o700, label: "registry directory")
            return directoryFD
        } catch {
            close(directoryFD)
            throw error
        }
    }

    private static func openValidatedDirectoryIfPresent(_ directoryURL: URL) throws -> Int32? {
        let directoryFD = open(directoryURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else {
            if errno == ENOENT {
                return nil
            }
            throw CLIError.denied(message: "Git client registry directory is unavailable or unsafe.")
        }
        do {
            try self.validate(fileDescriptor: directoryFD, type: S_IFDIR, mode: 0o700, label: "registry directory")
            return directoryFD
        } catch {
            close(directoryFD)
            throw error
        }
    }

    private static func openLock(directoryFD: Int32) throws -> Int32 {
        var lockDescriptor = openat(directoryFD, self.lockFileName, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
        if lockDescriptor < 0, errno == ENOENT {
            lockDescriptor = openat(
                directoryFD, self.lockFileName, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600
            )
            if lockDescriptor < 0, errno == EEXIST {
                lockDescriptor = openat(directoryFD, self.lockFileName, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
            }
        }
        guard lockDescriptor >= 0 else { throw CLIError.denied(message: "Git client registry lock is unsafe.") }
        return lockDescriptor
    }

    private static func validRegistryLeaf(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." && !value.hasPrefix(".")
            && value.utf8.count <= 255 && !value.contains("/")
            && !value.unicodeScalars.contains(where: {
                $0.properties.isBidiControl || $0.value < 0x20 || $0.value == 0x7F
            })
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
