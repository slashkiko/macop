import Darwin
import Foundation

enum ConfigFilesystemValidator {
    static func readValidated(fileURL: URL) throws -> Data {
        let directoryURL = fileURL.deletingLastPathComponent()
        let directoryFD = open(directoryURL.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else { throw self.openError(errno, description: "Config directory") }
        defer { close(directoryFD) }
        try self.validate(descriptor: directoryFD, description: "Config directory", type: S_IFDIR, mode: 0o700)

        // Inspect mode 000 before opening. The later O_NOFOLLOW open and fstat
        // bind the actual read to the object that passed validation.
        var entryDetails = stat()
        guard fstatat(directoryFD, "config.json", &entryDetails, AT_SYMLINK_NOFOLLOW) == 0 else {
            throw self.openError(errno, description: "Config file")
        }
        try self.validate(details: entryDetails, description: "Config file", type: S_IFREG, mode: 0o600)

        let fileFD = openat(directoryFD, "config.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fileFD >= 0 else { throw self.openError(errno, description: "Config file") }
        defer { close(fileFD) }
        try self.validate(descriptor: fileFD, description: "Config file", type: S_IFREG, mode: 0o600)
        return try self.readAll(descriptor: fileFD)
    }

    private static func validate(descriptor: Int32, description: String, type: mode_t, mode: mode_t) throws {
        var details = stat()
        guard fstat(descriptor, &details) == 0 else {
            throw CLIError.providerUnavailable(
                provider: "config",
                reason: "Unable to inspect \(description.lowercased())."
            )
        }
        try self.validate(details: details, description: description, type: type, mode: mode)
        try self.validateACL(descriptor: descriptor, description: description)
    }

    private static func validateACL(descriptor: Int32, description: String) throws {
        errno = 0
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            // APFS and some synthesized filesystems report no extended ACL.
            if errno == ENOENT || errno == ENOTSUP {
                return
            }
            throw CLIError.providerUnavailable(
                provider: "config",
                reason: "Unable to inspect \(description.lowercased()) ACL."
            )
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        let result = acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry)
        if result == 0 {
            throw CLIError.invalidArguments(message: "\(description) must not grant access through an extended ACL.")
        }
        // Darwin reports an empty extended ACL as -1/EINVAL. Treat only that
        // documented exhaustion form as safe; every other API failure fails
        // closed rather than weakening owner-only configuration protection.
        guard result == -1, errno == EINVAL else {
            throw CLIError.providerUnavailable(
                provider: "config",
                reason: "Unable to inspect \(description.lowercased()) ACL."
            )
        }
    }

    private static func validate(details: stat, description: String, type: mode_t, mode: mode_t) throws {
        guard (details.st_mode & S_IFMT) == type else {
            throw CLIError.invalidArguments(message: "\(description) must not be a symbolic link or special file.")
        }
        guard details.st_uid == getuid() else {
            throw CLIError.denied(message: "\(description) must be owned by the current user.")
        }
        let actualMode = details.st_mode & 0o777
        guard actualMode == mode else {
            throw CLIError.invalidArguments(
                message: "\(description) permissions must be owner-only (\(String(format: "%04o", mode))). Current mode: \(String(format: "%04o", actualMode))"
            )
        }
    }

    private static func readAll(descriptor: Int32) throws -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let bufferSize = buffer.count
            let count = buffer.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, bufferSize) }
            if count == 0 {
                return data
            }
            if count < 0 {
                if errno == EINTR {
                    continue
                }
                throw CLIError.providerUnavailable(provider: "config", reason: "Failed to read config file.")
            }
            data.append(buffer, count: count)
        }
    }

    private static func openError(_ code: Int32, description: String) -> CLIError {
        switch code {
        case ENOENT: .notFound(message: "\(description) was not found.")
        case EACCES, EPERM: .denied(message: "Cannot access \(description.lowercased()).")
        case ELOOP, ENOTDIR: .invalidArguments(message: "\(description) must not be a symbolic link or special file.")
        default: .providerUnavailable(provider: "config", reason: "Cannot open \(description.lowercased()).")
        }
    }
}
