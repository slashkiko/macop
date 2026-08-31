import Darwin
import Foundation

// swiftlint:disable file_length type_body_length

/// Installed entrypoints refuse service while the installer has made the
/// generation unavailable. The pending marker is deliberately checked by
/// every executable *before* it parses input or opens an adapter socket.
///
/// A pending generation may run only its two non-interactive doctor checks and
/// the companion's tightly-shaped probe. Those checks require an inherited
/// descriptor for the active journal capability; environment values are hints
/// only and can never by themselves grant the exception.
public enum InstallGenerationGuard {
    public enum InvocationDecision: Equatable, Sendable {
        case permitted
        case blocked(InvocationBlockReason)
    }

    public enum InvocationBlockReason: Equatable, Sendable {
        case updateInProgress
        case recoveryRequired

        public var diagnostic: String {
            switch self {
            case .updateInProgress:
                "installation update is in progress; retry after it completes"
            case .recoveryRequired:
                "installation recovery is required; rerun the macop installer before using macop"
            }
        }
    }

    enum BrokerProbeLaunchPermission: Equatable {
        case notPending
        case authorized(descriptor: Int32)
        case denied
    }

    private static let stateLeaf = "Library/Application Support/macop/install-state"
    private static let capabilityLeaf = "INSTALLER_CAPABILITY"
    private static let pendingLeaf = "PENDING"

    private struct FileIdentity: Equatable {
        let device: Int64
        let inode: UInt64
        let mode: mode_t
        let owner: uid_t

        var isRegularFile: Bool {
            (self.mode & mode_t(S_IFMT)) == mode_t(S_IFREG)
        }

        var isDirectory: Bool {
            (self.mode & mode_t(S_IFMT)) == mode_t(S_IFDIR)
        }

        var isSymbolicLink: Bool {
            (self.mode & mode_t(S_IFMT)) == mode_t(S_IFLNK)
        }
    }

    private struct Capability {
        let nonce: String
        let operations: Set<String>
        let macopExecutable: String
        let authExecutable: String
    }

    /// All entrypoints share this state root. It is not taken from a caller
    /// supplied descriptor: MacopAuth lives in an app bundle, so its image path
    /// cannot be trusted as an installation-root authority.
    public static func stateDirectory(
        environment _: [String: String] = ProcessInfo.processInfo.environment
    ) -> URL {
        self.defaultStateDirectory()
    }

    public static func isAvailable(environment: [String: String] = ProcessInfo.processInfo.environment) -> Bool {
        self.permitsInvocation(argv: CommandLine.arguments, environment: environment)
    }

    public static func permitsInvocation(
        argv: [String],
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> Bool {
        self.invocationDecision(argv: argv, environment: environment) == .permitted
    }

    public static func invocationDecision(
        argv: [String],
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> InvocationDecision {
        self.invocationDecision(argv: argv, environment: environment, executablePath: nil, stateDirectory: nil)
    }

    /// Narrow internal test seam. Production callers can neither select a
    /// state directory nor substitute an executable identity.
    static func permitsInvocation(
        argv: [String],
        environment: [String: String],
        executablePath: String? = nil,
        stateDirectory: URL? = nil
    ) -> Bool {
        self.invocationDecision(
            argv: argv,
            environment: environment,
            executablePath: executablePath,
            stateDirectory: stateDirectory
        ) == .permitted
    }

    static func invocationDecision(
        argv: [String],
        environment: [String: String],
        executablePath: String? = nil,
        stateDirectory: URL? = nil
    ) -> InvocationDecision {
        guard let executable = (try? executablePath ?? RunningExecutable.path()).map(self.canonicalPath) else {
            return .blocked(.recoveryRequired)
        }
        let candidates = stateDirectory.map { [$0] } ?? self.stateDirectoryCandidates(for: executable)
        let pendingStates = candidates.filter { self.pathExists($0.appendingPathComponent("pending")) }
        // Two competing pending markers are ambiguous. Do not guess which
        // transaction supplied a descriptor.
        guard pendingStates.count <= 1 else { return .blocked(.recoveryRequired) }
        guard let activeState = pendingStates.first else { return .permitted }
        if self.permitsPendingInvocation(
            argv: argv,
            environment: environment,
            executable: executable,
            stateDirectory: activeState
        ) {
            return .permitted
        }
        return .blocked(self.hasLiveInstallOwner(in: activeState) ? .updateInProgress : .recoveryRequired)
    }

    /// A broker probe may bypass LaunchServices only while an installer has
    /// validated the caller's inherited journal capability. The permission is
    /// deliberately tri-state: a pending but invalid invocation must not fall
    /// back to the ordinary launcher, because that would hide a broken update.
    static func brokerProbeLaunchPermission(
        argv: [String] = CommandLine.arguments,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        executablePath: String? = nil,
        stateDirectory: URL? = nil
    ) -> BrokerProbeLaunchPermission {
        guard let executable = (try? executablePath ?? RunningExecutable.path()).map(self.canonicalPath) else {
            return .denied
        }
        let candidates = stateDirectory.map { [$0] } ?? self.stateDirectoryCandidates(for: executable)
        let pendingStates = candidates.filter { self.pathExists($0.appendingPathComponent("pending")) }
        guard pendingStates.count <= 1 else { return .denied }
        guard let activeState = pendingStates.first else { return .notPending }
        guard let authorization = self.pendingAuthorization(
            argv: argv,
            environment: environment,
            executable: executable,
            stateDirectory: activeState
        ), authorization.mode == "broker" else { return .denied }
        return .authorized(descriptor: authorization.descriptor)
    }

    private static func permitsPendingInvocation(
        argv: [String],
        environment: [String: String],
        executable: String,
        stateDirectory: URL
    ) -> Bool {
        self.pendingAuthorization(
            argv: argv,
            environment: environment,
            executable: executable,
            stateDirectory: stateDirectory
        ) != nil
    }

    private static func pendingAuthorization(
        argv: [String],
        environment: [String: String],
        executable: String,
        stateDirectory: URL
    ) -> (mode: String, descriptor: Int32)? {
        guard let stateIdentity = self.identity(at: stateDirectory),
              stateIdentity.isDirectory,
              !stateIdentity.isSymbolicLink,
              stateIdentity.owner == geteuid(),
              stateIdentity.mode & 0o077 == 0,
              let pendingIdentity = self.identity(at: stateDirectory.appendingPathComponent("pending")),
              pendingIdentity.isRegularFile,
              !pendingIdentity.isSymbolicLink,
              pendingIdentity.owner == geteuid(),
              let pending = self.parseRecord(at: stateDirectory.appendingPathComponent("pending")),
              let mode = self.operation(for: argv, environment: environment),
              let descriptorText = environment["MACOP_INSTALL_VERIFY_FD"],
              let descriptor = Int32(descriptorText), descriptor >= 0,
              let capability = self.loadCapability(
                  descriptor: descriptor,
                  stateDirectory: stateDirectory,
                  stateIdentity: stateIdentity,
                  pending: pending
              )
        else { return nil }

        guard capability.operations.contains(mode),
              capability.nonce == pending["nonce"],
              (mode == "auth-probe" ? capability.authExecutable : capability.macopExecutable) == executable
        else { return nil }
        return (mode, descriptor)
    }

    private static func operation(for argv: [String], environment: [String: String]) -> String? {
        guard let mode = environment["MACOP_INSTALL_VERIFY_MODE"] else { return nil }
        switch mode {
        case "generation", "broker":
            return argv.count == 2 && argv[1] == "doctor" ? mode : nil
        case "auth-probe":
            // This is the exact argument vector used by the broker launcher.
            return argv.count == 4 && argv[1] == "--socket" && !argv[2].isEmpty && argv[3] == "--probe"
                ? mode : nil
        default:
            return nil
        }
    }

    private static func loadCapability(
        descriptor: Int32,
        stateDirectory: URL,
        stateIdentity: FileIdentity,
        pending: [String: String]
    ) -> Capability? {
        guard let descriptorIdentity = self.identity(ofDescriptor: descriptor),
              descriptorIdentity.isRegularFile,
              descriptorIdentity.owner == geteuid() else { return nil }
        guard let text = self.readDescriptor(descriptor), let record = self.parseRecord(text) else { return nil }
        guard
            self.hasExactKeys(record, [
                "schema", "state", "state_device", "state_inode", "journal", "journal_device", "journal_inode",
                "nonce", "operations", "macop_executable", "auth_executable"
            ]),
            record["schema"] == "1",
            let state = self.existingCanonicalURL(record["state"]),
            state.path == stateDirectory.standardizedFileURL.resolvingSymlinksInPath().path,
            self.identityMatches(record, prefix: "state", identity: stateIdentity),
            let journal = self.existingCanonicalURL(record["journal"]),
            journal.deletingLastPathComponent().path == state.path,
            journal.lastPathComponent.hasPrefix("journal."),
            let journalIdentity = self.identity(at: journal),
            journalIdentity.isDirectory,
            !journalIdentity.isSymbolicLink,
            journalIdentity.owner == geteuid(),
            self.identityMatches(record, prefix: "journal", identity: journalIdentity),
            let journalPending = self.identity(at: journal.appendingPathComponent(self.pendingLeaf)),
            journalPending.isRegularFile,
            !journalPending.isSymbolicLink,
            let journalCapability = self.identity(at: journal.appendingPathComponent(self.capabilityLeaf)),
            journalCapability == descriptorIdentity,
            let nonce = record["nonce"], self.isNonce(nonce),
            pending["schema"] == "1",
            pending["nonce"] == nonce,
            pending["journal"] == journal.path,
            pending["state_device"] == String(stateIdentity.device),
            pending["state_inode"] == String(stateIdentity.inode),
            let operations = record["operations"].map(self.operations),
            !operations.isEmpty,
            let macopExecutable = record["macop_executable"].flatMap(self.existingCanonicalURL)?.path,
            let authExecutable = record["auth_executable"].flatMap(self.existingCanonicalURL)?.path
        else { return nil }
        return Capability(
            nonce: nonce,
            operations: operations,
            macopExecutable: macopExecutable,
            authExecutable: authExecutable
        )
    }

    private static func stateDirectoryCandidates(for executable: String) -> [URL] {
        let executableURL = URL(fileURLWithPath: executable)
        var candidates = [self.defaultStateDirectory(), executableURL.deletingLastPathComponent()
            .appendingPathComponent(".macop-install-state", isDirectory: true)]
        var current = executableURL.deletingLastPathComponent()
        while current.path != "/" {
            if current.lastPathComponent == "MacopAuth.app" {
                candidates.append(current.deletingLastPathComponent()
                    .appendingPathComponent(".macop-install-state", isDirectory: true))
                break
            }
            current.deleteLastPathComponent()
        }
        var seen = Set<String>()
        return candidates.filter { seen.insert($0.standardizedFileURL.path).inserted }
    }

    private static func defaultStateDirectory() -> URL {
        URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(self.stateLeaf, isDirectory: true)
    }

    private static func pathExists(_ url: URL) -> Bool {
        self.identity(at: url) != nil
    }

    /// This check affects diagnostics only; it never grants an invocation.
    /// Malformed, replaced, and non-live locks are classified as requiring
    /// recovery rather than being treated as authorization evidence.
    private static func hasLiveInstallOwner(in stateDirectory: URL) -> Bool {
        let lock = stateDirectory.appendingPathComponent("lock", isDirectory: true)
        let owner = lock.appendingPathComponent("pid")
        guard let lockIdentity = self.identity(at: lock),
              lockIdentity.isDirectory,
              !lockIdentity.isSymbolicLink,
              lockIdentity.owner == geteuid(),
              let ownerIdentity = self.identity(at: owner),
              ownerIdentity.isRegularFile,
              !ownerIdentity.isSymbolicLink,
              ownerIdentity.owner == geteuid(),
              let data = try? Data(contentsOf: owner), data.count <= 32,
              let text = String(data: data, encoding: .utf8),
              text.hasSuffix("\n"),
              let pid = Int32(text.dropLast()), pid > 0
        else { return false }
        return kill(pid, 0) == 0 || errno == EPERM
    }

    private static func canonicalPath(_ path: String) -> String {
        URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().path
    }

    private static func existingCanonicalURL(_ path: String?) -> URL? {
        guard let path, path.hasPrefix("/"), !path.contains("\u{0000}") else { return nil }
        let url = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
        return url.path == path ? url : nil
    }

    private static func identity(at url: URL) -> FileIdentity? {
        var value = stat()
        guard lstat(url.path, &value) == 0 else { return nil }
        return FileIdentity(
            device: Int64(value.st_dev), inode: UInt64(value.st_ino), mode: value.st_mode,
            owner: value.st_uid
        )
    }

    private static func identity(ofDescriptor descriptor: Int32) -> FileIdentity? {
        var value = stat()
        guard fstat(descriptor, &value) == 0 else { return nil }
        return FileIdentity(
            device: Int64(value.st_dev), inode: UInt64(value.st_ino), mode: value.st_mode,
            owner: value.st_uid
        )
    }

    private static func readDescriptor(_ descriptor: Int32) -> String? {
        guard lseek(descriptor, 0, SEEK_SET) != -1,
              let data = try? FileHandle(fileDescriptor: descriptor, closeOnDealloc: false).readToEnd(),
              data.count <= 8192
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func parseRecord(at url: URL) -> [String: String]? {
        guard let data = try? Data(contentsOf: url), data.count <= 8192,
              let text = String(data: data, encoding: .utf8) else { return nil }
        return self.parseRecord(text)
    }

    private static func parseRecord(_ text: String) -> [String: String]? {
        guard text.hasSuffix("\n") else { return nil }
        var values = [String: String]()
        for line in text.dropLast().split(separator: "\n", omittingEmptySubsequences: false) {
            guard !line.isEmpty, let separator = line.firstIndex(of: "=") else { return nil }
            let key = String(line[..<separator])
            let value = String(line[line.index(after: separator)...])
            guard !key.isEmpty, !value.isEmpty, values[key] == nil,
                  key.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") })
            else { return nil }
            values[key] = value
        }
        return values
    }

    private static func hasExactKeys(_ values: [String: String], _ required: Set<String>) -> Bool {
        Set(values.keys) == required
    }

    private static func identityMatches(_ values: [String: String], prefix: String, identity: FileIdentity) -> Bool {
        values["\(prefix)_device"] == String(identity.device)
            && values["\(prefix)_inode"] == String(identity.inode)
    }

    private static func isNonce(_ value: String) -> Bool {
        value.count == 36 && value.allSatisfy { $0.isASCII && ($0.isHexDigit || $0 == "-") }
    }

    private static func operations(_ value: String) -> Set<String> {
        let values = value.split(separator: ",").map(String.init)
        let allowed: Set = ["generation", "broker", "auth-probe"]
        let set = Set(values)
        return !values.isEmpty && values.count == set.count && set.isSubset(of: allowed) ? set : []
    }
}

// swiftlint:enable type_body_length
