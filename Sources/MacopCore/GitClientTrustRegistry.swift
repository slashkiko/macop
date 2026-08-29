import Darwin
import Foundation

public struct GitClientTrustEntry: Codable, Equatable, Sendable {
    public let selectorPath: String
    public let resolvedPath: String
    public let identifier: String
    public let cdHash: String
    public let codeRequirement: String
    public let teamID: String
    public let publisherVerified: Bool
    public let signatureKind: String
    public let version: String

    enum CodingKeys: String, CodingKey {
        case selectorPath = "selector_path"
        case resolvedPath = "resolved_path"
        case identifier
        case cdHash = "cdhash"
        case codeRequirement = "code_requirement"
        case teamID = "team_id"
        case publisherVerified = "publisher_verified"
        case signatureKind = "signature_kind"
        case version
    }
}

struct GitClientTrustDocument: Codable {
    let schemaVersion: Int
    var clients: [GitClientTrustEntry]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case clients
    }
}

public protocol GitClientTrustInspecting: Sendable {
    func inspectSelector(_ selectorPath: String) throws -> LiveCodeIdentity
}

public struct SystemGitClientTrustInspector: GitClientTrustInspecting {
    public init() {}

    public func inspectSelector(_ selectorPath: String) throws -> LiveCodeIdentity {
        let standardized = try GitClientPathPolicy.validateSelector(selectorPath)
        try GitClientPathPolicy.validateChain(standardized)
        let resolved = LiveCodeIdentityInspector.canonicalPath(standardized)
        try GitClientPathPolicy.validateChain(resolved)
        try GitClientPathPolicy.validateExecutable(resolved)
        return try LiveCodeIdentityInspector.inspectStatic(path: resolved)
    }
}

public protocol GitClientTrustRegistryProviding: Sendable {
    func list() throws -> [GitClientTrustEntry]
}

public struct GitClientTrustRegistry: GitClientTrustRegistryProviding, Sendable {
    public static var defaultURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/macop/git-clients.json")
    }

    public let fileURL: URL
    private let inspector: any GitClientTrustInspecting

    public init(
        fileURL: URL = Self.defaultURL,
        inspector: any GitClientTrustInspecting = SystemGitClientTrustInspector()
    ) {
        self.fileURL = fileURL
        self.inspector = inspector
    }

    public func list() throws -> [GitClientTrustEntry] {
        guard self.entryExists() else { return [] }
        let data = try GitClientRegistryFilesystem.read(fileURL: self.fileURL)
        guard !StrictJSONDuplicateKeyScanner.containsDuplicateObjectKey(in: data),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys) == ["schema_version", "clients"],
              root["schema_version"] as? Int == 1,
              let rawClients = root["clients"] as? [[String: Any]],
              rawClients.allSatisfy({ Set($0.keys) == [
                  "selector_path", "resolved_path", "identifier", "cdhash", "code_requirement",
                  "team_id", "publisher_verified", "signature_kind", "version"
              ] })
        else { throw CLIError.invalidArguments(message: "Git client trust registry is malformed.") }
        let document = try JSONDecoder().decode(GitClientTrustDocument.self, from: data)
        guard document.schemaVersion == 1,
              Set(document.clients.map(\ .selectorPath)).count == document.clients.count
        else { throw CLIError.invalidArguments(message: "Git client trust registry is malformed or duplicated.") }
        try document.clients.forEach(Self.validateStoredEntry)
        return document.clients.sorted { $0.selectorPath < $1.selectorPath }
    }

    public func trust(selectorPath: String, version: String) throws -> GitClientTrustEntry {
        let selector = try GitClientPathPolicy.validateSelector(selectorPath)
        let identity = try self.inspector.inspectSelector(selector)
        return try self.commitTrust(selector: selector, inspected: identity, version: version)
    }

    public func trust(
        selectorPath: String,
        versionProbe: (String) -> String
    ) throws -> GitClientTrustEntry {
        let selector = try GitClientPathPolicy.validateSelector(selectorPath)
        let identity = try self.inspector.inspectSelector(selector)
        let version = versionProbe(identity.canonicalPath)
        return try self.commitTrust(selector: selector, inspected: identity, version: version)
    }

    private func commitTrust(
        selector: String,
        inspected identity: LiveCodeIdentity,
        version: String
    ) throws -> GitClientTrustEntry {
        guard let cdHash = identity.cdHash, Self.safeHex(cdHash), Self.safeIdentifier(identity.identifier) else {
            throw CLIError.denied(message: "Git client does not expose an exact code identity that macop can pin.")
        }
        let requirement = try LiveCodeIdentityInspector.finalRequirementText(for: identity)
        let entry = GitClientTrustEntry(
            selectorPath: selector,
            resolvedPath: identity.canonicalPath,
            identifier: identity.identifier,
            cdHash: cdHash,
            codeRequirement: requirement,
            teamID: identity.teamID ?? "",
            publisherVerified: identity.hasTrustedPublisher,
            signatureKind: Self.safeDisplay(identity.signatureSummary, limit: 512)
                ? identity.signatureSummary : "exact image pinned; signature metadata unavailable",
            version: Self.boundedVersion(version)
        )
        try Self.validateStoredEntry(entry)
        try GitClientRegistryFilesystem.withExclusiveLock(directoryURL: self.fileURL.deletingLastPathComponent()) {
            let current = try self.inspector.inspectSelector(selector)
            guard current.canonicalPath == identity.canonicalPath, current.identifier == identity.identifier,
                  current.cdHash == identity.cdHash
            else { throw CLIError.denied(message: "Git client changed while it was being trusted; retry after review.")
            }
            var clients = try self.list()
            clients.removeAll { $0.selectorPath == selector }
            clients.append(entry)
            try GitClientRegistryFilesystem.write(
                GitClientTrustDocument(
                    schemaVersion: 1, clients: clients.sorted { $0.selectorPath < $1.selectorPath }
                ),
                fileURL: self.fileURL
            )
        }
        return entry
    }

    @discardableResult
    public func remove(selectorPath: String) throws -> GitClientTrustEntry {
        let selector = try GitClientPathPolicy.validateSelector(selectorPath)
        var removed: GitClientTrustEntry?
        try GitClientRegistryFilesystem.withExclusiveLock(directoryURL: self.fileURL.deletingLastPathComponent()) {
            var clients = try self.list()
            guard let index = clients.firstIndex(where: { $0.selectorPath == selector }) else {
                throw CLIError.notFound(message: "Git client selector is not trusted: \(selector)")
            }
            removed = clients.remove(at: index)
            try GitClientRegistryFilesystem.write(
                GitClientTrustDocument(schemaVersion: 1, clients: clients), fileURL: self.fileURL
            )
        }
        guard let removed else { throw CLIError.runtimeError(message: "Git client removal did not complete.") }
        return removed
    }

    private func entryExists() -> Bool {
        var details = stat()
        if lstat(self.fileURL.path, &details) == 0 {
            return true
        }
        return errno != ENOENT
    }

    private static func validateStoredEntry(_ entry: GitClientTrustEntry) throws {
        guard try GitClientPathPolicy.validateSelector(entry.selectorPath) == entry.selectorPath,
              try GitClientPathPolicy.validateSelector(entry.resolvedPath) == entry.resolvedPath,
              self.safeIdentifier(entry.identifier), self.safeHex(entry.cdHash),
              self.validRequirement(entry),
              self.safeDisplay(entry.signatureKind, limit: 512),
              self.safeDisplay(entry.version, limit: 512)
        else { throw CLIError.invalidArguments(message: "Git client trust registry contains an unsafe entry.") }
    }

    private static func safeIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 256 && value.utf8.allSatisfy {
            $0 >= 48 && $0 <= 57 || $0 >= 65 && $0 <= 90 || $0 >= 97 && $0 <= 122 || [45, 46, 95].contains($0)
        }
    }

    private static func safeHex(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy {
            $0 >= 48 && $0 <= 57 || $0 >= 65 && $0 <= 70 || $0 >= 97 && $0 <= 102
        }
    }

    private static func validRequirement(_ entry: GitClientTrustEntry) -> Bool {
        let image = "identifier \"\(entry.identifier)\" and cdhash H\"\(entry.cdHash)\""
        if entry.publisherVerified {
            guard self.safeTeamID(entry.teamID) else { return false }
            return entry.codeRequirement == "anchor apple generic and certificate leaf[subject.OU] = \"\(entry.teamID)\" and \(image)"
        }
        return entry.teamID.isEmpty && entry.codeRequirement == image
    }

    private static func safeTeamID(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 64 && value.utf8.allSatisfy {
            $0 >= 48 && $0 <= 57 || $0 >= 65 && $0 <= 90
        }
    }

    private static func boundedVersion(_ value: String) -> String {
        let line = value.split(whereSeparator: \ .isNewline).first.map(String.init) ?? "unknown"
        guard self.safeDisplay(line, limit: 512) else { return "unknown" }
        return line
    }

    private static func safeDisplay(_ value: String, limit: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= limit
            && !value.unicodeScalars.contains(where: {
                $0.properties.isBidiControl || $0.value < 0x20 || $0.value == 0x7F
            })
    }
}

public enum GitClientRequesterTrust {
    public static func registeredCandidate(
        entries: [GitClientTrustEntry],
        livePath: String,
        resolve: (String) throws -> LiveCodeIdentity
    ) throws -> (entry: GitClientTrustEntry, current: LiveCodeIdentity)? {
        for entry in entries {
            let current = try? resolve(entry.selectorPath)
            if entry.resolvedPath == livePath || current?.canonicalPath == livePath {
                guard let current else {
                    throw CLIError.denied(
                        message: "The trusted Git selector is unavailable. Re-run `macop ssh git-client trust \(entry.selectorPath)` after review."
                    )
                }
                return (entry, current)
            }
        }
        return nil
    }

    public static func validatePinnedEntry(
        _ entry: GitClientTrustEntry,
        current: LiveCodeIdentity,
        live: LiveCodeInspection,
        before: ProcessSnapshot,
        after: ProcessSnapshot?
    ) throws {
        guard current.canonicalPath == entry.resolvedPath, current.identifier == entry.identifier,
              current.cdHash == entry.cdHash,
              live.identity.canonicalPath == entry.resolvedPath, live.identity.identifier == entry.identifier,
              live.identity.cdHash == entry.cdHash, live.codeRequirement == entry.codeRequirement,
              after == before
        else { throw CLIError.denied(message: "The trusted Git client changed; review it and run trust again.") }
    }

    public static func validateRegisteredProcess(
        entry: GitClientTrustEntry,
        current: LiveCodeIdentity,
        before: ProcessSnapshot,
        after: @autoclosure () -> ProcessSnapshot?,
        liveInspection: () throws -> LiveCodeInspection
    ) throws -> LiveCodeInspection {
        do {
            guard current.canonicalPath == entry.resolvedPath, current.identifier == entry.identifier,
                  current.cdHash == entry.cdHash
            else { throw AgentProtocolError.denied }
            let live = try liveInspection()
            try self.validatePinnedEntry(entry, current: current, live: live, before: before, after: after())
            return live
        } catch {
            throw CLIError.denied(
                message: "The trusted Git client changed. Re-run `macop ssh git-client trust \(entry.selectorPath)` after reviewing the update."
            )
        }
    }

    public static func validate(
        pid: Int32,
        registry: any GitClientTrustRegistryProviding = GitClientTrustRegistry()
    ) throws -> LiveCodeInspection {
        guard pid > 1, let before = SystemRequesterInspector().snapshot(of: pid) else {
            throw CLIError.denied(message: "The Git SSH adapter parent could not be inspected.")
        }
        let path = try self.executablePath(pid: pid)
        if let apple = try? LiveCodeIdentityInspector.inspectExpectedAppleGit(pid: pid, expectedPath: path) {
            guard SystemRequesterInspector().snapshot(of: pid) == before else { throw AgentProtocolError.denied }
            return apple
        }
        let entries = try registry.list()
        let matched = try self.registeredCandidate(entries: entries, livePath: path) {
            try SystemGitClientTrustInspector().inspectSelector($0)
        }
        guard let (entry, current) = matched else {
            throw CLIError.denied(
                message: "This non-Apple Git client is not trusted. Run `macop ssh git-client trust <absolute-git-path>` first."
            )
        }
        return try self.validateRegisteredProcess(
            entry: entry, current: current, before: before,
            after: SystemRequesterInspector().snapshot(of: pid),
            liveInspection: { try LiveCodeIdentityInspector.inspect(pid: pid, expectedPath: entry.resolvedPath) }
        )
    }

    private static func executablePath(pid: Int32) throws -> String {
        var buffer = [CChar](repeating: 0, count: 4096)
        let count = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard count > 0 else { throw AgentProtocolError.denied }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        guard let value = String(bytes: bytes, encoding: .utf8) else { throw AgentProtocolError.denied }
        return LiveCodeIdentityInspector.canonicalPath(value)
    }
}

enum GitClientPathPolicy {
    static func validateSelector(_ path: String) throws -> String {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        guard path.hasPrefix("/"), standardized == path, path.utf8.count <= 4096,
              !path.unicodeScalars
              .contains(where: { $0.properties.isBidiControl || $0.value < 0x20 || $0.value == 0x7F })
        else {
            throw CLIError
                .invalidArguments(message: "Git client selector must be an absolute standardized control-free path.")
        }
        return standardized
    }

    static func validateChain(_ path: String) throws {
        var current = "/"
        for component in path.split(separator: "/") {
            current = URL(fileURLWithPath: current).appendingPathComponent(String(component)).path
            var details = stat()
            guard lstat(current, &details) == 0 else {
                throw CLIError.notFound(message: "Git client path was not found: \(path)")
            }
            let type = details.st_mode & S_IFMT
            let ownerControlledWrite = details.st_mode & 0o002 == 0
                && (details.st_uid == getuid() || details.st_mode & 0o020 == 0)
            guard type == S_IFDIR || type == S_IFREG || type == S_IFLNK,
                  details.st_uid == 0 || details.st_uid == getuid(),
                  type == S_IFLNK || ownerControlledWrite
            else { throw CLIError.denied(message: "Git client path contains an unsafe component: \(current)") }
        }
    }

    static func validateExecutable(_ path: String) throws {
        var details = stat()
        guard lstat(path, &details) == 0, details.st_mode & S_IFMT == S_IFREG,
              details.st_uid == 0 || details.st_uid == getuid(), details.st_mode & 0o002 == 0,
              details.st_uid == getuid() || details.st_mode & 0o020 == 0,
              details.st_mode & 0o111 != 0
        else { throw CLIError.denied(message: "Resolved Git client must be an owner-controlled regular executable.") }
    }
}
