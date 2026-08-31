// swiftlint:disable file_length
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

/// Kept only to inspect and migrate an old on-disk file.  It is never returned
/// by `list()` and is never passed to requester validation.
private struct LegacyGitClientTrustDocument: Codable {
    let schemaVersion: Int
    let clients: [GitClientTrustEntry]
    static let entryKeys: Set<String> = [
        "selector_path", "resolved_path", "identifier", "cdhash", "code_requirement", "team_id",
        "publisher_verified", "signature_kind", "version"
    ]
    enum CodingKeys: String, CodingKey { case schemaVersion = "schema_version", clients }
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

public protocol GitClientTrustDocumentVerifying: Sendable {
    func verify(document: GitClientTrustDocument, canonicalDocument: Data, digest: Data) throws
}

public protocol GitClientTrustDocumentMutating: Sendable {
    func authorizeMutation(
        operation: GitClientTrustMutationOperation,
        expectedGeneration: UInt64,
        nextDocument: GitClientTrustDocument,
        canonicalDocument: Data,
        digest: Data
    ) throws
}

public protocol GitClientTrustProtectedStateQuerying: Sendable {
    /// `nil` is an authenticated key-loss/no-state verdict, never an inferred
    /// filesystem generation.
    func protectedGeneration() throws -> UInt64?
}

public enum GitClientTrustMutationOperation: UInt8, Sendable, Equatable {
    case enroll = 1
    case remove = 2
    case migrate = 3
    case reset = 4
}

/// Production callers must obtain the authenticated verdict from MacopAuth;
/// tests can inject a deterministic verifier without exposing protected state.
public struct RejectingGitClientTrustDocumentVerifier: GitClientTrustDocumentVerifying {
    public init() {}
    public func verify(document: GitClientTrustDocument, canonicalDocument: Data, digest: Data) throws {
        throw CLIError.providerUnavailable(
            provider: "MacopAuth",
            reason: "Git client trust state could not be verified."
        )
    }
}

public struct GitClientTrustRegistry: GitClientTrustRegistryProviding, Sendable {
    public static var defaultURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/macop/git-clients.json")
    }

    public let fileURL: URL
    private let inspector: any GitClientTrustInspecting
    private let verifier: any GitClientTrustDocumentVerifying
    private let mutator: any GitClientTrustDocumentMutating

    public init(
        fileURL: URL = Self.defaultURL,
        inspector: any GitClientTrustInspecting = SystemGitClientTrustInspector(),
        verifier: any GitClientTrustDocumentVerifying = AuthBrokerGitClientTrustVerifier(),
        mutator: any GitClientTrustDocumentMutating = AuthBrokerGitClientTrustVerifier()
    ) {
        self.fileURL = fileURL
        self.inspector = inspector
        self.verifier = verifier
        self.mutator = mutator
    }

    public func list() throws -> [GitClientTrustEntry] {
        guard let data = try GitClientRegistryFilesystem.readIfPresent(fileURL: self.fileURL) else {
            guard try self.protectedGeneration() == nil else {
                throw CLIError.denied(
                    message: "Git client trust registry is missing while protected trust state still exists. "
                        + "Restore the registry or run the authenticated reset."
                )
            }
            return []
        }
        let document: GitClientTrustDocument
        do { document = try GitClientTrustDocument.decodeCanonical(data) } catch {
            throw CLIError
                .invalidArguments(
                    message: "Git client trust registry is malformed, legacy, or non-canonical. Run the authenticated migration."
                )
        }
        let canonical = try document.canonicalBytes()
        try self.verifier.verify(document: document, canonicalDocument: canonical, digest: document.digest())
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
        let registryPath = try GitClientRegistryFilesystem.validatedPath(for: self.fileURL)
        try GitClientRegistryFilesystem
            .withExclusiveLock(registryPath: registryPath) { directory in
                let current = try self.inspector.inspectSelector(selector)
                guard current.canonicalPath == identity.canonicalPath, current.identifier == identity.identifier,
                      current.cdHash == identity.cdHash
                else {
                    throw CLIError.denied(message: "Git client changed while it was being trusted; retry after review.")
                }
                let currentDocument = try self.loadDocumentForMutation(in: directory)
                var clients = currentDocument.clients
                clients.removeAll { $0.selectorPath == selector }
                clients.append(entry)
                try directory.writeRegistry(
                    self.authorizeMutation(
                        operation: .enroll,
                        currentGeneration: currentDocument.generation,
                        clients: clients
                    )
                )
            }
        return entry
    }

    @discardableResult
    public func remove(selectorPath: String) throws -> GitClientTrustEntry {
        let selector = try GitClientPathPolicy.validateSelector(selectorPath)
        var removed: GitClientTrustEntry?
        let registryPath = try GitClientRegistryFilesystem.validatedPath(for: self.fileURL)
        try GitClientRegistryFilesystem
            .withExclusiveLock(registryPath: registryPath) { directory in
                let current = try self.loadDocumentForMutation(in: directory)
                var clients = current.clients
                guard let index = clients.firstIndex(where: { $0.selectorPath == selector }) else {
                    throw CLIError.notFound(message: "Git client selector is not trusted: \(selector)")
                }
                removed = clients.remove(at: index)
                try directory.writeRegistry(
                    self.authorizeMutation(operation: .remove, currentGeneration: current.generation, clients: clients)
                )
            }
        guard let removed else { throw CLIError.runtimeError(message: "Git client removal did not complete.") }
        return removed
    }

    /// v1 was never a trusted input.  Migration re-inspects every selector and
    /// requires MacopAuth to approve the newly pinned complete v2 set.
    public func migrateLegacy(versionProbe: (String) -> String) throws -> [GitClientTrustEntry] {
        let registryPath = try GitClientRegistryFilesystem.validatedPath(for: self.fileURL)
        return try GitClientRegistryFilesystem
            .withExclusiveLock(registryPath: registryPath) { directory in
                let legacy = try self.loadLegacyInspectionDocument(in: directory)
                var clients: [GitClientTrustEntry] = []
                for old in legacy.clients {
                    let selector = try GitClientPathPolicy.validateSelector(old.selectorPath)
                    let identity = try self.inspector.inspectSelector(selector)
                    guard let cdHash = identity.cdHash, Self.safeHex(cdHash),
                          Self.safeIdentifier(identity.identifier)
                    else {
                        throw CLIError
                            .denied(message: "Legacy Git client no longer has a pinnable live identity: \(selector)")
                    }
                    let entry = try GitClientTrustEntry(
                        selectorPath: selector, resolvedPath: identity.canonicalPath, identifier: identity.identifier,
                        cdHash: cdHash, codeRequirement: LiveCodeIdentityInspector.finalRequirementText(for: identity),
                        teamID: identity.teamID ?? "", publisherVerified: identity.hasTrustedPublisher,
                        signatureKind: Self.safeDisplay(identity.signatureSummary, limit: 512) ? identity
                            .signatureSummary : "exact image pinned; signature metadata unavailable",
                        version: Self.boundedVersion(versionProbe(identity.canonicalPath))
                    )
                    try Self.validateStoredEntry(entry); clients.append(entry)
                }
                guard Set(clients.map(\ .selectorPath)).count == clients.count else {
                    throw CLIError.invalidArguments(message: "Legacy Git client registry contains duplicate selectors.")
                }
                let next = try self.authorizeMutation(
                    operation: .migrate, currentGeneration: self.protectedGenerationForRecovery(), clients: clients
                )
                try directory.writeRegistry(next)
                return next.clients.sorted { $0.selectorPath < $1.selectorPath }
            }
    }

    public func reset() throws {
        let registryPath = try GitClientRegistryFilesystem.validatedPath(for: self.fileURL)
        try GitClientRegistryFilesystem
            .withExclusiveLock(registryPath: registryPath) { directory in
                // A missing or malformed file cannot establish the expected
                // generation.  Ask MacopAuth's protected state instead, so reset
                // remains recoverable after uninstall or interrupted publication.
                let generation = try self.protectedGenerationForRecovery()
                let next = try self.authorizeMutation(operation: .reset, currentGeneration: generation, clients: [])
                try directory.writeRegistry(next)
            }
    }

    private func loadDocumentForMutation(
        in directory: GitClientRegistryFilesystem.LockedDirectory
    ) throws -> GitClientTrustDocument {
        guard let data = try directory.readRegistryIfPresent() else {
            return GitClientTrustDocument(generation: 0, clients: [])
        }
        let document: GitClientTrustDocument
        do { document = try GitClientTrustDocument.decodeCanonical(data) } catch {
            throw CLIError
                .invalidArguments(message: "Git client trust registry requires an authenticated v1 migration or reset.")
        }
        // Do not accept this document for requester validation here.  A retry
        // after state-advance/file-publication interruption must be able to
        // reconstruct the same next document; MacopAuth binds and authorizes
        // that exact next value below.
        return document
    }

    private func loadLegacyInspectionDocument(
        in directory: GitClientRegistryFilesystem.LockedDirectory
    ) throws -> LegacyGitClientTrustDocument {
        let data = try directory.readRegistry()
        guard !StrictJSONDuplicateKeyScanner.containsDuplicateObjectKey(in: data),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys) == ["schema_version", "clients"], root["schema_version"] as? Int == 1,
              let rows = root["clients"] as? [[String: Any]],
              rows.allSatisfy({ Set($0.keys) == LegacyGitClientTrustDocument.entryKeys })
        else { throw CLIError.invalidArguments(message: "Git client registry is not a valid v1 inspection document.") }
        return try JSONDecoder().decode(LegacyGitClientTrustDocument.self, from: data)
    }

    private func authorizeMutation(
        operation: GitClientTrustMutationOperation,
        currentGeneration: UInt64,
        clients: [GitClientTrustEntry]
    ) throws -> GitClientTrustDocument {
        guard currentGeneration < UInt64.max else {
            throw CLIError.denied(message: "Git client trust generation is exhausted; use authenticated recovery.")
        }
        let next = GitClientTrustDocument(generation: currentGeneration + 1, clients: clients)
        let canonical = try next.canonicalBytes()
        try self.mutator.authorizeMutation(
            operation: operation, expectedGeneration: currentGeneration, nextDocument: next,
            canonicalDocument: canonical, digest: next.digest()
        )
        return next
    }

    static func validateStoredEntry(_ entry: GitClientTrustEntry) throws {
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

private extension GitClientTrustRegistry {
    func protectedGenerationForRecovery() throws -> UInt64 {
        try self.protectedGeneration() ?? 0
    }

    func protectedGeneration() throws -> UInt64? {
        guard let authority = self.mutator as? any GitClientTrustProtectedStateQuerying else {
            throw CLIError.providerUnavailable(
                provider: "MacopAuth",
                reason: "Git client protected state recovery is unavailable."
            )
        }
        return try authority.protectedGeneration()
    }
}

/// All system observations needed to validate the Git process that invoked the
/// SSH signing adapter. Keeping them together makes the process identity
/// boundary deterministic in tests without weakening the production path.
public struct GitClientRequesterValidationEnvironment: Sendable {
    public let snapshot: @Sendable (Int32) -> ProcessSnapshot?
    public let executablePath: @Sendable (Int32) throws -> String
    public let inspectAppleGit: @Sendable (Int32, String) throws -> LiveCodeInspection
    public let inspectSelector: @Sendable (String) throws -> LiveCodeIdentity
    public let inspectLiveCode: @Sendable (Int32, String) throws -> LiveCodeInspection
    public let loadRegistry: @Sendable () throws -> [GitClientTrustEntry]

    public init(
        snapshot: @escaping @Sendable (Int32) -> ProcessSnapshot?,
        executablePath: @escaping @Sendable (Int32) throws -> String,
        inspectAppleGit: @escaping @Sendable (Int32, String) throws -> LiveCodeInspection,
        inspectSelector: @escaping @Sendable (String) throws -> LiveCodeIdentity,
        inspectLiveCode: @escaping @Sendable (Int32, String) throws -> LiveCodeInspection,
        loadRegistry: @escaping @Sendable () throws -> [GitClientTrustEntry]
    ) {
        self.snapshot = snapshot
        self.executablePath = executablePath
        self.inspectAppleGit = inspectAppleGit
        self.inspectSelector = inspectSelector
        self.inspectLiveCode = inspectLiveCode
        self.loadRegistry = loadRegistry
    }

    public static func system(
        registry: any GitClientTrustRegistryProviding = GitClientTrustRegistry()
    ) -> Self {
        Self(
            snapshot: { SystemRequesterInspector().snapshot(of: $0) },
            executablePath: { try GitClientRequesterTrust.executablePath(pid: $0) },
            inspectAppleGit: { try LiveCodeIdentityInspector.inspectExpectedAppleGit(pid: $0, expectedPath: $1) },
            inspectSelector: { try SystemGitClientTrustInspector().inspectSelector($0) },
            inspectLiveCode: { try LiveCodeIdentityInspector.inspect(pid: $0, expectedPath: $1) },
            loadRegistry: { try registry.list() }
        )
    }
}

public enum GitClientRequesterTrust {
    public static func registeredCandidate(
        entries: [GitClientTrustEntry],
        livePath: String,
        resolve: (String) throws -> LiveCodeIdentity
    ) throws -> (entry: GitClientTrustEntry, current: LiveCodeIdentity)? {
        var staleCandidate: (entry: GitClientTrustEntry, current: LiveCodeIdentity)?
        let candidates = entries.filter { $0.resolvedPath == livePath }
        guard !candidates.isEmpty else { return nil }
        var staleSelector: GitClientTrustEntry?
        for entry in candidates {
            guard let current = try? resolve(entry.selectorPath), current.canonicalPath == livePath else {
                if staleSelector == nil {
                    staleSelector = entry
                }
                continue
            }
            guard current.identifier == entry.identifier, current.cdHash == entry.cdHash else {
                staleCandidate = staleCandidate ?? (entry, current)
                if staleSelector == nil {
                    staleSelector = entry
                }
                continue
            }
            return (entry, current)
        }
        if let staleCandidate {
            return staleCandidate
        }
        if let staleSelector {
            throw CLIError.denied(
                message: "The trusted Git selector is unavailable or retargeted. "
                    + "Re-run `macop ssh git-client trust \(staleSelector.selectorPath)` after review."
            )
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
        try self.validate(pid: pid, environment: .system(registry: registry))
    }

    public static func validate(
        pid: Int32,
        environment: GitClientRequesterValidationEnvironment
    ) throws -> LiveCodeInspection {
        guard pid > 1, let before = environment.snapshot(pid) else {
            throw CLIError.denied(message: "The Git SSH adapter parent could not be inspected.")
        }
        let path = try environment.executablePath(pid)
        if let apple = try? environment.inspectAppleGit(pid, path) {
            guard environment.snapshot(pid) == before else { throw AgentProtocolError.denied }
            return apple
        }
        let entries = try environment.loadRegistry()
        let matched = try self.registeredCandidate(entries: entries, livePath: path) {
            try environment.inspectSelector($0)
        }
        guard let (entry, current) = matched else {
            throw CLIError.denied(
                message: "This non-Apple Git client is not trusted. Run `macop ssh git-client trust <absolute-git-path>` first."
            )
        }
        return try self.validateRegisteredProcess(
            entry: entry, current: current, before: before,
            after: environment.snapshot(pid),
            liveInspection: { try environment.inspectLiveCode(pid, entry.resolvedPath) }
        )
    }

    fileprivate static func executablePath(pid: Int32) throws -> String {
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
