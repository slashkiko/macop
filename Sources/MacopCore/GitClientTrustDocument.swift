import CryptoKit
import Foundation

/// The complete, replay-protected trust set.  This is intentionally a document
/// rather than per-entry authentication: removing an entry is security
/// relevant and must change the value authenticated by MacopAuth.
public struct GitClientTrustDocument: Codable, Equatable, Sendable {
    public static let currentSchemaVersion = 2

    public let schemaVersion: Int
    public let generation: UInt64
    public var clients: [GitClientTrustEntry]

    public init(generation: UInt64, clients: [GitClientTrustEntry]) {
        self.schemaVersion = Self.currentSchemaVersion
        self.generation = generation
        self.clients = clients
    }

    enum CodingKeys: String, CodingKey { case schemaVersion = "schema_version", generation, clients }

    /// Canonical UTF-8 JSON.  The format is deliberately hand-written so a
    /// Swift/OS JSONEncoder implementation change cannot alter the signed set.
    public func canonicalBytes() throws -> Data {
        guard self.schemaVersion == Self.currentSchemaVersion else { throw GitClientTrustDocumentError.malformed }
        let sorted = self.clients.sorted { $0.selectorPath < $1.selectorPath }
        guard Set(sorted.map(\ .selectorPath)).count == sorted.count
        else { throw GitClientTrustDocumentError.duplicate }
        try sorted.forEach(GitClientTrustEntry.validateForTrustDocument)
        let rows = try sorted.map { try $0.canonicalJSONObject() }.joined(separator: ",")
        return Data("{\"schema_version\":2,\"generation\":\(self.generation),\"clients\":[\(rows)]}".utf8)
    }

    public func digest() throws -> Data {
        try Data(SHA256.hash(data: self.canonicalBytes()))
    }

    public static func decodeCanonical(_ data: Data) throws -> GitClientTrustDocument {
        guard !StrictJSONDuplicateKeyScanner.containsDuplicateObjectKey(in: data),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys) == ["schema_version", "generation", "clients"],
              root["schema_version"] as? Int == currentSchemaVersion,
              root["generation"] is UInt64,
              let rawClients = root["clients"] as? [[String: Any]]
        else { throw GitClientTrustDocumentError.malformed }
        let required: Set = [
            "selector_path", "resolved_path", "identifier", "cdhash", "code_requirement", "team_id",
            "publisher_verified", "signature_kind", "version"
        ]
        guard rawClients.allSatisfy({ Set($0.keys) == required }) else { throw GitClientTrustDocumentError.malformed }
        let document = try JSONDecoder().decode(GitClientTrustDocument.self, from: data)
        let canonical = try document.canonicalBytes()
        // Stored files must be canonical too.  This rejects ambiguity (including
        // numeric spellings and escaped equivalent strings) before it reaches UI.
        guard constantTimeEqual(data, canonical) else { throw GitClientTrustDocumentError.nonCanonical }
        return document
    }
}

public enum GitClientTrustDocumentError: Error, Equatable, Sendable {
    case malformed
    case duplicate
    case nonCanonical
}

private extension GitClientTrustEntry {
    static func validateForTrustDocument(_ entry: GitClientTrustEntry) throws {
        try GitClientTrustRegistry.validateStoredEntry(entry)
    }

    func canonicalJSONObject() throws -> String {
        try Self.validateForTrustDocument(self)
        func quote(_ value: String) -> String {
            // The entry validator rejects controls, so JSON escaping has only
            // the two syntactic cases and stays stable across Foundation.
            "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        return [
            "{\"selector_path\":\(quote(self.selectorPath))",
            "\"resolved_path\":\(quote(self.resolvedPath))",
            "\"identifier\":\(quote(self.identifier))",
            "\"cdhash\":\(quote(self.cdHash))",
            "\"code_requirement\":\(quote(self.codeRequirement))",
            "\"team_id\":\(quote(self.teamID))",
            "\"publisher_verified\":\(self.publisherVerified ? "true" : "false")",
            "\"signature_kind\":\(quote(self.signatureKind))",
            "\"version\":\(quote(self.version))}"
        ].joined(separator: ",")
    }
}

/// Test stores model the protected MacopAuth state without allowing a CLI to
/// obtain a Keychain key.  The production store lives in the MacopAuth target.
public struct GitClientTrustProtectedState: Equatable, Sendable {
    public let generation: UInt64
    public let documentDigest: Data
    public init(generation: UInt64, documentDigest: Data) {
        self.generation = generation; self.documentDigest = documentDigest
    }
}

public protocol GitClientTrustStateStoring: Sendable {
    func load() throws -> GitClientTrustProtectedState?
    func compareAndSwap(expectedGeneration: UInt64?, next: GitClientTrustProtectedState) throws -> Bool
}

public final class InMemoryGitClientTrustStateStore: GitClientTrustStateStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var state: GitClientTrustProtectedState?
    public init(initial: GitClientTrustProtectedState? = nil) {
        self.state = initial
    }

    public func load() throws -> GitClientTrustProtectedState? {
        self.lock
            .lock(); defer { self.lock.unlock() }; return self.state
    }

    public func compareAndSwap(expectedGeneration: UInt64?, next: GitClientTrustProtectedState) throws -> Bool {
        self.lock.lock(); defer { self.lock.unlock() }
        guard self.state?.generation == expectedGeneration else { return false }
        self.state = next; return true
    }
}

// Deterministic injected authority for unit/self tests.  It is intentionally
// not used by any production registry initializer.
// swiftformat:disable wrapMultilineStatementBraces
public final class InMemoryGitClientTrustAuthority: GitClientTrustDocumentVerifying,
    GitClientTrustDocumentMutating, GitClientTrustProtectedStateQuerying, @unchecked Sendable {
    private let state: any GitClientTrustStateStoring
    public init(state: any GitClientTrustStateStoring = InMemoryGitClientTrustStateStore()) {
        self.state = state
    }

    public func verify(document: GitClientTrustDocument, canonicalDocument: Data, digest: Data) throws {
        guard try constantTimeEqual(document.canonicalBytes(), canonicalDocument),
              try constantTimeEqual(document.digest(), digest),
              let protected = try self.state.load(), protected.generation == document.generation,
              constantTimeEqual(protected.documentDigest, digest)
        else { throw CLIError.denied(message: "Injected trust state does not match the registry.") }
    }

    public func protectedGeneration() throws -> UInt64? {
        try self.state.load()?.generation
    }

    public func authorizeMutation(
        operation: GitClientTrustMutationOperation, expectedGeneration: UInt64,
        nextDocument: GitClientTrustDocument, canonicalDocument: Data, digest: Data
    ) throws {
        guard nextDocument.generation == expectedGeneration + 1,
              try constantTimeEqual(nextDocument.canonicalBytes(), canonicalDocument),
              try constantTimeEqual(nextDocument.digest(), digest)
        else { throw CLIError.denied(message: "Injected trust mutation is malformed.") }
        let existing = try self.state.load()
        let expected: UInt64? = existing == nil && expectedGeneration == 0 ? nil : expectedGeneration
        guard try self.state.compareAndSwap(
            expectedGeneration: expected,
            next: GitClientTrustProtectedState(generation: nextDocument.generation, documentDigest: digest)
        ) else { throw CLIError.denied(message: "Injected trust generation changed.") }
    }
}

// swiftformat:enable wrapMultilineStatementBraces
