import Foundation

public enum SSHKeyMigrationPhase: String, Codable, Sendable, Equatable {
    case prepared
    case externallyRegistered = "externally_registered"
    case active
    case retiring
    case retired
    case deleting
}

public struct SSHKeyMigrationEntry: Codable, Sendable, Equatable {
    public let label: String
    public let legacyFingerprint: String
    public let directKeyID: DirectSecureEnclaveKeyID
    public let directPublicKeyBlob: Data
    public let phase: SSHKeyMigrationPhase

    public var directFingerprint: String {
        sshFingerprint(for: self.directPublicKeyBlob)
    }

    public init(
        label: String,
        legacyFingerprint: String,
        directKeyID: DirectSecureEnclaveKeyID,
        directPublicKeyBlob: Data,
        phase: SSHKeyMigrationPhase
    ) throws {
        try SSHIdentityLabelValidator.validate(label)
        guard !legacyFingerprint.isEmpty, !directPublicKeyBlob.isEmpty else {
            throw SSHKeyMigrationError.invalidRecord
        }
        self.label = label
        self.legacyFingerprint = legacyFingerprint
        self.directKeyID = directKeyID
        self.directPublicKeyBlob = directPublicKeyBlob
        self.phase = phase
    }

    public func applying(_ transition: SSHKeyMigrationTransition) throws -> Self? {
        let next: SSHKeyMigrationPhase?
        switch (self.phase, transition) {
        case (.prepared, .confirmExternalRegistration):
            next = .externallyRegistered
        case (.externallyRegistered, .activateDirectBackend):
            next = .active
        case (.active, .beginLegacyRetirement):
            next = .retiring
        case (.retiring, .confirmLegacyRetired):
            next = .retired
        case (.externallyRegistered, .returnToPreparation):
            next = .prepared
        case (.active, .returnToExternalRegistration):
            next = .externallyRegistered
        case (.retiring, .returnToActive):
            next = .active
        case (.deleting, .confirmDirectKeyDeleted):
            next = nil
        default:
            throw SSHKeyMigrationError.invalidTransition(from: self.phase, transition: transition)
        }
        guard let next else { return nil }
        return try Self(
            label: self.label,
            legacyFingerprint: self.legacyFingerprint,
            directKeyID: self.directKeyID,
            directPublicKeyBlob: self.directPublicKeyBlob,
            phase: next
        )
    }

    public func changingPhase(to phase: SSHKeyMigrationPhase) throws -> Self {
        try Self(
            label: self.label,
            legacyFingerprint: self.legacyFingerprint,
            directKeyID: self.directKeyID,
            directPublicKeyBlob: self.directPublicKeyBlob,
            phase: phase
        )
    }

    public var selectedBackend: AuthBrokerSSHKeyBackend {
        switch self.phase {
        case .prepared, .externallyRegistered, .deleting:
            .legacyCTK
        case .active, .retiring, .retired:
            .directSecureEnclaveV1
        }
    }

    /// Direct signing is available one phase before selection so the exact
    /// externally registered candidate can prove remote authentication. The
    /// ordinary backend remains legacy until activation.
    public var permitsDirectSigning: Bool {
        switch self.phase {
        case .prepared, .deleting:
            false
        case .externallyRegistered, .active, .retiring, .retired:
            true
        }
    }
}

public struct SSHKeyMigrationDocument: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = 1

    public let schemaVersion: Int
    public let generation: UInt64
    public let entries: [SSHKeyMigrationEntry]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case generation, entries
    }

    public init(generation: UInt64, entries: [SSHKeyMigrationEntry]) throws {
        self.schemaVersion = Self.currentSchemaVersion
        self.generation = generation
        self.entries = entries.sorted { $0.label < $1.label }
        try self.validate()
    }

    public func encoded() throws -> Data {
        try self.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= 1024 * 1024,
              !StrictJSONDuplicateKeyScanner.containsDuplicateObjectKey(in: data),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys) == ["schema_version", "generation", "entries"],
              root["schema_version"] as? Int == self.currentSchemaVersion,
              let rawEntries = root["entries"] as? [[String: Any]],
              rawEntries.allSatisfy({
                  Set($0.keys) == [
                      "label", "legacyFingerprint", "directKeyID", "directPublicKeyBlob", "phase"
                  ]
              })
        else { throw SSHKeyMigrationError.invalidRecord }
        let document = try JSONDecoder().decode(Self.self, from: data)
        try document.validate()
        guard try constantTimeEqual(data, document.encoded()) else {
            throw SSHKeyMigrationError.invalidRecord
        }
        return document
    }

    private func validate() throws {
        guard self.schemaVersion == Self.currentSchemaVersion,
              self.entries == self.entries.sorted(by: { $0.label < $1.label }),
              Set(self.entries.map(\ .label)).count == self.entries.count,
              Set(self.entries.map(\ .directKeyID)).count == self.entries.count
        else { throw SSHKeyMigrationError.invalidRecord }
        for entry in self.entries {
            _ = try SSHKeyMigrationEntry(
                label: entry.label,
                legacyFingerprint: entry.legacyFingerprint,
                directKeyID: entry.directKeyID,
                directPublicKeyBlob: entry.directPublicKeyBlob,
                phase: entry.phase
            )
        }
    }
}

public protocol SSHKeyMigrationStateStoring: Sendable {
    func load() throws -> SSHKeyMigrationDocument?
    func compareAndSwap(expectedGeneration: UInt64?, next: SSHKeyMigrationDocument) throws -> Bool
}

public final class InMemorySSHKeyMigrationStateStore: SSHKeyMigrationStateStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var document: SSHKeyMigrationDocument?

    public init(initial: SSHKeyMigrationDocument? = nil) {
        self.document = initial
    }

    public func load() throws -> SSHKeyMigrationDocument? {
        self.lock.lock(); defer { self.lock.unlock() }
        return self.document
    }

    public func compareAndSwap(expectedGeneration: UInt64?, next: SSHKeyMigrationDocument) throws -> Bool {
        self.lock.lock(); defer { self.lock.unlock() }
        guard self.document?.generation == expectedGeneration else { return false }
        self.document = next
        return true
    }
}

public enum SSHKeyMigrationTransition: String, Codable, Sendable, Equatable {
    case confirmExternalRegistration = "confirm_external_registration"
    case activateDirectBackend = "activate_direct_backend"
    case beginLegacyRetirement = "begin_legacy_retirement"
    case confirmLegacyRetired = "confirm_legacy_retired"
    case returnToPreparation = "return_to_preparation"
    case returnToExternalRegistration = "return_to_external_registration"
    case returnToActive = "return_to_active"
    case confirmDirectKeyDeleted = "confirm_direct_key_deleted"
}

public enum SSHKeyMigrationError: Error, Sendable, Equatable {
    case invalidRecord
    case invalidTransition(from: SSHKeyMigrationPhase, transition: SSHKeyMigrationTransition)
}
