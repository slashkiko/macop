import Foundation
import LocalAuthentication
import Security

public struct DirectSecureEnclaveKeyID: RawRepresentable, Codable, Hashable, Sendable {
    private static let tagPrefix = "io.github.slashkiko.macop.auth.ssh-key.v1."

    public let rawValue: String

    public init?(rawValue: String) {
        guard let uuid = UUID(uuidString: rawValue), uuid.uuidString.lowercased() == rawValue else { return nil }
        self.rawValue = rawValue
    }

    public static func generate() -> Self {
        // UUID().uuidString is always canonical. Keep the failable initializer
        // at the boundary where persisted or broker-provided data enters.
        self.init(rawValue: UUID().uuidString.lowercased())!
    }

    public var applicationTag: Data {
        Data((Self.tagPrefix + self.rawValue).utf8)
    }

    public static func parse(applicationTag: Data) -> Self? {
        guard let value = String(data: applicationTag, encoding: .utf8), value.hasPrefix(self.tagPrefix) else {
            return nil
        }
        return self.init(rawValue: String(value.dropFirst(self.tagPrefix.count)))
    }
}

public struct DirectSecureEnclaveKeyRecord: Sendable, Equatable {
    public let id: DirectSecureEnclaveKeyID
    public let label: String
    public let publicKeyBlob: Data
    public let fingerprint: String

    public init(id: DirectSecureEnclaveKeyID, label: String, publicKeyBlob: Data) {
        self.id = id
        self.label = label
        self.publicKeyBlob = publicKeyBlob
        self.fingerprint = sshFingerprint(for: publicKeyBlob)
    }
}

public enum DirectSecureEnclaveKeyStoreError: Error, Equatable, Sendable {
    case invalidAccessGroup
    case duplicateLabel
    case notFound
    case malformedStore
    case fingerprintMismatch
    case securityFailure(OSStatus)
    case creationFailed
    case indeterminate(DirectSecureEnclaveKeyID, OSStatus)
}

/// Produces every Keychain query from the same exact private access group and
/// versioned application-tag contract. No caller may omit either boundary and
/// fall back to the default or legacy CTK key space.
public struct DirectSecureEnclaveKeyQueryBuilder: Sendable {
    public let accessGroup: String

    public init(accessGroup: String) throws {
        guard !accessGroup.isEmpty, !accessGroup.contains("*"), accessGroup.hasSuffix(".ssh") else {
            throw DirectSecureEnclaveKeyStoreError.invalidAccessGroup
        }
        self.accessGroup = accessGroup
    }

    public func exact(_ id: DirectSecureEnclaveKeyID) -> [CFString: Any] {
        self.base().merging([
            kSecAttrApplicationTag: id.applicationTag
        ]) { _, new in new }
    }

    public func resolve(
        _ id: DirectSecureEnclaveKeyID,
        authenticationContext: LAContext? = nil
    ) -> [CFString: Any] {
        var query = self.exact(id).merging([
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnRef: true
        ]) { _, new in new }
        if let authenticationContext {
            query[kSecUseAuthenticationContext] = authenticationContext
        }
        return query
    }

    public func enumerate() -> [CFString: Any] {
        self.base().merging([
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnAttributes: true
        ]) { _, new in new }
    }

    private func base() -> [CFString: Any] {
        [
            kSecClass: kSecClassKey,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup: self.accessGroup,
            kSecUseDataProtectionKeychain: true
        ]
    }
}

/// A signer that retains the exact SecKey reference whose public key was
/// verified. It never re-resolves a mutable label between verification and
/// signing.
public struct DirectSecureEnclaveKeySigner: AgentKeySigning, @unchecked Sendable {
    public let publicKeyBlob: Data
    public let fingerprint: String
    private let privateKey: SecKey

    init(privateKey: SecKey, expectedPublicKeyBlob: Data) throws {
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let actual = try? CTKIdentitySigner.publicBlob(for: publicKey),
              constantTimeEqual(actual, expectedPublicKeyBlob)
        else { throw DirectSecureEnclaveKeyStoreError.fingerprintMismatch }
        self.privateKey = privateKey
        self.publicKeyBlob = expectedPublicKeyBlob
        self.fingerprint = sshFingerprint(for: expectedPublicKeyBlob)
    }

    public func sign(data: Data, flags: UInt32) throws -> Data {
        guard flags == 0,
              SecKeyIsAlgorithmSupported(self.privateKey, .sign, .ecdsaSignatureMessageX962SHA256)
        else { throw AgentProtocolError.unsupported }
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            self.privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else { throw AgentProtocolError.denied }
        let raw = try CTKIdentitySigner.strictDERToRawP256(der)
        let firstCoordinate = Self.mpint(raw.prefix(32))
        let secondCoordinate = Self.mpint(raw.suffix(32))
        return try SSHWire.string("ecdsa-sha2-nistp256") + SSHWire.string(
            SSHWire.string(firstCoordinate) + SSHWire.string(secondCoordinate)
        )
    }

    private static func mpint(_ bytes: Data.SubSequence) -> Data {
        let trimmed = bytes.drop { $0 == 0 }
        let value = trimmed.isEmpty ? Data([0]) : Data(trimmed)
        return value.first! & 0x80 == 0 ? value : Data([0]) + value
    }
}

/// System implementation owned by MacopAuth at runtime. The type is in
/// MacopCore so query construction and identity binding can be tested without
/// granting the CLI or agent the required access-group entitlement.
public final class DirectSecureEnclaveKeyStore: @unchecked Sendable {
    private struct Metadata {
        let id: DirectSecureEnclaveKeyID
        let label: String
    }

    private let queries: DirectSecureEnclaveKeyQueryBuilder

    public init(accessGroup: String) throws {
        self.queries = try DirectSecureEnclaveKeyQueryBuilder(accessGroup: accessGroup)
    }

    public func create(label: String) throws -> DirectSecureEnclaveKeyRecord {
        try SSHIdentityLabelValidator.validate(label)
        guard try self.metadata().allSatisfy({ $0.label != label }) else {
            throw DirectSecureEnclaveKeyStoreError.duplicateLabel
        }
        let id = DirectSecureEnclaveKeyID.generate()
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryAny, .companion, .devicePasscode, .or, .privateKeyUsage],
            nil
        ) else { throw DirectSecureEnclaveKeyStoreError.creationFailed }
        let privateAttributes: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: id.applicationTag,
            kSecAttrLabel: label,
            kSecAttrAccessGroup: self.queries.accessGroup,
            kSecAttrAccessControl: accessControl
        ]
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain: true,
            kSecPrivateKeyAttrs: privateAttributes
        ]
        guard let created = SecKeyCreateRandomKey(attributes as CFDictionary, nil) else {
            throw DirectSecureEnclaveKeyStoreError.creationFailed
        }
        do {
            let createdBlob = try self.publicKeyBlob(created)
            let persisted = try self.resolve(id)
            let persistedBlob = try self.publicKeyBlob(persisted)
            guard constantTimeEqual(createdBlob, persistedBlob) else {
                throw DirectSecureEnclaveKeyStoreError.fingerprintMismatch
            }
            return DirectSecureEnclaveKeyRecord(id: id, label: label, publicKeyBlob: persistedBlob)
        } catch {
            let cleanupStatus = SecItemDelete(self.queries.exact(id) as CFDictionary)
            guard cleanupStatus == errSecSuccess || cleanupStatus == errSecItemNotFound else {
                throw DirectSecureEnclaveKeyStoreError.indeterminate(id, cleanupStatus)
            }
            throw error
        }
    }

    public func list() throws -> [DirectSecureEnclaveKeyRecord] {
        try self.metadata().map { metadata in
            let key = try self.resolve(metadata.id)
            return try DirectSecureEnclaveKeyRecord(
                id: metadata.id,
                label: metadata.label,
                publicKeyBlob: self.publicKeyBlob(key)
            )
        }.sorted { ($0.label, $0.id.rawValue) < ($1.label, $1.id.rawValue) }
    }

    public func signer(
        id: DirectSecureEnclaveKeyID,
        expectedPublicKeyBlob: Data,
        authenticationContext: LAContext
    ) throws -> DirectSecureEnclaveKeySigner {
        try DirectSecureEnclaveKeySigner(
            privateKey: self.resolve(id, authenticationContext: authenticationContext),
            expectedPublicKeyBlob: expectedPublicKeyBlob
        )
    }

    public func delete(id: DirectSecureEnclaveKeyID, expectedPublicKeyBlob: Data) throws {
        let key = try self.resolve(id)
        let actual = try self.publicKeyBlob(key)
        guard constantTimeEqual(actual, expectedPublicKeyBlob) else {
            throw DirectSecureEnclaveKeyStoreError.fingerprintMismatch
        }
        let status = SecItemDelete(self.queries.exact(id) as CFDictionary)
        guard status == errSecSuccess else { throw DirectSecureEnclaveKeyStoreError.securityFailure(status) }
        do {
            _ = try self.resolve(id)
            throw DirectSecureEnclaveKeyStoreError.indeterminate(id, errSecSuccess)
        } catch DirectSecureEnclaveKeyStoreError.notFound {
            return
        }
    }

    private func metadata() throws -> [Metadata] {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(self.queries.enumerate() as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw DirectSecureEnclaveKeyStoreError.securityFailure(status)
        }
        guard let values = result as? [[CFString: Any]] else {
            throw DirectSecureEnclaveKeyStoreError.malformedStore
        }
        return try values.map { attributes in
            guard let tag = attributes[kSecAttrApplicationTag] as? Data,
                  let id = DirectSecureEnclaveKeyID.parse(applicationTag: tag),
                  let label = attributes[kSecAttrLabel] as? String,
                  (try? SSHIdentityLabelValidator.validate(label)) != nil
            else { throw DirectSecureEnclaveKeyStoreError.malformedStore }
            return Metadata(id: id, label: label)
        }
    }

    private func resolve(
        _ id: DirectSecureEnclaveKeyID,
        authenticationContext: LAContext? = nil
    ) throws -> SecKey {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(
            self.queries.resolve(id, authenticationContext: authenticationContext) as CFDictionary,
            &result
        )
        if status == errSecItemNotFound {
            throw DirectSecureEnclaveKeyStoreError.notFound
        }
        guard status == errSecSuccess else {
            throw DirectSecureEnclaveKeyStoreError.securityFailure(status)
        }
        guard let matches = result as? [SecKey], matches.count == 1, let key = matches.first else {
            throw DirectSecureEnclaveKeyStoreError.malformedStore
        }
        return key
    }

    private func publicKeyBlob(_ privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw DirectSecureEnclaveKeyStoreError.malformedStore
        }
        do {
            return try CTKIdentitySigner.publicBlob(for: publicKey)
        } catch {
            throw DirectSecureEnclaveKeyStoreError.malformedStore
        }
    }
}
