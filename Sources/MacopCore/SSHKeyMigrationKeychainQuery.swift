import Foundation
import Security

public struct SSHKeyMigrationKeychainQueryBuilder: Sendable {
    public let accessGroup: String
    public let service: String
    public let account: String

    public init(
        accessGroup: String,
        service: String = "io.github.slashkiko.macop.ssh-key-migration",
        account: String = "protected-state-v1"
    ) throws {
        guard !accessGroup.isEmpty, !accessGroup.contains("*"), accessGroup.hasSuffix(".ssh") else {
            throw DirectSecureEnclaveKeyStoreError.invalidAccessGroup
        }
        self.accessGroup = accessGroup
        self.service = service
        self.account = account
    }

    public func read() -> [CFString: Any] {
        self.base().merging([kSecMatchLimit: kSecMatchLimitOne, kSecReturnData: true]) { _, new in new }
    }

    public func add() -> [CFString: Any] {
        self.base()
    }

    public func update(generation: Data) -> [CFString: Any] {
        self.base().merging([kSecAttrGeneric: generation]) { _, new in new }
    }

    private func base() -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: self.service,
            kSecAttrAccount: self.account,
            kSecAttrAccessGroup: self.accessGroup,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecUseDataProtectionKeychain: true
        ]
    }
}
