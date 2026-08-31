import Foundation
import Security

/// Builds every protected-state Keychain operation from the same private access
/// group contract.  Keeping this value explicit prevents an accidental fallback
/// to a same-UID/default keychain item.
public struct GitClientTrustKeychainQueryBuilder: Sendable {
    public let accessGroup: String
    public let service: String
    public let account: String

    public init(
        accessGroup: String,
        service: String = "io.github.slashkiko.macop.git-client-trust",
        account: String = "protected-state-v1"
    ) {
        self.accessGroup = accessGroup; self.service = service; self.account = account
    }

    public func base() -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: self.service,
            kSecAttrAccount: self.account,
            kSecAttrAccessGroup: self.accessGroup,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecUseDataProtectionKeychain: true
        ]
    }

    public func read() -> [CFString: Any] {
        self.base().merging([kSecMatchLimit: kSecMatchLimitOne, kSecReturnData: true]) { _, new in new }
    }

    public func add() -> [CFString: Any] {
        self.base()
    }

    public func matching(generation: Data) -> [CFString: Any] {
        self.base().merging([kSecAttrGeneric: generation]) { _, new in new }
    }

    public func update(generation: Data) -> [CFString: Any] {
        self.matching(generation: generation)
    }

    public func delete() -> [CFString: Any] {
        self.base()
    }
}
