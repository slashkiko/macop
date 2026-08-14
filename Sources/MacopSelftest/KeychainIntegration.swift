import Foundation
import MacopCore
import Security

func runKeychainIntegrationIfRequested() throws {
    guard ProcessInfo.processInfo.environment["MACOP_RUN_KEYCHAIN_INTEGRATION"] == "1" else {
        print("selftest: Keychain integration skipped (set MACOP_RUN_KEYCHAIN_INTEGRATION=1 to enable)")
        return
    }
    let suffix = UUID().uuidString
    let account = "macop-selftest-\(suffix)"
    let genericService = "macop-selftest-generic-\(suffix)"
    let internetServer = "macop-selftest-\(suffix).invalid"
    let generic = [kSecClass: kSecClassGenericPassword, kSecAttrService: genericService,
                   kSecAttrAccount: account] as [CFString: Any]
    let internet = [kSecClass: kSecClassInternetPassword, kSecAttrServer: internetServer,
                    kSecAttrAccount: account] as [CFString: Any]
    var added: [[CFString: Any]] = []
    func cleanup() -> [OSStatus] {
        defer { added.removeAll() }
        return added.reversed().map { SecItemDelete($0 as CFDictionary) }.filter { $0 != errSecSuccess }
    }
    do {
        let genericStatus = SecItemAdd(
            (generic.merging([kSecValueData: Data("generic".utf8)]) { _, new in new }) as CFDictionary,
            nil
        )
        guard genericStatus == errSecSuccess
        else { throw SelftestFailure(message: "Keychain generic integration unavailable: \(genericStatus)") }
        added.append(generic)
        let internetStatus = SecItemAdd(
            (internet.merging([kSecValueData: Data("internet".utf8)]) { _, new in new }) as CFDictionary,
            nil
        )
        guard internetStatus == errSecSuccess
        else { throw SelftestFailure(message: "Keychain internet integration unavailable: \(internetStatus)") }
        added.append(internet)
        let client = SystemKeychainClient()
        let genericValue = try KeychainProvider.readText(
            .generic(service: genericService, account: account),
            client: client
        )
        try expect(genericValue == "generic", "generic Security integration read")
        let internetValue = try KeychainProvider.readText(
            .internet(server: internetServer, account: account),
            client: client
        )
        try expect(internetValue == "internet", "internet Security integration read")
    } catch {
        let failures = cleanup()
        if !failures.isEmpty {
            throw SelftestFailure(message: "Keychain cleanup failed after test error: \(failures)")
        }
        throw error
    }
    let failures = cleanup()
    guard failures.isEmpty else { throw SelftestFailure(message: "Keychain cleanup failed: \(failures)") }
}
