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
    let mutationService = "macop-selftest-mutation-\(suffix)"
    let generatedService = "macop-selftest-generated-\(suffix)"
    let internetServer = "macop-selftest-\(suffix).invalid"
    let generatedInternetServer = "macop-selftest-generated-\(suffix).invalid"
    let generic = [kSecClass: kSecClassGenericPassword, kSecAttrService: genericService,
                   kSecAttrAccount: account] as [CFString: Any]
    let internet = [kSecClass: kSecClassInternetPassword, kSecAttrServer: internetServer,
                    kSecAttrAccount: account, kSecAttrPath: "/one"] as [CFString: Any]
    let duplicateInternet = [kSecClass: kSecClassInternetPassword, kSecAttrServer: internetServer,
                             kSecAttrAccount: account, kSecAttrPath: "/two"] as [CFString: Any]
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
        let mutator = SystemKeychainMutator()
        let mutationQuery = KeychainQuery.generic(service: mutationService, account: account)
        let mutationCleanup = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: mutationService,
            kSecAttrAccount: account
        ] as [CFString: Any]
        try mutator.create(Data("created".utf8), query: mutationQuery)
        added.append(mutationCleanup)
        let createdValue = try KeychainProvider.readText(mutationQuery, client: client)
        try expect(
            createdValue == "created",
            "generic Security integration create"
        )
        try mutator.edit(Data("edited".utf8), query: mutationQuery)
        let editedValue = try KeychainProvider.readText(mutationQuery, client: client)
        try expect(
            editedValue == "edited",
            "generic Security integration edit"
        )
        try mutator.delete(query: mutationQuery)
        _ = added.popLast()
        do {
            _ = try KeychainProvider.readText(mutationQuery, client: client)
            throw SelftestFailure(message: "deleted Keychain item must not be readable")
        } catch let error as CLIError {
            guard case .notFound = error else { throw error }
        }
        let generatedQuery = KeychainQuery.generic(service: generatedService, account: account)
        let generatedCleanup = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: generatedService,
            kSecAttrAccount: account
        ] as [CFString: Any]
        let configDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("macop-keychain-generated-\(suffix)", isDirectory: true)
        try FileManager.default.createDirectory(at: configDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: configDirectory) }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: configDirectory.path)
        let generatedConfig = """
        { "version": 2, "items": {
          "Local/Generated": {
            "provider": "keychain-generic", "service": "\(generatedService)", "account": "\(account)"
          },
          "Local/ExistingInternet": {
            "provider": "keychain-internet", "server": "\(internetServer)", "account": "\(account)"
          },
          "Local/GeneratedInternet": {
            "provider": "keychain-internet", "server": "\(generatedInternetServer)", "account": "\(account)"
          }
        } }
        """
        let generatedConfigURL = configDirectory.appendingPathComponent("config.json")
        try Data(generatedConfig.utf8).write(to: generatedConfigURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: generatedConfigURL.path)
        let generatedApp = MacopApp(keychainClient: client, keychainMutator: mutator)
        let ambiguousInternetGenerate = generatedApp.run(
            argv: [
                "macop", "--config", configDirectory.path, "item", "generate", "ExistingInternet",
                "--length", "40"
            ],
            env: [:]
        )
        let existingInternetAfterRejectedGenerate = try KeychainProvider.readText(
            .internet(server: internetServer, account: account), client: client
        )
        try expect(
            ambiguousInternetGenerate.exitCode == ExitCode.invalidArguments.rawValue
                && existingInternetAfterRejectedGenerate == "internet",
            "internet password generation must require zero broad-selector matches before adding"
        )
        let generatedInternetQuery = KeychainQuery.internet(
            server: generatedInternetServer, account: account
        )
        let generatedInternetCleanup = [
            kSecClass: kSecClassInternetPassword,
            kSecAttrServer: generatedInternetServer,
            kSecAttrAccount: account
        ] as [CFString: Any]
        let generatedInternetCreate = generatedApp.run(
            argv: [
                "macop", "--config", configDirectory.path, "item", "generate", "GeneratedInternet",
                "--length", "41"
            ],
            env: [:]
        )
        try expect(generatedInternetCreate.exitCode == 0, "generated internet Keychain integration create")
        added.append(generatedInternetCleanup)
        let generatedInternetValue = try KeychainProvider.readText(generatedInternetQuery, client: client)
        try expect(
            generatedInternetValue.count == 41
                && !generatedInternetCreate.stdout.contains(generatedInternetValue),
            "internet creation must survive persistent-reference postflight without exposing the secret"
        )
        try mutator.delete(query: generatedInternetQuery)
        _ = added.popLast()
        let generatedCreate = generatedApp.run(
            argv: [
                "macop", "--config", configDirectory.path, "item", "generate", "Generated", "--length", "40"
            ],
            env: [:]
        )
        try expect(generatedCreate.exitCode == 0, "generated Keychain integration create")
        added.append(generatedCleanup)
        let firstGenerated = try KeychainProvider.readText(generatedQuery, client: client)
        try expect(
            firstGenerated.count == 40 && !generatedCreate.stdout.contains(firstGenerated),
            "generated Keychain integration must persist requested length without returning the secret"
        )
        let generatedRotate = generatedApp.run(
            argv: [
                "macop", "--config", configDirectory.path, "item", "generate", "--replace", "Generated",
                "--length", "48"
            ],
            env: [:]
        )
        try expect(generatedRotate.exitCode == 0, "generated Keychain integration rotate")
        let rotatedGenerated = try KeychainProvider.readText(generatedQuery, client: client)
        try expect(rotatedGenerated.count == 48, "generated Keychain rotation must update the exact item")
        try mutator.delete(query: generatedQuery)
        _ = added.popLast()
        let duplicateStatus = SecItemAdd(
            (duplicateInternet.merging([kSecValueData: Data("other-internet".utf8)]) { _, new in new }) as CFDictionary,
            nil
        )
        guard duplicateStatus == errSecSuccess
        else {
            throw SelftestFailure(message: "Keychain duplicate-internet integration unavailable: \(duplicateStatus)")
        }
        added.append(duplicateInternet)
        do {
            _ = try KeychainProvider.readText(.internet(server: internetServer, account: account), client: client)
            throw SelftestFailure(message: "ambiguous internet Keychain selector must be rejected")
        } catch let error as CLIError {
            guard case .invalidArguments = error else { throw error }
        }
    } catch {
        let failures = cleanup()
        if !failures.isEmpty {
            throw SelftestFailure(message: "Keychain cleanup failed after test error: \(failures)")
        }
        if let failure = error as? SelftestFailure {
            throw failure
        }
        throw SelftestFailure(message: "Keychain integration unexpected provider error: \(String(describing: error))")
    }
    let failures = cleanup()
    guard failures.isEmpty else { throw SelftestFailure(message: "Keychain cleanup failed: \(failures)") }
}
