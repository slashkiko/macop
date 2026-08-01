import Foundation
import MacopCore

struct SelftestFailure: Error {
    let message: String
}

@inline(__always)
func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() {
        throw SelftestFailure(message: message)
    }
}

func run() throws {
    let app = MacopApp()
    let fileManager = FileManager.default
    let tempRoot = fileManager.temporaryDirectory
        .appendingPathComponent("macop-selftest-\(UUID().uuidString)", isDirectory: true)
    defer { try? fileManager.removeItem(at: tempRoot) }

    try fileManager.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    let configDirectory = tempRoot.path

    let version = app.run(argv: ["macop", "--version"], env: [:])
    try expect(version.exitCode == 0, "version should exit 0")
    try expect(version.stdout.contains("macop 0.1.0"), "version output should contain current version")

    let compatibility = app.run(argv: ["macop", "compatibility", "--format", "json"], env: [:])
    try expect(compatibility.exitCode == 0, "compatibility json should exit 0")
    try expect(compatibility.stdout.contains("\"schema_version\""), "compatibility json should include schema_version")

    let configInit = app.run(argv: ["macop", "--config", configDirectory, "config", "init"], env: [:])
    try expect(configInit.exitCode == 0, "config init should exit 0")

    let configValidate = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(configValidate.exitCode == 0, "config validate should exit 0")

    let configInitWithExtraArg = app.run(
        argv: ["macop", "--config", configDirectory, "config", "init", "extra"],
        env: [:]
    )
    try expect(configInitWithExtraArg.exitCode == 2, "config init should reject extra args")

    let configPath = tempRoot.appendingPathComponent("config.json")
    let config = """
    {
      "items" : {
        "Local/GitHub" : {
          "account" : "me@example.com",
          "fields" : [
            "token"
          ],
          "provider" : "keychain-generic",
          "service" : "github-token"
        }
      },
      "version" : 1
    }
    """
    guard let configData = config.data(using: .utf8) else {
        throw SelftestFailure(message: "failed to encode config fixture")
    }
    try configData.write(to: configPath, options: [.atomic])

    let providerPending = app.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(providerPending.exitCode == 4, "read should report provider unavailable after resolution")
    try expect(
        providerPending.stderr.contains("provider unavailable"),
        "provider unavailable should be rendered as unavailable"
    )
    try expect(
        providerPending.stderr.contains("provider wiring is not implemented yet"),
        "read should surface provider pending reason"
    )

    let invalidProviderConfig = """
    {
      "items" : {
        "Local/GitHub" : {
          "provider" : "bogus"
        }
      },
      "version" : 1
    }
    """
    guard let invalidProviderConfigData = invalidProviderConfig.data(using: .utf8) else {
        throw SelftestFailure(message: "failed to encode invalid provider fixture")
    }
    try invalidProviderConfigData.write(to: configPath, options: [.atomic])

    let unsupportedConfiguredProvider = app.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(unsupportedConfiguredProvider.exitCode == 3, "unknown configured provider should be unsupported")
    try expect(
        unsupportedConfiguredProvider.stderr.contains("unsupported provider"),
        "unknown configured provider should render unsupported provider"
    )

    try configData.write(to: configPath, options: [.atomic])
    try fileManager.setAttributes([.posixPermissions: 0o000], ofItemAtPath: configPath.path)
    let unreadableConfig = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configPath.path)
    try expect(unreadableConfig.exitCode == 5, "unreadable config should be denied")
    try expect(unreadableConfig.stderr.contains("access denied"), "unreadable config should render denied")

    let unsupportedProvider = app.run(argv: ["macop", "read", "apple-passwords://example.com/me/password"], env: [:])
    try expect(unsupportedProvider.exitCode == 3, "apple-passwords should be unsupported")
}

do {
    try run()
    print("selftest passed")
    exit(0)
} catch let error as SelftestFailure {
    FileHandle.standardError.write(Data("selftest failed: \(error.message)\n".utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("selftest failed: unexpected error\n".utf8))
    exit(1)
}
