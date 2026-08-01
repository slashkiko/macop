@testable import MacopCore
import Testing

@Test
func `version flag returns version`() {
    let app = MacopApp()
    let result = app.run(argv: ["macop", "--version"], env: [:])

    #expect(result.exitCode == 0)
    #expect(result.stdout.contains("macop 0.1.0"))
}

@Test
func `compatibility json returns schema version`() {
    let app = MacopApp()
    let result = app.run(argv: ["macop", "compatibility", "--format", "json"], env: [:])

    #expect(result.exitCode == 0)
    #expect(result.stdout.contains("\"schema_version\""))
}

@Test
func `unsupported command returns exit code three`() {
    let app = MacopApp()
    let result = app.run(argv: ["macop", "read", "op://Local/GitHub/token"], env: [:])

    #expect(result.exitCode == 3)
    #expect(result.stderr.contains("unsupported op command"))
}
