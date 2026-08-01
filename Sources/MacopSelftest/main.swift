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

    let version = app.run(argv: ["macop", "--version"], env: [:])
    try expect(version.exitCode == 0, "version should exit 0")
    try expect(version.stdout.contains("macop 0.1.0"), "version output should contain current version")

    let compatibility = app.run(argv: ["macop", "compatibility", "--format", "json"], env: [:])
    try expect(compatibility.exitCode == 0, "compatibility json should exit 0")
    try expect(compatibility.stdout.contains("\"schema_version\""), "compatibility json should include schema_version")

    let unsupportedRead = app.run(argv: ["macop", "read", "op://Local/GitHub/token"], env: [:])
    try expect(unsupportedRead.exitCode == 3, "unsupported read should exit 3")
    try expect(
        unsupportedRead.stderr.contains("unsupported op command"),
        "unsupported read should render error message"
    )
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
