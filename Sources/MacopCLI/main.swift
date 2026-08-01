import Foundation
import MacopCore

private func write(_ text: String, to handle: FileHandle) {
    guard let data = text.data(using: .utf8) else { return }
    try? handle.write(contentsOf: data)
}

let app = MacopApp()
let result = app.run(
    argv: CommandLine.arguments,
    env: ProcessInfo.processInfo.environment
)

if !result.stdout.isEmpty {
    write(result.stdout, to: .standardOutput)
}

if !result.stderr.isEmpty {
    write(result.stderr, to: .standardError)
}

exit(result.exitCode)
