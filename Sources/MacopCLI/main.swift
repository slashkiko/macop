import Foundation
import MacopCore

private func write(_ text: String, to handle: FileHandle) {
    guard let data = text.data(using: .utf8) else { return }
    try? handle.write(contentsOf: data)
}

let app = MacopApp()
let environment = ProcessInfo.processInfo.environment
if GitSSHSigningCommand.isSigningInvocation(CommandLine.arguments) {
    let result = GitSSHSigningCommand.run(argv: CommandLine.arguments, env: environment)
    if !result.stdout.isEmpty {
        write(result.stdout, to: .standardOutput)
    }
    if !result.stderr.isEmpty {
        write(result.stderr, to: .standardError)
    }
    exit(result.exitCode)
}

let parsed = try? ArgumentParser.parse(argv: CommandLine.arguments, env: environment)
let result = app.runInteractivelyIfNeeded(argv: CommandLine.arguments, env: environment) ?? {
    if let streamed = app.runStreamingIfNeeded(
        argv: CommandLine.arguments,
        env: environment,
        stdout: { try? FileHandle.standardOutput.write(contentsOf: $0) },
        stderr: { try? FileHandle.standardError.write(contentsOf: $0) }
    ) {
        return streamed
    }
    let readsStandardInput = parsed?.command == .inject
        && (try? InjectCommand.requiresStandardInput(args: parsed?.commandArgs ?? [])) == true
        || parsed?.command == .item
        && (["create", "edit", "import"].contains(parsed?.commandArgs.first ?? "")
            || parsed?.commandArgs.first == "otp"
            && ["import", "edit"].contains(parsed?.commandArgs.dropFirst().first ?? ""))
    let input = readsStandardInput ? FileHandle.standardInput.readDataToEndOfFile() : Data()
    return app.run(argv: CommandLine.arguments, env: environment, input: input)
}()

if !result.stdout.isEmpty {
    write(result.stdout, to: .standardOutput)
}

if !result.stderr.isEmpty {
    write(result.stderr, to: .standardError)
}

exit(result.exitCode)
