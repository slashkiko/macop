import Foundation
import MacopCore

let environment = ProcessInfo.processInfo.environment
/// This must remain ahead of app construction, adapter dispatch, argument
/// parsing, interactive input and streaming setup.
let invocationDecision = InstallGenerationGuard.invocationDecision(
    argv: CommandLine.arguments,
    environment: environment
)
if case let .blocked(reason) = invocationDecision {
    FileHandle.standardError.write(Data("macop: \(reason.diagnostic).\n".utf8))
    exit(ExitCode.providerUnavailable.rawValue)
}

private func write(_ text: String, to handle: FileHandle) {
    guard let data = text.data(using: .utf8) else { return }
    try? handle.write(contentsOf: data)
}

let app = MacopApp()
if GitSSHSigningCommand.isAdapterInvocation(CommandLine.arguments) {
    let result = if GitSSHVerificationCommand.isVerificationInvocation(CommandLine.arguments) {
        GitSSHVerificationCommand.run(argv: CommandLine.arguments)
    } else {
        GitSSHSigningCommand.run(
            argv: CommandLine.arguments,
            env: environment,
            directSSHKeys: DirectSSHKeyBrokerClient()
        )
    }
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
