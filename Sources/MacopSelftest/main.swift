import Darwin

// swiftlint:disable file_length
import Foundation
import MacopCore

struct SelftestFailure: Error {
    let message: String
}

let appleTableHeader = "Key Type  Public Key Hash                            Prot  Label                 Common Name  Email Address  Valid To  Valid\n"
func appleTableRow(_ hash: String, _ label: String, commonName: String = "") -> String {
    let keyType = "p-256-ne"
    return keyType + String(repeating: " ", count: 10 - keyType.count)
        + hash + String(repeating: " ", count: 53 - 10 - hash.count)
        + "bio" + String(repeating: " ", count: 59 - 53 - 3)
        + label + String(repeating: " ", count: max(1, 81 - 59 - label.count))
        + commonName + "\n"
}

final class StreamCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Data()
    func append(_ data: Data) {
        self.lock.lock(); defer { self.lock.unlock() }; self.value.append(data)
    }

    func read() -> Data {
        self.lock.lock(); defer { self.lock.unlock() }; return self.value
    }
}

final class RecordingSSHExecutor: SSHStreamingExecuting, @unchecked Sendable {
    struct Invocation { let path: String; let arguments: [String]; let environment: [String: String] }
    var invocations = [Invocation]()
    private var listCount = 0
    func execute(path: String, arguments: [String], environment: CommandEnvironment) throws -> CommandResult {
        self.invocations.append(Invocation(path: path, arguments: arguments, environment: environment))
        if path == SSHCommand.scAuth, arguments.first == "list-ctk-identities" {
            self.listCount += 1
            return CommandResult(
                exitCode: 0,
                stdout: self.listCount == 1 ? appleTableHeader
                    : appleTableHeader + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github")
            )
        }
        if path == SSHCommand.sshKeygen {
            return CommandResult(exitCode: 0, stdout: "ecdsa-sha2-nistp256 AAAA github\n")
        }
        if path == SSHCommand.ssh, arguments.first == "-G" {
            return CommandResult(
                exitCode: 0,
                stdout: "forwardagent no\npkcs11provider /usr/lib/ssh-keychain.dylib\nidentitiesonly yes\n"
            )
        }
        return CommandResult(exitCode: 0)
    }

    func executeStreaming(
        path: String, arguments: [String], environment: CommandEnvironment,
        stdout: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32 {
        self.invocations.append(Invocation(path: path, arguments: arguments, environment: environment))
        stdout(Data("streamed-child-output\n".utf8))
        return 23
    }
}

final class SequencedSSHExecutor: CommandExecuting, @unchecked Sendable {
    struct Invocation { let path: String; let arguments: [String] }
    var invocations = [Invocation]()
    var lists: [String]

    init(lists: [String]) {
        self.lists = lists
    }

    func execute(path: String, arguments: [String], environment _: CommandEnvironment) throws -> CommandResult {
        self.invocations.append(Invocation(path: path, arguments: arguments))
        if path == SSHCommand.scAuth, arguments.first == "list-ctk-identities" {
            return CommandResult(exitCode: 0, stdout: self.lists.isEmpty ? "" : self.lists.removeFirst())
        }
        if path == SSHCommand.sshKeygen {
            return CommandResult(exitCode: 0, stdout: "ecdsa-sha2-nistp256 AAAA My SSH Key\n")
        }
        return CommandResult(exitCode: 0)
    }
}

final class GitHubTestExecutor: SSHStreamingExecuting, @unchecked Sendable {
    let output: String
    let code: Int32
    init(output: String, code: Int32) {
        self.output = output; self.code = code
    }

    func execute(path: String, arguments: [String], environment _: CommandEnvironment) throws -> CommandResult {
        if path == SSHCommand.scAuth, arguments.first == "list-ctk-identities" {
            return CommandResult(exitCode: 0, stdout: appleTableHeader
                + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github"))
        }
        return CommandResult(exitCode: self.code, stderr: self.output)
    }

    func executeStreaming(
        path _: String, arguments _: [String], environment _: CommandEnvironment,
        stdout _: @escaping @Sendable (Data) -> Void, stderr: @escaping @Sendable (Data) -> Void
    ) throws -> Int32 {
        stderr(Data(self.output.utf8)); return self.code
    }
}

private func write(_ text: String, to handle: FileHandle) {
    try? handle.write(contentsOf: Data(text.utf8))
}

/// Small process-level harnesses used by `make test-pty`. They deliberately
/// exercise the same public MacopCore entry points as MacopCLI, while keeping
/// Keychain access deterministic and local to the test executable.
private func runHarnessIfRequested() -> Never? {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let mode = arguments.first else { return nil }
    let secret = mode == "--pty-run-large-stdin" ? String(repeating: "large-stdin-secret-", count: 32768)
        : "test-secret"
    let app = MacopApp(keychainClient: FakeKeychainClient(response: .success(Data(secret.utf8))))

    switch mode {
    case "--pty-run", "--pty-run-large-stdin":
        let argv = ["macop"] + Array(arguments.dropFirst())
        let environment = ProcessInfo.processInfo.environment.merging(
            ["GH_TOKEN": "keychain://generic/service/account"]
        ) { _, supplied in supplied }
        let result = app.runInteractivelyIfNeeded(argv: argv, env: environment)
            ?? app.runStreamingIfNeeded(
                argv: argv,
                env: environment,
                stdout: { try? FileHandle.standardOutput.write(contentsOf: $0) },
                stderr: { try? FileHandle.standardError.write(contentsOf: $0) }
            )
            ?? app.run(argv: argv, env: environment)
        write(result.stdout, to: .standardOutput)
        write(result.stderr, to: .standardError)
        exit(result.exitCode)
    case "--inject-stdin":
        let input = FileHandle.standardInput.readDataToEndOfFile()
        let result = app.run(argv: ["macop", "inject"], env: [:], input: input)
        write(result.stdout, to: .standardOutput)
        write(result.stderr, to: .standardError)
        exit(result.exitCode)
    default:
        return nil
    }
}

func run() throws {
    try runKeychainIntegrationIfRequested()
    let app = MacopApp(keychainClient: FakeKeychainClient(response: .success(Data("test-secret".utf8))))
    let fileManager = FileManager.default
    let tempRoot = fileManager.temporaryDirectory
        .appendingPathComponent("macop-selftest-\(UUID().uuidString)", isDirectory: true)
    defer { try? fileManager.removeItem(at: tempRoot) }

    try fileManager.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    let configDirectory = tempRoot.path

    var terminalSelectionPipe = [Int32](repeating: -1, count: 2)
    try expect(pipe(&terminalSelectionPipe) == 0, "selftest should create a non-terminal descriptor")
    defer { _ = close(terminalSelectionPipe[0]); _ = close(terminalSelectionPipe[1]) }
    try expect(
        !RunCommand.isInteractiveTerminal(stdin: terminalSelectionPipe[0], stdout: terminalSelectionPipe[1]),
        "PTY selection must require both parent descriptors to be terminals"
    )

    let version = app.run(argv: ["macop", "--version"], env: [:])
    try expect(version.exitCode == 0, "version should exit 0")
    try expect(version.stdout.contains("macop 0.1.0"), "version output should contain current version")

    let compatibility = app.run(argv: ["macop", "compatibility", "--format", "json"], env: [:])
    try expect(compatibility.exitCode == 0, "compatibility json should exit 0")
    guard let compatibilityObject = try JSONSerialization
        .jsonObject(with: Data(compatibility.stdout.utf8)) as? [String: Any],
        let entries = compatibilityObject["entries"] as? [[String: Any]]
    else {
        throw SelftestFailure(message: "compatibility JSON should match the published schema")
    }
    try expect(compatibilityObject["schema_version"] as? Int == 3, "compatibility schema version should be stable")
    try expect(
        entries.first { $0["command"] as? String == "run" }?["status"] as? String == "supported",
        "run must be marked supported once implemented"
    )
    try expect(
        entries.allSatisfy { $0["kind"] is String && $0["id"] is String },
        "compatibility entries should declare kind and ID"
    )
    let expectedCompatibilityIDs: Set = [
        "read", "read --no-newline", "read --out-file", "read --file-mode", "read --force", "run", "run --env-file",
        "run --stdin",
        "run --no-masking", "run --environment", "inject", "inject -i", "inject --in-file", "inject --out-file",
        "inject --file-mode",
        "inject --force", "item list", "item list --long", "item list --format", "item get", "item get --fields",
        "item get --reveal",
        "item get --format", "item get --vault", "item get --categories", "item get --tags", "item get --favorite",
        "item get --include-archive", "item get --otp", "item get --share-link", "item create", "item edit",
        "item delete",
        "item move", "item share", "item template", "completion", "help", "version", "whoami", "signin", "signout",
        "update", "vault", "account", "user", "group", "service-account", "connect", "events-api", "document",
        "environment",
        "plugin", "compatibility", "config init", "config validate", "doctor", "ssh", "--help", "--version",
        "--format",
        "--config", "--no-color", "--debug", "--encoding=utf-8", "--account", "--session", "--cache",
        "--iso-timestamps",
        "--encoding=<non-UTF-8>"
    ]
    let actualCompatibilityIDs = Set(entries.compactMap { $0["id"] as? String })
    try expect(
        actualCompatibilityIDs == expectedCompatibilityIDs,
        "compatibility matrix should enumerate every documented operation and flag"
    )
    let compatibilityHuman = app.run(argv: ["macop", "compatibility"], env: [:])
    try expect(
        compatibilityHuman.stdout.contains("read, run, inject"),
        "human compatibility must list implemented commands as supported"
    )
    try expect(
        compatibilityHuman.stdout.contains("Supported or partial op commands:"),
        "human matrix should label commands"
    )
    try expect(
        compatibilityHuman.stdout
            .contains("Macop extensions: compatibility, config init, config validate, doctor, ssh"),
        "human matrix should label extensions"
    )
    try expect(compatibilityHuman.stdout.contains("Flags:"), "human matrix should label flags separately")

    let sshExecutor = RecordingSSHExecutor()
    let sshApp = MacopApp(keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: sshExecutor)
    let createdIdentity = sshApp.run(argv: ["macop", "ssh", "create", "github", "--touch-id"], env: [:])
    try expect(createdIdentity.exitCode == 0, "ssh create should use the injectable Apple command executor")
    let createdJSONExecutor = SequencedSSHExecutor(lists: [
        appleTableHeader,
        appleTableHeader + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "new-github")
    ])
    let createdJSONApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: createdJSONExecutor
    )
    let createdJSON = createdJSONApp.run(
        argv: ["macop", "ssh", "create", "new-github", "--touch-id", "--format=json"], env: [:]
    )
    let createdObject = try JSONSerialization.jsonObject(with: Data(createdJSON.stdout.utf8)) as? [String: Any]
    try expect(
        (createdObject?["identities"] as? [[String: Any]])?.first?["public_key_hash"] as? String
            == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ssh create JSON must return the verified public-key hash"
    )
    try expect(
        sshExecutor.invocations.contains {
            $0.arguments == [
                "create-ctk-identity",
                "-l",
                "github",
                "-k",
                "p-256-ne",
                "-t",
                "bio"
            ]
        },
        "ssh create must request a non-exportable P-256 key protected by biometrics"
    )
    let publicKey = sshApp.run(argv: ["macop", "ssh", "public-key", "github", "--format=json"], env: [:])
    try expect(
        publicKey.exitCode == 0 && publicKey.stdout.contains("ecdsa-sha2-nistp256"),
        "ssh public-key should return provider public material only"
    )
    let tableFixture = appleTableHeader
        + appleTableRow("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "GitHub Work", commonName: "Example User")
        + appleTableRow("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "personal key")
        + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "github")
    let tableExecutor = SequencedSSHExecutor(lists: [tableFixture])
    let tableApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: tableExecutor
    )
    let listed = tableApp.run(argv: ["macop", "ssh", "list", "--format=json"], env: [:])
    let listedJSON = try JSONSerialization.jsonObject(with: Data(listed.stdout.utf8)) as? [String: Any]
    let listedIdentities = listedJSON?["identities"] as? [[String: Any]]
    try expect(
        listedIdentities?.count == 3
            && listedIdentities?.contains { $0["label"] as? String == "GitHub Work" } == true
            && listedIdentities?.contains { $0["label"] as? String == "personal key" } == true,
        "ssh list must parse Apple table rows and labels with spaces"
    )
    let malformedTable = tableFixture + "p-256-ne  DDDD                                               bio  malformed\n"
    let malformedExecutor = SequencedSSHExecutor(lists: [malformedTable, malformedTable])
    let malformedApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: malformedExecutor
    )
    try expect(
        malformedApp.run(argv: ["macop", "ssh", "list"], env: [:]).exitCode == 4
            && malformedApp.run(argv: ["macop", "ssh", "create", "fresh-key"], env: [:]).exitCode == 4
            && !malformedExecutor.invocations.contains { $0.arguments.first == "create-ctk-identity" },
        "a malformed table row must fail closed and prevent create mutation"
    )
    let legacyExecutor = SequencedSSHExecutor(lists: [
        "CTK Identity\nLabel: github\nPublic Key Hash: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    ])
    let legacyApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: legacyExecutor
    )
    try expect(
        legacyApp.run(argv: ["macop", "ssh", "create", "fresh-key"], env: [:]).exitCode == 4
            && !legacyExecutor.invocations.contains { $0.arguments.first == "create-ctk-identity" },
        "undocumented legacy CTK blocks must fail closed before create mutation"
    )
    let spacedLabelExecutor = SequencedSSHExecutor(lists: Array(repeating: appleTableHeader
            + appleTableRow("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "開発 SSH 鍵"), count: 4))
    let spacedLabelApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: spacedLabelExecutor
    )
    try expect(
        spacedLabelApp.run(argv: ["macop", "ssh", "public-key", "開発 SSH 鍵"], env: [:]).exitCode == 0
            && spacedLabelApp.run(argv: ["macop", "ssh", "run", "開発 SSH 鍵", "--", "git", "status"], env: [:])
            .exitCode == 0
            && spacedLabelApp.run(argv: ["macop", "ssh", "delete", "開発 SSH 鍵"], env: [:]).exitCode == 0,
        "safe Unicode labels must select public-key, run, and delete exactly"
    )
    let existingExecutor = SequencedSSHExecutor(lists: [tableFixture])
    let existingApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: existingExecutor
    )
    let duplicateCreate = existingApp.run(argv: ["macop", "ssh", "create", "github"], env: [:])
    try expect(
        duplicateCreate.exitCode == 2 && !existingExecutor.invocations
            .contains { $0.arguments.first == "create-ctk-identity" },
        "ssh create must preflight an exact existing label without mutating CTK"
    )
    let emptyTable = appleTableHeader
    let missingPostExecutor = SequencedSSHExecutor(lists: [emptyTable, emptyTable])
    let missingPostApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: missingPostExecutor
    )
    let missingPostCreate = missingPostApp.run(argv: ["macop", "ssh", "create", "new-key"], env: [:])
    try expect(
        missingPostCreate.exitCode == 4,
        "ssh create must fail when post-create identity verification is missing"
    )
    let duplicatePost = appleTableHeader
        + appleTableRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "new-key")
        + appleTableRow("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "new-key")
    let duplicatePostExecutor = SequencedSSHExecutor(lists: [emptyTable, duplicatePost])
    let duplicatePostApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: duplicatePostExecutor
    )
    let duplicatePostCreate = duplicatePostApp.run(argv: ["macop", "ssh", "create", "new-key"], env: [:])
    try expect(
        duplicatePostCreate.exitCode == 4,
        "ssh create must fail when post-create identity verification is ambiguous"
    )
    let publicKeyJSON = try JSONSerialization.jsonObject(with: Data(publicKey.stdout.utf8)) as? [String: Any]
    try expect(
        publicKeyJSON?["schema_version"] as? Int == 1 && publicKeyJSON?["label"] as? String == "github"
            && publicKeyJSON?["public_key"] is String && publicKeyJSON?["provider"] as? String == "ssh-keychain",
        "ssh public-key JSON must conform to its typed schema"
    )
    let deletedIdentity = sshApp.run(argv: ["macop", "ssh", "delete", "github"], env: [:])
    try expect(deletedIdentity.exitCode == 0, "ssh delete should resolve a single public hash before deletion")
    try expect(
        sshExecutor.invocations.last?.arguments == [
            "delete-ctk-identity", "-h", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ],
        "ssh delete must never perform a broad CTK deletion"
    )
    let gitRun = sshApp.run(
        argv: ["macop", "ssh", "run", "github", "--", "git", "clone", "git@github.com:owner/repo.git"],
        env: [:]
    )
    try expect(gitRun.exitCode == 0, "ssh run should invoke git without a shell")
    let notGitRun = sshApp.run(argv: ["macop", "ssh", "run", "github", "--", "notgit", "status"], env: [:])
    try expect(notGitRun.exitCode == 3, "ssh run must reject executables whose basename is not exactly git")
    let absoluteGitRun = sshApp.run(
        argv: ["macop", "ssh", "run", "github", "--", "/usr/bin/git", "status"], env: [:]
    )
    try expect(absoluteGitRun.exitCode == 0, "ssh run should accept an absolute executable whose basename is git")
    try expect(
        sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?
            .contains("PKCS11Provider=/usr/lib/ssh-keychain.dylib") == true
            && sshExecutor.invocations.last?.environment["GIT_SSH_COMMAND"]?.contains("ForwardAgent=no") == true,
        "ssh run must force the Apple provider and disable forwarding"
    )
    try expect(
        sshExecutor.invocations.last?
            .environment["KEYCHAIN_CERTIFICATES"] == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ssh run must restrict the Apple provider to the selected public-key hash"
    )
    let streamedSSH = StreamCollector()
    let streamingSSH = sshApp.runStreamingIfNeeded(
        argv: ["macop", "ssh", "run", "github", "--", "git", "status"], env: [:],
        stdout: { streamedSSH.append($0) }, stderr: { _ in }
    )
    try expect(
        streamingSSH?.exitCode == 23
            && String(bytes: streamedSSH.read(), encoding: .utf8) == "streamed-child-output\n",
        "ssh run should use the streaming executor and preserve the child exit status"
    )
    let greeting = "Hi user! You've successfully authenticated, but GitHub does not provide shell access.\n"
    let greetingApp = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: GitHubTestExecutor(output: greeting, code: 1)
    )
    let greetingResult = greetingApp.run(argv: ["macop", "ssh", "test", "github", "--format=json"], env: [:])
    let greetingJSON = try JSONSerialization.jsonObject(with: Data(greetingResult.stdout.utf8)) as? [String: Any]
    try expect(
        greetingResult.exitCode == 0 && greetingJSON?["raw_exit_code"] as? Int == 1
            && greetingJSON?["status"] as? String == "authenticated",
        "GitHub's documented authenticated greeting at raw exit 1 must normalize to success"
    )
    let greetingStream = StreamCollector()
    let streamedGreeting = greetingApp.runStreamingIfNeeded(
        argv: ["macop", "ssh", "test", "github"], env: [:],
        stdout: { greetingStream.append($0) }, stderr: { greetingStream.append($0) }
    )
    try expect(
        streamedGreeting?.exitCode == 0 && String(bytes: greetingStream.read(), encoding: .utf8) == greeting,
        "streaming GitHub test must normalize success while preserving visible output"
    )
    let unrelatedExit = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: GitHubTestExecutor(output: "permission denied\n", code: 1)
    ).run(argv: ["macop", "ssh", "test", "github"], env: [:])
    try expect(unrelatedExit.exitCode == 1, "arbitrary GitHub exit 1 must remain a failure")
    let transportFailure = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())),
        commandExecutor: GitHubTestExecutor(output: greeting, code: 255)
    ).run(argv: ["macop", "ssh", "test", "github"], env: [:])
    try expect(transportFailure.exitCode == 255, "GitHub transport exit 255 must remain a failure")
    let unsafeLabel = sshApp.run(argv: ["macop", "ssh", "create", "bad\nlabel"], env: [:])
    try expect(unsafeLabel.exitCode == 2, "ssh labels must reject argument-injection characters")
    let unicodeNewlineLabel = sshApp.run(argv: ["macop", "ssh", "create", "bad\u{2028}label"], env: [:])
    try expect(unicodeNewlineLabel.exitCode == 2, "ssh labels must reject Unicode line separators")
    let doctor = sshApp.run(argv: ["macop", "doctor", "--format=json"], env: [:])
    let doctorJSON = try JSONSerialization.jsonObject(with: Data(doctor.stdout.utf8)) as? [String: Any]
    try expect(doctorJSON?["schema_version"] as? Int == 1 && doctorJSON?["status"] is String
        && doctorJSON?["checks"] is [[String: Any]] && !doctor.stdout.contains("test-secret"),
        "doctor JSON must be typed and secret-free")
    let brokenCTKExecutor = SequencedSSHExecutor(lists: ["Error: Failed to get TKTokenDriver configuration\n"])
    let brokenDoctor = MacopApp(
        keychainClient: FakeKeychainClient(response: .success(Data())), commandExecutor: brokenCTKExecutor
    ).run(argv: ["macop", "doctor", "--format=json"], env: [:])
    let brokenDoctorJSON = try JSONSerialization.jsonObject(with: Data(brokenDoctor.stdout.utf8)) as? [String: Any]
    let brokenChecks = brokenDoctorJSON?["checks"] as? [[String: Any]]
    try expect(
        brokenDoctor.exitCode == 4
            && brokenChecks?.first(where: { $0["name"] as? String == "cryptotokenkit" })?["status"] as? String == "fail"
            && brokenCTKExecutor.invocations.contains { $0.path == "/usr/bin/codesign" },
        "doctor must reject exit-zero CTK error text and continue later checks"
    )

    let compatibilityEquals = app.run(argv: ["macop", "compatibility", "--format=json"], env: [:])
    try expect(compatibilityEquals.exitCode == 0, "equals global format should be accepted after command")
    try expect(compatibilityEquals.stdout.contains("\"schema_version\""), "equals format should render JSON")

    let successfulDebug = app.run(argv: ["macop", "compatibility", "--format=json", "--debug"], env: [:])
    _ = try JSONSerialization.jsonObject(with: Data(successfulDebug.stdout.utf8))
    try expect(
        successfulDebug.stderr.contains("debug exit_code=0"),
        "successful commands should render safe debug output"
    )
    try expect(
        successfulDebug.stderr.contains("command=compatibility"),
        "success debug should include a sanitized command category"
    )
    let streamingDebugFailure = app.runStreamingIfNeeded(
        argv: ["macop", "run", "--format=json", "--debug"],
        env: [:],
        stdout: { _ in },
        stderr: { _ in }
    )
    guard let streamingDebugFailure,
          let streamingErrorObject = try JSONSerialization
          .jsonObject(with: Data(streamingDebugFailure.stderr.utf8)) as? [String: Any],
          let streamingError = streamingErrorObject["error"] as? [String: Any]
    else {
        throw SelftestFailure(message: "streaming run errors should remain one JSON object")
    }
    try expect(streamingError["debug"] != nil, "streaming run errors should retain safe debug metadata")

    let configInit = app.run(argv: ["macop", "--config", configDirectory, "config", "init"], env: [:])
    try expect(configInit.exitCode == 0, "config init should exit 0")

    let configValidate = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(configValidate.exitCode == 0, "config validate should exit 0")

    let configValidateEquals = app.run(argv: ["macop", "config", "validate", "--config=\(configDirectory)"], env: [:])
    try expect(configValidateEquals.exitCode == 0, "equals config should be accepted after command")

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
    try expect(providerPending.exitCode == 0, "read should fetch through the injected Keychain client")
    try expect(providerPending.stdout == "test-secret\n", "read should append a newline by default")

    let injected = app.run(
        argv: ["macop", "--config", configDirectory, "inject"],
        env: [:],
        input: Data("token=op://Local/GitHub/token\n".utf8)
    )
    try expect(injected.exitCode == 0, "inject stdin should succeed")
    try expect(injected.stdout == "token=test-secret\n", "inject should resolve references in memory")
    let adjacentReferences = app.run(
        argv: ["macop", "--config", configDirectory, "inject"],
        env: [:],
        input: Data("a=op://Local/GitHub/tokenkeychain://generic/service/account.\n".utf8)
    )
    try expect(
        adjacentReferences.stdout == "a=test-secrettest-secret.\n",
        "inject should resolve adjacent references without consuming trailing punctuation"
    )
    let unsupportedInjectedProvider = app.run(
        argv: ["macop", "inject"],
        env: [:],
        input: Data("apple-passwords://example.com/account".utf8)
    )
    try expect(unsupportedInjectedProvider.exitCode == 3, "inject should reject unsupported reference schemes")
    let templatePath = tempRoot.appendingPathComponent("config.tpl")
    try Data("a=op://Local/GitHub/token;b=op://Local/GitHub/token".utf8).write(to: templatePath)
    let injectedFile = app.run(
        argv: ["macop", "--config", configDirectory, "inject", "--in-file", templatePath.path], env: [:]
    )
    try expect(injectedFile.stdout == "a=test-secret;b=test-secret", "inject file should resolve multiple references")
    let forbiddenInjectOutput = app.run(
        argv: ["macop", "inject", "--out-file=result"], env: [:]
    )
    try expect(forbiddenInjectOutput.exitCode == 3, "inject persistent output must be rejected")

    let runMasked = app.run(
        argv: ["macop", "run", "--", "/usr/bin/printenv", "GH_TOKEN"],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(runMasked.exitCode == 0, "run should launch a command directly")
    try expect(runMasked.stdout == "<concealed by macop>\n", "run should mask environment secrets by default")
    let runUnmasked = app.run(
        argv: ["macop", "run", "--no-masking", "--", "/usr/bin/printenv", "GH_TOKEN"],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(runUnmasked.stdout == "test-secret\n", "run --no-masking should be the explicit bypass")
    let opaqueClient = QuerySensitiveKeychainClient()
    let opaqueApp = MacopApp(keychainClient: opaqueClient)
    let opaqueRun = opaqueApp.run(
        argv: ["macop", "run", "--no-masking", "--", "/usr/bin/printenv", "OPAQUE_SECRET"],
        env: ["OPAQUE_SECRET": "keychain://generic/service/account"]
    )
    try expect(
        opaqueRun.stdout == "keychain://generic/other/account\n" && opaqueClient.queries.count == 1,
        "provider-returned URI-looking secret must remain opaque after exactly one resolution"
    )
    let compositeRun = app.run(
        argv: [
            "macop", "run", "--", "/bin/sh", "-c",
            "printf '%s' test-secret; printf '%s' test-secret >&2"
        ],
        env: ["AUTH": "Bearer keychain://generic/service/account"]
    )
    try expect(
        compositeRun.stdout == "<concealed by macop>" && compositeRun.stderr == "<concealed by macop>",
        "composite environment references must register each source secret for both streams"
    )
    let dotenvPath = tempRoot.appendingPathComponent(".env")
    try Data("FIRST=one\nGH_TOKEN=op://Local/GitHub/token\n".utf8).write(to: dotenvPath)
    let dotenvRun = app.run(
        argv: [
            "macop",
            "--config",
            configDirectory,
            "run",
            "--env-file",
            dotenvPath.path,
            "--",
            "/usr/bin/printenv",
            "GH_TOKEN"
        ],
        env: [:]
    )
    try expect(dotenvRun.stdout == "<concealed by macop>\n", "dotenv references should be resolved and masked")
    let compositeDotenvPath = tempRoot.appendingPathComponent("composite.env")
    try Data("AUTH=Bearer keychain://generic/service/account:keychain://generic/service/account\n".utf8)
        .write(to: compositeDotenvPath)
    let compositeDotenvRun = app.run(
        argv: [
            "macop", "run", "--env-file", compositeDotenvPath.path, "--", "/bin/sh", "-c",
            "printf '%s' test-secret; printf '%s' test-secret >&2"
        ], env: [:]
    )
    try expect(
        compositeDotenvRun.stdout == "<concealed by macop>"
            && compositeDotenvRun.stderr == "<concealed by macop>",
        "composite dotenv templates with duplicate references must register original secrets"
    )
    let escapedDotenvPath = tempRoot.appendingPathComponent("escaped.env")
    try Data(#"ESCAPED="line\nquote:\" slash:\\ tab:\t dollar:\$""#.utf8).write(to: escapedDotenvPath)
    let escapedDotenv = app.run(
        argv: ["macop", "run", "--env-file", escapedDotenvPath.path, "--", "/usr/bin/printenv", "ESCAPED"], env: [:]
    )
    try expect(
        escapedDotenv.stdout == "line\nquote:\" slash:\\ tab:\t dollar:$\n",
        "dotenv double quotes should decode conventional escapes"
    )
    for expansion in ["PLAIN=$NAME\n", "BRACED=${NAME}\n", "QUOTED=\"$NAME\"\n"] {
        let expansionPath = tempRoot.appendingPathComponent("expansion.env")
        try Data(expansion.utf8).write(to: expansionPath)
        let expansionRun = app.run(
            argv: ["macop", "run", "--env-file", expansionPath.path, "--", "/usr/bin/true"], env: [:]
        )
        try expect(expansionRun.exitCode == 3, "unescaped dotenv variable expansion must be explicitly unsupported")
    }
    let singleQuotedPath = tempRoot.appendingPathComponent("single.env")
    try Data("LITERAL='$NAME'\n".utf8).write(to: singleQuotedPath)
    let singleQuotedRun = app.run(
        argv: ["macop", "run", "--env-file", singleQuotedPath.path, "--", "/usr/bin/printenv", "LITERAL"], env: [:]
    )
    try expect(singleQuotedRun.stdout == "$NAME\n", "single-quoted dotenv dollars should remain literal")
    let oddSlashPath = tempRoot.appendingPathComponent("odd-slash.env")
    try Data(#"LITERAL="\$NAME""#.utf8).write(to: oddSlashPath)
    let oddSlashRun = app.run(
        argv: ["macop", "run", "--env-file", oddSlashPath.path, "--", "/usr/bin/printenv", "LITERAL"], env: [:]
    )
    try expect(oddSlashRun.stdout == "$NAME\n", "odd backslash parity should escape dotenv expansion")
    let evenSlashPath = tempRoot.appendingPathComponent("even-slash.env")
    try Data(#"EXPANSION="\\$NAME""#.utf8).write(to: evenSlashPath)
    let evenSlashRun = app.run(
        argv: ["macop", "run", "--env-file", evenSlashPath.path, "--", "/usr/bin/true"], env: [:]
    )
    try expect(evenSlashRun.exitCode == 3, "even backslash parity must not escape dotenv expansion")
    let firstEnvPath = tempRoot.appendingPathComponent("first.env")
    let laterEnvPath = tempRoot.appendingPathComponent("later.env")
    try Data("GH_TOKEN=keychain://generic/service/$ACCOUNT\nACCOUNT=wrong\n".utf8).write(to: firstEnvPath)
    try Data("ACCOUNT=account\n".utf8).write(to: laterEnvPath)
    let precedenceRun = app.run(
        argv: [
            "macop", "run", "--env-file", firstEnvPath.path, "--env-file", laterEnvPath.path,
            "--", "/usr/bin/printenv", "GH_TOKEN"
        ],
        env: [:]
    )
    try expect(
        precedenceRun.stdout == "<concealed by macop>\n",
        "dotenv references should expand against the final last-file-wins environment"
    )
    let stdinRun = app.run(
        argv: ["macop", "--config", configDirectory, "run", "--stdin", "op://Local/GitHub/token", "--", "/bin/cat"],
        env: [:]
    )
    try expect(stdinRun.stdout == "<concealed by macop>", "run --stdin should inject without argv exposure")
    let redactor = SecretRedactor(secrets: ["test-secret", "secret"])
    let firstChunk = redactor.process(Data("before test-".utf8))
    let secondChunk = redactor.process(Data("secret after".utf8), final: true)
    try expect(
        String(bytes: firstChunk + secondChunk, encoding: .utf8) == "before <concealed by macop> after",
        "redactor must mask an overlapping secret across chunk boundaries"
    )
    let collisionRedactor = SecretRedactor(secrets: ["<concealed by macop>", "aba", "ba"])
    let collisionOutput = collisionRedactor.process(Data("aba<concealed ".utf8))
        + collisionRedactor.process(Data("by macop>aba".utf8), final: true)
    try expect(
        String(bytes: collisionOutput, encoding: .utf8) ==
            "<concealed by macop><concealed by macop><concealed by macop>",
        "redactor must use longest source matches and never rescan replacements"
    )
    let stderrMasked = app.run(
        argv: ["macop", "run", "--", "/bin/sh", "-c", "printf '%s' \"$GH_TOKEN\" >&2"],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(stderrMasked.stderr == "<concealed by macop>", "run should mask stderr independently")
    let stderrUnmasked = app.run(
        argv: ["macop", "run", "--no-masking", "--", "/bin/sh", "-c", "printf '%s' \"$GH_TOKEN\" >&2"],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(stderrUnmasked.stderr == "test-secret", "--no-masking should also bypass stderr masking")

    let largeOutput = app.run(
        argv: [
            "macop", "run", "--", "/bin/sh", "-c",
            "i=0; while [ \"$i\" -lt 20000 ]; do printf 'out:%s\\n' \"$GH_TOKEN\"; printf 'err:%s\\n' \"$GH_TOKEN\" >&2; i=$((i + 1)); done"
        ],
        env: ["GH_TOKEN": "keychain://generic/service/account"]
    )
    try expect(largeOutput.exitCode == 0, "large stdout and stderr command should complete")
    try expect(!largeOutput.stdout.contains("test-secret") && !largeOutput.stderr.contains("test-secret"),
               "large output must mask every secret across real pipe reads")
    try expect(largeOutput.stdout.components(separatedBy: "<concealed by macop>").count == 20001,
               "large stdout should retain every redacted record")
    try expect(largeOutput.stderr.components(separatedBy: "<concealed by macop>").count == 20001,
               "large stderr should retain every redacted record")

    let earlyClose = app.run(
        argv: ["macop", "run", "--stdin", "keychain://generic/service/account", "--", "/bin/sh", "-c", "exit 0"],
        env: [:]
    )
    try expect(earlyClose.exitCode == 0, "run --stdin should tolerate a child that closes stdin early")
    let largeSecret = String(repeating: "large-stdin-secret-", count: 32768)
    let largeInputApp = MacopApp(keychainClient: FakeKeychainClient(response: .success(Data(largeSecret.utf8))))
    let largeInput = largeInputApp.run(
        argv: ["macop", "run", "--stdin", "keychain://generic/service/account", "--", "/bin/cat"], env: [:]
    )
    try expect(largeInput.exitCode == 0 && largeInput.stdout == "<concealed by macop>",
               "run --stdin should deliver and mask large input without deadlocking")
    let noNewlineRead = app.run(
        argv: ["macop", "--config", configDirectory, "read", "--no-newline", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(noNewlineRead.stdout == "test-secret", "read --no-newline should not append a newline")
    let itemList = app.run(argv: ["macop", "--config", configDirectory, "item", "list", "--format=json"], env: [:])
    let itemListObject = try JSONSerialization.jsonObject(with: Data(itemList.stdout.utf8)) as? [String: Any]
    try expect(itemListObject?["schema_version"] as? Int == 1, "item list JSON should use the macop schema")
    let listEntries = itemListObject?["items"] as? [[String: Any]]
    try expect(listEntries?.first?["name"] as? String == "Local/GitHub", "item list JSON should expose configured name")
    try expect(
        listEntries?.first?["provider"] as? String == "keychain-generic",
        "item list JSON should expose provider"
    )
    let longList = app.run(
        argv: ["macop", "--config", configDirectory, "item", "list", "--long", "--format=json"],
        env: [:]
    )
    let longEntries = try (JSONSerialization
        .jsonObject(with: Data(longList.stdout.utf8)) as? [String: Any])?["items"] as? [[String: Any]]
    try expect(
        longEntries?.first?["account"] as? String == "me@example.com",
        "item list --long should expose non-secret account metadata"
    )
    try expect(
        longEntries?.first?["locator"] as? String == "github-token",
        "item list --long should expose non-secret locator metadata"
    )
    let maskedItem = app.run(
        argv: ["macop", "--config", configDirectory, "item", "get", "GitHub", "--fields", "label=token",
               "--format=json"],
        env: [:]
    )
    try expect(maskedItem.stdout.contains("<concealed by macop>"), "item get should mask without reveal")
    try expect(!maskedItem.stdout.contains("test-secret"), "masked item output must not leak secrets")
    let maskedObject = try JSONSerialization.jsonObject(with: Data(maskedItem.stdout.utf8)) as? [String: Any]
    let maskedFields = (maskedObject?["items"] as? [String: Any])?["fields"] as? [[String: Any]]
    try expect(maskedFields?.first?["label"] as? String == "token", "item get JSON should preserve field label")
    try expect(
        maskedFields?.first?["value"] as? String == "<concealed by macop>",
        "item get JSON should mask by default"
    )
    let revealedItem = app.run(
        argv: ["macop", "--config", configDirectory, "item", "get", "GitHub", "--fields=label=token", "--reveal",
               "--format=json"],
        env: [:]
    )
    try expect(revealedItem.stdout.contains("test-secret"), "item get reveal should fetch the selected field")
    let revealedObject = try JSONSerialization.jsonObject(with: Data(revealedItem.stdout.utf8)) as? [String: Any]
    let revealedFields = (revealedObject?["items"] as? [String: Any])?["fields"] as? [[String: Any]]
    try expect(
        revealedFields?.first?["value"] as? String == "test-secret",
        "item get JSON should reveal only with --reveal"
    )

    let recordingClient = RecordingKeychainClient(.success(Data("test-secret".utf8)))
    let recordingApp = MacopApp(keychainClient: recordingClient)
    _ = recordingApp.run(argv: ["macop", "read", "keychain://generic/service/account"], env: [:])
    try expect(
        recordingClient.queries == [.generic(service: "service", account: "account")],
        "generic URI query should preserve service/account"
    )
    _ = recordingApp.run(argv: ["macop", "read", "keychain://internet/server.example/account"], env: [:])
    try expect(
        recordingClient.queries.last == .internet(server: "server.example", account: "account"),
        "internet URI query should preserve server/account"
    )
    for (status, expected) in [
        (errSecItemNotFound, Int32(6)),
        (errSecAuthFailed, Int32(5)),
        (errSecUserCanceled, Int32(5)),
        (errSecNotAvailable, Int32(4)),
        (-9999, Int32(1))
    ] {
        let statusApp = MacopApp(keychainClient: FakeKeychainClient(response: .failure(KeychainFailure(status))))
        let result = statusApp.run(argv: ["macop", "read", "keychain://generic/service/account"], env: [:])
        try expect(result.exitCode == expected, "OSStatus should map to the documented exit code")
    }
    for invalid in [Data([0xFF]), Data("secret\0value".utf8)] {
        let invalidApp = MacopApp(keychainClient: FakeKeychainClient(response: .success(invalid)))
        let result = invalidApp.run(argv: ["macop", "read", "keychain://generic/service/account"], env: [:])
        try expect(result.exitCode == 1, "invalid UTF-8 or NUL Keychain data should fail at runtime")
        try expect(!result.stderr.contains("secret\0value"), "invalid secret values must not leak")
    }
    let equalsOutputFlag = app.run(
        argv: ["macop", "read", "--out-file=token", "keychain://generic/service/account"],
        env: [:]
    )
    try expect(equalsOutputFlag.exitCode == 3, "persistent output equals flags should be unsupported")

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
    try expect(unreadableConfig.exitCode == 2, "non-owner-only config mode should be rejected")
    try expect(
        unreadableConfig.stderr.contains("permissions must be owner-only"),
        "unsafe config mode should be explained"
    )

    let unsupportedProvider = app.run(argv: ["macop", "read", "apple-passwords://example.com/me/password"], env: [:])
    try expect(unsupportedProvider.exitCode == 3, "apple-passwords should be unsupported")

    let unsupportedPath = app.run(argv: ["macop", "vault", "list", "--format=json"], env: [:])
    try expect(unsupportedPath.exitCode == 3, "unsupported command should exit 3")
    try expect(unsupportedPath.stderr.contains("\"command\" : \"vault list\""), "unsupported path should be preserved")
    try expect(unsupportedPath.stderr.contains("documentation"), "unsupported JSON errors should include guidance")
    let debugJSONError = app.run(argv: ["macop", "vault", "list", "--format=json", "--debug"], env: [:])
    guard let debugObject = try JSONSerialization.jsonObject(with: Data(debugJSONError.stderr.utf8)) as? [String: Any],
          let debugError = debugObject["error"] as? [String: Any]
    else {
        throw SelftestFailure(message: "debug JSON error should remain a single JSON object")
    }
    try expect(debugError["debug"] != nil, "JSON debug errors should retain safe debug metadata")
    try expect(
        (debugError["debug"] as? [String: Any])?["context"] as? String == "command=vault",
        "error debug should include a sanitized command category"
    )
    try expect(!debugJSONError.stderr.contains("op://"), "debug errors must not include secret references")
    let rawDebugError = app.run(
        argv: ["macop", "--debug", "--format=not-a-format"],
        env: ["OP_DEBUG": "0"]
    )
    try expect(
        rawDebugError.stderr.contains("debug exit_code=2"),
        "explicit debug should override false OP_DEBUG during parse errors"
    )

    let unsupportedGlobal = app.run(argv: ["macop", "read", "--account=team", "op://Local/GitHub/token"], env: [:])
    try expect(unsupportedGlobal.exitCode == 3, "known unsupported global flags should exit 3")
    let unknownGlobal = app.run(argv: ["macop", "--not-a-flag", "read"], env: [:])
    try expect(unknownGlobal.exitCode == 2, "unknown global syntax should exit 2")
    let utf8Encoding = app.run(argv: ["macop", "compatibility", "--encoding=utf-8"], env: [:])
    try expect(utf8Encoding.exitCode == 0, "UTF-8 encoding should be accepted")
    let nonUTF8Encoding = app.run(argv: ["macop", "compatibility", "--encoding", "utf-16"], env: [:])
    try expect(nonUTF8Encoding.exitCode == 3, "non-UTF-8 encoding should be unsupported")

    let queryReference = app.run(argv: ["macop", "read", "op://Local/GitHub/token?attribute=otp"], env: [:])
    try expect(queryReference.exitCode == 3, "reference query parameters should be unsupported")
    let cyclicReference = app.run(argv: ["macop", "read", "$A"], env: ["A": "$B", "B": "$A"])
    try expect(cyclicReference.exitCode == 2, "cyclic reference environment expansion should fail")
    let undefinedReference = app.run(argv: ["macop", "read", "$MISSING_REFERENCE"], env: [:])
    try expect(undefinedReference.exitCode == 2, "undefined reference environment expansion should fail")

    let secureEnclaveRead = app.run(argv: ["macop", "read", "secure-enclave://github"], env: [:])
    try expect(secureEnclaveRead.exitCode == 3, "secure-enclave reads must be unsupported rather than unavailable")

    let duplicateFieldsConfig = """
    { "version": 1, "items": { "Local/GitHub": { "provider": "keychain-generic", "service": "github", "account": "me", "fields": ["token", "token"] } } }
    """
    try duplicateFieldsConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let duplicateFields = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(duplicateFields.exitCode == 2, "duplicate fields should fail schema validation")

    let secretConfig = """
    { "version": 1, "items": { "Local/GitHub": { "provider": "keychain-generic", "service": "github", "account": "me", "secret": "do-not-store" } } }
    """
    try secretConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let secretConfigResult = app.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(secretConfigResult.exitCode == 2, "normal config load must reject secret-looking keys")

    let duplicateKeyConfig = """
    { "version": 1, "version": 1, "items": {} }
    """
    try duplicateKeyConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let duplicateKey = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(duplicateKey.exitCode == 2, "duplicate JSON keys should fail validation")

    let escapedDuplicateKeyConfig = """
    {
      "version": 1,
      "items": {
        "Local/GitHub": { "provider": "keychain-generic", "service": "github", "account": "me" },
        "Local\\u002fGitHub": { "provider": "keychain-generic", "service": "github", "account": "me" }
      }
    }
    """
    try escapedDuplicateKeyConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let escapedDuplicateKey = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(escapedDuplicateKey.exitCode == 2, "escaped semantic duplicate keys should fail validation")

    let malformedConfig = "{ \"version\": 1, \"items\": "
    try malformedConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let malformedValidate = app.run(argv: ["macop", "--config", configDirectory, "config", "validate"], env: [:])
    try expect(malformedValidate.exitCode == 2, "malformed config validate should be invalid arguments")
    let malformedLoad = app.run(
        argv: ["macop", "--config", configDirectory, "read", "op://Local/GitHub/token"],
        env: [:]
    )
    try expect(malformedLoad.exitCode == 2, "malformed normal config load should be invalid arguments")

    let secureConfig = """
    { "version": 1, "items": {
      "Local/GitHub": { "provider": "keychain-generic", "service": "github-token", "account": "me@example.com", "fields": ["token"] },
      "Local/SSH": { "provider": "secure-enclave", "label": "github" }
    } }
    """
    try secureConfig.data(using: .utf8)!.write(to: configPath, options: [.atomic])
    let secureRecording = RecordingKeychainClient(.success(Data("test-secret".utf8)))
    let secureApp = MacopApp(keychainClient: secureRecording)
    let filteredList = secureApp.run(
        argv: ["macop", "--config", configDirectory, "item", "list", "--format=json"],
        env: [:]
    )
    try expect(!filteredList.stdout.contains("Local/SSH"), "item list must exclude secure-enclave config entries")
    let queriesBefore = secureRecording.queries.count
    let secureGet = secureApp.run(
        argv: ["macop", "--config", configDirectory, "item", "get", "SSH", "--reveal"],
        env: [:]
    )
    try expect(secureGet.exitCode != 0, "secure-enclave item get reveal must fail closed")
    try expect(secureRecording.queries.count == queriesBefore, "secure-enclave item get must not query Keychain")

    let zshCompletion = app.run(argv: ["macop", "completion", "zsh"], env: [:])
    try expect(zshCompletion.stdout.contains("commands=(read run inject"), "zsh completion should offer commands")
    try expect(zshCompletion.stdout.contains("compdef _macop macop op"), "zsh completion should register both names")
    let bashCompletion = app.run(argv: ["macop", "completion", "bash"], env: [:])
    try expect(bashCompletion.stdout.contains("init validate"), "bash completion should offer config subcommands")
    let fishCompletion = app.run(argv: ["macop", "completion", "fish"], env: [:])
    try expect(fishCompletion.stdout.contains("-l format"), "fish completion should offer format values")
}

if runHarnessIfRequested() == nil {
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
}
