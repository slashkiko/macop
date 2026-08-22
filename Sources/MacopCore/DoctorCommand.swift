import Foundation
import LocalAuthentication
import Security

public enum DoctorCommand {
    private static func keychainAPIStatus() -> OSStatus {
        let authenticationContext = LAContext()
        authenticationContext.interactionNotAllowed = true
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "com.slashkiko.macop.doctor",
            kSecAttrAccount: UUID().uuidString,
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: authenticationContext
        ]
        var result: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &result)
    }

    public static func run(options: GlobalOptions, context: DoctorContext) throws -> CommandResult {
        var checks = [DoctorCheck]()
        func add(_ name: String, _ status: DoctorStatus, _ detail: String) {
            checks.append(DoctorCheck(name: name, status: status, detail: detail))
        }
        func diagnostic(_ path: String, _ arguments: [String]) -> CommandResult? {
            do {
                return try context.executor.execute(path: path, arguments: arguments, environment: context.env)
            } catch {
                return nil
            }
        }
        let version = ProcessInfo.processInfo.operatingSystemVersion
        add(
            "macos",
            version.majorVersion >= 14 ? .pass : .fail,
            "macOS \(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
        )

        let executable: String
        do {
            executable = try RunningExecutable.path()
            add(
                "current_executable",
                FileManager.default.isExecutableFile(atPath: executable) ? .pass : .warn,
                executable
            )
        } catch {
            executable = ""
            add("current_executable", .warn, "Unable to resolve the running executable")
        }
        for (name, path) in [
            ("sc_auth", SSHCommand.scAuth),
            ("ssh", SSHCommand.ssh),
            ("ssh-keygen", SSHCommand.sshKeygen),
            ("ssh-keychain", SSHCommand.provider)
        ] {
            add(name, FileManager.default.fileExists(atPath: path) ? .pass : .fail, path)
        }
        let keychainStatus = self.keychainAPIStatus()
        let keychainAvailable = keychainStatus == errSecSuccess || keychainStatus == errSecItemNotFound
        add(
            "keychain_api",
            keychainAvailable ? .pass : .warn,
            keychainAvailable ? "Keychain API available without secret access"
                : "Keychain API unavailable without interaction (status \(keychainStatus))"
        )

        if FileManager.default.fileExists(atPath: SSHCommand.scAuth) {
            let ctk = diagnostic(SSHCommand.scAuth, ["list-ctk-identities", "-t", "sha1", "-e", "hex"])
            do {
                guard let ctk, ctk.exitCode == 0 else {
                    throw CLIError.providerUnavailable(
                        provider: "CryptoTokenKit",
                        reason: "identity enumeration failed"
                    )
                }
                try SSHCommand.validateIdentityTable(ctk.stdout)
                add("cryptotokenkit", .pass, "CTK identity enumeration available")
            } catch {
                add("cryptotokenkit", .fail, "CTK identity enumeration returned an invalid table")
            }
        } else {
            add("cryptotokenkit", .warn, "Skipped because sc_auth is unavailable")
        }
        do {
            let url = try ConfigStore.validate(configDirectory: options.configDirectory)
            add("config", .pass, "validated \(url.path)")
        } catch let error as CLIError { add("config", .warn, "\(error)")
        } catch { add("config", .warn, "configuration validation unavailable") }

        let sshG = diagnostic(
            SSHCommand.ssh,
            [
                "-G",
                "-o",
                "ForwardAgent=no",
                "-o",
                "PKCS11Provider=\(SSHCommand.provider)",
                "-o",
                "IdentitiesOnly=yes",
                "example.invalid"
            ]
        )
        let effective = Set((sshG?.stdout ?? "").split(whereSeparator: \.isNewline).map { $0.lowercased() })
        let forward = effective.contains("forwardagent no")
        let provider = effective.contains("pkcs11provider \(SSHCommand.provider)")
        let identities = effective.contains("identitiesonly yes")
        add(
            "forward_agent",
            forward ? .pass : .fail,
            forward ? "effective ForwardAgent=no" : "unable to verify ForwardAgent=no"
        )
        add(
            "ssh_identity_selection",
            provider && identities ? .pass : .fail,
            provider && identities ? "effective PKCS11Provider and IdentitiesOnly=yes" : "unable to verify SSH identity selection"
        )
        let sshVersion = diagnostic(SSHCommand.ssh, ["-V"])
        add(
            "ssh_client",
            sshVersion?.exitCode == 0 ? .pass : .warn,
            sshVersion?.exitCode == 0 ? "Apple SSH selected" : "Unable to query selected SSH client"
        )
        if executable.isEmpty {
            add("code_signature", .warn, "Skipped because the running executable could not be resolved")
        } else {
            let signature = diagnostic("/usr/bin/codesign", ["-dv", "--verbose=4", executable])
            let signatureText = (signature?.stdout ?? "") + (signature?.stderr ?? "")
            if signature?.exitCode != 0 {
                add("code_signature", .warn, "codesign metadata unavailable")
            } else if signatureText.contains("Signature=adhoc") {
                add(
                    "code_signature",
                    .warn,
                    "ad-hoc signature; Keychain ACL and XARA authorization may repeat after rebuilds"
                )
            } else {
                add("code_signature", .pass, "non-ad-hoc codesign metadata available")
            }
        }

        let status: DoctorStatus = checks
            .contains { $0.status == .fail } ? .fail : (checks.contains { $0.status == .warn } ? .warn : .pass)
        let exitCode: Int32 = status == .fail ? ExitCode.providerUnavailable.rawValue : 0
        if options.format == .json {
            do {
                let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                return try CommandResult(
                    exitCode: exitCode,
                    stdout: (String(
                        bytes: encoder.encode(DoctorResponse(status: status, checks: checks)),
                        encoding: .utf8
                    ) ?? "") + "\n"
                )
            } catch { throw CLIError.runtimeError(message: "Unable to encode doctor response.") }
        }
        return CommandResult(
            exitCode: exitCode,
            stdout: checks.map { "[\($0.status.rawValue)] \($0.name): \($0.detail)" }.joined(separator: "\n") + "\n"
        )
    }
}

public struct DoctorContext: Sendable {
    public let env: CommandEnvironment
    public let executor: CommandExecutor
    public init(env: CommandEnvironment, executor: CommandExecutor) {
        self.env = env; self.executor = executor
    }
}

private enum DoctorStatus: String, Encodable { case pass, warn, fail }
private struct DoctorCheck: Encodable { let name: String; let status: DoctorStatus; let detail: String }
private struct DoctorResponse: Encodable {
    let schemaVersion = 1
    let status: DoctorStatus
    let checks: [DoctorCheck]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case status
        case checks
    }
}
