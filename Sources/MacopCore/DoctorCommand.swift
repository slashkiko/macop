import CryptoKit
import Foundation
import LocalAuthentication
import Security

// swiftlint:disable file_length

private struct InstallManifest: Decodable {
    struct Component: Decodable {
        let sha256: String
        let cdhash: String
        let identifier: String
        let team: String
    }

    let schemaVersion: Int
    let buildGeneration: String
    let brokerProtocolVersion: Int
    let components: [String: Component]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case buildGeneration = "build_generation"
        case brokerProtocolVersion = "broker_protocol_version"
        case components
    }
}

// The command intentionally keeps all doctor checks together for deterministic output ordering.
// swiftlint:disable:next type_body_length
public enum DoctorCommand {
    public static func verifyInstalledBroker() -> CommandResult {
        do {
            try AuthBrokerClientConnection.verifyInstalledBroker()
            return CommandResult(
                exitCode: ExitCode.success.rawValue,
                stdout: "installed broker peer, capabilities, and protocol v\(AuthBrokerWire.currentVersion) verified\n"
            )
        } catch let failure as AuthBrokerFailure {
            return CommandResult(
                exitCode: ExitCode.providerUnavailable.rawValue,
                stderr: "installed broker verification failed (\(failure.category.rawValue))\n"
            )
        } catch {
            return CommandResult(
                exitCode: ExitCode.providerUnavailable.rawValue,
                stderr: "installed broker verification failed\n"
            )
        }
    }

    /// Installer-only, noninteractive generation gate. It avoids unrelated
    /// doctor prerequisites such as configured identities and CTK availability.
    public static func verifyInstalledGeneration() -> CommandResult {
        guard let executable = try? RunningExecutable.path() else {
            return CommandResult(
                exitCode: ExitCode.providerUnavailable.rawValue,
                stderr: "Unable to resolve the installed executable for generation verification.\n"
            )
        }
        let result = self.installedGenerationStatus(executable: executable) { path, arguments, environment in
            try? SystemCommandExecutor().execute(path: path, arguments: arguments, environment: environment ?? [:])
        }
        return CommandResult(
            exitCode: result.0 == .pass ? ExitCode.success.rawValue : ExitCode.providerUnavailable.rawValue,
            stdout: result.0 == .pass ? "\(result.1)\n" : "",
            stderr: result.0 == .pass ? "" : "\(result.1)\n"
        )
    }

    private static func installedGenerationStatus(
        executable: String,
        diagnostic: (String, [String], CommandEnvironment?) -> CommandResult?
    ) -> (DoctorStatus, String) {
        let root = URL(fileURLWithPath: executable).deletingLastPathComponent()
        let manifestURL = root.appendingPathComponent("macop-install-manifest.json")
        let componentPaths = [
            "macop": root.appendingPathComponent("macop"),
            "agent": root.appendingPathComponent("macop-agent"),
            "auth_app": root.appendingPathComponent("MacopAuth.app")
        ]
        let installedCandidate = componentPaths.values.contains { FileManager.default.fileExists(atPath: $0.path) }
        let developmentBuild = executable.contains("/.build/debug/") || executable.contains("/.build/release/")
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            return installedCandidate && !developmentBuild
                ? (.fail, "installed component set has no generation manifest")
                : (.warn, "development or uninstalled executable; no generation manifest")
        }
        if (try? FileManager.default.destinationOfSymbolicLink(atPath: manifestURL.path)) != nil {
            return (.fail, "generation manifest must not be a symbolic link")
        }
        guard let data = try? Data(contentsOf: manifestURL),
              let manifest = try? JSONDecoder().decode(InstallManifest.self, from: data),
              manifest.schemaVersion == 1,
              !manifest.buildGeneration.isEmpty,
              manifest.brokerProtocolVersion == Int(AuthBrokerWire.currentVersion)
        else { return (.fail, "generation manifest is malformed or uses an unsupported broker protocol") }

        let expected: [(String, String)] = [
            ("macop", "macop"), ("agent", "macop-agent"), ("auth_app", "io.github.slashkiko.macop.auth")
        ]
        guard manifest.components.count == expected.count,
              Set(manifest.components.keys) == Set(expected.map(\.0))
        else { return (.fail, "generation manifest component set is not exact") }
        for (name, identifier) in expected {
            guard let component = manifest.components[name], component.identifier == identifier,
                  let path = componentPaths[name], FileManager.default.fileExists(atPath: path.path)
            else { return (.fail, "generation manifest is missing or disagrees about \(name)") }
            if (try? FileManager.default.destinationOfSymbolicLink(atPath: path.path)) != nil {
                return (.fail, "installed \(name) must not be a symbolic link")
            }
            // Never accept a CDHash or executable digest from an unsealed
            // bundle.  For MacopAuth this verifies CodeDirectory *and* its
            // sealed resources (Info.plist, embedded profile, and resources)
            // before the manifest metadata below is considered.
            let verificationArguments = name == "auth_app"
                ? ["--verify", "--deep", "--strict", path.path]
                : ["--verify", "--strict", path.path]
            guard let verification = diagnostic("/usr/bin/codesign", verificationArguments, nil),
                  verification.exitCode == 0
            else { return (.fail, "installed \(name) code signature or sealed resources are invalid") }
            let hashPath = name == "auth_app"
                ? path.appendingPathComponent("Contents/MacOS/MacopAuth") : path
            guard let bytes = try? Data(contentsOf: hashPath) else {
                return (.fail, "installed \(name) executable is missing")
            }
            let digest = Data(SHA256.hash(data: bytes)).map { String(format: "%02x", $0) }.joined()
            guard digest == component.sha256 else {
                return (.fail, "installed \(name) hash does not match its generation manifest")
            }
            guard let signature = diagnostic("/usr/bin/codesign", ["-dv", "--verbose=4", path.path], nil) else {
                return (.fail, "cannot verify installed \(name) code identity")
            }
            let metadata = signature.stdout + signature.stderr
            let actualIdentifier = metadata.split(separator: "\n").first { $0.hasPrefix("Identifier=") }
                .map { String($0.dropFirst("Identifier=".count)) }
            let actualTeam = metadata.split(separator: "\n").first { $0.hasPrefix("TeamIdentifier=") }
                .map { String($0.dropFirst("TeamIdentifier=".count)) } ?? "not set"
            let actualCDHash = metadata.split(separator: "\n").first { $0.hasPrefix("CDHash=") }
                .map { String($0.dropFirst("CDHash=".count)) }
            guard signature.exitCode == 0, actualIdentifier == identifier, actualTeam == component.team,
                  actualCDHash == component.cdhash
            else {
                return (.fail, "installed \(name) code identity does not match its generation manifest")
            }
        }
        return (
            .pass,
            "generation manifest, hashes, identities, and broker protocol v\(AuthBrokerWire.currentVersion) agree"
        )
    }

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
        if context.env["MACOP_INSTALL_VERIFY_MODE"] == "generation" {
            return self.verifyInstalledGeneration()
        }
        if context.env["MACOP_INSTALL_VERIFY_MODE"] == "broker" {
            return self.verifyInstalledBroker()
        }
        var checks = [DoctorCheck]()
        func add(_ name: String, _ status: DoctorStatus, _ detail: String) {
            checks.append(DoctorCheck(name: name, status: status, detail: detail))
        }
        func diagnostic(
            _ path: String,
            _ arguments: [String],
            environment: CommandEnvironment? = nil
        ) -> CommandResult? {
            do {
                return try context.executor.execute(
                    path: path,
                    arguments: arguments,
                    environment: environment ?? context.env
                )
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
        if executable.isEmpty {
            add("install_generation", .warn, "Skipped because the running executable could not be resolved")
        } else {
            let generation = self.installedGenerationStatus(executable: executable) { path, arguments, environment in
                diagnostic(path, arguments, environment: environment)
            }
            add("install_generation", generation.0, generation.1)
        }
        for (name, path) in [
            ("sc_auth", SSHCommand.scAuth),
            ("ssh", SSHCommand.ssh)
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

        var ctkIdentityHashes: [String]?
        var ctkIdentityOutput: String?
        if FileManager.default.fileExists(atPath: SSHCommand.scAuth) {
            let ctk = diagnostic(SSHCommand.scAuth, ["list-ctk-identities", "-t", "sha1", "-e", "hex"])
            do {
                guard let ctk, ctk.exitCode == 0 else {
                    throw CLIError.providerUnavailable(
                        provider: "CryptoTokenKit",
                        reason: "identity enumeration failed"
                    )
                }
                let hashes = try SSHCommand.validatedIdentityHashes(ctk.stdout)
                ctkIdentityHashes = hashes
                ctkIdentityOutput = ctk.stdout
                add(
                    "cryptotokenkit",
                    .pass,
                    hashes.isEmpty ? "CTK identity enumeration available; no identities found"
                        : "CTK identity enumeration available (\(hashes.count) identities)"
                )
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

        if let hashes = ctkIdentityHashes {
            if hashes.isEmpty {
                add("security_identity_keys", .warn, "No CTK identity is available for a Security.framework check")
            } else {
                do {
                    let count = try SSHCommand.validatedSecurityIdentityCount(
                        ctkIdentityOutput ?? "",
                        executor: context.executor
                    )
                    add("security_identity_keys", .pass, "Security.framework resolved \(count) CTK public key(s)")
                } catch {
                    add("security_identity_keys", .fail, "Security.framework could not resolve every CTK public key")
                }
            }
        } else {
            add("security_identity_keys", .fail, "Skipped because CTK identity enumeration was invalid")
        }

        let sshG = diagnostic(SSHCommand.ssh, ["-G"] + SSHCommand.isolatedAgentSSHOptions() + ["example.invalid"])
        let effective = Set((sshG?.stdout ?? "").split(whereSeparator: \.isNewline).map { $0.lowercased() })
        let forward = effective.contains("forwardagent no")
        let providerRows = effective.filter { $0.hasPrefix("pkcs11provider ") }
        // Apple SSH omits PKCS11Provider from `ssh -G` when its effective value
        // is `none`; some fixture/tool versions print the explicit value.
        let noExternalProvider = providerRows.isEmpty || providerRows == ["pkcs11provider none"]
        let identities = effective.contains("identitiesonly no")
        let identityFile = effective.contains("identityfile none")
        let identityAgent = effective.contains("identityagent ssh_auth_sock")
        let publicKeyOnly = effective.contains("preferredauthentications publickey")
        let sshConfigResolved = sshG?.exitCode == 0
        add(
            "forward_agent",
            sshConfigResolved && forward ? .pass : .fail,
            sshConfigResolved && forward ? "effective ForwardAgent=no" : "unable to verify ForwardAgent=no"
        )
        add(
            "ssh_agent_selection",
            sshConfigResolved && noExternalProvider && identities && identityFile && identityAgent && publicKeyOnly ?
                .pass :
                .fail,
            sshConfigResolved && noExternalProvider && identities && identityFile && identityAgent && publicKeyOnly
                ? "effective PKCS11Provider=none, publickey-only authentication, IdentityFile=none, and session agent selection"
                : "unable to verify isolated SSH agent selection"
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

        let companionPresent = AuthBrokerCompanionResolver.companionIsPresent(
            currentExecutable: executable.isEmpty ? nil : executable
        )
        add(
            "broker_companion",
            companionPresent ? .pass : .fail,
            companionPresent ? "MacopAuth companion bundle is present" : "MacopAuth companion bundle is unavailable"
        )
        if companionPresent {
            do {
                _ = try AuthBrokerCompanionResolver.resolve(currentExecutable: executable)
                add("broker_signature", .pass, "MacopAuth signature and same-team identity verified")
            } catch let failure as AuthBrokerFailure {
                add("broker_signature", .fail, Self.brokerDiagnostic(failure.category))
            } catch {
                add("broker_signature", .fail, "MacopAuth signature verification failed")
            }
        } else {
            add("broker_signature", .warn, "Skipped because MacopAuth companion is unavailable")
        }
        do {
            try AuthBrokerClientConnection.verifyInstalledBroker()
            add("broker_socket", .pass, "MacopAuth socket probe completed without a protected request")
            add(
                "broker_wire_version",
                .pass,
                "MacopAuth negotiated current wire version v\(AuthBrokerWire.currentVersion)"
            )
        } catch let failure as AuthBrokerFailure {
            add("broker_socket", .fail, Self.brokerDiagnostic(failure.category))
            add(
                "broker_wire_version",
                .fail,
                failure.category == .protocolMismatch
                    ? "MacopAuth does not support current wire version v\(AuthBrokerWire.currentVersion)"
                    : "Skipped because the non-secret MacopAuth socket probe did not complete"
            )
        } catch {
            add("broker_socket", .fail, "MacopAuth socket probe failed")
            add("broker_wire_version", .fail, "Skipped because the non-secret MacopAuth socket probe did not complete")
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

    private static func brokerDiagnostic(_ category: AuthBrokerFailureCategory) -> String {
        switch category {
        case .companionUnavailable:
            "MacopAuth companion is unavailable; reinstall or repair macop"
        case .identityInvalid:
            "MacopAuth identity verification failed; reinstall from a trusted release"
        case .protocolMismatch:
            "MacopAuth protocol is incompatible; update macop and MacopAuth together"
        case .transportFailure:
            "MacopAuth could not be reached; close a stale prompt and retry"
        case .userDenied:
            "MacopAuth probe was not approved"
        }
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
