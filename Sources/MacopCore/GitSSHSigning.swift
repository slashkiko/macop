import CryptoKit
import Darwin
import Foundation

public struct GitSSHSignature: Sendable {
    public let publicKeyBlob: Data
    public let signatureBlob: Data

    public init(publicKeyBlob: Data, signatureBlob: Data) {
        self.publicKeyBlob = publicKeyBlob
        self.signatureBlob = signatureBlob
    }
}

public protocol GitSSHSigningProviding: Sendable {
    func sign(
        identity: SSHCommand.VerifiedSessionIdentity,
        data: Data,
        requesterPID: Int32
    ) throws -> GitSSHSignature
}

public protocol GitSSHSigningRequesterValidating: Sendable {
    func validateRequester() throws -> Int32
}

public struct SystemGitSSHSigningRequesterValidator: GitSSHSigningRequesterValidating {
    public init() {}

    public func validateRequester() throws -> Int32 {
        let parent = getppid()
        guard parent > 1 else { throw CLIError.denied(message: "Git SSH signing requires an Apple Git parent.") }
        var buffer = [CChar](repeating: 0, count: 4 * 1024)
        let count = proc_pidpath(parent, &buffer, UInt32(buffer.count))
        guard count > 0 else { throw CLIError.denied(message: "Git SSH signing parent could not be inspected.") }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        guard let pathString = String(bytes: bytes, encoding: .utf8) else {
            throw CLIError.denied(message: "Git SSH signing parent path is invalid.")
        }
        let path = LiveCodeIdentityInspector.canonicalPath(pathString)
        do {
            _ = try LiveCodeIdentityInspector.inspectExpectedAppleGit(pid: parent, expectedPath: path)
        } catch {
            throw CLIError.denied(message: "Git SSH signing accepts only the active Apple Git process.")
        }
        return parent
    }
}

public struct CompanionGitSSHSigningProvider: GitSSHSigningProviding {
    public init() {}

    public func sign(
        identity: SSHCommand.VerifiedSessionIdentity,
        data: Data,
        requesterPID: Int32
    ) throws -> GitSSHSignature {
        let connection = try AuthBrokerClientConnection.launchAndConnect(
            requiredCapabilities: AuthBrokerCapability.sshSigning.rawValue
        )
        let request = try AuthBrokerRequester.approvalRequest(
            operation: .gitSSHSign,
            purpose: .gitSSHSign,
            credentialLabel: identity.label,
            service: "",
            account: "",
            credentialFingerprint: identity.fingerprint,
            rootPID: requesterPID
        )
        guard case let .approvalResponse(approval) = try connection.send(.approvalRequest(request)),
              approval.requestID == request.requestID,
              approval.status == .approved,
              approval.resultStatus == errSecSuccess,
              constantTimeEqual(approval.resultData, identity.publicKeyBlob)
        else { throw CLIError.denied(message: "Git SSH signing was denied or cancelled.") }
        let signRequest = AuthBrokerSSHSignRequest(
            authorizationID: request.requestID,
            data: data,
            flags: 0
        )
        guard case let .sshSignResponse(response) = try connection.send(.sshSignRequest(signRequest)),
              response.authorizationID == request.requestID,
              !response.signature.isEmpty
        else { throw CLIError.runtimeError(message: "Git SSH signing returned an invalid response.") }
        return GitSSHSignature(publicKeyBlob: approval.resultData, signatureBlob: response.signature)
    }
}

public enum GitSSHSigningCommand {
    public static func run(
        argv: [String],
        env: [String: String],
        executor: CommandExecutor = SystemCommandExecutor(),
        provider: any GitSSHSigningProviding = CompanionGitSSHSigningProvider(),
        requesterValidator: any GitSSHSigningRequesterValidating = SystemGitSSHSigningRequesterValidator()
    ) -> CommandResult {
        do {
            let invocation = try self.parse(argv: argv)
            let requesterPID = try requesterValidator.validateRequester()
            try self.requireNewSignaturePath(invocation.messagePath + ".sig")
            let publicKey = try self.readPublicKey(path: invocation.keyPath)
            let identity = try SSHCommand.verifiedSessionIdentity(
                matchingPublicKeyBlob: publicKey,
                env: env,
                executor: executor
            )
            let message = try self.readRegularFile(path: invocation.messagePath, limit: 4 * 1024 * 1024)
            let signedData = try self.signedData(message: message, namespace: invocation.namespace)
            let signature = try provider.sign(
                identity: identity,
                data: signedData,
                requesterPID: requesterPID
            )
            guard constantTimeEqual(signature.publicKeyBlob, publicKey) else {
                throw CLIError.denied(message: "Git signing identity changed during authorization.")
            }
            let armored = try self.armoredSignature(
                publicKey: publicKey,
                namespace: invocation.namespace,
                signature: signature.signatureBlob
            )
            try self.writeNewSignature(armored, path: invocation.messagePath + ".sig")
            return CommandResult(exitCode: 0)
        } catch let error as CLIError {
            return ErrorRenderer.render(error: error, format: .humanReadable)
        } catch {
            return ErrorRenderer.render(
                error: .runtimeError(message: "Git SSH signing failed."),
                format: .humanReadable
            )
        }
    }

    public static func isSigningInvocation(_ argv: [String]) -> Bool {
        argv.dropFirst().first == "-Y"
    }

    private struct Invocation {
        let namespace: String
        let keyPath: String
        let messagePath: String
    }

    private static func parse(argv: [String]) throws -> Invocation {
        let args = Array(argv.dropFirst())
        guard args.count == 7, args[0] == "-Y", args[1] == "sign", args[2] == "-n",
              args[4] == "-f", !args[3].isEmpty, args[3] == "git",
              !args[5].isEmpty, !args[6].isEmpty,
              !args[5].hasPrefix("-"), !args[6].hasPrefix("-"),
              args[5].hasPrefix("/"), args[6].hasPrefix("/")
        else {
            throw CLIError.invalidArguments(
                message: "The Git SSH adapter accepts only: -Y sign -n git -f <public-key> <message-file>."
            )
        }
        return Invocation(namespace: args[3], keyPath: args[5], messagePath: args[6])
    }

    private static func readPublicKey(path: String) throws -> Data {
        let data = try self.readRegularFile(path: path, limit: 16 * 1024)
        guard let text = String(data: data, encoding: .utf8), !text.contains("\0"),
              let line = text.split(whereSeparator: \Character.isNewline).first
        else { throw CLIError.invalidArguments(message: "Git signing key must be an OpenSSH public key.") }
        let fields = line.split(whereSeparator: \Character.isWhitespace)
        guard fields.count >= 2,
              let blob = Data(base64Encoded: String(fields[1])),
              blob.count <= SSHWire.maxStringLength
        else { throw CLIError.invalidArguments(message: "Git signing key must be an OpenSSH public key.") }
        var cursor = SSHCursor(blob)
        guard let algorithm = try String(data: cursor.string(), encoding: .utf8),
              algorithm == String(fields[0]), algorithm == "ecdsa-sha2-nistp256"
        else { throw CLIError.invalidArguments(message: "Git signing key must be a macop P-256 public key.") }
        return blob
    }

    private static func signedData(message: Data, namespace: String) throws -> Data {
        let digest = Data(SHA256.hash(data: message))
        return try Data("SSHSIG".utf8)
            + (SSHWire.string(namespace))
            + (SSHWire.string(Data()))
            + (SSHWire.string("sha256"))
            + (SSHWire.string(digest))
    }

    private static func armoredSignature(
        publicKey: Data,
        namespace: String,
        signature: Data
    ) throws -> Data {
        var blob = Data("SSHSIG".utf8)
        blob += try SSHWire.u32(1)
        blob += try SSHWire.string(publicKey)
        blob += try SSHWire.string(namespace)
        blob += try SSHWire.string(Data())
        blob += try SSHWire.string("sha256")
        blob += try SSHWire.string(signature)
        let base64 = blob.base64EncodedString()
        let lines = stride(from: 0, to: base64.count, by: 70).map { offset -> String in
            let start = base64.index(base64.startIndex, offsetBy: offset)
            let end = base64.index(start, offsetBy: min(70, base64.count - offset))
            return String(base64[start ..< end])
        }
        return Data(([
            "-----BEGIN SSH SIGNATURE-----"
        ] + lines + [
            "-----END SSH SIGNATURE-----", ""
        ]).joined(separator: "\n").utf8)
    }

    private static func readRegularFile(path: String, limit: Int) throws -> Data {
        let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw CLIError.denied(message: "Cannot open Git signing input safely.") }
        defer { close(descriptor) }
        var details = stat()
        guard fstat(descriptor, &details) == 0, details.st_mode & S_IFMT == S_IFREG,
              details.st_uid == getuid(), details.st_size >= 0, details.st_size <= limit
        else { throw CLIError.denied(message: "Git signing input must be an owner-controlled regular file.") }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            if count == 0 {
                return data
            }
            if count < 0, errno == EINTR {
                continue
            }
            guard count > 0, data.count + count <= limit else {
                throw CLIError.invalidArguments(message: "Git signing input is too large.")
            }
            data.append(buffer, count: count)
        }
    }

    private static func writeNewSignature(_ data: Data, path: String) throws {
        let url = URL(fileURLWithPath: path)
        let parent = url.deletingLastPathComponent()
        let directory = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directory >= 0 else {
            throw CLIError.denied(message: "Git signature directory is not accessible safely.")
        }
        defer { close(directory) }
        var parentDetails = stat()
        guard fstat(directory, &parentDetails) == 0,
              parentDetails.st_mode & S_IFMT == S_IFDIR,
              parentDetails.st_uid == getuid(), parentDetails.st_mode & 0o022 == 0
        else { throw CLIError.denied(message: "Git signature directory must be owner-controlled.") }
        let descriptor = openat(
            directory,
            url.lastPathComponent,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0o600
        )
        guard descriptor >= 0 else {
            throw CLIError.denied(message: "Refusing to overwrite an existing Git signature file.")
        }
        var succeeded = false
        defer {
            close(descriptor)
            if !succeeded {
                unlink(path)
            }
        }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes {
                Darwin.write(descriptor, $0.baseAddress!.advanced(by: offset), data.count - offset)
            }
            if count < 0, errno == EINTR {
                continue
            }
            guard count > 0 else { throw CLIError.runtimeError(message: "Could not write Git signature.") }
            offset += count
        }
        guard fsync(descriptor) == 0 else { throw CLIError.runtimeError(message: "Could not persist Git signature.") }
        succeeded = true
    }

    private static func requireNewSignaturePath(_ path: String) throws {
        var details = stat()
        if lstat(path, &details) == 0 || errno != ENOENT {
            throw CLIError.denied(message: "Refusing to overwrite an existing Git signature file.")
        }
    }
}
