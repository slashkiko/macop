import Darwin
import Foundation

public enum AuthBrokerRequester {
    public static func approvalRequest(
        operation: AuthBrokerOperation,
        command: String,
        credentialLabel: String,
        service: String,
        account: String,
        keychainSynchronizable: Bool = false,
        credentialFingerprint: String = "",
        host: String = "",
        rootPID: Int32 = getpid()
    ) throws -> AuthBrokerApprovalRequest {
        let executable = try RunningExecutable.path()
        let expectedPath = rootPID == getpid() ? executable : try self.executablePath(pid: rootPID)
        let inspection = try LiveCodeIdentityInspector.inspect(pid: rootPID, expectedPath: expectedPath)
        guard inspection.identity.hasTrustedPublisher,
              let snapshot = SystemRequesterInspector().snapshot(of: rootPID)
        else { throw AgentProtocolError.denied }
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        let lifetime: UInt64 = operation == .passwordAutoFill ? 600_000 : 120_000
        return AuthBrokerApprovalRequest(
            requestID: UUID(),
            issuedAtMilliseconds: now,
            expiresAtMilliseconds: now + lifetime,
            operation: operation,
            rootPID: rootPID,
            rootStartTime: snapshot.startTime,
            rootIdentifier: inspection.identity.identifier,
            rootCodeRequirement: inspection.codeRequirement,
            rootExecutablePath: inspection.identity.canonicalPath,
            command: command,
            credentialLabel: credentialLabel,
            credentialFingerprint: credentialFingerprint,
            host: host,
            keychainService: service,
            keychainAccount: account,
            keychainSynchronizable: keychainSynchronizable
        )
    }

    private static func executablePath(pid: Int32) throws -> String {
        var buffer = [CChar](repeating: 0, count: 4 * 1024)
        let count = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard count > 0 else { throw AgentProtocolError.denied }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        guard let path = String(bytes: bytes, encoding: .utf8) else {
            throw AgentProtocolError.denied
        }
        return LiveCodeIdentityInspector.canonicalPath(path)
    }
}
