import Darwin
import Foundation

public enum AuthBrokerRequester {
    /// Builds the Git signing request from Apple's platform-Git requirement,
    /// not the generic certificate-backed publisher policy. Platform Git may
    /// legitimately have no Team ID; `inspectExpectedAppleGit` instead pins
    /// the live Apple requirement, library validation, identifier, path, and
    /// cdhash into the returned code requirement.
    public static func gitSSHSigningApprovalRequest(
        credentialLabel: String,
        credentialFingerprint: String,
        rootPID: Int32,
        requesterEnvironment: GitClientRequesterValidationEnvironment? = nil
    ) throws -> AuthBrokerApprovalRequest {
        guard rootPID > 1 else { throw AgentProtocolError.denied }
        let before: ProcessSnapshot
        let inspection: LiveCodeInspection
        if let requesterEnvironment {
            guard let captured = requesterEnvironment.snapshot(rootPID) else {
                throw AgentProtocolError.denied
            }
            inspection = try GitClientRequesterTrust.validate(pid: rootPID, environment: requesterEnvironment)
            guard requesterEnvironment.snapshot(rootPID) == captured else {
                throw AgentProtocolError.denied
            }
            before = captured
        } else {
            let requesterInspector = SystemRequesterInspector()
            guard let captured = requesterInspector.snapshot(of: rootPID) else {
                throw AgentProtocolError.denied
            }
            inspection = try GitClientRequesterTrust.validate(pid: rootPID)
            guard requesterInspector.snapshot(of: rootPID) == captured else {
                throw AgentProtocolError.denied
            }
            before = captured
        }
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        return AuthBrokerApprovalRequest(
            requestID: UUID(),
            issuedAtMilliseconds: now,
            expiresAtMilliseconds: now + 120_000,
            operation: .gitSSHSign,
            rootPID: rootPID,
            rootStartTime: before.startTime,
            rootIdentifier: inspection.identity.identifier,
            rootCodeRequirement: inspection.codeRequirement,
            rootExecutablePath: inspection.identity.canonicalPath,
            presentation: .requesterOnly,
            purpose: .gitSSHSign,
            credentialLabel: credentialLabel,
            credentialFingerprint: credentialFingerprint,
            host: ""
        )
    }

    public static func approvalRequest(
        operation: AuthBrokerOperation,
        purpose: AuthBrokerPurpose,
        credentialLabel: String,
        service: String,
        account: String,
        keychainSynchronizable: Bool = false,
        credentialFingerprint: String = "",
        host: String = "",
        rootPID: Int32 = getpid()
    ) throws -> AuthBrokerApprovalRequest {
        guard purpose.isValid(for: operation) else { throw AuthBrokerProtocolError.malformed }
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
            presentation: .requesterOnly,
            purpose: purpose,
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
