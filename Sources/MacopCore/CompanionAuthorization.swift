import Foundation

public struct CompanionAuthenticationSessionPrompt: SessionAuthorizationResultPrompting {
    public init() {}

    public func authorizeResult(
        _ presentation: SessionAuthorizationPresentation,
        completion: @escaping @Sendable (SessionAuthorizationResult) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let connection = try AuthBrokerClientConnection.launchAndConnect(
                    requiredCapabilities: AuthBrokerCapability.sshSigning.rawValue
                )
                let now = UInt64(Date().timeIntervalSince1970 * 1000)
                let expiry = UInt64(presentation.expiresAt.timeIntervalSince1970 * 1000)
                let request = AuthBrokerApprovalRequest(
                    requestID: presentation.sessionID,
                    issuedAtMilliseconds: now,
                    expiresAtMilliseconds: expiry,
                    operation: .sshSession,
                    rootPID: presentation.rootPID,
                    rootStartTime: presentation.rootStartTime,
                    rootIdentifier: presentation.rootIdentifier,
                    rootCodeRequirement: presentation.rootCodeRequirement,
                    rootExecutablePath: presentation.application,
                    purpose: .sshSession,
                    credentialLabel: presentation.identityLabel,
                    credentialFingerprint: presentation.fingerprint,
                    host: ""
                )
                guard case let .approvalResponse(response) = try connection.send(.approvalRequest(request)),
                      response.requestID == request.requestID,
                      response.status == .approved,
                      response.resultStatus == 0,
                      !response.resultData.isEmpty,
                      constantTimeEqual(
                          Data(sshFingerprint(for: response.resultData).utf8),
                          Data(presentation.fingerprint.utf8)
                      )
                else {
                    completion(SessionAuthorizationResult(approved: false, authenticationContext: nil))
                    return
                }
                let signer = CompanionAgentSigner(
                    connection: connection,
                    authorizationID: request.requestID,
                    publicKeyBlob: response.resultData,
                    fingerprint: presentation.fingerprint
                )
                completion(SessionAuthorizationResult(
                    approved: true,
                    authenticationContext: nil,
                    signer: signer
                ))
            } catch {
                completion(SessionAuthorizationResult(approved: false, authenticationContext: nil))
            }
        }
    }
}

public final class CompanionAgentSigner: AgentKeySigning, @unchecked Sendable {
    public let publicKeyBlob: Data
    public let fingerprint: String
    private let connection: AuthBrokerClientConnection
    private let authorizationID: UUID

    public init(
        connection: AuthBrokerClientConnection,
        authorizationID: UUID,
        publicKeyBlob: Data,
        fingerprint: String
    ) {
        self.connection = connection
        self.authorizationID = authorizationID
        self.publicKeyBlob = publicKeyBlob
        self.fingerprint = fingerprint
    }

    public func sign(data: Data, flags: UInt32) throws -> Data {
        guard !data.isEmpty, data.count <= AuthBrokerWire.maximumFrameLength else {
            throw AgentProtocolError.denied
        }
        let request = AuthBrokerSSHSignRequest(
            authorizationID: self.authorizationID,
            data: data,
            flags: flags
        )
        guard case let .sshSignResponse(response) = try self.connection.send(.sshSignRequest(request), timeout: 30),
              response.authorizationID == self.authorizationID,
              !response.signature.isEmpty
        else { throw AgentProtocolError.denied }
        return response.signature
    }
}
