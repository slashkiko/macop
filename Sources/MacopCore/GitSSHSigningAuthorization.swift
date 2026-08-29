import Foundation
import Security

public enum GitSSHSigningFailure: Error, Sendable, Equatable {
    case brokerUnavailable
    case authorizationRequestInvalid
    case authorizationCancelled
    case authorizationDenied
    case requesterInvalid
    case signerUnavailable
    case identityMismatch
    case signatureFailed
    case authorizationResponseUnavailable
    case invalidAuthorizationResponse
    case deliveryIndeterminate
    case invalidResponse

    var cliError: CLIError {
        switch self {
        case .brokerUnavailable:
            .providerUnavailable(
                provider: "MacopAuth",
                reason: "The signed authorization broker could not be started or negotiated. "
                    + "No signature request was sent."
            )
        case .authorizationRequestInvalid:
            .runtimeError(
                message: "Git SSH signing authorization could not be prepared safely. No signature request was sent."
            )
        case .authorizationCancelled:
            .denied(message: "Git SSH signing was cancelled. No signature request was sent.")
        case .authorizationDenied:
            .denied(message: "Git SSH signing was not authorized. No signature request was sent.")
        case .requesterInvalid:
            .denied(message: "Git SSH signing requester could not be revalidated. No signature was created.")
        case .signerUnavailable:
            .providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "The approved Secure Enclave signing key could not be prepared. No signature was created."
            )
        case .identityMismatch:
            .denied(message: "The approved Git SSH signing identity no longer matches. No signature was created.")
        case .signatureFailed:
            .providerUnavailable(
                provider: "CryptoTokenKit",
                reason: "The Secure Enclave signature operation failed. No signature was created."
            )
        case .authorizationResponseUnavailable:
            .runtimeError(
                message: "Git SSH signing authorization result was not received. No signature request was sent."
            )
        case .invalidAuthorizationResponse:
            .runtimeError(
                message: "Git SSH signing returned an invalid authorization response. "
                    + "No signature request was sent."
            )
        case .deliveryIndeterminate:
            .runtimeError(
                message: "Git SSH signing may have completed, but the broker response was lost. "
                    + "Do not retry automatically."
            )
        case .invalidResponse:
            .runtimeError(
                message: "Git SSH signing returned an invalid broker response. The signing result is indeterminate; "
                    + "do not retry automatically."
            )
        }
    }
}

public enum GitSSHSigningAuthorizationClassifier {
    public static func approvedPublicKey(
        from message: AuthBrokerMessage,
        requestID: UUID,
        expectedPublicKey: Data
    ) throws -> Data {
        switch message {
        case let .approvalResponse(response):
            guard response.requestID == requestID,
                  response.message.isEmpty,
                  response.verifiedUsername.isEmpty
            else { throw GitSSHSigningFailure.invalidAuthorizationResponse }
            switch response.status {
            case .approved:
                guard response.resultStatus == errSecSuccess,
                      !response.resultData.isEmpty,
                      constantTimeEqual(response.resultData, expectedPublicKey)
                else { throw GitSSHSigningFailure.invalidAuthorizationResponse }
                return response.resultData
            case .cancelled:
                guard response.resultStatus == errSecAuthFailed, response.resultData.isEmpty else {
                    throw GitSSHSigningFailure.invalidAuthorizationResponse
                }
                throw GitSSHSigningFailure.authorizationCancelled
            case .denied:
                guard response.resultStatus == errSecAuthFailed, response.resultData.isEmpty else {
                    throw GitSSHSigningFailure.invalidAuthorizationResponse
                }
                throw GitSSHSigningFailure.authorizationDenied
            }
        case .sshSignResponse:
            do {
                _ = try GitSSHSigningResponseClassifier.signature(
                    from: message,
                    authorizationID: requestID,
                    stage: .authorization
                )
            } catch let failure as GitSSHSigningFailure {
                switch failure {
                case .requesterInvalid, .signerUnavailable, .identityMismatch:
                    throw failure
                default:
                    throw GitSSHSigningFailure.invalidAuthorizationResponse
                }
            } catch {
                throw GitSSHSigningFailure.invalidAuthorizationResponse
            }
            throw GitSSHSigningFailure.invalidAuthorizationResponse
        default:
            throw GitSSHSigningFailure.invalidAuthorizationResponse
        }
    }
}

public enum GitSSHSigningAuthorizationBoundary {
    public static func connect<Connection>(_ operation: () throws -> Connection) throws -> Connection {
        do {
            return try operation()
        } catch {
            throw GitSSHSigningFailure.brokerUnavailable
        }
    }

    public static func prepare<Request>(_ operation: () throws -> Request) throws -> Request {
        do {
            return try operation()
        } catch {
            throw GitSSHSigningFailure.authorizationRequestInvalid
        }
    }

    public static func receive<Response>(_ operation: () throws -> Response) throws -> Response {
        do {
            return try operation()
        } catch {
            throw GitSSHSigningFailure.authorizationResponseUnavailable
        }
    }
}

public enum GitSSHSigningResponseStage: Sendable, Equatable {
    case authorization
    case signature
}

public enum GitSSHSigningResponseClassifier {
    public static func signature(
        from message: AuthBrokerMessage,
        authorizationID: UUID,
        stage: GitSSHSigningResponseStage
    ) throws -> Data {
        guard case let .sshSignResponse(response) = message,
              response.authorizationID == authorizationID
        else { throw GitSSHSigningFailure.invalidResponse }
        switch response.outcome {
        case .signed:
            guard stage == .signature, !response.signature.isEmpty else {
                throw GitSSHSigningFailure.invalidResponse
            }
            return response.signature
        case .requesterInvalid:
            throw GitSSHSigningFailure.requesterInvalid
        case .signerUnavailable:
            guard stage == .authorization else { throw GitSSHSigningFailure.invalidResponse }
            throw GitSSHSigningFailure.signerUnavailable
        case .identityMismatch:
            guard stage == .authorization else { throw GitSSHSigningFailure.invalidResponse }
            throw GitSSHSigningFailure.identityMismatch
        case .signatureFailed:
            guard stage == .signature else { throw GitSSHSigningFailure.invalidResponse }
            throw GitSSHSigningFailure.signatureFailed
        }
    }
}
