// swiftlint:disable file_length
import Foundation
import Security

public enum AuthBrokerProtocolError: Error, Equatable, Sendable {
    case malformed
    case unsupportedVersion
    case unsupportedMessage
    case tooLarge
    case expired
}

public enum AuthBrokerCapability: UInt32, Sendable {
    case approvalUI = 1
    case managedKeychain = 2
    case sshSigning = 4
    case passwordAutoFill = 8
    case passwordAutoFillUsername = 16
    case gitClientTrust = 32
}

public struct AuthBrokerHello: Sendable, Equatable {
    public let minimumVersion: UInt16
    public let maximumVersion: UInt16
    public let capabilities: UInt32
    public let nonce: Data

    public init(minimumVersion: UInt16, maximumVersion: UInt16, capabilities: UInt32, nonce: Data) {
        self.minimumVersion = minimumVersion
        self.maximumVersion = maximumVersion
        self.capabilities = capabilities
        self.nonce = nonce
    }
}

public struct AuthBrokerHelloReply: Sendable, Equatable {
    public let selectedVersion: UInt16
    public let capabilities: UInt32
    public let nonce: Data

    public init(selectedVersion: UInt16, capabilities: UInt32, nonce: Data) {
        self.selectedVersion = selectedVersion
        self.capabilities = capabilities
        self.nonce = nonce
    }
}

public enum AuthBrokerOperation: UInt8, Sendable {
    case sshSession = 1
    case managedKeychainRead = 2
    case sshSign = 3
    case managedKeychainImport = 4
    case passwordAutoFill = 5
    case managedKeychainDelete = 6
    case gitSSHSign = 7
    case managedKeychainUpdate = 8
}

public enum AuthBrokerOperationFamily: Sendable, Equatable {
    case signing
    case managedKeychain
}

public enum AuthBrokerPhaseTwoKind: Sendable, Equatable {
    case none
    case signing
    case managedKeychainMutation
}

public extension AuthBrokerOperation {
    var requiredCapability: AuthBrokerCapability {
        switch self {
        case .sshSession, .sshSign, .gitSSHSign:
            .sshSigning
        case .managedKeychainRead, .managedKeychainImport, .passwordAutoFill,
             .managedKeychainDelete, .managedKeychainUpdate:
            .managedKeychain
        }
    }

    var family: AuthBrokerOperationFamily {
        switch self {
        case .sshSession, .sshSign, .gitSSHSign:
            .signing
        case .managedKeychainRead, .managedKeychainImport, .passwordAutoFill,
             .managedKeychainDelete, .managedKeychainUpdate:
            .managedKeychain
        }
    }

    var phaseTwoKind: AuthBrokerPhaseTwoKind {
        switch self {
        case .sshSession, .gitSSHSign:
            .signing
        case .managedKeychainImport, .managedKeychainUpdate:
            .managedKeychainMutation
        case .sshSign, .managedKeychainRead, .passwordAutoFill, .managedKeychainDelete:
            .none
        }
    }
}

/// Closed, attested presentation intent for an approval request. This is a
/// wire-level enum rather than caller-controlled display text so an older or
/// malicious client cannot influence security-sensitive UI wording.
public enum AuthBrokerPurpose: UInt8, Sendable, Equatable {
    case sshSession = 1
    case managedKeychainRead = 2
    case otpRead = 3
    case otpRun = 4
    case otpInject = 5
    case otpProfile = 6
    case otpItem = 7
    case managedKeychainImport = 8
    case otpImport = 9
    case managedKeychainUpdate = 10
    case otpUpdate = 11
    case passwordAutoFillRead = 12
    case managedKeychainDelete = 13
    case otpDelete = 14
    case managedKeychainDeleteAll = 15
    case gitSSHSign = 16
    case passwordRun = 17
    case passwordInject = 18
    case passwordProfile = 19
    case passwordItemGet = 20
    case passwordItemAcquire = 21
    case managedKeychainGenerate = 22
    case passwordAutoFillRun = 23
    case passwordAutoFillInject = 24
    case passwordAutoFillProfile = 25
    case passwordAutoFillItemAcquire = 26

    public func isValid(for operation: AuthBrokerOperation) -> Bool {
        switch (operation, self) {
        case (.sshSession, .sshSession),
             (.managedKeychainRead, .managedKeychainRead),
             (.managedKeychainRead, .otpRead),
             (.managedKeychainRead, .otpRun),
             (.managedKeychainRead, .otpInject),
             (.managedKeychainRead, .otpProfile),
             (.managedKeychainRead, .otpItem),
             (.managedKeychainRead, .passwordRun),
             (.managedKeychainRead, .passwordInject),
             (.managedKeychainRead, .passwordProfile),
             (.managedKeychainRead, .passwordItemGet),
             (.managedKeychainRead, .passwordItemAcquire),
             (.managedKeychainImport, .managedKeychainImport),
             (.managedKeychainImport, .managedKeychainGenerate),
             (.managedKeychainImport, .otpImport),
             (.managedKeychainUpdate, .managedKeychainUpdate),
             (.managedKeychainUpdate, .otpUpdate),
             (.passwordAutoFill, .passwordAutoFillRead),
             (.passwordAutoFill, .passwordAutoFillRun),
             (.passwordAutoFill, .passwordAutoFillInject),
             (.passwordAutoFill, .passwordAutoFillProfile),
             (.passwordAutoFill, .passwordAutoFillItemAcquire),
             (.managedKeychainDelete, .managedKeychainDelete),
             (.managedKeychainDelete, .otpDelete),
             (.managedKeychainDelete, .managedKeychainDeleteAll),
             (.gitSSHSign, .gitSSHSign):
            true
        default:
            false
        }
    }

    public var displayName: String {
        switch self {
        case .sshSession: "SSHセッション"
        case .managedKeychainRead: "macop read"
        case .otpRead: "macop read (OTP)"
        case .otpRun: "macop run (OTP)"
        case .otpInject: "macop inject (OTP)"
        case .otpProfile: "macop profile run (OTP)"
        case .otpItem: "macop item otp"
        case .managedKeychainImport: "macop item import"
        case .otpImport: "macop item otp import"
        case .managedKeychainUpdate: "macop item generate --replace"
        case .otpUpdate: "macop item otp edit"
        case .passwordAutoFillRead: "macop read (Passwords)"
        case .managedKeychainDelete: "macop item delete"
        case .otpDelete: "macop item otp delete"
        case .managedKeychainDeleteAll: "macop item delete --all-managed"
        case .gitSSHSign: "Git SSH署名"
        case .passwordRun: "macop run"
        case .passwordInject: "macop inject"
        case .passwordProfile: "macop profile run"
        case .passwordItemGet: "macop item get"
        case .passwordItemAcquire: "macop item acquire"
        case .managedKeychainGenerate: "macop item generate"
        case .passwordAutoFillRun: "macop run (Passwords)"
        case .passwordAutoFillInject: "macop inject (Passwords)"
        case .passwordAutoFillProfile: "macop profile run (Passwords)"
        case .passwordAutoFillItemAcquire: "macop item acquire (Passwords)"
        }
    }

    public var concernsOTP: Bool {
        switch self {
        case .otpRead, .otpRun, .otpInject, .otpProfile, .otpItem, .otpImport, .otpUpdate, .otpDelete:
            true
        default:
            false
        }
    }
}

/// Display-only information for an approval request. The requester binding is
/// always represented by the root fields on `AuthBrokerApprovalRequest`; the
/// SSH target below is a separately pinned live image that the user needs to
/// see before allowing a shell session.
public enum AuthBrokerApprovalPresentation: Sendable, Equatable {
    /// Retain the established requester-focused presentation.
    case requesterOnly
    /// A suspended shell target whose live code identity was pinned before the
    /// authorization prompt. This must only accompany an SSH session request.
    case sshSessionTarget(
        application: String,
        signingAuthority: String,
        cdHash: String,
        verification: String
    )

    public func isValid(for operation: AuthBrokerOperation) -> Bool {
        switch (operation, self) {
        case (.sshSession, .requesterOnly):
            false
        case (_, .requesterOnly):
            true
        case let (.sshSession, .sshSessionTarget(application, signingAuthority, cdHash, verification)):
            !application.isEmpty && !signingAuthority.isEmpty && !cdHash.isEmpty && !verification.isEmpty
        default:
            false
        }
    }
}

public struct AuthBrokerApprovalRequest: Sendable, Equatable {
    public let requestID: UUID
    public let issuedAtMilliseconds: UInt64
    public let expiresAtMilliseconds: UInt64
    public let operation: AuthBrokerOperation
    public let rootPID: Int32
    public let rootStartTime: UInt64
    public let rootIdentifier: String
    public let rootCodeRequirement: String
    public let rootExecutablePath: String
    public let presentation: AuthBrokerApprovalPresentation
    public let purpose: AuthBrokerPurpose
    public let credentialLabel: String
    public let credentialFingerprint: String
    public let host: String
    public let keychainService: String
    public let keychainAccount: String
    public let keychainSynchronizable: Bool

    public init(
        requestID: UUID,
        issuedAtMilliseconds: UInt64,
        expiresAtMilliseconds: UInt64,
        operation: AuthBrokerOperation,
        rootPID: Int32,
        rootStartTime: UInt64,
        rootIdentifier: String,
        rootCodeRequirement: String,
        rootExecutablePath: String,
        presentation: AuthBrokerApprovalPresentation,
        purpose: AuthBrokerPurpose,
        credentialLabel: String,
        credentialFingerprint: String,
        host: String,
        keychainService: String = "",
        keychainAccount: String = "",
        keychainSynchronizable: Bool = false
    ) {
        self.requestID = requestID
        self.issuedAtMilliseconds = issuedAtMilliseconds
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.operation = operation
        self.rootPID = rootPID
        self.rootStartTime = rootStartTime
        self.rootIdentifier = rootIdentifier
        self.rootCodeRequirement = rootCodeRequirement
        self.rootExecutablePath = rootExecutablePath
        self.presentation = presentation
        self.purpose = purpose
        self.credentialLabel = credentialLabel
        self.credentialFingerprint = credentialFingerprint
        self.host = host
        self.keychainService = keychainService
        self.keychainAccount = keychainAccount
        self.keychainSynchronizable = keychainSynchronizable
    }
}

public enum AuthBrokerApprovalStatus: UInt8, Sendable {
    case approved = 1
    case cancelled = 2
    case denied = 3

    /// User decisions never share a presentation category with companion,
    /// identity, protocol, or socket preparation failures.
    public var failureCategory: AuthBrokerFailureCategory? {
        switch self {
        case .approved: nil
        case .cancelled, .denied: .userDenied
        }
    }
}

public struct AuthBrokerApprovalResponse: Sendable, Equatable {
    public let requestID: UUID
    public let status: AuthBrokerApprovalStatus
    public let message: String
    public let resultStatus: Int32
    public let resultData: Data
    public let verifiedUsername: String

    public init(
        requestID: UUID,
        status: AuthBrokerApprovalStatus,
        message: String = "",
        resultStatus: Int32 = 0,
        resultData: Data = Data(),
        verifiedUsername: String = ""
    ) {
        self.requestID = requestID
        self.status = status
        self.message = message
        self.resultStatus = resultStatus
        self.resultData = resultData
        self.verifiedUsername = verifiedUsername
    }
}

public struct AuthBrokerManagedKeychainImportRequest: Sendable, Equatable {
    public let authorizationID: UUID
    public let secret: Data

    public init(authorizationID: UUID, secret: Data) {
        self.authorizationID = authorizationID
        self.secret = secret
    }
}

public struct AuthBrokerManagedKeychainImportResponse: Sendable, Equatable {
    public let authorizationID: UUID
    public let outcome: AuthBrokerMutationOutcome
    public let status: Int32

    public init(
        authorizationID: UUID,
        outcome: AuthBrokerMutationOutcome,
        status: Int32
    ) {
        self.authorizationID = authorizationID
        self.outcome = outcome
        self.status = status
    }
}

public enum AuthBrokerMutationOutcome: UInt8, Sendable, Equatable {
    case committed = 1
    case failed = 2
    case indeterminate = 3
}

public struct AuthBrokerSSHSignRequest: Sendable, Equatable {
    public let authorizationID: UUID
    public let data: Data
    public let flags: UInt32

    public init(authorizationID: UUID, data: Data, flags: UInt32) {
        self.authorizationID = authorizationID
        self.data = data
        self.flags = flags
    }
}

public struct AuthBrokerSSHSignResponse: Sendable, Equatable {
    public let authorizationID: UUID
    public let outcome: AuthBrokerSSHSignOutcome
    public let signature: Data

    public init(
        authorizationID: UUID,
        outcome: AuthBrokerSSHSignOutcome,
        signature: Data = Data()
    ) {
        self.authorizationID = authorizationID
        self.outcome = outcome
        self.signature = signature
    }
}

public enum AuthBrokerGitClientTrustStatus: UInt8, Sendable, Equatable {
    case trusted = 1
    case mismatch = 2
    case unavailable = 3
    case approved = 4
    case rejected = 5
    case generationConflict = 6
}

public struct AuthBrokerGitClientTrustVerifyRequest: Sendable, Equatable {
    public let requestID: UUID
    public let canonicalDocument: Data
    public let digest: Data
    public init(requestID: UUID, canonicalDocument: Data, digest: Data) {
        self.requestID = requestID; self.canonicalDocument = canonicalDocument; self.digest = digest
    }
}

public struct AuthBrokerGitClientTrustVerifyResponse: Sendable, Equatable {
    public let requestID: UUID
    public let digest: Data
    public let generation: UInt64
    public let status: AuthBrokerGitClientTrustStatus
    public init(requestID: UUID, digest: Data, generation: UInt64, status: AuthBrokerGitClientTrustStatus) {
        self.requestID = requestID; self.digest = digest; self.generation = generation; self.status = status
    }
}

public struct AuthBrokerGitClientTrustMutationRequest: Sendable, Equatable {
    public let authorizationID: UUID
    public let operation: GitClientTrustMutationOperation
    public let expectedGeneration: UInt64
    public let canonicalDocument: Data
    public let digest: Data
    public init(
        authorizationID: UUID,
        operation: GitClientTrustMutationOperation,
        expectedGeneration: UInt64,
        canonicalDocument: Data,
        digest: Data
    ) {
        self.authorizationID = authorizationID; self.operation = operation; self.expectedGeneration = expectedGeneration
        self.canonicalDocument = canonicalDocument; self.digest = digest
    }
}

public struct AuthBrokerGitClientTrustMutationResponse: Sendable, Equatable {
    public let authorizationID: UUID
    public let digest: Data
    public let generation: UInt64
    public let status: AuthBrokerGitClientTrustStatus
    public init(authorizationID: UUID, digest: Data, generation: UInt64, status: AuthBrokerGitClientTrustStatus) {
        self.authorizationID = authorizationID; self.digest = digest; self.generation = generation; self.status = status
    }
}

public struct AuthBrokerGitClientTrustStateRequest: Sendable, Equatable {
    public let requestID: UUID
    public init(requestID: UUID) {
        self.requestID = requestID
    }
}

public struct AuthBrokerGitClientTrustStateResponse: Sendable, Equatable {
    public let requestID: UUID
    public let generation: UInt64
    public let status: AuthBrokerGitClientTrustStatus
    public init(requestID: UUID, generation: UInt64, status: AuthBrokerGitClientTrustStatus) {
        self.requestID = requestID; self.generation = generation; self.status = status
    }
}

/// Closed, secret-free result of an approved signing flow. Preparation
/// failures are intentionally split so the client can explain which
/// fail-closed boundary stopped the operation without receiving arbitrary
/// server text.
public enum AuthBrokerSSHSignOutcome: UInt8, Sendable, Equatable {
    case signed = 1
    case requesterInvalid = 2
    case signerUnavailable = 3
    case identityMismatch = 4
    case signatureFailed = 5
}

public enum AuthBrokerMessage: Sendable, Equatable {
    case hello(AuthBrokerHello)
    case helloReply(AuthBrokerHelloReply)
    case approvalRequest(AuthBrokerApprovalRequest)
    case approvalResponse(AuthBrokerApprovalResponse)
    case sshSignRequest(AuthBrokerSSHSignRequest)
    case sshSignResponse(AuthBrokerSSHSignResponse)
    case managedKeychainImportRequest(AuthBrokerManagedKeychainImportRequest)
    case managedKeychainImportResponse(AuthBrokerManagedKeychainImportResponse)
    case gitClientTrustVerifyRequest(AuthBrokerGitClientTrustVerifyRequest)
    case gitClientTrustVerifyResponse(AuthBrokerGitClientTrustVerifyResponse)
    case gitClientTrustMutationRequest(AuthBrokerGitClientTrustMutationRequest)
    case gitClientTrustMutationResponse(AuthBrokerGitClientTrustMutationResponse)
    case gitClientTrustStateRequest(AuthBrokerGitClientTrustStateRequest)
    case gitClientTrustStateResponse(AuthBrokerGitClientTrustStateResponse)
}

// swiftlint:disable:next type_body_length
public enum AuthBrokerWire {
    public static let currentVersion: UInt16 = 8
    public static let maximumFrameLength = 256 * 1024
    public static let maximumCommandLength = 4 * 1024
    public static let maximumMetadataLength = 512
    private static let magic = Data([0x4D, 0x43, 0x41, 0x55]) // MCAU

    public static func frame(_ message: AuthBrokerMessage) throws -> Data {
        let payload = try self.payload(message)
        guard payload.count <= self.maximumFrameLength else { throw AuthBrokerProtocolError.tooLarge }
        return self.u32(UInt32(payload.count)) + payload
    }

    public static func takeFrame(
        from input: inout Data,
        nowMilliseconds: UInt64? = nil
    ) throws -> AuthBrokerMessage? {
        guard input.count >= 4 else { return nil }
        let length = try Int(self.readU32(input.prefix(4)))
        guard length <= self.maximumFrameLength else { throw AuthBrokerProtocolError.tooLarge }
        guard input.count >= 4 + length else { return nil }
        let payload = input.subdata(in: 4 ..< 4 + length)
        input.removeSubrange(0 ..< 4 + length)
        return try self.decodePayload(payload, nowMilliseconds: nowMilliseconds)
    }

    public static func selectVersion(clientMinimum: UInt16, clientMaximum: UInt16) throws -> UInt16 {
        guard clientMinimum > 0, clientMinimum <= clientMaximum,
              clientMinimum <= self.currentVersion, self.currentVersion <= clientMaximum
        else { throw AuthBrokerProtocolError.unsupportedVersion }
        return self.currentVersion
    }

    private static func payload(_ message: AuthBrokerMessage) throws -> Data {
        var value = self.magic + self.u16(self.currentVersion)
        switch message {
        case let .hello(hello):
            try self.validateHello(
                minimum: hello.minimumVersion,
                maximum: hello.maximumVersion,
                nonce: hello.nonce
            )
            value.append(1)
            value += self.u16(hello.minimumVersion) + self.u16(hello.maximumVersion)
            value += self.u32(hello.capabilities) + self.bytes(hello.nonce)
        case let .helloReply(reply):
            guard reply.selectedVersion == self.currentVersion else {
                throw AuthBrokerProtocolError.unsupportedVersion
            }
            try self.validateNonce(reply.nonce)
            value.append(2)
            value += self.u16(reply.selectedVersion) + self.u32(reply.capabilities) + self.bytes(reply.nonce)
        case let .approvalRequest(request):
            guard request.issuedAtMilliseconds < request.expiresAtMilliseconds else {
                throw AuthBrokerProtocolError.expired
            }
            guard request.purpose.isValid(for: request.operation) else {
                throw AuthBrokerProtocolError.malformed
            }
            guard request.presentation.isValid(for: request.operation) else {
                throw AuthBrokerProtocolError.malformed
            }
            value.append(3)
            value += try self.text(request.requestID.uuidString, maximum: 36)
            value += self.u64(request.issuedAtMilliseconds) + self.u64(request.expiresAtMilliseconds)
            value.append(request.operation.rawValue)
            value.append(request.purpose.rawValue)
            value += self.u32(UInt32(bitPattern: request.rootPID))
            value += self.u64(request.rootStartTime)
            value += try self.text(request.rootIdentifier, maximum: self.maximumMetadataLength)
            value += try self.text(request.rootCodeRequirement, maximum: self.maximumCommandLength)
            value += try self.text(request.rootExecutablePath, maximum: self.maximumCommandLength)
            try self.appendPresentation(request.presentation, to: &value)
            value += try self.text(request.credentialLabel, maximum: self.maximumMetadataLength)
            value += try self.text(request.credentialFingerprint, maximum: self.maximumMetadataLength)
            value += try self.text(request.host, maximum: self.maximumMetadataLength)
            value += try self.text(request.keychainService, maximum: self.maximumMetadataLength)
            value += try self.text(request.keychainAccount, maximum: self.maximumMetadataLength)
            value.append(request.keychainSynchronizable ? 1 : 0)
        case let .approvalResponse(response):
            value.append(4)
            value += try self.text(response.requestID.uuidString, maximum: 36)
            value.append(response.status.rawValue)
            value += try self.text(response.message, maximum: self.maximumMetadataLength)
            value += self.u32(UInt32(bitPattern: response.resultStatus))
            value += self.bytes(response.resultData)
            value += try self.text(response.verifiedUsername, maximum: self.maximumMetadataLength)
        case let .sshSignRequest(request):
            value.append(5)
            value += try self.text(request.authorizationID.uuidString, maximum: 36)
            value += self.u32(request.flags) + self.bytes(request.data)
        case let .sshSignResponse(response):
            guard self.validSSHSignResponse(response) else {
                throw AuthBrokerProtocolError.malformed
            }
            value.append(6)
            value += try self.text(response.authorizationID.uuidString, maximum: 36)
            value.append(response.outcome.rawValue)
            value += self.bytes(response.signature)
        case let .managedKeychainImportRequest(request):
            guard !request.secret.isEmpty else { throw AuthBrokerProtocolError.malformed }
            value.append(7)
            value += try self.text(request.authorizationID.uuidString, maximum: 36)
            value += self.bytes(request.secret)
        case let .managedKeychainImportResponse(response):
            guard self.validMutationOutcome(response.outcome, status: response.status) else {
                throw AuthBrokerProtocolError.malformed
            }
            value.append(8)
            value += try self.text(response.authorizationID.uuidString, maximum: 36)
            value.append(response.outcome.rawValue)
            value += self.u32(UInt32(bitPattern: response.status))
        case let .gitClientTrustVerifyRequest(request):
            guard self.validTrustDocument(request.canonicalDocument, digest: request.digest)
            else { throw AuthBrokerProtocolError.malformed }
            value.append(9)
            value += try self.text(request.requestID.uuidString, maximum: 36) + self
                .bytes(request.canonicalDocument) + self.bytes(request.digest)
        case let .gitClientTrustVerifyResponse(response):
            guard response.digest.count == 32 else { throw AuthBrokerProtocolError.malformed }
            value.append(10)
            value += try self.text(response.requestID.uuidString, maximum: 36) + self.bytes(response.digest) + self
                .u64(response.generation)
            value.append(response.status.rawValue)
        case let .gitClientTrustMutationRequest(request):
            guard self.validTrustDocument(request.canonicalDocument, digest: request.digest)
            else { throw AuthBrokerProtocolError.malformed }
            value.append(11)
            value += try self.text(request.authorizationID.uuidString, maximum: 36)
            value.append(request.operation.rawValue)
            value += self.u64(request.expectedGeneration) + self.bytes(request.canonicalDocument) + self
                .bytes(request.digest)
        case let .gitClientTrustMutationResponse(response):
            guard response.digest.count == 32 else { throw AuthBrokerProtocolError.malformed }
            value.append(12)
            value += try self.text(response.authorizationID.uuidString, maximum: 36) + self
                .bytes(response.digest) + self.u64(response.generation)
            value.append(response.status.rawValue)
        case let .gitClientTrustStateRequest(request):
            value.append(13)
            value += try self.text(request.requestID.uuidString, maximum: 36)
        case let .gitClientTrustStateResponse(response):
            value.append(14)
            value += try self.text(response.requestID.uuidString, maximum: 36) + self.u64(response.generation)
            value.append(response.status.rawValue)
        }
        return value
    }

    private static func decodePayload(_ data: Data, nowMilliseconds: UInt64?) throws -> AuthBrokerMessage {
        var cursor = AuthBrokerCursor(data)
        guard try cursor.bytes(count: self.magic.count) == self.magic else {
            throw AuthBrokerProtocolError.malformed
        }
        guard try cursor.u16() == self.currentVersion else { throw AuthBrokerProtocolError.unsupportedVersion }
        switch try cursor.byte() {
        case 1:
            let minimum = try cursor.u16()
            let maximum = try cursor.u16()
            let capabilities = try cursor.u32()
            let nonce = try cursor.bytes()
            guard cursor.isAtEnd else { throw AuthBrokerProtocolError.malformed }
            try self.validateHello(minimum: minimum, maximum: maximum, nonce: nonce)
            return .hello(AuthBrokerHello(
                minimumVersion: minimum,
                maximumVersion: maximum,
                capabilities: capabilities,
                nonce: nonce
            ))
        case 2:
            let selected = try cursor.u16()
            let capabilities = try cursor.u32()
            let nonce = try cursor.bytes()
            guard cursor.isAtEnd, selected == self.currentVersion else {
                throw AuthBrokerProtocolError.unsupportedVersion
            }
            try self.validateNonce(nonce)
            return .helloReply(AuthBrokerHelloReply(
                selectedVersion: selected,
                capabilities: capabilities,
                nonce: nonce
            ))
        case 3:
            guard let requestID = try UUID(uuidString: cursor.text(maximum: 36)) else {
                throw AuthBrokerProtocolError.malformed
            }
            let issued = try cursor.u64()
            let expires = try cursor.u64()
            guard issued < expires else { throw AuthBrokerProtocolError.expired }
            if let nowMilliseconds, expires <= nowMilliseconds {
                throw AuthBrokerProtocolError.expired
            }
            guard let operation = try AuthBrokerOperation(rawValue: cursor.byte()) else {
                throw AuthBrokerProtocolError.unsupportedMessage
            }
            guard let purpose = try AuthBrokerPurpose(rawValue: cursor.byte()),
                  purpose.isValid(for: operation)
            else { throw AuthBrokerProtocolError.malformed }
            let rootPID = try Int32(bitPattern: cursor.u32())
            let rootStartTime = try cursor.u64()
            let rootIdentifier = try cursor.text(maximum: self.maximumMetadataLength)
            let rootCodeRequirement = try cursor.text(maximum: self.maximumCommandLength)
            let rootExecutablePath = try cursor.text(maximum: self.maximumCommandLength)
            let presentation = try self.presentation(from: &cursor, operation: operation)
            let credentialLabel = try cursor.text(maximum: self.maximumMetadataLength)
            let credentialFingerprint = try cursor.text(maximum: self.maximumMetadataLength)
            let host = try cursor.text(maximum: self.maximumMetadataLength)
            let keychainService = try cursor.text(maximum: self.maximumMetadataLength)
            let keychainAccount = try cursor.text(maximum: self.maximumMetadataLength)
            let keychainSynchronizable = try cursor.byte()
            guard cursor.isAtEnd, rootPID > 0, rootStartTime > 0,
                  !rootIdentifier.isEmpty, !rootCodeRequirement.isEmpty, !rootExecutablePath.isEmpty,
                  presentation.isValid(for: operation),
                  keychainSynchronizable <= 1
            else { throw AuthBrokerProtocolError.malformed }
            return .approvalRequest(AuthBrokerApprovalRequest(
                requestID: requestID,
                issuedAtMilliseconds: issued,
                expiresAtMilliseconds: expires,
                operation: operation,
                rootPID: rootPID,
                rootStartTime: rootStartTime,
                rootIdentifier: rootIdentifier,
                rootCodeRequirement: rootCodeRequirement,
                rootExecutablePath: rootExecutablePath,
                presentation: presentation,
                purpose: purpose,
                credentialLabel: credentialLabel,
                credentialFingerprint: credentialFingerprint,
                host: host,
                keychainService: keychainService,
                keychainAccount: keychainAccount,
                keychainSynchronizable: keychainSynchronizable == 1
            ))
        case 4:
            guard let requestID = try UUID(uuidString: cursor.text(maximum: 36)),
                  let status = try AuthBrokerApprovalStatus(rawValue: cursor.byte())
            else { throw AuthBrokerProtocolError.malformed }
            let message = try cursor.text(maximum: self.maximumMetadataLength)
            let resultStatus = try Int32(bitPattern: cursor.u32())
            let resultData = try cursor.bytes()
            let verifiedUsername = try cursor.text(maximum: self.maximumMetadataLength)
            guard cursor.isAtEnd else { throw AuthBrokerProtocolError.malformed }
            return .approvalResponse(AuthBrokerApprovalResponse(
                requestID: requestID,
                status: status,
                message: message,
                resultStatus: resultStatus,
                resultData: resultData,
                verifiedUsername: verifiedUsername
            ))
        case 5:
            guard let authorizationID = try UUID(uuidString: cursor.text(maximum: 36)) else {
                throw AuthBrokerProtocolError.malformed
            }
            let flags = try cursor.u32()
            let data = try cursor.bytes()
            guard cursor.isAtEnd, !data.isEmpty else { throw AuthBrokerProtocolError.malformed }
            return .sshSignRequest(AuthBrokerSSHSignRequest(
                authorizationID: authorizationID,
                data: data,
                flags: flags
            ))
        case 6:
            guard let authorizationID = try UUID(uuidString: cursor.text(maximum: 36)) else {
                throw AuthBrokerProtocolError.malformed
            }
            guard let outcome = try AuthBrokerSSHSignOutcome(rawValue: cursor.byte()) else {
                throw AuthBrokerProtocolError.malformed
            }
            let signature = try cursor.bytes()
            let response = AuthBrokerSSHSignResponse(
                authorizationID: authorizationID,
                outcome: outcome,
                signature: signature
            )
            guard cursor.isAtEnd, self.validSSHSignResponse(response) else {
                throw AuthBrokerProtocolError.malformed
            }
            return .sshSignResponse(response)
        case 7:
            guard let authorizationID = try UUID(uuidString: cursor.text(maximum: 36)) else {
                throw AuthBrokerProtocolError.malformed
            }
            let secret = try cursor.bytes()
            guard cursor.isAtEnd, !secret.isEmpty else { throw AuthBrokerProtocolError.malformed }
            return .managedKeychainImportRequest(AuthBrokerManagedKeychainImportRequest(
                authorizationID: authorizationID,
                secret: secret
            ))
        case 8:
            guard let authorizationID = try UUID(uuidString: cursor.text(maximum: 36)) else {
                throw AuthBrokerProtocolError.malformed
            }
            guard let outcome = try AuthBrokerMutationOutcome(rawValue: cursor.byte()) else {
                throw AuthBrokerProtocolError.malformed
            }
            let status = try Int32(bitPattern: cursor.u32())
            guard cursor.isAtEnd, self.validMutationOutcome(outcome, status: status) else {
                throw AuthBrokerProtocolError.malformed
            }
            return .managedKeychainImportResponse(AuthBrokerManagedKeychainImportResponse(
                authorizationID: authorizationID,
                outcome: outcome,
                status: status
            ))
        case 9:
            guard let requestID = try UUID(uuidString: cursor.text(maximum: 36))
            else { throw AuthBrokerProtocolError.malformed }
            let document = try cursor.bytes(); let digest = try cursor.bytes()
            guard cursor.isAtEnd,
                  self.validTrustDocument(document, digest: digest) else { throw AuthBrokerProtocolError.malformed }
            return .gitClientTrustVerifyRequest(AuthBrokerGitClientTrustVerifyRequest(
                requestID: requestID,
                canonicalDocument: document,
                digest: digest
            ))
        case 10:
            guard let requestID = try UUID(uuidString: cursor.text(maximum: 36))
            else { throw AuthBrokerProtocolError.malformed }
            let digest = try cursor.bytes(); let generation = try cursor.u64()
            guard let status = try AuthBrokerGitClientTrustStatus(rawValue: cursor.byte()), cursor.isAtEnd,
                  digest.count == 32 else { throw AuthBrokerProtocolError.malformed }
            return .gitClientTrustVerifyResponse(AuthBrokerGitClientTrustVerifyResponse(
                requestID: requestID,
                digest: digest,
                generation: generation,
                status: status
            ))
        case 11:
            guard let authorizationID = try UUID(uuidString: cursor.text(maximum: 36)),
                  let operation = try GitClientTrustMutationOperation(rawValue: cursor.byte())
            else { throw AuthBrokerProtocolError.malformed }
            let expectedGeneration = try cursor.u64(); let document = try cursor.bytes(); let digest = try cursor
                .bytes()
            guard cursor.isAtEnd,
                  self.validTrustDocument(document, digest: digest) else { throw AuthBrokerProtocolError.malformed }
            return .gitClientTrustMutationRequest(AuthBrokerGitClientTrustMutationRequest(
                authorizationID: authorizationID,
                operation: operation,
                expectedGeneration: expectedGeneration,
                canonicalDocument: document,
                digest: digest
            ))
        case 12:
            guard let authorizationID = try UUID(uuidString: cursor.text(maximum: 36))
            else { throw AuthBrokerProtocolError.malformed }
            let digest = try cursor.bytes(); let generation = try cursor.u64()
            guard let status = try AuthBrokerGitClientTrustStatus(rawValue: cursor.byte()), cursor.isAtEnd,
                  digest.count == 32 else { throw AuthBrokerProtocolError.malformed }
            return .gitClientTrustMutationResponse(AuthBrokerGitClientTrustMutationResponse(
                authorizationID: authorizationID,
                digest: digest,
                generation: generation,
                status: status
            ))
        case 13:
            guard let requestID = try UUID(uuidString: cursor.text(maximum: 36)), cursor.isAtEnd else {
                throw AuthBrokerProtocolError.malformed
            }
            return .gitClientTrustStateRequest(AuthBrokerGitClientTrustStateRequest(requestID: requestID))
        case 14:
            guard let requestID = try UUID(uuidString: cursor.text(maximum: 36)) else {
                throw AuthBrokerProtocolError.malformed
            }
            let generation = try cursor.u64()
            guard let status = try AuthBrokerGitClientTrustStatus(rawValue: cursor.byte()), cursor.isAtEnd else {
                throw AuthBrokerProtocolError.malformed
            }
            return .gitClientTrustStateResponse(AuthBrokerGitClientTrustStateResponse(
                requestID: requestID, generation: generation, status: status
            ))
        default:
            throw AuthBrokerProtocolError.unsupportedMessage
        }
    }

    private static func validateHello(minimum: UInt16, maximum: UInt16, nonce: Data) throws {
        _ = try self.selectVersion(clientMinimum: minimum, clientMaximum: maximum)
        try self.validateNonce(nonce)
    }

    private static func validateNonce(_ nonce: Data) throws {
        guard nonce.count == 32 else { throw AuthBrokerProtocolError.malformed }
    }

    private static func validMutationOutcome(_ outcome: AuthBrokerMutationOutcome, status: Int32) -> Bool {
        switch outcome {
        case .committed: status == errSecSuccess
        case .failed: status != errSecSuccess
        case .indeterminate: true
        }
    }

    private static func validSSHSignResponse(_ response: AuthBrokerSSHSignResponse) -> Bool {
        switch response.outcome {
        case .signed:
            !response.signature.isEmpty
        case .requesterInvalid, .signerUnavailable, .identityMismatch, .signatureFailed:
            response.signature.isEmpty
        }
    }

    private static func validTrustDocument(_ document: Data, digest: Data) -> Bool {
        guard digest.count == 32, document.count <= self.maximumFrameLength else { return false }
        guard let decoded = try? GitClientTrustDocument.decodeCanonical(document),
              let canonical = try? decoded.canonicalBytes(),
              let calculated = try? decoded.digest()
        else { return false }
        return constantTimeEqual(document, canonical) && constantTimeEqual(digest, calculated)
    }

    private static func appendPresentation(
        _ presentation: AuthBrokerApprovalPresentation,
        to value: inout Data
    ) throws {
        switch presentation {
        case .requesterOnly:
            value.append(0)
        case let .sshSessionTarget(application, signingAuthority, cdHash, verification):
            value.append(1)
            value += try self.text(application, maximum: self.maximumCommandLength)
            value += try self.text(signingAuthority, maximum: self.maximumMetadataLength)
            value += try self.text(cdHash, maximum: self.maximumMetadataLength)
            value += try self.text(verification, maximum: self.maximumMetadataLength)
        }
    }

    private static func presentation(
        from cursor: inout AuthBrokerCursor,
        operation: AuthBrokerOperation
    ) throws -> AuthBrokerApprovalPresentation {
        switch try cursor.byte() {
        case 0:
            return .requesterOnly
        case 1:
            let application = try cursor.text(maximum: self.maximumCommandLength)
            let signingAuthority = try cursor.text(maximum: self.maximumMetadataLength)
            let cdHash = try cursor.text(maximum: self.maximumMetadataLength)
            let verification = try cursor.text(maximum: self.maximumMetadataLength)
            let presentation = AuthBrokerApprovalPresentation.sshSessionTarget(
                application: application,
                signingAuthority: signingAuthority,
                cdHash: cdHash,
                verification: verification
            )
            guard presentation.isValid(for: operation) else {
                throw AuthBrokerProtocolError.malformed
            }
            return presentation
        default:
            throw AuthBrokerProtocolError.malformed
        }
    }

    private static func text(_ value: String, maximum: Int) throws -> Data {
        let data = Data(value.utf8)
        guard data.count <= maximum, self.safeDisplayText(value) else {
            throw AuthBrokerProtocolError.tooLarge
        }
        return self.bytes(data)
    }

    private static func safeDisplayText(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { scalar in
            if scalar.properties.isBidiControl || scalar.value == 0x1B {
                return false
            }
            return !CharacterSet.controlCharacters.contains(scalar)
        }
    }

    private static func bytes(_ value: Data) -> Data {
        self.u32(UInt32(value.count)) + value
    }

    private static func u16(_ value: UInt16) -> Data {
        Data([UInt8(value >> 8), UInt8(value & 0xFF)])
    }

    private static func u32(_ value: UInt32) -> Data {
        Data([UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)])
    }

    private static func u64(_ value: UInt64) -> Data {
        Data((0 ..< 8).map { shift in UInt8((value >> UInt64((7 - shift) * 8)) & 0xFF) })
    }

    private static func readU32(_ data: some DataProtocol) throws -> UInt32 {
        guard data.count == 4 else { throw AuthBrokerProtocolError.malformed }
        return data.reduce(0) { ($0 << 8) | UInt32($1) }
    }
}

private struct AuthBrokerCursor {
    private let data: Data
    private var offset = 0

    init(_ data: Data) {
        self.data = data
    }

    mutating func byte() throws -> UInt8 {
        guard self.offset < self.data.count else { throw AuthBrokerProtocolError.malformed }
        defer { self.offset += 1 }
        return self.data[self.offset]
    }

    mutating func u16() throws -> UInt16 {
        let value = try self.bytes(count: 2)
        return value.reduce(0) { ($0 << 8) | UInt16($1) }
    }

    mutating func u32() throws -> UInt32 {
        let value = try self.bytes(count: 4)
        return value.reduce(0) { ($0 << 8) | UInt32($1) }
    }

    mutating func u64() throws -> UInt64 {
        let value = try self.bytes(count: 8)
        return value.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    mutating func bytes() throws -> Data {
        let count = try Int(self.u32())
        guard count <= AuthBrokerWire.maximumFrameLength else { throw AuthBrokerProtocolError.tooLarge }
        return try self.bytes(count: count)
    }

    mutating func bytes(count: Int) throws -> Data {
        guard count >= 0, self.data.count - self.offset >= count else {
            throw AuthBrokerProtocolError.malformed
        }
        defer { self.offset += count }
        return self.data.subdata(in: self.offset ..< self.offset + count)
    }

    mutating func text(maximum: Int) throws -> String {
        let data = try self.bytes()
        guard data.count <= maximum, let value = String(data: data, encoding: .utf8) else {
            throw AuthBrokerProtocolError.tooLarge
        }
        guard value.unicodeScalars.allSatisfy({ scalar in
            !scalar.properties.isBidiControl && scalar.value != 0x1B
                && !CharacterSet.controlCharacters.contains(scalar)
        }) else { throw AuthBrokerProtocolError.malformed }
        return value
    }

    var isAtEnd: Bool {
        self.offset == self.data.count
    }
}
