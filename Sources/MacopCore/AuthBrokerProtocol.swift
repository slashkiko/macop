// swiftlint:disable file_length
import Foundation

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
    public let command: String
    public let credentialLabel: String
    public let credentialFingerprint: String
    public let host: String
    public let keychainService: String
    public let keychainAccount: String

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
        command: String,
        credentialLabel: String,
        credentialFingerprint: String,
        host: String,
        keychainService: String = "",
        keychainAccount: String = ""
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
        self.command = command
        self.credentialLabel = credentialLabel
        self.credentialFingerprint = credentialFingerprint
        self.host = host
        self.keychainService = keychainService
        self.keychainAccount = keychainAccount
    }
}

public enum AuthBrokerApprovalStatus: UInt8, Sendable {
    case approved = 1
    case cancelled = 2
    case denied = 3
}

public struct AuthBrokerApprovalResponse: Sendable, Equatable {
    public let requestID: UUID
    public let status: AuthBrokerApprovalStatus
    public let message: String
    public let resultStatus: Int32
    public let resultData: Data

    public init(
        requestID: UUID,
        status: AuthBrokerApprovalStatus,
        message: String = "",
        resultStatus: Int32 = 0,
        resultData: Data = Data()
    ) {
        self.requestID = requestID
        self.status = status
        self.message = message
        self.resultStatus = resultStatus
        self.resultData = resultData
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
    public let status: Int32

    public init(authorizationID: UUID, status: Int32) {
        self.authorizationID = authorizationID
        self.status = status
    }
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
    public let signature: Data

    public init(authorizationID: UUID, signature: Data) {
        self.authorizationID = authorizationID
        self.signature = signature
    }
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
}

// swiftlint:disable:next type_body_length
public enum AuthBrokerWire {
    public static let currentVersion: UInt16 = 1
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
            value.append(3)
            value += try self.text(request.requestID.uuidString, maximum: 36)
            value += self.u64(request.issuedAtMilliseconds) + self.u64(request.expiresAtMilliseconds)
            value.append(request.operation.rawValue)
            value += self.u32(UInt32(bitPattern: request.rootPID))
            value += self.u64(request.rootStartTime)
            value += try self.text(request.rootIdentifier, maximum: self.maximumMetadataLength)
            value += try self.text(request.rootCodeRequirement, maximum: self.maximumCommandLength)
            value += try self.text(request.rootExecutablePath, maximum: self.maximumCommandLength)
            value += try self.text(request.command, maximum: self.maximumCommandLength)
            value += try self.text(request.credentialLabel, maximum: self.maximumMetadataLength)
            value += try self.text(request.credentialFingerprint, maximum: self.maximumMetadataLength)
            value += try self.text(request.host, maximum: self.maximumMetadataLength)
            value += try self.text(request.keychainService, maximum: self.maximumMetadataLength)
            value += try self.text(request.keychainAccount, maximum: self.maximumMetadataLength)
        case let .approvalResponse(response):
            value.append(4)
            value += try self.text(response.requestID.uuidString, maximum: 36)
            value.append(response.status.rawValue)
            value += try self.text(response.message, maximum: self.maximumMetadataLength)
            value += self.u32(UInt32(bitPattern: response.resultStatus))
            value += self.bytes(response.resultData)
        case let .sshSignRequest(request):
            value.append(5)
            value += try self.text(request.authorizationID.uuidString, maximum: 36)
            value += self.u32(request.flags) + self.bytes(request.data)
        case let .sshSignResponse(response):
            value.append(6)
            value += try self.text(response.authorizationID.uuidString, maximum: 36)
            value += self.bytes(response.signature)
        case let .managedKeychainImportRequest(request):
            guard !request.secret.isEmpty else { throw AuthBrokerProtocolError.malformed }
            value.append(7)
            value += try self.text(request.authorizationID.uuidString, maximum: 36)
            value += self.bytes(request.secret)
        case let .managedKeychainImportResponse(response):
            value.append(8)
            value += try self.text(response.authorizationID.uuidString, maximum: 36)
            value += self.u32(UInt32(bitPattern: response.status))
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
            let rootPID = try Int32(bitPattern: cursor.u32())
            let rootStartTime = try cursor.u64()
            let rootIdentifier = try cursor.text(maximum: self.maximumMetadataLength)
            let rootCodeRequirement = try cursor.text(maximum: self.maximumCommandLength)
            let rootExecutablePath = try cursor.text(maximum: self.maximumCommandLength)
            let command = try cursor.text(maximum: self.maximumCommandLength)
            let credentialLabel = try cursor.text(maximum: self.maximumMetadataLength)
            let credentialFingerprint = try cursor.text(maximum: self.maximumMetadataLength)
            let host = try cursor.text(maximum: self.maximumMetadataLength)
            let keychainService = try cursor.text(maximum: self.maximumMetadataLength)
            let keychainAccount = try cursor.text(maximum: self.maximumMetadataLength)
            guard cursor.isAtEnd, rootPID > 0, rootStartTime > 0,
                  !rootIdentifier.isEmpty, !rootCodeRequirement.isEmpty, !rootExecutablePath.isEmpty
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
                command: command,
                credentialLabel: credentialLabel,
                credentialFingerprint: credentialFingerprint,
                host: host,
                keychainService: keychainService,
                keychainAccount: keychainAccount
            ))
        case 4:
            guard let requestID = try UUID(uuidString: cursor.text(maximum: 36)),
                  let status = try AuthBrokerApprovalStatus(rawValue: cursor.byte())
            else { throw AuthBrokerProtocolError.malformed }
            let message = try cursor.text(maximum: self.maximumMetadataLength)
            let resultStatus = try Int32(bitPattern: cursor.u32())
            let resultData = try cursor.bytes()
            guard cursor.isAtEnd else { throw AuthBrokerProtocolError.malformed }
            return .approvalResponse(AuthBrokerApprovalResponse(
                requestID: requestID,
                status: status,
                message: message,
                resultStatus: resultStatus,
                resultData: resultData
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
            let signature = try cursor.bytes()
            guard cursor.isAtEnd, !signature.isEmpty else { throw AuthBrokerProtocolError.malformed }
            return .sshSignResponse(AuthBrokerSSHSignResponse(
                authorizationID: authorizationID,
                signature: signature
            ))
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
            let status = try Int32(bitPattern: cursor.u32())
            guard cursor.isAtEnd else { throw AuthBrokerProtocolError.malformed }
            return .managedKeychainImportResponse(AuthBrokerManagedKeychainImportResponse(
                authorizationID: authorizationID,
                status: status
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
