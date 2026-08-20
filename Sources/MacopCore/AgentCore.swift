import CryptoKit
import Foundation
import Security

/// Closed OpenSSH-agent codec.  The transport must pass each complete payload to
/// `AgentConnection.reply`; malformed requests never escape as a socket error.
public enum AgentProtocolError: Error, Equatable, Sendable { case malformed, tooLarge, unsupported, denied }

public enum SSHWire {
    public static let maxFrameLength = 256 * 1024
    public static let maxStringLength = 128 * 1024
    public static func frame(_ payload: Data) throws -> Data {
        guard payload.count <= self.maxFrameLength else { throw AgentProtocolError.tooLarge }
        return try self.u32(UInt32(payload.count)) + payload
    }

    public static func takeFrame(from input: inout Data) throws -> Data? {
        guard input.count >= 4 else { return nil }
        let length = try readU32(input.prefix(4))
        guard length <= UInt32(self.maxFrameLength) else { throw AgentProtocolError.tooLarge }
        guard input.count >= 4 + Int(length) else { return nil }
        defer { input.removeSubrange(0 ..< 4 + Int(length)) }
        return input.subdata(in: 4 ..< 4 + Int(length))
    }

    public static func u32(_ value: UInt32) throws -> Data {
        Data([
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ])
    }

    public static func string(_ value: Data) throws -> Data {
        guard value.count <= self.maxStringLength else { throw AgentProtocolError.tooLarge }
        return try self.u32(UInt32(value.count)) + value
    }

    public static func string(_ value: String) throws -> Data {
        try self.string(Data(value.utf8))
    }

    public static func boolean(_ value: Bool) -> Data {
        Data([value ? 1 : 0])
    }

    static func readU32(_ data: some DataProtocol) throws -> UInt32 {
        guard data.count == 4 else { throw AgentProtocolError.malformed }
        return data.reduce(0) { ($0 << 8) | UInt32($1) }
    }
}

public struct SSHCursor: Sendable {
    private let data: Data; private var offset = 0
    public init(_ data: Data) {
        self.data = data
    }

    public mutating func byte() throws -> UInt8 {
        guard self.offset < self.data.count
        else { throw AgentProtocolError.malformed }; defer { offset += 1 }; return self.data[self.offset]
    }

    public mutating func u32() throws -> UInt32 {
        guard self.data.count - self.offset >= 4
        else { throw AgentProtocolError.malformed }; defer { offset += 4 }; return try SSHWire
            .readU32(self.data[self.offset ..< self.offset + 4])
    }

    public mutating func string() throws -> Data {
        let count = try Int(u32()); guard count <= SSHWire.maxStringLength
        else { throw AgentProtocolError.tooLarge }; guard self.data.count - self.offset >= count
        else { throw AgentProtocolError.malformed }; defer { offset += count }; return self.data
            .subdata(in: self.offset ..< self.offset + count)
    }

    public mutating func bool() throws -> Bool {
        let value = try byte(); guard value == 0 || value == 1
        else { throw AgentProtocolError.malformed }; return value == 1
    }

    public var isAtEnd: Bool {
        self.offset == self.data.count
    }
}

public enum AgentMessage {
    public static let failure: UInt8 = 5, success: UInt8 = 6, requestIdentities: UInt8 = 11,
                      identitiesAnswer: UInt8 = 12
    public static let signRequest: UInt8 = 13, signResponse: UInt8 = 14, extensionRequest: UInt8 = 27,
                      extensionFailure: UInt8 = 28
}

public protocol SessionBindingVerifying: Sendable { func verify(hostKey: Data, sessionID: Data, signature: Data) throws
}

/// Verifies the OpenSSH `session-bind@openssh.com` signature, which signs the
/// raw exchange-hash/session-id.  Only algorithms with strict wire parsers are
/// accepted; unknown host keys fail closed.
public struct SecuritySessionBindingVerifier: SessionBindingVerifying {
    public init() {}
    public func verify(hostKey: Data, sessionID: Data, signature: Data) throws {
        var key = SSHCursor(hostKey); let algorithm = try text(key.string())
        switch algorithm {
        case "ssh-ed25519":
            let raw = try key.string(); guard raw.count == 32, key.isAtEnd else { throw AgentProtocolError.malformed }
            var signatureCursor = SSHCursor(signature)
            guard try self.text(signatureCursor.string()) == algorithm else { throw AgentProtocolError.denied }
            let value = try signatureCursor.string()
            guard signatureCursor.isAtEnd, value.count == 64 else { throw AgentProtocolError.malformed }
            let publicKey: Curve25519.Signing.PublicKey
            do {
                publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
            } catch {
                throw AgentProtocolError.denied
            }
            guard publicKey.isValidSignature(value, for: sessionID) else { throw AgentProtocolError.denied }
        case "ecdsa-sha2-nistp256":
            guard try self.text(key.string()) == "nistp256" else { throw AgentProtocolError.malformed }
            let point = try key.string(); guard point.count == 65, point.first == 4,
                                                key.isAtEnd else { throw AgentProtocolError.malformed }
            let secKey = try self.makeKey(point, type: kSecAttrKeyTypeECSECPrimeRandom as CFString, size: 256)
            let der = try ecdsaSignatureDER(signature, expectedAlgorithm: algorithm)
            guard SecKeyVerifySignature(
                secKey,
                .ecdsaSignatureMessageX962SHA256,
                sessionID as CFData,
                der as CFData,
                nil
            ) else { throw AgentProtocolError.denied }
        default: throw AgentProtocolError.unsupported
        }
    }

    private func text(_ data: Data) throws -> String {
        guard let value = String(data: data, encoding: .utf8)
        else { throw AgentProtocolError.malformed }; return value
    }

    private func makeKey(_ data: Data, type: CFString, size: Int) throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(
            data as CFData,
            [kSecAttrKeyType: type, kSecAttrKeyClass: kSecAttrKeyClassPublic,
             kSecAttrKeySizeInBits: size] as CFDictionary,
            &error
        ) else { throw AgentProtocolError.denied }
        return key
    }
}

public final class SessionBindingState: @unchecked Sendable {
    private var binding: Binding?; private let lock = NSLock()
    public init() {}
    public func accept(payload: Data, verifier: any SessionBindingVerifying) throws {
        var cursor = SSHCursor(payload)
        guard try String(data: cursor.string(), encoding: .utf8) == "session-bind@openssh.com"
        else { throw AgentProtocolError.unsupported }
        // PROTOCOL.agent: extension type 27 is followed directly by these four
        // fields.  There is no enclosing payload string.
        let hostKey = try cursor.string(); let sessionID = try cursor.string(); let signature = try cursor.string()
        let forwarding = try cursor.bool()
        guard cursor.isAtEnd, !hostKey.isEmpty, (1 ... 128).contains(sessionID.count),
              !forwarding else { throw AgentProtocolError.denied }
        self.lock.lock(); defer { lock.unlock() }
        guard self.binding == nil else { throw AgentProtocolError.denied }
        try verifier.verify(hostKey: hostKey, sessionID: sessionID, signature: signature)
        self.binding = Binding(hostKey: hostKey, sessionID: sessionID)
    }

    public var isBound: Bool {
        self.lock.lock(); defer { lock.unlock() }; return self.binding != nil
    }

    public func matchesAuthorizationData(_ data: Data, signerKey: Data) throws {
        self.lock.lock(); defer { lock.unlock() }
        guard let binding else { throw AgentProtocolError.denied }
        var cursor = SSHCursor(data)
        let sessionID = try cursor.string(); let message = try cursor.byte(); let user = try text(cursor.string())
        let service = try text(cursor.string()); let method = try text(cursor.string())
        guard constantTimeEqual(sessionID, binding.sessionID), message == 50, user != nil, service == "ssh-connection",
              method == "publickey" || method == "publickey-hostbound-v00@openssh.com", try cursor.bool()
        else {
            throw AgentProtocolError.denied
        }
        let algorithm = try text(cursor.string()); let key = try cursor.string()
        var signerCursor = SSHCursor(signerKey); let signerAlgorithm = try text(signerCursor.string())
        guard algorithm == signerAlgorithm, constantTimeEqual(key, signerKey) else {
            throw AgentProtocolError.denied
        }
        if method == "publickey-hostbound-v00@openssh.com" {
            guard try constantTimeEqual(cursor.string(), binding.hostKey) else { throw AgentProtocolError.denied }
        }
        guard cursor.isAtEnd else { throw AgentProtocolError.malformed }
    }

    private struct Binding { let hostKey: Data; let sessionID: Data }

    private func text(_ data: Data) -> String? {
        String(data: data, encoding: .utf8)
    }
}

public protocol AgentKeySigning: Sendable { var publicKeyBlob: Data { get }; var fingerprint: String { get }; func sign(
    data: Data,
    flags: UInt32
) throws -> Data }
public struct UnsupportedCTKSigner: AgentKeySigning {
    public let publicKeyBlob: Data; public let fingerprint: String
    public init(publicKeyBlob: Data, fingerprint: String) {
        self.publicKeyBlob = publicKeyBlob; self.fingerprint = fingerprint
    }

    public func sign(data: Data, flags: UInt32) throws -> Data {
        throw AgentProtocolError.unsupported
    }
}

public struct AgentConnection: Sendable {
    public let requester: RequesterVerifier
    public let registry: SessionRegistry
    public let sessionID: UUID
    public let signer: any AgentKeySigning
    public let bindingVerifier: any SessionBindingVerifying
    private let state = SessionBindingState()
    public init(
        requester: RequesterVerifier,
        registry: SessionRegistry,
        sessionID: UUID,
        signer: any AgentKeySigning,
        bindingVerifier: any SessionBindingVerifying = SecuritySessionBindingVerifier()
    ) {
        self.requester = requester; self.registry = registry; self.sessionID = sessionID; self.signer = signer
        self.bindingVerifier = bindingVerifier
    }

    /// Converts every protocol failure into the OpenSSH reply required for its
    /// request class: generic failure (5), or extension failure (28).
    public func reply(peer: RequesterPeer, payload: Data, now: Date = .now) -> Data {
        let extensionRequest = payload.first == AgentMessage.extensionRequest
        do { return try self.handle(peer: peer, payload: payload, now: now) } catch {
            return Data([extensionRequest ? AgentMessage.extensionFailure : AgentMessage.failure])
        }
    }

    public func handle(peer: RequesterPeer, payload: Data, now: Date = .now) throws -> Data {
        guard let session = self.registry.session(self.sessionID, now: now), self.requester.verify(
            peer: peer,
            session: session,
            now: now
        ),
            let type = payload.first else { throw AgentProtocolError.denied }
        let body = Data(payload.dropFirst())
        switch type {
        case AgentMessage.requestIdentities:
            guard body.isEmpty else { throw AgentProtocolError.malformed }
            let fingerprint = sshFingerprint(for: self.signer.publicKeyBlob)
            return try Data([AgentMessage.identitiesAnswer]) + (SSHWire.u32(1)) +
                (SSHWire.string(self.signer.publicKeyBlob)) + (SSHWire.string(fingerprint))
        case AgentMessage.extensionRequest:
            try self.state.accept(payload: body, verifier: self.bindingVerifier); return Data([AgentMessage.success])
        case AgentMessage.signRequest:
            guard self.state.isBound
            else { throw AgentProtocolError.denied }; var cursor = SSHCursor(body); let key = try cursor
                .string(); let data = try cursor.string(); let flags = try cursor.u32(); guard cursor.isAtEnd,
                constantTimeEqual(key, self.signer.publicKeyBlob) else { throw AgentProtocolError.denied }
            let fingerprint = sshFingerprint(for: signer.publicKeyBlob)
            guard self.registry.verifySign(sessionID: self.sessionID, signerFingerprint: fingerprint, now: now) != nil
            else {
                throw AgentProtocolError.denied
            }
            try self.state.matchesAuthorizationData(data, signerKey: self.signer.publicKeyBlob)
            return try Data([AgentMessage.signResponse]) + (SSHWire.string(self.signer.sign(data: data, flags: flags)))
        default: throw AgentProtocolError.unsupported
        }
    }
}

public func sshFingerprint(for publicKeyBlob: Data) -> String {
    let digest = SHA256.hash(data: publicKeyBlob)
    return "SHA256:" + Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
}

private func ecdsaSignatureDER(_ signature: Data, expectedAlgorithm: String) throws -> Data {
    var outer = SSHCursor(signature); guard try String(data: outer.string(), encoding: .utf8) == expectedAlgorithm
    else { throw AgentProtocolError.denied }; let inner = try outer.string(); guard outer.isAtEnd
    else { throw AgentProtocolError.malformed }
    var values = SSHCursor(inner)
    let firstCoordinate = try canonicalP256MPInt(values.string())
    let secondCoordinate = try canonicalP256MPInt(values.string())
    guard values.isAtEnd else { throw AgentProtocolError.malformed }
    let body = try derInteger(firstCoordinate) + derInteger(secondCoordinate); guard body.count < 128
    else { throw AgentProtocolError.malformed }; return Data([
        0x30,
        UInt8(body.count)
    ]) + body
}

private func canonicalP256MPInt(_ value: Data) throws -> Data {
    guard !value.isEmpty, value.count <= 33,
          value.first != 0x00 || value.count == 1 || value
          .dropFirst().first! >= 0x80
    else { throw AgentProtocolError.malformed
    }; guard value.first! < 0x80
    else { throw AgentProtocolError.malformed
    }; return value
}

private func derInteger(_ positive: Data) throws -> Data {
    let body = positive
        .first! >= 0x80 ? Data([0]) + positive : positive
    guard let length = UInt8(exactly: body.count) else { throw AgentProtocolError.malformed }
    return Data([
        0x02,
        length
    ]) + body
}
