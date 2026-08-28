import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// A non-exporting signer for one, already selected CryptoTokenKit identity.
/// The CTK label is matched exactly and the resulting certificate public key
/// must produce the selected SSH blob.
public struct CTKIdentitySigner: AgentKeySigning, @unchecked Sendable {
    public let publicKeyBlob: Data
    public let fingerprint: String
    private let privateKey: SecKey

    public init(
        identityLabel: String,
        expectedPublicKeyBlob: Data,
        authenticationContext: LAContext? = nil
    ) throws {
        let matches = try Self.resolveIdentities(
            identityLabel: identityLabel,
            authenticationContext: authenticationContext
        ).filter { $0.publicKeyBlob == expectedPublicKeyBlob }
        guard matches.count == 1, let resolved = matches.first else { throw AgentProtocolError.denied }
        var privateKey: SecKey?
        guard SecIdentityCopyPrivateKey(resolved.identity, &privateKey) == errSecSuccess,
              let privateKey else { throw AgentProtocolError.denied }
        self.publicKeyBlob = expectedPublicKeyBlob
        self.fingerprint = sshFingerprint(for: expectedPublicKeyBlob)
        self.privateKey = privateKey
    }

    /// Resolves only public material from an exact Keychain identity label.
    /// This path is used by the verified-session agent and intentionally does
    /// not depend on Apple's PKCS#11 SSH provider.
    public static func publicKeyBlob(identityLabel: String, publicKeyHash: String) throws -> Data {
        let matches = try self.resolveIdentities(identityLabel: identityLabel, authenticationContext: nil)
            .filter { $0.publicKeyHash == publicKeyHash.uppercased() }
        guard matches.count == 1, let resolved = matches.first else { throw AgentProtocolError.denied }
        return resolved.publicKeyBlob
    }

    private struct ResolvedIdentity {
        let identity: SecIdentity
        let publicKeyBlob: Data
        let publicKeyHash: String
    }

    private static func resolveIdentities(
        identityLabel: String,
        authenticationContext: LAContext?
    ) throws -> [ResolvedIdentity] {
        guard !identityLabel.isEmpty else { throw AgentProtocolError.denied }
        var query: [CFString: Any] = [
            kSecClass: kSecClassIdentity,
            kSecAttrLabel: identityLabel,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnRef: true
        ]
        if let authenticationContext {
            query[kSecUseAuthenticationContext] = authenticationContext
        }
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let result,
              CFGetTypeID(result) == CFArrayGetTypeID()
        else { throw AgentProtocolError.denied }
        let values = unsafeDowncast(result, to: CFArray.self)
        return (0 ..< CFArrayGetCount(values)).compactMap { index in
            let value = CFArrayGetValueAtIndex(values, index)
            guard let value else { return nil }
            let item = unsafeBitCast(value, to: CFTypeRef.self)
            guard CFGetTypeID(item) == SecIdentityGetTypeID() else { return nil }
            let identity = unsafeDowncast(item, to: SecIdentity.self)
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
                  let certificate,
                  let key = SecCertificateCopyKey(certificate),
                  let material = try? self.publicMaterial(for: key)
            else { return nil }
            return ResolvedIdentity(
                identity: identity,
                publicKeyBlob: material.blob,
                publicKeyHash: material.hash
            )
        }
    }

    public func sign(data: Data, flags: UInt32) throws -> Data {
        // ECDSA has no RSA SHA2 flag variants.  Refusing unknown flags avoids a
        // caller believing a different algorithm was selected.
        guard flags == 0,
              SecKeyIsAlgorithmSupported(self.privateKey, .sign, .ecdsaSignatureMessageX962SHA256)
        else { throw AgentProtocolError.unsupported }
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else { throw AgentProtocolError.denied }
        let raw = try Self.strictDERToRawP256(der)
        let firstCoordinate = Self.mpint(raw.prefix(32))
        let secondCoordinate = Self.mpint(raw.suffix(32))
        return try SSHWire.string("ecdsa-sha2-nistp256") + SSHWire.string(
            SSHWire.string(firstCoordinate) + SSHWire.string(secondCoordinate)
        )
    }

    public static func publicBlob(for publicKey: SecKey) throws -> Data {
        try self.publicMaterial(for: publicKey).blob
    }

    private static func publicMaterial(for publicKey: SecKey) throws -> (blob: Data, hash: String) {
        guard let attributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any],
              let keyType = attributes[kSecAttrKeyType] as? String,
              keyType == kSecAttrKeyTypeECSECPrimeRandom as String,
              let keySize = attributes[kSecAttrKeySizeInBits] as? NSNumber,
              keySize.intValue == 256
        else { throw AgentProtocolError.unsupported }
        var error: Unmanaged<CFError>?
        guard let point = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?, point.count == 65,
              point.first == 4 else { throw AgentProtocolError.denied }
        let blob = try SSHWire.string("ecdsa-sha2-nistp256") + SSHWire.string("nistp256") + SSHWire.string(point)
        let hash = Insecure.SHA1.hash(data: point).map { String(format: "%02X", $0) }.joined()
        return (blob, hash)
    }

    /// Requires canonical ASN.1 DER INTEGERs and exactly P-256-sized positive
    /// values; accepting a permissive DER encoding here would produce malleable
    /// SSH signatures.
    public static func strictDERToRawP256(_ der: Data) throws -> Data {
        var index = 0
        func byte() throws -> UInt8 {
            guard index < der.count
            else { throw AgentProtocolError.malformed }; defer { index += 1 }; return der[index]
        }
        func length() throws -> Int {
            let first = try byte(); guard first < 0x80
            else { throw AgentProtocolError.malformed }; return Int(first)
        }
        guard try byte() == 0x30, try length() == der.count - index else { throw AgentProtocolError.malformed }
        func integer() throws -> Data {
            guard try byte() == 0x02
            else { throw AgentProtocolError.malformed }; let count = try length(); guard count > 0, count <= 33,
                                                                                         index + count <= der.count
            else {
                throw AgentProtocolError
                    .malformed
            }
            let value = der.subdata(in: index ..< index + count); index += count
            guard value.first! & 0x80 == 0,
                  !(value.count > 1 && value[0] == 0 && value[1] & 0x80 == 0)
            else { throw AgentProtocolError.malformed }
            let unsigned = value.first == 0 ? Data(value.dropFirst()) : value
            guard !unsigned.isEmpty, unsigned.count <= 32 else { throw AgentProtocolError.malformed }
            return Data(repeating: 0, count: 32 - unsigned.count) + unsigned
        }
        let firstCoordinate = try integer()
        let secondCoordinate = try integer()
        guard index == der.count else { throw AgentProtocolError.malformed }
        return firstCoordinate + secondCoordinate
    }

    private static func mpint(_ bytes: Data.SubSequence) -> Data {
        let trimmed = bytes.drop { $0 == 0 }; let value = trimmed.isEmpty ? Data([0]) : Data(trimmed)
        return value.first! & 0x80 == 0 ? value : Data([0]) + value
    }
}
