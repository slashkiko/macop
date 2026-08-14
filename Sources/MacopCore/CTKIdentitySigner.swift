import Foundation
import LocalAuthentication
import Security

/// A non-exporting signer for one, already selected CryptoTokenKit identity.
/// `applicationLabel` is the authoritative public-key hash from `sc_auth`; the
/// matching public SSH blob is checked again so a broad Keychain query cannot
/// silently select another identity.
public struct CTKIdentitySigner: AgentKeySigning, @unchecked Sendable {
    public let publicKeyBlob: Data
    public let fingerprint: String
    private let privateKey: SecKey

    public init(
        applicationLabel: Data,
        expectedPublicKeyBlob: Data,
        authenticationContext: LAContext? = nil
    ) throws {
        guard !applicationLabel.isEmpty else { throw AgentProtocolError.denied }
        var query: [CFString: Any] = [
            kSecClass: kSecClassIdentity,
            kSecAttrApplicationLabel: applicationLabel,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnRef: true
        ]
        if let authenticationContext {
            query[kSecUseAuthenticationContext] = authenticationContext
        }
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let identities = result as? [SecIdentity], identities.count == 1 else { throw AgentProtocolError.denied }
        var certificate: SecCertificate?; guard SecIdentityCopyCertificate(identities[0], &certificate) ==
            errSecSuccess,
            let certificate,
            let key = SecCertificateCopyKey(certificate)
        else { throw AgentProtocolError.denied }
        guard try Self.publicBlob(for: key) == expectedPublicKeyBlob else { throw AgentProtocolError.denied }
        var privateKey: SecKey?; guard SecIdentityCopyPrivateKey(identities[0], &privateKey) == errSecSuccess,
                                       let privateKey else { throw AgentProtocolError.denied }
        self.publicKeyBlob = expectedPublicKeyBlob
        self.fingerprint = sshFingerprint(for: expectedPublicKeyBlob)
        self.privateKey = privateKey
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
        guard SecKeyGetBlockSize(publicKey) == 32 else { throw AgentProtocolError.unsupported }
        var error: Unmanaged<CFError>?
        guard let point = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?, point.count == 65,
              point.first == 4 else { throw AgentProtocolError.denied }
        return try SSHWire.string("ecdsa-sha2-nistp256") + SSHWire.string("nistp256") + SSHWire.string(point)
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
