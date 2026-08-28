import CryptoKit
import Foundation

public struct ParsedTOTPSeed: Sendable {
    public let seed: Data
    public let algorithm: String
    public let digits: Int
    public let period: Int
    public let label: String?
    public let issuer: String?
}

public enum TOTPGenerator {
    public static func parse(_ input: String) throws -> ParsedTOTPSeed {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("otpauth://") {
            return try Self.parseURI(trimmed)
        }
        return try ParsedTOTPSeed(
            seed: Self.decodeBase32(trimmed), algorithm: "SHA1", digits: 6, period: 30,
            label: nil, issuer: nil
        )
    }

    public static func code(
        seed: Data,
        algorithm: String,
        digits: Int,
        period: Int,
        date: Date
    ) throws -> String {
        guard !seed.isEmpty, [6, 7, 8].contains(digits), (15 ... 120).contains(period),
              date.timeIntervalSince1970 >= 0
        else { throw CLIError.invalidArguments(message: "OTP parameters are invalid.") }
        let counter = UInt64(floor(date.timeIntervalSince1970 / Double(period)))
        var bigEndian = counter.bigEndian
        let message = withUnsafeBytes(of: &bigEndian) { Data($0) }
        let key = SymmetricKey(data: seed)
        let digest: Data = switch algorithm.uppercased() {
        case "SHA1": Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case "SHA256": Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case "SHA512": Data(HMAC<SHA512>.authenticationCode(for: message, using: key))
        default: throw CLIError.invalidArguments(message: "OTP algorithm must be SHA1, SHA256, or SHA512.")
        }
        let offset = Int(digest.last! & 0x0F)
        guard offset + 4 <= digest.count else { throw CLIError.runtimeError(message: "OTP calculation failed.") }
        let value = (UInt32(digest[offset] & 0x7F) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        let modulus = UInt32(pow(10.0, Double(digits)))
        return String(format: "%0*u", digits, value % modulus)
    }

    public static func decodeBase32(_ raw: String) throws -> Data {
        let canonicalRemainders = Set([0, 2, 4, 5, 7])
        let rawBytes = Array(raw.utf8)
        guard !rawBytes.isEmpty, canonicalRemainders.contains(rawBytes.count % 8),
              rawBytes.allSatisfy({
                  (65 ... 90).contains($0) || (97 ... 122).contains($0) || (50 ... 55).contains($0)
              })
        else {
            throw CLIError.invalidArguments(message: "OTP seed must be unpadded RFC 4648 Base32.")
        }
        // Normalize only after proving every source byte is ASCII. Unicode
        // case folding must never turn a non-ASCII scalar into a Base32 letter.
        let value = raw.uppercased()
        var accumulator = 0
        var bits = 0
        var output = Data()
        for byte in value.utf8 {
            let digit = byte >= 65 ? Int(byte - 65) : Int(byte - 50 + 26)
            accumulator = (accumulator << 5) | digit
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((accumulator >> bits) & 0xFF))
                accumulator &= (1 << bits) - 1
            }
        }
        guard !output.isEmpty, bits == 0 || accumulator == 0 else {
            throw CLIError.invalidArguments(message: "OTP seed has non-zero trailing Base32 bits.")
        }
        return output
    }

    private static func parseURI(_ value: String) throws -> ParsedTOTPSeed {
        guard let delimiter = value.range(of: "://"),
              value[..<delimiter.lowerBound].utf8.allSatisfy({ $0 < 0x80 }),
              value[..<delimiter.lowerBound].lowercased() == "otpauth"
        else { throw CLIError.invalidArguments(message: "Only otpauth://totp URIs are accepted.") }
        let authorityStart = delimiter.upperBound
        guard let pathStart = value[authorityStart...].firstIndex(of: "/"),
              value[authorityStart ..< pathStart].utf8.elementsEqual("totp".utf8)
        else { throw CLIError.invalidArguments(message: "Only otpauth://totp URIs are accepted.") }
        guard let components = URLComponents(string: value), components.scheme?.lowercased() == "otpauth",
              components.host == "totp", components.port == nil,
              components.fragment == nil, components.user == nil, components.password == nil
        else { throw CLIError.invalidArguments(message: "Only otpauth://totp URIs are accepted.") }
        let allowed = Set(["secret", "algorithm", "digits", "period", "issuer"])
        var query = [String: String]()
        for item in components.queryItems ?? [] {
            guard allowed.contains(item.name), let itemValue = item.value, query[item.name] == nil else {
                throw CLIError.invalidArguments(message: "OTP URI contains an unknown or duplicate parameter.")
            }
            query[item.name] = itemValue
        }
        guard let secret = query["secret"] else {
            throw CLIError.invalidArguments(message: "OTP URI requires a secret parameter.")
        }
        let pathParts = components.path.split(separator: "/", omittingEmptySubsequences: false)
        guard pathParts.count == 2, pathParts[0].isEmpty, !pathParts[1].isEmpty else {
            throw CLIError.invalidArguments(message: "OTP URI requires exactly one non-empty label path segment.")
        }
        let label = String(pathParts[1])
        let separatorCount = label.unicodeScalars.lazy.filter { $0.value == 0x3A }.count
        guard Self.validMetadata(label), separatorCount <= 1 else {
            throw CLIError.invalidArguments(message: "OTP URI requires a non-empty printable label.")
        }
        let labelScalars = label.unicodeScalars
        let scalarSeparator = labelScalars.firstIndex { $0.value == 0x3A }
        let labelIssuer = scalarSeparator.map { String(labelScalars[..<$0]) }
        let labelAccount = scalarSeparator.map {
            String(labelScalars[labelScalars.index(after: $0)...])
        } ?? label
        guard Self.validMetadata(labelAccount), labelIssuer == nil || Self.validMetadata(labelIssuer!) else {
            throw CLIError.invalidArguments(message: "OTP URI label is invalid.")
        }
        let issuer = query["issuer"]
        guard issuer == nil || Self.validMetadata(issuer!),
              issuer == nil || labelIssuer == nil || issuer == labelIssuer
        else { throw CLIError.invalidArguments(message: "OTP URI issuer does not match its label.") }
        let algorithm = (query["algorithm"] ?? "SHA1").uppercased()
        guard let digits = Int(query["digits"] ?? "6"), let period = Int(query["period"] ?? "30") else {
            throw CLIError.invalidArguments(message: "OTP URI digits and period must be integers.")
        }
        let parsed = try ParsedTOTPSeed(
            seed: Self.decodeBase32(secret),
            algorithm: algorithm,
            digits: digits,
            period: period,
            label: label,
            issuer: issuer
        )
        _ = try Self.code(
            seed: parsed.seed,
            algorithm: algorithm,
            digits: digits,
            period: period,
            date: Date(timeIntervalSince1970: 0)
        )
        return parsed
    }

    private static func validMetadata(_ value: String) -> Bool {
        !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && value.utf8.count <= AuthBrokerWire.maximumMetadataLength
            && value.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0) && !CharacterSet.newlines.contains($0)
                    && !$0.properties.isBidiControl && $0.value != 0x1B
            }
    }
}
