import Foundation
import Security

public enum CredentialFieldResolver {
    public static func read(
        item: ConfigItem,
        section: String?,
        field: String,
        client: any KeychainClient,
        otpClient: any KeychainClient = CompanionManagedKeychainClient(),
        now: Date = Date()
    ) throws -> String {
        let requested = section.map { "\($0)/\(field)" } ?? field
        if item.schemaVersion == 1 {
            if let fields = item.fields, !fields.isEmpty, !fields.contains(requested) {
                throw CLIError.notFound(message: "Field is not configured for this item.")
            }
            return try KeychainProvider.readText(Self.passwordQuery(for: item), client: client)
        }
        let deniedByFieldList = !Self.isWellKnown(section: section, field: field)
            && !(item.fields?.contains(requested) ?? false)
        if deniedByFieldList {
            throw CLIError.notFound(message: "Field is not configured for this item.")
        }
        guard section == nil else {
            return try KeychainProvider.readText(Self.passwordQuery(for: item), client: client)
        }
        switch field.lowercased() {
        case "username":
            guard let account = item.account, !account.isEmpty else {
                throw CLIError.notFound(message: "This item has no username metadata.")
            }
            return account
        case "password", "token":
            return try KeychainProvider.readText(Self.passwordQuery(for: item), client: client)
        case "otp":
            return try Self.otp(item: item, client: otpClient, now: now)
        default:
            return try KeychainProvider.readText(Self.passwordQuery(for: item), client: client)
        }
    }

    public static func otp(item: ConfigItem, client: any KeychainClient, now: Date = Date()) throws -> String {
        guard item.schemaVersion == 2, let otp = item.otp else {
            throw CLIError.notFound(message: "OTP is not configured for this item.")
        }
        var seed: Data
        switch client.read(.managed(
            service: otp.service,
            account: otp.account,
            synchronizable: otp.synchronizable
        )) {
        case let .success(value): seed = value
        case let .failure(failure): throw Self.map(failure)
        }
        defer { seed.resetBytes(in: seed.startIndex ..< seed.endIndex) }
        return try TOTPGenerator.code(
            seed: seed,
            algorithm: otp.algorithm,
            digits: otp.digits,
            period: otp.period,
            date: now
        )
    }

    public static func passwordQuery(for item: ConfigItem) throws -> KeychainQuery {
        if item.provider == "keychain-generic", let service = item.service, let account = item.account {
            return .generic(service: service, account: account)
        }
        if item.provider == "keychain-internet", let server = item.server, let account = item.account {
            return .internet(server: server, account: account)
        }
        if item.provider == "keychain-managed", let service = item.service, let account = item.account {
            return .managed(service: service, account: account, synchronizable: item.managedKeychainSynchronizable)
        }
        throw CLIError.unsupportedProvider(provider: item.provider, reason: "This provider has no password field.")
    }

    private static func isWellKnown(section: String?, field: String) -> Bool {
        section == nil && ["username", "password", "token", "otp"].contains(field.lowercased())
    }

    private static func map(_ failure: KeychainFailure) -> CLIError {
        if failure.isAmbiguous {
            return .invalidArguments(message: "OTP seed selector is ambiguous.")
        }
        return switch failure.status {
        case errSecItemNotFound: .notFound(message: "OTP seed was not found.")
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
            .denied(message: "OTP access was denied or cancelled.")
        case errSecNotAvailable: .providerUnavailable(provider: "keychain", reason: "Keychain is unavailable.")
        default: .runtimeError(message: "OTP Keychain read failed (OSStatus \(failure.status)).")
        }
    }
}
