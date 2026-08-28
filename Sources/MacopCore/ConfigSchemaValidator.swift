import Foundation

enum ConfigSchemaValidator {
    private static let segmentPattern = #"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"#
    private static let environmentPattern = #"^[A-Za-z_][A-Za-z0-9_]*$"#

    static func validate(profile: CredentialProfile) throws {
        guard profile.executable.hasPrefix("/"),
              !profile.executable.contains("\0"),
              URL(fileURLWithPath: profile.executable).standardizedFileURL.path == profile.executable
        else { throw CLIError.invalidArguments(message: "Profile executable must be a canonical absolute path.") }
        guard !profile.environment.isEmpty else {
            throw CLIError.invalidArguments(message: "Profile environment must not be empty.")
        }
        for (key, reference) in profile.environment {
            guard key.range(of: self.environmentPattern, options: .regularExpression) != nil else {
                throw CLIError.invalidArguments(message: "Profile environment contains an invalid variable name.")
            }
            guard self.isStaticReference(reference) else {
                throw CLIError.invalidArguments(message: "Profile environment values must be static secret references.")
            }
        }
    }

    static func validate(host: SSHHostProfile) throws {
        guard self.validSegment(host.hostname) else {
            throw CLIError.invalidArguments(message: "SSH host hostname must be a safe non-empty value.")
        }
        try SSHIdentityLabelValidator.validate(host.identity)
        if let user = host.user, !Self.validSegment(user) {
            throw CLIError.invalidArguments(message: "SSH host user is invalid.")
        }
        if let port = host.port, !(1 ... 65535).contains(port) {
            throw CLIError.invalidArguments(message: "SSH host port must be between 1 and 65535.")
        }
    }

    static func validateOTP(_ otp: ConfigOTP) throws {
        guard self.validSelectorMetadata(otp.service), self.validSelectorMetadata(otp.account),
              ["SHA1", "SHA256", "SHA512"].contains(otp.algorithm.uppercased()),
              [6, 7, 8].contains(otp.digits),
              (15 ... 120).contains(otp.period),
              otp.synchronization == nil || otp.synchronization == "local" || otp.synchronization == "icloud",
              otp.label == nil || self.validDisplayMetadata(otp.label!),
              otp.issuer == nil || self.validDisplayMetadata(otp.issuer!)
        else { throw CLIError.invalidArguments(message: "OTP configuration is invalid.") }
    }

    static func validateOTPJSONObject(_ raw: Any, itemKey: String) throws {
        guard let object = raw as? [String: Any],
              Set(object.keys).isSubset(of: [
                  "service", "account", "algorithm", "digits", "period", "synchronization", "label", "issuer"
              ]),
              let service = object["service"] as? String,
              let account = object["account"] as? String,
              let algorithm = object["algorithm"] as? String,
              let digits = object["digits"] as? Int,
              let period = object["period"] as? Int,
              object["synchronization"] == nil || object["synchronization"] is String,
              object["label"] == nil || object["label"] is String,
              object["issuer"] == nil || object["issuer"] is String
        else { throw CLIError.invalidArguments(message: "Config item \"\(itemKey)\" OTP schema is invalid.") }
        try Self.validateOTP(ConfigOTP(
            service: service, account: account, algorithm: algorithm, digits: digits, period: period,
            synchronization: object["synchronization"] as? String,
            label: object["label"] as? String,
            issuer: object["issuer"] as? String
        ))
    }

    static func validateProfilesJSONObject(_ raw: Any?) throws {
        guard let raw else { return }
        guard let profiles = raw as? [String: Any] else {
            throw CLIError.invalidArguments(message: "Config profiles must be an object.")
        }
        for (name, value) in profiles {
            guard Self.validSegment(name), let object = value as? [String: Any],
                  Set(object.keys) == Set(["executable", "environment"]),
                  let executable = object["executable"] as? String,
                  let environment = object["environment"] as? [String: String]
            else { throw CLIError.invalidArguments(message: "Credential profile schema is invalid.") }
            try Self.validate(profile: CredentialProfile(executable: executable, environment: environment))
        }
    }

    static func validateSSHHostsJSONObject(_ raw: Any?) throws {
        guard let raw else { return }
        guard let hosts = raw as? [String: Any] else {
            throw CLIError.invalidArguments(message: "Config ssh_hosts must be an object.")
        }
        for (alias, value) in hosts {
            guard Self.validSegment(alias), let object = value as? [String: Any],
                  Set(object.keys).isSubset(of: ["hostname", "user", "port", "identity"]),
                  let hostname = object["hostname"] as? String,
                  let identity = object["identity"] as? String,
                  object["user"] == nil || object["user"] is String,
                  object["port"] == nil || object["port"] is Int
            else { throw CLIError.invalidArguments(message: "SSH host profile schema is invalid.") }
            try Self.validate(host: SSHHostProfile(
                hostname: hostname, user: object["user"] as? String,
                port: object["port"] as? Int, identity: identity
            ))
        }
    }

    private static func validSegment(_ value: String) -> Bool {
        value.range(of: self.segmentPattern, options: .regularExpression) != nil && !value.contains("\0")
    }

    private static func validMetadata(_ value: String) -> Bool {
        !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && value.utf8.count <= AuthBrokerWire.maximumMetadataLength
            && !value.contains("\0")
    }

    static func validSelectorMetadata(_ value: String) -> Bool {
        ManagedKeychainStore.validSelector(value)
    }

    private static func validDisplayMetadata(_ value: String) -> Bool {
        self.validMetadata(value) && value.unicodeScalars.allSatisfy {
            !CharacterSet.controlCharacters.contains($0) && !CharacterSet.newlines.contains($0)
                && !$0.properties.isBidiControl && $0.value != 0x1B
        }
    }

    private static func isStaticReference(_ value: String) -> Bool {
        guard !value.contains("$"), let parsed = try? ReferenceResolver.parse(value, env: [:]) else { return false }
        return switch parsed {
        case .opReference, .opOTP, .keychainGeneric, .keychainInternet: true
        case .secureEnclave: false
        }
    }
}
