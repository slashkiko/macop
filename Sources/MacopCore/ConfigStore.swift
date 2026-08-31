// swiftlint:disable file_length
import Darwin
import Foundation

public enum ConfigProviderKind: Sendable {
    case keychainGeneric
    case keychainInternet
    case keychainManaged
    case secureEnclave
}

public struct ConfigItem: Codable, Sendable {
    public let provider: String
    public let service: String?
    public let account: String?
    public let server: String?
    public let label: String?
    public let fields: [String]?
    public let synchronization: String?
    public let otp: ConfigOTP?
    public var schemaVersion: Int = 1

    enum CodingKeys: String, CodingKey {
        case provider, service, account, server, label, fields, synchronization, otp
    }

    public var managedKeychainSynchronizable: Bool {
        self.provider == "keychain-managed" && self.synchronization == "icloud"
    }
}

public struct ConfigOTP: Codable, Sendable {
    public let service: String
    public let account: String
    public let algorithm: String
    public let digits: Int
    public let period: Int
    public let synchronization: String?
    public let label: String?
    public let issuer: String?

    public var synchronizable: Bool {
        self.synchronization == "icloud"
    }
}

public struct CredentialProfile: Codable, Sendable {
    public let executable: String
    public let environment: [String: String]
}

public struct SSHHostProfile: Codable, Sendable {
    public let hostname: String
    public let user: String?
    public let port: Int?
    public let identity: String
}

public struct ConfigDocument: Codable, Sendable {
    public let version: Int
    public var items: [String: ConfigItem]
    public let profiles: [String: CredentialProfile]?
    public let sshHosts: [String: SSHHostProfile]?

    enum CodingKeys: String, CodingKey {
        case version, items, profiles
        case sshHosts = "ssh_hosts"
    }
}

// The schema and duplicate-key scanner intentionally remain colocated with config I/O.
// swiftlint:disable:next type_body_length
public enum ConfigStore {
    public static func configFilePath(configDirectory: String?) throws -> URL {
        let directoryURL: URL
        if let configDirectory, !configDirectory.isEmpty {
            directoryURL = URL(fileURLWithPath: configDirectory, isDirectory: true)
        } else {
            let homeDirectory = FileManager.default.homeDirectoryForCurrentUser
            directoryURL = homeDirectory
                .appendingPathComponent("Library", isDirectory: true)
                .appendingPathComponent("Application Support", isDirectory: true)
                .appendingPathComponent("macop", isDirectory: true)
        }
        return directoryURL.appendingPathComponent("config.json", isDirectory: false)
    }

    public static func initialize(configDirectory: String?) throws -> URL {
        try self.initialize(configDirectory: configDirectory, fsyncOperation: Darwin.fsync)
    }

    static func initialize(
        configDirectory: String?,
        fsyncOperation: (Int32) -> Int32
    ) throws -> URL {
        let fileURL = try configFilePath(configDirectory: configDirectory)
        let directoryURL = fileURL.deletingLastPathComponent()
        let fileManager = FileManager.default
        let directoryExisted = fileManager.fileExists(atPath: directoryURL.path)

        try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directoryURL.path)
        if !directoryExisted {
            try self.syncDirectory(
                at: directoryURL.deletingLastPathComponent(), fsyncOperation: fsyncOperation
            )
        }

        if fileManager.fileExists(atPath: fileURL.path) {
            throw CLIError.invalidArguments(message: "Config already exists at \(fileURL.path)")
        }

        let document = ConfigDocument(version: 2, items: [:], profiles: nil, sshHosts: nil)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        var data = try encoder.encode(document)
        data.append(contentsOf: Data("\n".utf8))
        try self.writeNewConfig(data, to: fileURL, fsyncOperation: fsyncOperation)
        return fileURL
    }

    static func writeNewConfig(
        _ data: Data,
        to fileURL: URL,
        fsyncOperation: (Int32) -> Int32 = Darwin.fsync
    ) throws {
        let temporaryURL = fileURL.deletingLastPathComponent()
            .appendingPathComponent(".config-\(UUID().uuidString).tmp")
        let descriptor = open(
            temporaryURL.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer {
            close(descriptor)
            unlink(temporaryURL.path)
        }
        guard fchmod(descriptor, S_IRUSR | S_IWUSR) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { buffer in
                write(descriptor, buffer.baseAddress!.advanced(by: offset), data.count - offset)
            }
            if count < 0, errno == EINTR {
                continue
            }
            guard count > 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
            offset += count
        }
        guard fsyncOperation(descriptor) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        guard renameatx_np(
            AT_FDCWD,
            temporaryURL.path,
            AT_FDCWD,
            fileURL.path,
            UInt32(RENAME_EXCL)
        ) == 0 else {
            if errno == EEXIST {
                throw CLIError.invalidArguments(message: "Config already exists at \(fileURL.path)")
            }
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        try self.syncDirectory(
            at: fileURL.deletingLastPathComponent(), fsyncOperation: fsyncOperation
        )
    }

    private static func syncDirectory(
        at directoryURL: URL,
        fsyncOperation: (Int32) -> Int32
    ) throws {
        let directoryDescriptor = open(
            directoryURL.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        )
        guard directoryDescriptor >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { close(directoryDescriptor) }
        guard fsyncOperation(directoryDescriptor) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
    }

    public static func load(configDirectory: String?) throws -> ConfigDocument {
        let fileURL = try configFilePath(configDirectory: configDirectory)
        let data: Data
        do {
            data = try ConfigFilesystemValidator.readValidated(fileURL: fileURL)
        } catch let error as CLIError {
            throw error
        } catch let error as NSError {
            if error.domain == NSCocoaErrorDomain, error.code == NSFileReadNoSuchFileError {
                throw CLIError.notFound(message: "Config file not found at \(fileURL.path)")
            }
            if error.domain == NSCocoaErrorDomain, error.code == NSFileReadNoPermissionError {
                throw CLIError.denied(message: "Cannot read config file at \(fileURL.path)")
            }
            if error.domain == NSPOSIXErrorDomain, error.code == EACCES {
                throw CLIError.denied(message: "Cannot read config file at \(fileURL.path)")
            }
            throw CLIError.providerUnavailable(
                provider: "config",
                reason: "Failed to read config file at \(fileURL.path): \(error.localizedDescription)"
            )
        } catch {
            throw CLIError.providerUnavailable(
                provider: "config",
                reason: "Failed to read config file at \(fileURL.path): \(error.localizedDescription)"
            )
        }
        try self.validateJSONSchema(data: data)
        let decoder = JSONDecoder()
        do {
            var document = try decoder.decode(ConfigDocument.self, from: data)
            for key in document.items.keys {
                document.items[key]?.schemaVersion = document.version
            }
            try self.validateDocument(document)
            return document
        } catch let error as CLIError {
            throw error
        } catch {
            throw CLIError.invalidArguments(message: "Config file is not valid JSON schema.")
        }
    }

    public static func validate(configDirectory: String?) throws -> URL {
        let fileURL = try configFilePath(configDirectory: configDirectory)
        _ = try self.load(configDirectory: configDirectory)
        return fileURL
    }

    public static func resolveItem(namespace: String, item: String, configDirectory: String?) throws -> ConfigItem {
        let document = try load(configDirectory: configDirectory)
        let key = "\(namespace)/\(item)"
        guard let configItem = document.items[key] else {
            throw CLIError.notFound(message: "No config entry matches the requested reference.")
        }
        _ = try self.providerKind(for: configItem)
        return configItem
    }

    public static func items(configDirectory: String?) throws -> [String: ConfigItem] {
        try self.load(configDirectory: configDirectory).items
    }

    public static func providerKind(for item: ConfigItem) throws -> ConfigProviderKind {
        try self.validateItem(item)
    }

    private static func validateItemKey(_ key: String) throws {
        // Keep empty components: String.split's default would turn `Local//GitHub`
        // into a seemingly-valid two component selector.
        let parts = key.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2 else {
            throw CLIError.invalidArguments(message: "Config item key must be \"<namespace>/<item>\": \(key)")
        }
        try self.validateMappingSegment(String(parts[0]), role: "namespace")
        try self.validateMappingSegment(String(parts[1]), role: "item")
    }

    private static func validateItem(_ item: ConfigItem) throws -> ConfigProviderKind {
        try self.validateFields(item.fields)
        if let otp = item.otp {
            try ConfigSchemaValidator.validateOTP(otp)
        }
        switch item.provider {
        case "keychain-generic":
            guard self.hasSelectorValue(item.service, schemaVersion: item.schemaVersion),
                  self.hasSelectorValue(item.account, schemaVersion: item.schemaVersion)
            else {
                throw CLIError.invalidArguments(
                    message: "keychain-generic requires service and account in config item."
                )
            }
            guard item.server == nil, item.label == nil, item.synchronization == nil else {
                throw CLIError
                    .invalidArguments(message: "keychain-generic does not allow server or label in config item.")
            }
            return .keychainGeneric
        case "keychain-internet":
            guard self.hasSelectorValue(item.server, schemaVersion: item.schemaVersion),
                  self.hasSelectorValue(item.account, schemaVersion: item.schemaVersion)
            else {
                throw CLIError.invalidArguments(
                    message: "keychain-internet requires server and account in config item."
                )
            }
            guard item.service == nil, item.label == nil, item.synchronization == nil else {
                throw CLIError
                    .invalidArguments(message: "keychain-internet does not allow service or label in config item.")
            }
            return .keychainInternet
        case "keychain-managed":
            guard let service = item.service,
                  let account = item.account,
                  ConfigSchemaValidator.validSelectorMetadata(service),
                  ConfigSchemaValidator.validSelectorMetadata(account)
            else {
                throw CLIError.invalidArguments(
                    message: "keychain-managed requires service and account in config item."
                )
            }
            guard item.server == nil, item.label == nil else {
                throw CLIError.invalidArguments(
                    message: "keychain-managed does not allow server or label in config item."
                )
            }
            guard item.synchronization == nil || item.synchronization == "local"
                || item.synchronization == "icloud"
            else {
                throw CLIError.invalidArguments(
                    message: "keychain-managed synchronization must be local or icloud."
                )
            }
            return .keychainManaged
        case "secure-enclave":
            guard let label = item.label else {
                throw CLIError.invalidArguments(message: "secure-enclave requires label in config item.")
            }
            try SSHIdentityLabelValidator.validate(label)
            guard item.service == nil, item.account == nil, item.server == nil, item.fields == nil,
                  item.synchronization == nil, item.otp == nil
            else {
                throw CLIError.invalidArguments(message: "secure-enclave config items only allow provider and label.")
            }
            return .secureEnclave
        default:
            throw CLIError.unsupportedProvider(
                provider: item.provider,
                reason: "Provider is not supported by this build."
            )
        }
    }

    private static func hasValue(_ value: String?) -> Bool {
        guard let value else { return false }
        return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !value.contains("\0")
    }

    private static func hasSelectorValue(_ value: String?, schemaVersion: Int) -> Bool {
        guard let value else { return false }
        return schemaVersion == 1
            ? self.hasValue(value)
            : ConfigSchemaValidator.validSelectorMetadata(value)
    }

    private static func validateDocument(_ document: ConfigDocument) throws {
        guard document.version == 1 || document.version == 2 else {
            throw CLIError.invalidArguments(message: "Unsupported config version: \(document.version)")
        }
        for (itemKey, item) in document.items {
            try self.validateItemKey(itemKey)
            _ = try self.validateItem(item)
        }
        for (name, profile) in document.profiles ?? [:] {
            try self.validateMappingSegment(name, role: "profile name")
            try ConfigSchemaValidator.validate(profile: profile)
        }
        for (alias, host) in document.sshHosts ?? [:] {
            try self.validateMappingSegment(alias, role: "SSH host alias")
            try ConfigSchemaValidator.validate(host: host)
        }
        try self.validateOTPSelectorSeparation(document)
    }

    private static func validateFields(_ fields: [String]?) throws {
        guard let fields else { return }
        var seen = Set<String>()
        for field in fields {
            let segments = field.split(separator: "/", omittingEmptySubsequences: false)
            guard segments.count == 1 || segments.count == 2 else {
                throw CLIError.invalidArguments(
                    message: "Config fields must be \"<field>\" or \"<section>/<field>\"."
                )
            }
            for segment in segments {
                try self.validateMappingSegment(String(segment), role: "field")
            }
            guard seen.insert(field).inserted else {
                throw CLIError.invalidArguments(message: "Config fields must not contain duplicates: \(field)")
            }
        }
    }

    /// Config keys are the decoded, static counterparts of `op://` path
    /// segments. Literal `%` and `$` are valid decoded selector characters;
    /// percent-decoding and `$NAME` expansion happen only in ReferenceResolver
    /// while it processes the reference input.
    private static func validateMappingSegment(_ value: String, role: String) throws {
        guard self.hasValue(value) else {
            throw CLIError.invalidArguments(message: "Config \(role) must be a non-empty path segment.")
        }
    }

    private static func validateJSONSchema(data: Data) throws {
        guard !StrictJSONDuplicateKeyScanner.containsDuplicateObjectKey(in: data) else {
            throw CLIError.invalidArguments(message: "Config file must not contain duplicate keys.")
        }
        let rootObject: Any
        do {
            rootObject = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw CLIError.invalidArguments(message: "Config file is not valid JSON schema.")
        }
        guard let root = rootObject as? [String: Any],
              Set(root.keys).isSubset(of: Set(["version", "items", "profiles", "ssh_hosts"])),
              root["version"] != nil, root["items"] != nil,
              let version = root["version"] as? Int,
              let items = root["items"] as? [String: Any]
        else {
            throw CLIError.invalidArguments(message: "Config file is not valid JSON schema.")
        }
        guard version == 1 || version == 2 else {
            throw CLIError.invalidArguments(message: "Unsupported config version: \(root["version"] ?? "unknown")")
        }
        if version == 1, root["profiles"] != nil || root["ssh_hosts"] != nil {
            throw CLIError.invalidArguments(message: "Config profiles and ssh_hosts require version 2.")
        }
        for (key, value) in items {
            try self.validateItemKey(key)
            guard let item = value as? [String: Any], let provider = item["provider"] as? String else {
                throw CLIError.invalidArguments(message: "Config item \"\(key)\" must be an object with a provider.")
            }
            let allowed: Set<String> = switch provider {
            case "keychain-generic": version == 2
                ? ["provider", "service", "account", "fields", "otp"]
                : ["provider", "service", "account", "fields"]
            case "keychain-managed": version == 2
                ? ["provider", "service", "account", "fields", "synchronization", "otp"]
                : ["provider", "service", "account", "fields", "synchronization"]
            case "keychain-internet": version == 2
                ? ["provider", "server", "account", "fields", "otp"]
                : ["provider", "server", "account", "fields"]
            case "secure-enclave": ["provider", "label"]
            default: ["provider"]
            }
            guard Set(item.keys).isSubset(of: allowed) else {
                throw CLIError
                    .invalidArguments(message: "Config item \"\(key)\" contains an unknown or secret-looking key.")
            }
            for name in ["service", "account", "server", "label", "synchronization"] where item[name] != nil {
                guard item[name] is String else {
                    throw CLIError
                        .invalidArguments(message: "Config item \"\(key)\" field \"\(name)\" must be a string.")
                }
            }
            if let fields = item["fields"] {
                guard let values = fields as? [String] else {
                    throw CLIError
                        .invalidArguments(message: "Config item \"\(key)\" fields must be an array of strings.")
                }
                try self.validateFields(values)
            }
            if let otp = item["otp"] {
                try ConfigSchemaValidator.validateOTPJSONObject(otp, itemKey: key)
            }
        }
        try ConfigSchemaValidator.validateProfilesJSONObject(root["profiles"])
        try ConfigSchemaValidator.validateSSHHostsJSONObject(root["ssh_hosts"])
    }

    private struct ManagedSelector: Hashable {
        let service: String
        let account: String
        let synchronizable: Bool
    }

    private static func validateOTPSelectorSeparation(_ document: ConfigDocument) throws {
        guard document.version == 2 else { return }
        var passwordSelectors = Set<ManagedSelector>()
        for item in document.items.values where item.provider == "keychain-managed" {
            guard let service = item.service, let account = item.account else { continue }
            passwordSelectors.insert(ManagedSelector(
                service: service, account: account, synchronizable: item.managedKeychainSynchronizable
            ))
        }
        var otpSelectors = Set<ManagedSelector>()
        for item in document.items.values {
            guard let otp = item.otp else { continue }
            let selector = ManagedSelector(
                service: otp.service, account: otp.account, synchronizable: otp.synchronizable
            )
            guard !passwordSelectors.contains(selector), otpSelectors.insert(selector).inserted else {
                throw CLIError.invalidArguments(
                    message: "Every OTP seed must use a unique managed Keychain selector distinct from passwords."
                )
            }
        }
    }
}
