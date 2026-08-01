import Foundation

public enum ConfigProviderKind: Sendable {
    case keychainGeneric
    case keychainInternet
    case secureEnclave
}

public struct ConfigItem: Codable, Sendable {
    public let provider: String
    public let service: String?
    public let account: String?
    public let server: String?
    public let label: String?
    public let fields: [String]?
}

public struct ConfigDocument: Codable, Sendable {
    public let version: Int
    public let items: [String: ConfigItem]
}

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
        let fileURL = try configFilePath(configDirectory: configDirectory)
        let directoryURL = fileURL.deletingLastPathComponent()
        let fileManager = FileManager.default

        try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directoryURL.path)

        if fileManager.fileExists(atPath: fileURL.path) {
            throw CLIError.invalidArguments(message: "Config already exists at \(fileURL.path)")
        }

        let document = ConfigDocument(version: 1, items: [:])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        var data = try encoder.encode(document)
        data.append(contentsOf: Data("\n".utf8))
        try data.write(to: fileURL, options: [.atomic])
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        return fileURL
    }

    public static func load(configDirectory: String?) throws -> ConfigDocument {
        let fileURL = try configFilePath(configDirectory: configDirectory)
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
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
        let decoder = JSONDecoder()
        do {
            return try decoder.decode(ConfigDocument.self, from: data)
        } catch {
            throw CLIError.invalidArguments(message: "Config file is not valid JSON schema.")
        }
    }

    public static func validate(configDirectory: String?) throws -> URL {
        let fileURL = try configFilePath(configDirectory: configDirectory)
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: fileURL.path) else {
            throw CLIError.notFound(message: "Config file not found at \(fileURL.path)")
        }

        let document = try load(configDirectory: configDirectory)
        guard document.version == 1 else {
            throw CLIError.invalidArguments(message: "Unsupported config version: \(document.version)")
        }

        guard let permissions = try fileManager.attributesOfItem(atPath: fileURL.path)[.posixPermissions] as? NSNumber
        else {
            throw CLIError.invalidArguments(message: "Unable to read config permissions.")
        }

        let mode = permissions.uint16Value
        if mode & 0o077 != 0 {
            throw CLIError.invalidArguments(
                message: "Config permissions must be owner-only (0600). Current mode: \(String(format: "%04o", mode))"
            )
        }

        for (itemKey, item) in document.items {
            try self.validateItemKey(itemKey)
            _ = try self.validateItem(item)
        }

        return fileURL
    }

    public static func resolveItem(namespace: String, item: String, configDirectory: String?) throws -> ConfigItem {
        let document = try load(configDirectory: configDirectory)
        let key = "\(namespace)/\(item)"
        guard let configItem = document.items[key] else {
            throw CLIError.notFound(message: "No config entry for \"\(key)\"")
        }
        _ = try self.providerKind(for: configItem)
        return configItem
    }

    public static func providerKind(for item: ConfigItem) throws -> ConfigProviderKind {
        try self.validateItem(item)
    }

    private static func validateItemKey(_ key: String) throws {
        let parts = key.split(separator: "/")
        guard parts.count == 2 else {
            throw CLIError.invalidArguments(message: "Config item key must be \"<namespace>/<item>\": \(key)")
        }
        if parts[0].isEmpty || parts[1].isEmpty {
            throw CLIError.invalidArguments(message: "Config item key has empty namespace/item: \(key)")
        }
    }

    private static func validateItem(_ item: ConfigItem) throws -> ConfigProviderKind {
        switch item.provider {
        case "keychain-generic":
            guard self.hasValue(item.service), self.hasValue(item.account) else {
                throw CLIError.invalidArguments(
                    message: "keychain-generic requires service and account in config item."
                )
            }
            return .keychainGeneric
        case "keychain-internet":
            guard self.hasValue(item.server), self.hasValue(item.account) else {
                throw CLIError.invalidArguments(
                    message: "keychain-internet requires server and account in config item."
                )
            }
            return .keychainInternet
        case "secure-enclave":
            guard self.hasValue(item.label) else {
                throw CLIError.invalidArguments(message: "secure-enclave requires label in config item.")
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
        return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
