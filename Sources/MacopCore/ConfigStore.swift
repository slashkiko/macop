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
}

public struct ConfigDocument: Codable, Sendable {
    public let version: Int
    public let items: [String: ConfigItem]
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
        try self.writeNewConfig(data, to: fileURL)
        return fileURL
    }

    private static func writeNewConfig(_ data: Data, to fileURL: URL) throws {
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
        guard fsync(descriptor) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
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
            let document = try decoder.decode(ConfigDocument.self, from: data)
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
        switch item.provider {
        case "keychain-generic":
            guard self.hasValue(item.service), self.hasValue(item.account) else {
                throw CLIError.invalidArguments(
                    message: "keychain-generic requires service and account in config item."
                )
            }
            guard item.server == nil, item.label == nil else {
                throw CLIError
                    .invalidArguments(message: "keychain-generic does not allow server or label in config item.")
            }
            return .keychainGeneric
        case "keychain-internet":
            guard self.hasValue(item.server), self.hasValue(item.account) else {
                throw CLIError.invalidArguments(
                    message: "keychain-internet requires server and account in config item."
                )
            }
            guard item.service == nil, item.label == nil else {
                throw CLIError
                    .invalidArguments(message: "keychain-internet does not allow service or label in config item.")
            }
            return .keychainInternet
        case "keychain-managed":
            guard self.hasValue(item.service), self.hasValue(item.account) else {
                throw CLIError.invalidArguments(
                    message: "keychain-managed requires service and account in config item."
                )
            }
            guard item.server == nil, item.label == nil else {
                throw CLIError.invalidArguments(
                    message: "keychain-managed does not allow server or label in config item."
                )
            }
            return .keychainManaged
        case "secure-enclave":
            guard self.hasValue(item.label) else {
                throw CLIError.invalidArguments(message: "secure-enclave requires label in config item.")
            }
            guard item.service == nil, item.account == nil, item.server == nil, item.fields == nil else {
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

    private static func validateDocument(_ document: ConfigDocument) throws {
        guard document.version == 1 else {
            throw CLIError.invalidArguments(message: "Unsupported config version: \(document.version)")
        }
        for (itemKey, item) in document.items {
            try self.validateItemKey(itemKey)
            _ = try self.validateItem(item)
        }
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
        guard !self.containsDuplicateObjectKey(in: data) else {
            throw CLIError.invalidArguments(message: "Config file must not contain duplicate keys.")
        }
        let rootObject: Any
        do {
            rootObject = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw CLIError.invalidArguments(message: "Config file is not valid JSON schema.")
        }
        guard let root = rootObject as? [String: Any],
              Set(root.keys) == Set(["version", "items"]),
              let version = root["version"] as? Int,
              let items = root["items"] as? [String: Any]
        else {
            throw CLIError.invalidArguments(message: "Config file is not valid JSON schema.")
        }
        guard version == 1 else {
            throw CLIError.invalidArguments(message: "Unsupported config version: \(root["version"] ?? "unknown")")
        }
        for (key, value) in items {
            try self.validateItemKey(key)
            guard let item = value as? [String: Any], let provider = item["provider"] as? String else {
                throw CLIError.invalidArguments(message: "Config item \"\(key)\" must be an object with a provider.")
            }
            let allowed: Set<String> = switch provider {
            case "keychain-generic", "keychain-managed": ["provider", "service", "account", "fields"]
            case "keychain-internet": ["provider", "server", "account", "fields"]
            case "secure-enclave": ["provider", "label"]
            default: ["provider"]
            }
            guard Set(item.keys).isSubset(of: allowed) else {
                throw CLIError
                    .invalidArguments(message: "Config item \"\(key)\" contains an unknown or secret-looking key.")
            }
            for name in ["service", "account", "server", "label"] where item[name] != nil {
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
        }
    }

    private static func containsDuplicateObjectKey(in data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8) else { return false }
        var stack: [Set<String>] = []
        var index = text.startIndex
        var expectingKey = false
        while index < text.endIndex {
            let character = text[index]
            if character == "\"" {
                let start = text.index(after: index)
                var cursor = start
                var escaped = false
                while cursor < text.endIndex {
                    let current = text[cursor]
                    if current == "\"", !escaped {
                        break
                    }
                    if current == "\\", !escaped {
                        escaped = true
                    } else {
                        escaped = false
                    }
                    cursor = text.index(after: cursor)
                }
                guard cursor < text.endIndex else { return false }
                guard let string = self.decodeJSONString(String(text[start ..< cursor])) else {
                    return false
                }
                var after = text.index(after: cursor)
                while after < text.endIndex, text[after].isWhitespace {
                    after = text.index(after: after)
                }
                if expectingKey, after < text.endIndex, text[after] == ":" {
                    if stack.last?.contains(string) == true {
                        return true
                    }
                    stack[stack.count - 1].insert(string)
                    expectingKey = false
                }
                index = text.index(after: cursor)
                continue
            }
            if character == "{" {
                stack.append([]); expectingKey = true
            }
            if character == "}" {
                _ = stack.popLast(); expectingKey = false
            }
            if character == ",", !stack.isEmpty {
                expectingKey = true
            }
            index = text.index(after: index)
        }
        return false
    }

    private static func decodeJSONString(_ rawValue: String) -> String? {
        let data = Data("[\"\(rawValue)\"]".utf8)
        return try? JSONDecoder().decode([String].self, from: data).first
    }
}
