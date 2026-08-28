import Foundation

public enum ItemCommand {
    public static func run(
        args: [String],
        options: GlobalOptions,
        input: Data = Data(),
        client: any KeychainClient,
        importer: any ManagedKeychainImporting = CompanionManagedKeychainImporter(),
        deleter: any ManagedKeychainDeleting = CompanionManagedKeychainDeleter(),
        passwordAutoFillProvider: any PasswordAutoFillProviding = CompanionPasswordAutoFillProvider()
    ) throws -> CommandResult {
        guard let subcommand = args.first
        else { throw CLIError.invalidArguments(message: "item requires list, get, import, acquire, or delete.") }
        switch subcommand {
        case "list": return try self.list(Array(args.dropFirst()), options: options)
        case "get": return try self.get(Array(args.dropFirst()), options: options, client: client)
        case "import": return try self.importItem(
                Array(args.dropFirst()), options: options, input: input, importer: importer
            )
        case "acquire": return try CredentialAcquireCommand.run(
                Array(args.dropFirst()),
                options: options,
                client: client,
                passwordAutoFillProvider: passwordAutoFillProvider
            )
        case "delete": return try ManagedKeychainDeleteCommand.run(
                Array(args.dropFirst()), options: options, deleter: deleter
            )
        default:
            if let reason = self.unsupportedSubcommandReason(subcommand) {
                throw CLIError.unsupportedCommand(command: "item \(subcommand)", reason: reason)
            }
            throw CLIError.invalidArguments(message: "Unknown item subcommand: \(subcommand)")
        }
    }

    private static func importItem(
        _ args: [String],
        options: GlobalOptions,
        input: Data,
        importer: any ManagedKeychainImporting
    ) throws -> CommandResult {
        guard args.count == 1, let name = args.first, !name.hasPrefix("-") else {
            throw CLIError.invalidArguments(message: "item import requires one configured item name and secret stdin.")
        }
        guard !input.isEmpty, input.count <= ManagedKeychainStore.maximumSecretLength,
              let text = String(data: input, encoding: .utf8), !text.contains("\0")
        else {
            throw CLIError.invalidArguments(message: "item import requires 1 to 65536 bytes of UTF-8 secret stdin.")
        }
        let item = try ManagedItemLocator.item(named: name, options: options)
        let service = item.value.service!
        let account = item.value.account!
        try importer.importSecret(input, service: service, account: account)
        if options.format == .json {
            return CommandResult(exitCode: 0, stdout: "{\"schema_version\":1,\"status\":\"imported\"}\n")
        }
        return CommandResult(exitCode: 0, stdout: "Imported \(item.key) into the managed Keychain.\n")
    }

    private static func list(_ args: [String], options: GlobalOptions) throws -> CommandResult {
        for arg in args {
            if arg == "--long" {
                continue
            }
            if let unsupportedFlag = self.unsupportedListFlag(arg) {
                throw CLIError.unsupportedFlag(
                    flag: unsupportedFlag,
                    reason: "This item list flag is not supported by macop."
                )
            }
            throw CLIError.invalidArguments(message: "Unknown item list argument: \(arg)")
        }
        let includeLongMetadata = args.contains("--long")
        let items = try ConfigStore.items(configDirectory: options.configDirectory).filter(self.supported)
        let payload = items.keys.sorted().compactMap { key -> [String: String]? in
            guard let item = items[key] else { return nil }
            var metadata = ["name": key, "provider": item.provider]
            if includeLongMetadata {
                metadata["account"] = item.account ?? ""
                metadata["locator"] = item.service ?? item.server ?? ""
            }
            return metadata
        }
        return self.render(payload, options: options)
    }

    private static func get(
        _ args: [String],
        options: GlobalOptions,
        client: any KeychainClient
    ) throws -> CommandResult {
        var name: String?
        var field: String?
        var reveal = false
        var index = 0
        while index < args.count {
            let arg = args[index]
            if arg == "--reveal" {
                reveal = true
            } else if arg == "--fields" {
                let hasFieldValue = index + 1 < args.count
                guard hasFieldValue
                else { throw CLIError.invalidArguments(message: "--fields requires label=<field>.") }
                field = try self.parseField(args[index + 1]); index += 1
            } else if arg.hasPrefix("--fields=") {
                field = try self.parseField(String(arg.dropFirst("--fields=".count)))
            } else if let unsupportedFlag = unsupportedGetFlag(arg) {
                throw CLIError.unsupportedFlag(
                    flag: unsupportedFlag,
                    reason: "This item get flag is not supported by macop."
                )
            } else if arg.hasPrefix("-") {
                throw CLIError.invalidArguments(message: "Unknown item get flag: \(arg)")
            } else if name == nil {
                name = arg
            } else {
                throw CLIError.invalidArguments(message: "item get accepts one item name.")
            }
            index += 1
        }
        guard let name else { throw CLIError.invalidArguments(message: "item get requires an item name.") }
        let matches = try ConfigStore.items(configDirectory: options.configDirectory)
            .filter { self.supported($0) && $0.key.split(separator: "/").last == Substring(name) }
        guard matches.count == 1,
              let item = matches.first
        else { throw CLIError.notFound(message: "Configured item \"\(name)\" was not found.") }
        let fields = item.value.fields ?? []
        let selected = field.map { [$0] } ?? fields
        guard selected.allSatisfy(fields.contains)
        else { throw CLIError.notFound(message: "Requested field is not configured for this item.") }
        let secret = reveal ? try KeychainProvider.readText(self.query(
            for: item.value
        ), client: client) : "<concealed by macop>"
        let values = selected.map { label -> [String: String] in
            [
                "label": label,
                "value": secret
            ]
        }
        return self.render(
            ["name": item.key, "provider": item.value.provider, "fields": values] as [String: Any],
            options: options
        )
    }

    private static func supported(_ entry: (key: String, value: ConfigItem)) -> Bool {
        ["keychain-generic", "keychain-internet", "keychain-managed"].contains(entry.value.provider)
    }

    private static func query(for item: ConfigItem) throws -> KeychainQuery {
        let genericValues = (item.service, item.account)
        if item.provider == "keychain-generic", let service = genericValues.0, let account = genericValues.1 {
            return .generic(
                service: service,
                account: account
            )
        }
        let internetValues = (item.server, item.account)
        if item.provider == "keychain-internet", let server = internetValues.0, let account = internetValues.1 {
            return .internet(
                server: server,
                account: account
            )
        }
        if item.provider == "keychain-managed", let service = item.service, let account = item.account {
            return .managed(service: service, account: account)
        }
        throw CLIError.unsupportedProvider(
            provider: item.provider,
            reason: "This provider cannot supply item secret text."
        )
    }

    private static func parseField(_ value: String) throws -> String {
        guard value.hasPrefix("label=")
        else { throw CLIError.invalidArguments(message: "--fields only supports label=<field>.") }
        let field = String(value.dropFirst("label=".count))
        guard !field.isEmpty else { throw CLIError.invalidArguments(message: "--fields requires a field label.") }
        return field
    }

    private static func unsupportedGetFlag(_ arg: String) -> String? {
        self.unsupportedItemFlag(arg, including: [
            "--id",
            "--stdin"
        ])
    }

    private static func unsupportedListFlag(_ arg: String) -> String? {
        self.unsupportedItemFlag(arg, including: [])
    }

    private static func unsupportedItemFlag(_ arg: String, including additional: [String]) -> String? {
        let flags = [
            "--vault",
            "--categories",
            "--tags",
            "--favorite",
            "--include-archive",
            "--otp",
            "--share-link"
        ] + additional
        return flags.first { arg == $0 || arg.hasPrefix("\($0)=") }
    }

    private static func unsupportedSubcommandReason(_ subcommand: String) -> String? {
        CompatibilityCommand.entries.first {
            $0.kind == "subcommand" && $0.status == "unsupported" && $0.command == "item \(subcommand)"
        }?.reason
    }

    private static func render(_ payload: Any, options: GlobalOptions) -> CommandResult {
        if options.format == .json {
            let data = try? JSONSerialization.data(
                withJSONObject: ["schema_version": 1, "items": payload],
                options: [.prettyPrinted, .sortedKeys]
            )
            return CommandResult(
                exitCode: 0,
                stdout: (data.flatMap { String(data: $0, encoding: .utf8) } ?? "{}") + "\n"
            )
        }
        if let rows = payload as? [[String: String]] {
            return CommandResult(
                exitCode: 0,
                stdout: rows.map { row in
                    [row["name"], row["provider"], row["account"], row["locator"]]
                        .compactMap(\.self)
                        .joined(separator: "\t")
                }
                .joined(separator: "\n") + (rows.isEmpty ? "" : "\n")
            )
        }
        if let item = payload as? [String: Any] {
            let fields = (item["fields"] as? [[String: String]] ?? [])
                .map { "\($0["label"] ?? "")\t\($0["value"] ?? "")" }.joined(separator: "\n")
            return CommandResult(exitCode: 0, stdout: "\(item["name"] as? String ?? "")\n\(fields)\n")
        }
        return CommandResult(exitCode: 0)
    }
}
