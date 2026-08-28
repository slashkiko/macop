import Foundation

public enum ItemCommand {
    public static func run(
        args: [String],
        options: GlobalOptions,
        input: Data = Data(),
        client: any KeychainClient,
        otpClient: any KeychainClient = CompanionManagedKeychainClient(),
        importer: any ManagedKeychainImporting = CompanionManagedKeychainImporter(),
        deleter: any ManagedKeychainDeleting = CompanionManagedKeychainDeleter(),
        mutator: any KeychainMutating = SystemKeychainMutator(),
        passwordAutoFillProvider: any PasswordAutoFillProviding = CompanionPasswordAutoFillProvider()
    ) throws -> CommandResult {
        guard let subcommand = args.first
        else {
            throw CLIError.invalidArguments(
                message: "item requires list, get, create, edit, import, acquire, generate, otp, or delete."
            )
        }
        switch subcommand {
        case "list": return try self.list(Array(args.dropFirst()), options: options)
        case "get": return try self.get(
                Array(args.dropFirst()), options: options, client: client, otpClient: otpClient
            )
        case "create", "edit": return try KeychainMutationCommand.run(
                subcommand,
                args: Array(args.dropFirst()),
                options: options,
                input: input,
                mutator: mutator
            )
        case "import": return try self.importItem(
                Array(args.dropFirst()), options: options, input: input, importer: importer
            )
        case "acquire": return try CredentialAcquireCommand.run(
                Array(args.dropFirst()),
                options: options,
                client: client,
                passwordAutoFillProvider: passwordAutoFillProvider
            )
        case "generate": return try ItemGenerateCommand.run(
                Array(args.dropFirst()), options: options, importer: importer, mutator: mutator
            )
        case "otp": return try OTPCommand.run(
                Array(args.dropFirst()), options: options, input: input, client: otpClient,
                importer: importer, deleter: deleter
            )
        case "delete": return try ManagedKeychainDeleteCommand.run(
                Array(args.dropFirst()), options: options, deleter: deleter, mutator: mutator
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
        do {
            try importer.importSecret(
                input,
                service: service,
                account: account,
                synchronizable: item.value.managedKeychainSynchronizable
            )
        } catch let failure as ManagedKeychainMutationFailure {
            throw CLIError.runtimeError(
                message: "Managed item creation is indeterminate. \(failure.diagnostic) "
                    + "Retry item import for the same configured item with the same stdin: success means the retry "
                    + "created it, while already-exists means the original create completed. Never put the secret "
                    + "in command arguments."
            )
        }
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
        client: any KeychainClient,
        otpClient: any KeychainClient
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
        let wellKnown = item.value.schemaVersion == 2
            ? ["username", "password", "token"] + (item.value.otp == nil ? [] : ["otp"])
            : []
        guard selected.allSatisfy({ fields.contains($0) || wellKnown.contains($0) })
        else { throw CLIError.notFound(message: "Requested field is not configured for this item.") }
        let values = try selected.map { label -> [String: String] in
            let value = if item.value.schemaVersion == 2, label == "username" {
                item.value.account ?? ""
            } else if reveal {
                try CredentialFieldResolver.read(
                    item: item.value, section: nil, field: label, client: client, otpClient: otpClient
                )
            } else {
                "<concealed by macop>"
            }
            return [
                "label": label,
                "value": value
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
}

private extension ItemCommand {
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
