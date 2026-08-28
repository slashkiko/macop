import Foundation

public enum SecretReference: Sendable {
    case opReference(namespace: String, item: String, section: String?, field: String)
    case opOTP(namespace: String, item: String)
    case keychainGeneric(service: String, account: String)
    case keychainInternet(server: String, account: String)
    case secureEnclave(label: String)
}

public enum ReferenceResolver {
    public static func parse(_ input: String, env: [String: String]) throws -> SecretReference {
        let expanded = try expandEnvironmentVariables(in: input, env: env)
        if expanded.hasPrefix("op://") {
            return try self.parseOpReference(expanded)
        }
        guard !expanded.contains("?") else {
            throw CLIError.unsupportedFlag(
                flag: "reference query parameter",
                reason: "Query parameters are supported only for op ?attribute=otp references."
            )
        }
        if expanded.hasPrefix("keychain://") {
            return try self.parseKeychainReference(expanded)
        }
        if expanded.hasPrefix("secure-enclave://") {
            return try self.parseSecureEnclaveReference(expanded)
        }
        if expanded.hasPrefix("apple-passwords://") {
            throw CLIError.unsupportedProvider(
                provider: "apple-passwords",
                reason: "Apple Passwords does not expose a public CLI/API for live credential access."
            )
        }
        throw CLIError.invalidArguments(message: "Unsupported reference scheme.")
    }

    private static func parseOpReference(_ value: String) throws -> SecretReference {
        let parts = value.split(separator: "?", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { throw CLIError.invalidArguments(message: "Reference query is invalid.") }
        let body = String(parts[0].dropFirst("op://".count))
        let rawSegments = body.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        let segments = try decodeSegments(rawSegments)

        guard segments.count == 3 || segments.count == 4 else {
            throw CLIError.invalidArguments(
                message: "op reference must be op://<namespace>/<item>/[<section>/]<field>"
            )
        }

        if parts.count == 2 {
            guard parts[1] == "attribute=otp", segments.count == 3 else {
                throw CLIError.unsupportedFlag(
                    flag: "reference query parameter",
                    reason: "Only ?attribute=otp on an op reference is supported."
                )
            }
            return .opOTP(namespace: segments[0], item: segments[1])
        }

        let namespace = segments[0]
        let item = segments[1]
        if segments.count == 3 {
            return .opReference(namespace: namespace, item: item, section: nil, field: segments[2])
        }
        return .opReference(namespace: namespace, item: item, section: segments[2], field: segments[3])
    }

    private static func parseKeychainReference(_ value: String) throws -> SecretReference {
        let body = String(value.dropFirst("keychain://".count))
        let rawSegments = body.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        let segments = try decodeSegments(rawSegments)

        guard segments.count == 3 else {
            throw CLIError.invalidArguments(
                message: "keychain reference must be keychain://generic/<service>/<account> or keychain://internet/<server>/<account>"
            )
        }

        switch segments[0] {
        case "generic":
            return .keychainGeneric(service: segments[1], account: segments[2])
        case "internet":
            return .keychainInternet(server: segments[1], account: segments[2])
        default:
            throw CLIError.invalidArguments(message: "Unsupported keychain reference kind.")
        }
    }

    private static func parseSecureEnclaveReference(_ value: String) throws -> SecretReference {
        let body = String(value.dropFirst("secure-enclave://".count))
        let segments = try decodeSegments([body])
        guard let label = segments.first, !label.isEmpty else {
            throw CLIError.invalidArguments(message: "secure-enclave reference requires identity label.")
        }
        return .secureEnclave(label: label)
    }

    private static func decodeSegments(_ segments: [String]) throws -> [String] {
        try segments.map { segment -> String in
            guard !segment.isEmpty else {
                throw CLIError.invalidArguments(message: "Reference path contains an empty segment.")
            }
            guard let value = segment.removingPercentEncoding else {
                throw CLIError.invalidArguments(message: "Reference contains invalid percent-encoding.")
            }
            return value
        }
    }

    private static func expandEnvironmentVariables(in input: String, env: [String: String]) throws -> String {
        try self.expandEnvironmentVariables(in: input, env: env, resolving: [])
    }

    private static func expandEnvironmentVariables(
        in input: String,
        env: [String: String],
        resolving: Set<String>
    ) throws -> String {
        let pattern = #"\$[A-Za-z_][A-Za-z0-9_]*"#
        let regex = try NSRegularExpression(pattern: pattern)
        let range = NSRange(input.startIndex ..< input.endIndex, in: input)
        let matches = regex.matches(in: input, range: range)
        if matches.isEmpty {
            return input
        }

        var output = input
        for match in matches.reversed() {
            guard let matchRange = Range(match.range, in: output) else { continue }
            let token = String(output[matchRange])
            let name = String(token.dropFirst())
            guard let replacement = env[name] else {
                throw CLIError.invalidArguments(message: "Reference uses an undefined environment variable.")
            }
            guard !resolving.contains(name) else {
                throw CLIError.invalidArguments(message: "Reference contains a cyclic environment variable expansion.")
            }
            var nested = resolving
            nested.insert(name)
            let expandedReplacement = try expandEnvironmentVariables(in: replacement, env: env, resolving: nested)
            output.replaceSubrange(matchRange, with: expandedReplacement)
        }
        return output
    }
}
