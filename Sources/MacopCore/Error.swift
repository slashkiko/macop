import Foundation

public enum CLIError: Error {
    case runtimeError(message: String)
    case invalidArguments(message: String)
    case unsupportedCommand(command: String, reason: String)
    case unsupportedFlag(flag: String, reason: String)
    case unsupportedProvider(provider: String, reason: String)
    case providerUnavailable(provider: String, reason: String)
    case brokerFailure(AuthBrokerFailureCategory)
    case denied(message: String)
    case notFound(message: String)
}

public enum ErrorRenderer {
    public static func render(error: CLIError, format: OutputFormat) -> CommandResult {
        let exitCode: Int32
        let message: String
        let code: String
        let command: String?
        let flag: String?
        let provider: String?
        let brokerCategory: AuthBrokerFailureCategory?

        switch error {
        case let .runtimeError(detail):
            exitCode = ExitCode.runtimeError.rawValue
            message = detail
            code = "runtime_error"
            command = nil
            flag = nil
            provider = nil
            brokerCategory = nil
        case let .invalidArguments(detail):
            exitCode = ExitCode.invalidArguments.rawValue
            message = detail
            code = "invalid_arguments"
            command = nil
            flag = nil
            provider = nil
            brokerCategory = nil
        case let .unsupportedCommand(unsupportedCommand, reason):
            exitCode = ExitCode.unsupported.rawValue
            message = reason
            code = "unsupported_command"
            command = unsupportedCommand
            flag = nil
            provider = nil
            brokerCategory = nil
        case let .unsupportedFlag(unsupportedFlag, reason):
            exitCode = ExitCode.unsupported.rawValue
            message = reason
            code = "unsupported_flag"
            command = nil
            flag = unsupportedFlag
            provider = nil
            brokerCategory = nil
        case let .unsupportedProvider(unsupportedProvider, reason):
            exitCode = ExitCode.unsupported.rawValue
            message = reason
            code = "unsupported_provider"
            command = nil
            flag = nil
            provider = unsupportedProvider
            brokerCategory = nil
        case let .providerUnavailable(unavailableProvider, reason):
            exitCode = ExitCode.providerUnavailable.rawValue
            message = reason
            code = "provider_unavailable"
            command = nil
            flag = nil
            provider = unavailableProvider
            brokerCategory = nil
        case let .brokerFailure(category):
            exitCode = category == .userDenied ? ExitCode.denied.rawValue : ExitCode.providerUnavailable.rawValue
            message = Self.brokerMessage(category)
            code = "broker_failure"
            command = nil
            flag = nil
            provider = "MacopAuth"
            brokerCategory = category
        case let .denied(detail):
            exitCode = ExitCode.denied.rawValue
            message = detail
            code = "denied"
            command = nil
            flag = nil
            provider = nil
            brokerCategory = nil
        case let .notFound(detail):
            exitCode = ExitCode.notFound.rawValue
            message = detail
            code = "not_found"
            command = nil
            flag = nil
            provider = nil
            brokerCategory = nil
        }

        switch format {
        case .humanReadable:
            var lines = [String]()
            if let command {
                lines.append("macop: unsupported op command \"\(command)\"")
            } else if let flag {
                lines.append("macop: unsupported flag \"\(flag)\"")
            } else if code == "provider_unavailable" {
                let label = provider.map { " \"\($0)\"" } ?? ""
                lines.append("macop: provider unavailable\(label)")
            } else if code == "broker_failure", let brokerCategory {
                lines.append("macop: MacopAuth broker failure (\(brokerCategory.rawValue))")
            } else if code == "unsupported_provider", let provider {
                lines.append("macop: unsupported provider \"\(provider)\"")
            } else if code == "denied" {
                lines.append("macop: access denied")
            } else if let provider {
                lines.append("macop: unsupported provider \"\(provider)\"")
            } else if code == "not_found" {
                lines.append("macop: not found")
            } else {
                lines.append("macop: \(message)")
            }
            lines.append("Reason: \(message)")
            if exitCode == ExitCode.unsupported.rawValue {
                lines.append(contentsOf: CompatibilityCommand.humanSupportGuidance())
            }
            return CommandResult(exitCode: exitCode, stderr: lines.joined(separator: "\n") + "\n")
        case .json:
            var payload: [String: Any] = [
                "error": [
                    "code": code,
                    "message": message
                ]
            ]

            if let command, var errorInfo = payload["error"] as? [String: Any] {
                errorInfo["command"] = command
                payload["error"] = errorInfo
            }
            if let flag, var errorInfo = payload["error"] as? [String: Any] {
                errorInfo["flag"] = flag
                payload["error"] = errorInfo
            }
            if let provider, var errorInfo = payload["error"] as? [String: Any] {
                errorInfo["provider"] = provider
                payload["error"] = errorInfo
            }
            if let brokerCategory, var errorInfo = payload["error"] as? [String: Any] {
                errorInfo["category"] = brokerCategory.rawValue
                payload["error"] = errorInfo
            }
            if exitCode == ExitCode.unsupported.rawValue, var errorInfo = payload["error"] as? [String: Any] {
                errorInfo["documentation"] = "https://github.com/slashkiko/macop#op-compatibility"
                errorInfo["guidance"] = "Run macop compatibility for the support matrix."
                payload["error"] = errorInfo
            }

            let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
            let text = data.flatMap { String(
                data: $0,
                encoding: .utf8
            ) } ?? "{\"error\":{\"code\":\"runtime_error\",\"message\":\"failed to render error\"}}"
            return CommandResult(exitCode: exitCode, stderr: text + "\n")
        }
    }

    private static func brokerMessage(_ category: AuthBrokerFailureCategory) -> String {
        switch category {
        case .companionUnavailable:
            "MacopAuth companion is unavailable. Reinstall or repair macop, then run macop doctor."
        case .identityInvalid:
            "MacopAuth identity verification failed. Reinstall macop from a trusted release, then run macop doctor."
        case .protocolMismatch:
            "MacopAuth protocol is incompatible. Update macop and MacopAuth together, then run macop doctor."
        case .transportFailure:
            "MacopAuth could not be reached. Close a stale MacopAuth prompt and retry, then run macop doctor if it persists."
        case .userDenied:
            "The MacopAuth request was denied or cancelled. Approve the request and retry if access is intended."
        }
    }
}

public extension AuthBrokerFailure {
    var cliError: CLIError {
        .brokerFailure(self.category)
    }
}
