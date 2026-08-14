import Foundation

public enum CLIError: Error {
    case runtimeError(message: String)
    case invalidArguments(message: String)
    case unsupportedCommand(command: String, reason: String)
    case unsupportedFlag(flag: String, reason: String)
    case unsupportedProvider(provider: String, reason: String)
    case providerUnavailable(provider: String, reason: String)
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

        switch error {
        case let .runtimeError(detail):
            exitCode = ExitCode.runtimeError.rawValue
            message = detail
            code = "runtime_error"
            command = nil
            flag = nil
            provider = nil
        case let .invalidArguments(detail):
            exitCode = ExitCode.invalidArguments.rawValue
            message = detail
            code = "invalid_arguments"
            command = nil
            flag = nil
            provider = nil
        case let .unsupportedCommand(unsupportedCommand, reason):
            exitCode = ExitCode.unsupported.rawValue
            message = reason
            code = "unsupported_command"
            command = unsupportedCommand
            flag = nil
            provider = nil
        case let .unsupportedFlag(unsupportedFlag, reason):
            exitCode = ExitCode.unsupported.rawValue
            message = reason
            code = "unsupported_flag"
            command = nil
            flag = unsupportedFlag
            provider = nil
        case let .unsupportedProvider(unsupportedProvider, reason):
            exitCode = ExitCode.unsupported.rawValue
            message = reason
            code = "unsupported_provider"
            command = nil
            flag = nil
            provider = unsupportedProvider
        case let .providerUnavailable(unavailableProvider, reason):
            exitCode = ExitCode.providerUnavailable.rawValue
            message = reason
            code = "provider_unavailable"
            command = nil
            flag = nil
            provider = unavailableProvider
        case let .denied(detail):
            exitCode = ExitCode.denied.rawValue
            message = detail
            code = "denied"
            command = nil
            flag = nil
            provider = nil
        case let .notFound(detail):
            exitCode = ExitCode.notFound.rawValue
            message = detail
            code = "not_found"
            command = nil
            flag = nil
            provider = nil
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
}
