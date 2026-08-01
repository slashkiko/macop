import Foundation

public enum CLIError: Error {
    case invalidArguments(message: String)
    case unsupportedCommand(command: String, reason: String)
    case unsupportedFlag(flag: String, reason: String)
}

public enum ErrorRenderer {
    public static func render(error: CLIError, format: OutputFormat) -> CommandResult {
        let exitCode: Int32
        let message: String
        let code: String
        let command: String?
        let flag: String?

        switch error {
        case let .invalidArguments(detail):
            exitCode = ExitCode.invalidArguments.rawValue
            message = detail
            code = "invalid_arguments"
            command = nil
            flag = nil
        case let .unsupportedCommand(unsupportedCommand, reason):
            exitCode = ExitCode.unsupported.rawValue
            message = reason
            code = "unsupported_command"
            command = unsupportedCommand
            flag = nil
        case let .unsupportedFlag(unsupportedFlag, reason):
            exitCode = ExitCode.unsupported.rawValue
            message = reason
            code = "unsupported_flag"
            command = nil
            flag = unsupportedFlag
        }

        switch format {
        case .humanReadable:
            var lines = [String]()
            if let command {
                lines.append("macop: unsupported op command \"\(command)\"")
            } else if let flag {
                lines.append("macop: unsupported flag \"\(flag)\"")
            } else {
                lines.append("macop: \(message)")
            }
            lines.append("Reason: \(message)")
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

            let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
            let text = data.flatMap { String(
                data: $0,
                encoding: .utf8
            ) } ?? "{\"error\":{\"code\":\"runtime_error\",\"message\":\"failed to render error\"}}"
            return CommandResult(exitCode: exitCode, stderr: text + "\n")
        }
    }
}
