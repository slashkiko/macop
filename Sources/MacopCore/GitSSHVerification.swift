import Darwin
import Foundation

public protocol GitSSHVerificationExecuting: Sendable {
    func execute(arguments: [String]) throws -> Int32
}

public struct SystemGitSSHVerificationExecutor: GitSSHVerificationExecuting {
    public static let executablePath = "/usr/bin/ssh-keygen"

    public init() {}

    public func execute(arguments: [String]) throws -> Int32 {
        var values = (["ssh-keygen"] + arguments).map { strdup($0) } + [nil]
        guard values.dropLast().allSatisfy({ $0 != nil }) else {
            values.compactMap(\.self).forEach { free($0) }
            throw CLIError.runtimeError(message: "Could not prepare Apple ssh-keygen verification arguments.")
        }
        defer { values.compactMap(\.self).forEach { free($0) } }
        let result = values.withUnsafeMutableBufferPointer { buffer in
            execv(Self.executablePath, buffer.baseAddress)
        }
        guard result == -1 else { return result }
        throw CLIError.runtimeError(message: "Could not execute Apple ssh-keygen verification.")
    }
}

public enum GitSSHVerificationCommand {
    private static let verificationOperations = Set(["find-principals", "verify", "check-novalidate"])

    public static func isVerificationInvocation(_ argv: [String]) -> Bool {
        let args = Array(argv.dropFirst())
        return args.count >= 2 && args[0] == "-Y" && self.verificationOperations.contains(args[1])
    }

    public static func run(
        argv: [String],
        executor: any GitSSHVerificationExecuting = SystemGitSSHVerificationExecutor(),
        requesterValidator: any GitSSHSigningRequesterValidating = SystemGitSSHSigningRequesterValidator()
    ) -> CommandResult {
        do {
            let arguments = try self.parse(argv: argv)
            _ = try requesterValidator.validateRequester()
            return try CommandResult(exitCode: executor.execute(arguments: arguments))
        } catch let error as CLIError {
            return ErrorRenderer.render(error: error, format: .humanReadable)
        } catch let failure as AuthBrokerFailure {
            return ErrorRenderer.render(error: failure.cliError, format: .humanReadable)
        } catch {
            return ErrorRenderer.render(
                error: .runtimeError(message: "Git SSH verification failed."),
                format: .humanReadable
            )
        }
    }

    private static func parse(argv: [String]) throws -> [String] {
        let args = Array(argv.dropFirst())
        let valid = self.validFindPrincipals(args)
            || self.validVerify(args)
            || self.validCheckNoValidate(args)
        guard valid else {
            throw CLIError.invalidArguments(
                message: "The Git SSH adapter accepts only Apple's exact Git verification invocations."
            )
        }
        return args
    }

    private static func validFindPrincipals(_ args: [String]) -> Bool {
        args.count == 7
            && args[0] == "-Y" && args[1] == "find-principals"
            && args[2] == "-f" && self.validPath(args[3])
            && args[4] == "-s" && self.validPath(args[5])
            && self.validVerifyTime(args[6])
    }

    private static func validVerify(_ args: [String]) -> Bool {
        args.count == 11
            && args[0] == "-Y" && args[1] == "verify"
            && args[2] == "-n" && args[3] == "git"
            && args[4] == "-f" && self.validPath(args[5])
            && args[6] == "-I" && self.validPrincipal(args[7])
            && args[8] == "-s" && self.validPath(args[9])
            && self.validVerifyTime(args[10])
    }

    private static func validCheckNoValidate(_ args: [String]) -> Bool {
        args.count == 7
            && args[0] == "-Y" && args[1] == "check-novalidate"
            && args[2] == "-n" && args[3] == "git"
            && args[4] == "-s" && self.validPath(args[5])
            && self.validVerifyTime(args[6])
    }

    private static func validPath(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return !bytes.isEmpty && bytes.count < Int(PATH_MAX) && bytes.first == 0x2F
            && !value.hasPrefix("-") && !bytes.contains(0)
            && value.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
    }

    private static func validPrincipal(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return !bytes.isEmpty && bytes.count <= 256 && bytes.first != 0x2D
            && bytes.allSatisfy { $0 >= 0x21 && $0 <= 0x7E }
    }

    private static func validVerifyTime(_ value: String) -> Bool {
        let prefix = "-Overify-time="
        guard value.hasPrefix(prefix) else { return false }
        let timestamp = String(value.dropFirst(prefix.count))
        let bytes = Array(timestamp.utf8)
        guard bytes.count == 14, bytes.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return false }
        func component(_ range: Range<Int>) -> Int {
            bytes[range].reduce(0) { $0 * 10 + Int($1 - 0x30) }
        }
        let year = component(0 ..< 4)
        let month = component(4 ..< 6)
        let day = component(6 ..< 8)
        let hour = component(8 ..< 10)
        let minute = component(10 ..< 12)
        let second = component(12 ..< 14)
        guard year > 0 else { return false }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let requested = DateComponents(
            timeZone: calendar.timeZone,
            year: year,
            month: month,
            day: day,
            hour: hour,
            minute: minute,
            second: second
        )
        guard let date = calendar.date(from: requested) else { return false }
        let actual = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        return actual.year == year && actual.month == month && actual.day == day
            && actual.hour == hour && actual.minute == minute && actual.second == second
    }
}
