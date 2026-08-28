import Foundation
import Security

public struct PasswordGenerationOptions: Sendable {
    public let length: Int
    public let includeDigits: Bool
    public let includeSymbols: Bool
    public let excluded: Set<Character>

    public init(
        length: Int = 32,
        includeDigits: Bool = true,
        includeSymbols: Bool = true,
        excluded: Set<Character> = []
    ) {
        self.length = length
        self.includeDigits = includeDigits
        self.includeSymbols = includeSymbols
        self.excluded = excluded
    }
}

public enum PasswordGenerator {
    private static let letters = Array("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    private static let digits = Array("23456789")
    private static let symbols = Array("!@#$%^&*()-_=+[]{}:,.?")

    public static func generate(_ options: PasswordGenerationOptions) throws -> String {
        guard (12 ... 256).contains(options.length) else {
            throw CLIError.invalidArguments(message: "Password length must be between 12 and 256.")
        }
        let requiredSets = [Self.letters]
            + (options.includeDigits ? [Self.digits] : [])
            + (options.includeSymbols ? [Self.symbols] : [])
        let filteredSets = requiredSets.map { $0.filter { !options.excluded.contains($0) } }
        guard filteredSets.allSatisfy({ !$0.isEmpty }) else {
            throw CLIError.invalidArguments(message: "Excluded characters remove a required character class.")
        }
        let alphabet = Array(Set(filteredSets.flatMap(\.self))).sorted()
        guard alphabet.count >= 2 else { throw CLIError.invalidArguments(message: "Password alphabet is too small.") }
        var characters = try filteredSets.map(Self.randomCharacter)
        while characters.count < options.length {
            try characters.append(Self.randomCharacter(from: alphabet))
        }
        for index in characters.indices.reversed() where index > 0 {
            let swapIndex = try Self.randomIndex(upperBound: index + 1)
            characters.swapAt(index, swapIndex)
        }
        return String(characters)
    }

    private static func randomCharacter(from values: [Character]) throws -> Character {
        try values[self.randomIndex(upperBound: values.count)]
    }

    private static func randomIndex(upperBound: Int) throws -> Int {
        precondition(upperBound > 0 && upperBound <= 256)
        let accepted = 256 - (256 % upperBound)
        while true {
            var byte: UInt8 = 0
            guard SecRandomCopyBytes(kSecRandomDefault, 1, &byte) == errSecSuccess else {
                throw CLIError.providerUnavailable(provider: "SecRandom", reason: "Secure random generation failed.")
            }
            if Int(byte) < accepted {
                return Int(byte) % upperBound
            }
        }
    }
}

enum PasswordGenerationArguments {
    static func parse(_ args: [String]) throws -> PasswordGenerationOptions {
        var length = 32
        var digits = true
        var symbols = true
        var excluded = Set<Character>()
        var index = 0
        while index < args.count {
            let arg = args[index]
            switch arg {
            case "--length":
                guard index + 1 < args.count, let parsed = Int(args[index + 1]) else {
                    throw CLIError.invalidArguments(message: "--length requires an integer.")
                }
                length = parsed; index += 1
            case let value where value.hasPrefix("--length="):
                guard let parsed = Int(value.dropFirst("--length=".count)) else {
                    throw CLIError.invalidArguments(message: "--length requires an integer.")
                }
                length = parsed
            case "--no-digits": digits = false
            case "--no-symbols": symbols = false
            case "--exclude":
                guard index + 1 < args.count else {
                    throw CLIError.invalidArguments(message: "--exclude requires characters.")
                }
                excluded.formUnion(args[index + 1]); index += 1
            case let value where value.hasPrefix("--exclude="):
                excluded.formUnion(value.dropFirst("--exclude=".count))
            default: throw CLIError.invalidArguments(message: "Unknown password generation option: \(arg)")
            }
            index += 1
        }
        return PasswordGenerationOptions(
            length: length, includeDigits: digits, includeSymbols: symbols, excluded: excluded
        )
    }
}

public enum GenerateCommand {
    public static func run(args: [String], options: GlobalOptions) throws -> CommandResult {
        guard args.first == "password" else {
            throw CLIError.invalidArguments(message: "generate requires the password subcommand.")
        }
        let password = try PasswordGenerator.generate(PasswordGenerationArguments.parse(Array(args.dropFirst())))
        if options.format == .json {
            let data = try JSONSerialization.data(withJSONObject: ["schema_version": 1, "password": password])
            guard let output = String(bytes: data, encoding: .utf8) else {
                throw CLIError.runtimeError(message: "Unable to render generated password.")
            }
            return CommandResult(exitCode: 0, stdout: output + "\n")
        }
        return CommandResult(exitCode: 0, stdout: password + "\n")
    }
}
