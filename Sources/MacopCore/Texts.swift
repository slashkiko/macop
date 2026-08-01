import Foundation

public enum HelpText {
    public static let main = """
    macop - Apple-native op-compatible CLI (MVP scaffold)

    Usage:
      macop [global-options] <command> [args]

    Global options:
      --help, -h
      --version, -v
      --format <human-readable|json>
      --no-color
      --debug
      --config <directory>

    Commands:
      read
      run
      inject
      item
      completion
      compatibility
      ssh
      config
      doctor
    """
}

public enum CompletionText {
    public static func render(shell: String) -> String {
        switch shell {
        case "zsh":
            return "#compdef macop op\n_arguments '*: :->args'\n"
        case "bash":
            return "_macop_complete(){ :; }\ncomplete -F _macop_complete macop op\n"
        case "fish":
            return "complete -c macop -f\ncomplete -c op -f\n"
        default:
            return "macop: unsupported shell for completion: \(shell)\n"
        }
    }
}

