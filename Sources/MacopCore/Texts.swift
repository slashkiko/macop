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
            "#compdef macop op\n_arguments '*: :->args'\n"
        case "bash":
            "_macop_complete(){ :; }\ncomplete -F _macop_complete macop op\n"
        case "fish":
            "complete -c macop -f\ncomplete -c op -f\n"
        default:
            "macop: unsupported shell for completion: \(shell)\n"
        }
    }
}
