import Foundation

enum ShellIntegration {
    static func render(shell: String) throws -> String {
        switch shell {
        case "zsh", "bash":
            return self.posix(shell: shell)
        case "fish":
            return self.fish
        default:
            throw CLIError.invalidArguments(message: "ssh shell-init supports zsh, bash, or fish.")
        }
    }

    private static func posix(shell: String) -> String {
        """
        # macop verified-session shell integration for \(shell)
        # Set MACOP_SSH_IDENTITY to a configured Secure Enclave identity label.
        if [[ $- == *i* ]] \\
          && [[ -z ${MACOP_SHELL_INTEGRATION_ACTIVE:-} ]] \\
          && [[ -n ${MACOP_SSH_IDENTITY:-} ]]; then
          export MACOP_SHELL_INTEGRATION_ACTIVE=1
          exec macop ssh agent shell "$MACOP_SSH_IDENTITY" -- "${SHELL:-/bin/\(shell)}" -l
        fi
        """
    }

    private static let fish = """
    # macop verified-session shell integration for fish
    # Set MACOP_SSH_IDENTITY to a configured Secure Enclave identity label.
    if status is-interactive \\
      && not set -q MACOP_SHELL_INTEGRATION_ACTIVE \\
      && set -q MACOP_SSH_IDENTITY
      set -gx MACOP_SHELL_INTEGRATION_ACTIVE 1
      exec macop ssh agent shell "$MACOP_SSH_IDENTITY" -- "$SHELL" -l
    end
    """
}
