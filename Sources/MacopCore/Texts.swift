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
            """
            #compdef macop op
            _macop() {
              local -a commands
              commands=(read run inject item completion compatibility ssh config doctor)
              _arguments '1:command:(${commands})' '*::argument:->args'
              case $words[2] in
                config) _values 'config command' init validate ;;
                ssh) _values 'ssh command' create list public-key delete test run ;;
                completion) _values 'shell' bash zsh fish ;;
              esac
            }
            compdef _macop macop op
            """
        case "bash":
            """
            _macop_complete() {
              local cur="${COMP_WORDS[COMP_CWORD]}"
              local commands="read run inject item completion compatibility ssh config doctor"
              local flags="--help --version --format --config --no-color --debug --encoding"
              case "${COMP_WORDS[1]}" in
                config) COMPREPLY=( $(compgen -W "init validate ${flags}" -- "$cur") ) ;;
                ssh) COMPREPLY=( $(compgen -W "create list public-key delete test run ${flags}" -- "$cur") ) ;;
                completion) COMPREPLY=( $(compgen -W "bash zsh fish ${flags}" -- "$cur") ) ;;
                *) COMPREPLY=( $(compgen -W "${commands} ${flags}" -- "$cur") ) ;;
              esac
            }
            complete -F _macop_complete macop op
            """
        case "fish":
            """
            complete -c macop -f -a 'read run inject item completion compatibility ssh config doctor'
            complete -c op -f -a 'read run inject item completion compatibility ssh config doctor'
            complete -c macop -l format -a 'human-readable json'
            complete -c op -l format -a 'human-readable json'
            complete -c macop -n '__fish_seen_subcommand_from config' -a 'init validate'
            complete -c op -n '__fish_seen_subcommand_from config' -a 'init validate'
            complete -c macop -n '__fish_seen_subcommand_from ssh' -a 'create list public-key delete test run'
            complete -c op -n '__fish_seen_subcommand_from ssh' -a 'create list public-key delete test run'
            """
        default:
            "macop: unsupported shell for completion: \(shell)\n"
        }
    }
}
