import Foundation

public enum HelpText {
    public static let main = """
    macop - Apple-native local credential CLI

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
      generate password
      item list [--long]
      item get <item> [--fields label=<field>] [--reveal]
      item create <item>
      item edit <item>
      item import <item>
      item acquire <item> [--from-passwords]
      item generate [--replace] <item> [generation-options]
      item otp <item>
      item otp <import|edit|delete> <item>
      item delete <item>|--all-managed
      profile
      completion
      compatibility
      ssh
      ssh git-client trust <absolute-selector-path>
      ssh git-client list
      ssh git-client remove <absolute-selector-path>
      ssh git-client migrate
      ssh git-client reset
      config
      doctor

    Item names:
      Use the full <namespace>/<item> key printed by item list.
      A unique trailing <item> name is accepted for backward compatibility.
    """
}

public enum CompletionText {
    public static func render(shell: String) -> String {
        switch shell {
        case "zsh":
            """
            #compdef macop op
            __macop_zsh_next_positional_index() {
              local index=$1
              while (( index <= ${#words[@]} )); do
                local word=${words[$index]}
                case $word in
                  --config|--format|--encoding) (( index += 2 )) ;;
                  --config=*|--format=*|--encoding=*|--no-color|--debug|--help|-h|--version|-v)
                    (( index += 1 )) ;;
                  *) print -r -- $index; return 0 ;;
                esac
              done
              return 1
            }
            _macop() {
              local -a commands
              local command_index command subcommand_index
              commands=(read run inject generate item profile completion compatibility ssh config doctor)
              _arguments '1:command:(${commands})' '*::argument:->args'
              command_index=$(__macop_zsh_next_positional_index 2)
              command=${words[$command_index]}
              case $command in
                item)
                  subcommand_index=$(__macop_zsh_next_positional_index $(( command_index + 1 )))
                  if [[ ${words[$subcommand_index]} == otp ]]; then
                    _values 'otp command' import edit delete
                  else
                    _values 'item command' list get create edit import acquire generate otp delete
                  fi ;;
                generate) _values 'generate command' password ;;
                profile) _values 'profile command' run shell-init ;;
                config) _values 'config command' init validate ;;
                ssh)
                  subcommand_index=$(__macop_zsh_next_positional_index $(( command_index + 1 )))
                  if [[ ${words[$subcommand_index]} == git-client ]]; then
                    _values 'git client command' trust list remove migrate reset
                  elif [[ ${words[$subcommand_index]} == migration ]]; then
                    _values 'ssh migration command' status orphans prepare public-key confirm-registered \
                      activate retire confirm-retired rollback delete-prepared delete-orphan
                  else
                    _values 'ssh command' create list public-key delete test run agent shell-init git-signing-config git-client migration connect host-config
                  fi ;;
                completion) _values 'shell' bash zsh fish ;;
              esac
            }
            compdef _macop macop op
            """
        case "bash":
            """
            __macop_bash_next_positional_index() {
              local index="$1"
              while (( index < ${#COMP_WORDS[@]} )); do
                local word="${COMP_WORDS[index]}"
                case "$word" in
                  --config|--format|--encoding) (( index += 2 )) ;;
                  --config=*|--format=*|--encoding=*|--no-color|--debug|--help|-h|--version|-v)
                    (( index += 1 )) ;;
                  *) printf '%s\n' "$index"; return 0 ;;
                esac
              done
              return 1
            }
            _macop_complete() {
              local cur="${COMP_WORDS[COMP_CWORD]}"
              local commands="read run inject generate item profile completion compatibility ssh config doctor"
              local flags="--help --version --format --config --no-color --debug --encoding"
              local ssh_commands="create list public-key delete test run agent shell-init git-signing-config git-client migration connect host-config"
              local migration_commands="status orphans prepare public-key confirm-registered \
                activate retire confirm-retired rollback delete-prepared delete-orphan"
              local command_index subcommand_index command
              command_index="$(__macop_bash_next_positional_index 1)"
              command="${COMP_WORDS[command_index]}"
              case "$command" in
                item)
                  subcommand_index="$(__macop_bash_next_positional_index "$(( command_index + 1 ))")"
                  if [[ "${COMP_WORDS[subcommand_index]}" == "otp" ]]; then
                    COMPREPLY=( $(compgen -W "import edit delete ${flags}" -- "$cur") )
                  else
                    COMPREPLY=( $(compgen -W "list get create edit import acquire generate otp delete ${flags}" -- "$cur") )
                  fi ;;
                generate) COMPREPLY=( $(compgen -W "password ${flags}" -- "$cur") ) ;;
                profile) COMPREPLY=( $(compgen -W "run shell-init ${flags}" -- "$cur") ) ;;
                config) COMPREPLY=( $(compgen -W "init validate ${flags}" -- "$cur") ) ;;
                ssh)
                  subcommand_index="$(__macop_bash_next_positional_index "$(( command_index + 1 ))")"
                  if [[ "${COMP_WORDS[subcommand_index]}" == "git-client" ]]; then
                    COMPREPLY=( $(compgen -W "trust list remove migrate reset ${flags}" -- "$cur") )
                  elif [[ "${COMP_WORDS[subcommand_index]}" == "migration" ]]; then
                    COMPREPLY=( $(compgen -W "${migration_commands} ${flags}" -- "$cur") )
                  else
                    COMPREPLY=( $(compgen -W "${ssh_commands} ${flags}" -- "$cur") )
                  fi ;;
                completion) COMPREPLY=( $(compgen -W "bash zsh fish ${flags}" -- "$cur") ) ;;
                *) COMPREPLY=( $(compgen -W "${commands} ${flags}" -- "$cur") ) ;;
              esac
            }
            complete -F _macop_complete macop op
            """
        case "fish":
            """
            complete -c macop -f -a 'read run inject generate item profile completion compatibility ssh config doctor'
            complete -c op -f -a 'read run inject generate item profile completion compatibility ssh config doctor'
            complete -c macop -l format -a 'human-readable json'
            complete -c op -l format -a 'human-readable json'
            function __macop_next_positional_index
              set -l words (commandline -opc)
              set -l index $argv[1]
              while test $index -le (count $words)
                set -l word $words[$index]
                switch $word
                  case --config --format --encoding
                    set index (math $index + 2)
                  case '--config=*' '--format=*' '--encoding=*' --no-color --debug
                    set index (math $index + 1)
                  case --help -h --version -v
                    set index (math $index + 1)
                  case '*'
                    echo $index
                    return 0
                end
              end
              return 1
            end
            function __macop_command_index
              __macop_next_positional_index 2
            end
            function __macop_command
              set -l words (commandline -opc)
              set -l index (__macop_command_index)
              test -n "$index"; and echo $words[$index]
            end
            function __macop_command_position
              string match -q -- $argv[1] (__macop_command)
            end
            function __macop_item_position
              __macop_command_position item
            end
            function __macop_otp_position
              set -l words (commandline -opc)
              set -l command_index (__macop_command_index)
              test -n "$command_index"; or return 1
              set -l otp_index (__macop_next_positional_index (math $command_index + 1))
              test -n "$otp_index"; and string match -q -- otp $words[$otp_index]
            end
            function __macop_git_client_position
              set -l words (commandline -opc)
              set -l command_index (__macop_command_index)
              test -n "$command_index"; or return 1
              set -l ssh_index (__macop_next_positional_index (math $command_index + 1))
              test -n "$ssh_index"; and string match -q -- git-client $words[$ssh_index]
            end
            function __macop_ssh_migration_position
              set -l words (commandline -opc)
              set -l command_index (__macop_command_index)
              test -n "$command_index"; or return 1
              set -l ssh_index (__macop_next_positional_index (math $command_index + 1))
              test -n "$ssh_index"; and string match -q -- migration $words[$ssh_index]
            end
            complete -c macop -n '__macop_item_position; and not __macop_otp_position' \\
              -a 'list get create edit import acquire generate otp delete'
            complete -c op -n '__macop_item_position; and not __macop_otp_position' \\
              -a 'list get create edit import acquire generate otp delete'
            complete -c macop -n '__macop_item_position; and __macop_otp_position' -a 'import edit delete'
            complete -c op -n '__macop_item_position; and __macop_otp_position' -a 'import edit delete'
            complete -c macop -n '__macop_command_position generate' -a 'password'
            complete -c op -n '__macop_command_position generate' -a 'password'
            complete -c macop -n '__macop_command_position profile' -a 'run shell-init'
            complete -c op -n '__macop_command_position profile' -a 'run shell-init'
            complete -c macop -n '__macop_command_position config' -a 'init validate'
            complete -c op -n '__macop_command_position config' -a 'init validate'
            set -l macop_ssh_commands 'create list public-key delete test run agent shell-init git-signing-config git-client migration connect host-config'
            complete -c macop -n '__macop_command_position ssh; and not __macop_git_client_position; and not __macop_ssh_migration_position' \
              -a "$macop_ssh_commands"
            complete -c op -n '__macop_command_position ssh; and not __macop_git_client_position; and not __macop_ssh_migration_position' \
              -a "$macop_ssh_commands"
            complete -c macop -n '__macop_command_position ssh; and __macop_git_client_position' \
              -a 'trust list remove migrate reset'
            complete -c op -n '__macop_command_position ssh; and __macop_git_client_position' \
              -a 'trust list remove migrate reset'
            complete -c macop -n '__macop_command_position ssh; and __macop_ssh_migration_position' \
              -a 'status orphans prepare public-key confirm-registered activate retire confirm-retired rollback delete-prepared delete-orphan'
            complete -c op -n '__macop_command_position ssh; and __macop_ssh_migration_position' \
              -a 'status orphans prepare public-key confirm-registered activate retire confirm-retired rollback delete-prepared delete-orphan'
            """
        default:
            "macop: unsupported shell for completion: \(shell)\n"
        }
    }
}
