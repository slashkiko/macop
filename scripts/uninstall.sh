#!/bin/bash
set -euo pipefail

bin_dir="${MACOP_BIN_DIR:-$HOME/.local/bin}"
shell_profile="${MACOP_SHELL_PROFILE:-}"
keep_path=false
delete_managed_keychain=false

usage() {
  cat <<'EOF'
Usage: scripts/uninstall.sh [options]

Remove macop executables installed by scripts/build-install.sh.

Options:
  --bin-dir <directory>  Install directory (default: ~/.local/bin)
  --shell-profile <file> Profile containing the managed PATH block
  --keep-path            Preserve the managed PATH block
  --delete-managed-keychain
                         Delete all macop-managed Keychain items before uninstalling
  --help                 Show this help

The script preserves configuration, Keychain items, CTK identities, and the
install directory by default. --delete-managed-keychain requires the installed,
signed macop and MacopAuth.app and interactive macOS authentication. An op
symlink is removed only when it targets macop. The managed PATH block is removed
unless --keep-path is passed.
MACOP_BIN_DIR and MACOP_SHELL_PROFILE may be used instead of their options.
EOF
}

fail() {
  printf 'macop uninstall: %s\n' "$1" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)
      [[ $# -ge 2 ]] || fail "--bin-dir requires a value."
      bin_dir="$2"
      shift 2
      ;;
    --shell-profile)
      [[ $# -ge 2 ]] || fail "--shell-profile requires a value."
      shell_profile="$2"
      shift 2
      ;;
    --keep-path)
      keep_path=true
      shift
      ;;
    --delete-managed-keychain)
      delete_managed_keychain=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || fail "macOS is required."
[[ "$bin_dir" == /* ]] || fail "the install directory must be an absolute path."
[[ "$bin_dir" != "/" && "$bin_dir" != "$HOME" ]] \
  || fail "refusing to use a broad uninstall directory."

strip_managed_path_block() {
  local source="$1"
  local destination="$2"
  awk '
    $0 == "# >>> macop PATH >>>" {
      if (managed || saw_start) invalid = 1
      managed = 1
      saw_start = 1
      next
    }
    $0 == "# <<< macop PATH <<<" {
      if (!managed || saw_end) invalid = 1
      managed = 0
      saw_end = 1
      next
    }
    !managed { print }
    END {
      if (managed || saw_start != saw_end || invalid) exit 42
    }
  ' "$source" >"$destination"
}

remove_managed_path() {
  if [[ "$keep_path" == true ]]; then
    return
  fi
  if [[ -z "$shell_profile" ]]; then
    case "${SHELL##*/}" in
      zsh) shell_profile="$HOME/.zprofile" ;;
      bash) shell_profile="$HOME/.bash_profile" ;;
      *) return ;;
    esac
  fi
  [[ "$shell_profile" == /* ]] || fail "the shell profile must be an absolute path."
  if [[ ! -e "$shell_profile" ]]; then
    return
  fi
  [[ ! -L "$shell_profile" && -f "$shell_profile" ]] \
    || fail "refusing to edit a symlink or non-file shell profile: $shell_profile"
  if ! grep -Fqx '# >>> macop PATH >>>' "$shell_profile"; then
    return
  fi
  local profile_directory temporary_profile original_mode
  profile_directory="$(dirname "$shell_profile")"
  temporary_profile="$(mktemp "$profile_directory/.macop-profile.XXXXXX")"
  original_mode="$(stat -f '%Lp' "$shell_profile")"
  if ! strip_managed_path_block "$shell_profile" "$temporary_profile"; then
    rm -f "$temporary_profile"
    fail "managed PATH markers are malformed in $shell_profile"
  fi
  chmod "$original_mode" "$temporary_profile"
  mv -f "$temporary_profile" "$shell_profile"
  printf 'Removed managed PATH entry from %s\n' "$shell_profile"
}

validate_managed_path_removal() {
  if [[ "$keep_path" == true ]]; then
    return
  fi
  if [[ -z "$shell_profile" ]]; then
    case "${SHELL##*/}" in
      zsh) shell_profile="$HOME/.zprofile" ;;
      bash) shell_profile="$HOME/.bash_profile" ;;
      *) return ;;
    esac
  fi
  [[ "$shell_profile" == /* ]] || fail "the shell profile must be an absolute path."
  if [[ ! -e "$shell_profile" ]]; then
    return
  fi
  [[ ! -L "$shell_profile" && -f "$shell_profile" ]] \
    || fail "refusing to edit a symlink or non-file shell profile: $shell_profile"
  if ! strip_managed_path_block "$shell_profile" /dev/null; then
    fail "managed PATH markers are malformed in $shell_profile"
  fi
}

validate_managed_path_removal

if [[ ! -e "$bin_dir" ]]; then
  if [[ "$delete_managed_keychain" == true ]]; then
    fail "cannot delete managed Keychain items because $bin_dir does not exist."
  fi
  remove_managed_path
  printf 'Nothing to uninstall: %s does not exist.\n' "$bin_dir"
  exit 0
fi
[[ -d "$bin_dir" ]] || fail "install path is not a directory: $bin_dir"
[[ "$(stat -f '%u' "$bin_dir")" == "$(id -u)" ]] \
  || fail "install directory must be owned by the current user."

delete_managed_keychain_items() {
  if [[ "$delete_managed_keychain" != true ]]; then
    return
  fi
  local macop_path="$bin_dir/macop"
  local auth_app_path="$bin_dir/MacopAuth.app"
  [[ ! -L "$macop_path" && -f "$macop_path" && -x "$macop_path" ]] \
    || fail "managed Keychain deletion requires the installed macop executable."
  [[ ! -L "$auth_app_path" && -d "$auth_app_path" ]] \
    || fail "managed Keychain deletion requires the installed MacopAuth.app."
  local macop_identifier auth_identifier
  macop_identifier="$(codesign -d --verbose=4 "$macop_path" 2>&1 | sed -n 's/^Identifier=//p' | head -n 1)"
  auth_identifier="$(codesign -d --verbose=4 "$auth_app_path" 2>&1 | sed -n 's/^Identifier=//p' | head -n 1)"
  [[ "$macop_identifier" == "macop" ]] \
    || fail "refusing Keychain deletion because the macop code-signing identifier is unexpected."
  [[ "$auth_identifier" == "io.github.slashkiko.macop.auth" ]] \
    || fail "refusing Keychain deletion because the MacopAuth.app identifier is unexpected."
  "$macop_path" item delete --all-managed
  printf '%s\n' 'Deleted all macop-managed Keychain items.'
}

delete_managed_keychain_items

op_path="$bin_dir/op"
if [[ -L "$op_path" ]]; then
  op_target="$(readlink "$op_path")"
  if [[ "$op_target" == "macop" || "$op_target" == "$bin_dir/macop" ]]; then
    rm -f "$op_path"
    printf 'Removed %s\n' "$op_path"
  else
    printf 'Preserved unrelated op symlink: %s -> %s\n' "$op_path" "$op_target"
  fi
elif [[ -e "$op_path" ]]; then
  printf 'Preserved unrelated op command: %s\n' "$op_path"
fi

remove_signed_binary() {
  local path="$1"
  local expected_identifier="$2"
  if [[ ! -e "$path" ]]; then
    return
  fi
  [[ ! -L "$path" && -f "$path" ]] \
    || fail "refusing to remove a symlink or non-file: $path"
  local identifier
  identifier="$(codesign -d --verbose=4 "$path" 2>&1 | sed -n 's/^Identifier=//p' | head -n 1)"
  [[ "$identifier" == "$expected_identifier" ]] \
    || fail "refusing to remove $path because its code-signing identifier is not $expected_identifier."
  rm -f "$path"
  printf 'Removed %s\n' "$path"
}

remove_signed_binary "$bin_dir/macop-agent" "macop-agent"
remove_signed_binary "$bin_dir/macop" "macop"

auth_app="$bin_dir/MacopAuth.app"
if [[ -e "$auth_app" ]]; then
  [[ ! -L "$auth_app" && -d "$auth_app" ]] \
    || fail "refusing to remove a symlink or non-directory: $auth_app"
  auth_identifier="$(codesign -d --verbose=4 "$auth_app" 2>&1 | sed -n 's/^Identifier=//p' | head -n 1)"
  [[ "$auth_identifier" == "io.github.slashkiko.macop.auth" ]] \
    || fail "refusing to remove $auth_app because its code-signing identifier is unexpected."
  rm -rf "$auth_app"
  printf 'Removed %s\n' "$auth_app"
fi
remove_managed_path

if [[ "$delete_managed_keychain" == true ]]; then
  printf '%s\n' 'Preserved macop configuration, CTK identities, and the install directory.'
else
  printf '%s\n' 'Preserved macop configuration, Keychain items, CTK identities, and the install directory.'
fi
