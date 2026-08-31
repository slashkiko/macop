#!/bin/bash
set -euo pipefail

bin_dir="${MACOP_BIN_DIR:-$HOME/.local/bin}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install_fs="$script_dir/install-fs.py"
shell_profile="${MACOP_SHELL_PROFILE:-}"
keep_path=false
delete_managed_keychain=false
remove_data=false

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
  --remove-data          Delete the machine-local trusted Git client registry
  --help                 Show this help

The script preserves configuration, Keychain items, CTK identities, and the
trusted Git client registry by default. --remove-data removes only
~/Library/Application Support/macop/git-clients.json; it does not remove
config.json, Keychain items, or CTK identities.
--delete-managed-keychain requires the installed, signed macop and MacopAuth.app
and interactive macOS authentication. An op
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
    --remove-data)
      remove_data=true
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

remove_machine_local_data() {
  if [[ "$remove_data" != true ]]; then
    return
  fi
  local registry_directory="$HOME/Library/Application Support/macop"
  local registry_path="$registry_directory/git-clients.json"
  local registry_lock="$registry_directory/.git-clients.lock"
  if [[ ! -e "$registry_path" && ! -L "$registry_path" \
      && ! -e "$registry_lock" && ! -L "$registry_lock" ]]; then
    return
  fi
  [[ ! -L "$registry_directory" && -d "$registry_directory" ]] \
    || fail "refusing to remove data through an unsafe registry directory."
  [[ "$(stat -f '%u' "$registry_directory")" == "$(id -u)" \
      && "$(stat -f '%Lp' "$registry_directory")" == "700" ]] \
    || fail "trusted Git registry directory must be current-user-owned with mode 0700."
  local registry_was_present=false
  if [[ -e "$registry_path" || -L "$registry_path" ]]; then
    registry_was_present=true
  fi
  /usr/bin/perl -MFcntl=:DEFAULT,:flock -e '
    use strict; use warnings;
    my ($directory, $registry, $lock, $uid) = @ARGV;
    my @directory_stat = lstat($directory);
    die "unsafe registry directory\n" unless @directory_stat
      && (($directory_stat[2] & 0170000) == 0040000)
      && $directory_stat[4] == $uid && (($directory_stat[2] & 0777) == 0700);
    sysopen(my $lock_handle, $lock, O_RDWR | O_CREAT | O_NOFOLLOW, 0600)
      or die "unsafe registry lock\n";
    my @lock_stat = stat($lock_handle);
    die "unsafe registry lock metadata\n" unless @lock_stat
      && (($lock_stat[2] & 0170000) == 0100000)
      && $lock_stat[4] == $uid && (($lock_stat[2] & 0777) == 0600);
    flock($lock_handle, LOCK_EX) or die "cannot lock registry\n";
    exit 0 unless -e $registry || -l $registry;
    my @before = lstat($registry);
    die "unsafe registry file\n" unless @before
      && (($before[2] & 0170000) == 0100000)
      && $before[4] == $uid && (($before[2] & 0777) == 0600);
    sysopen(my $registry_handle, $registry, O_RDONLY | O_NOFOLLOW)
      or die "cannot open registry safely\n";
    my @after = stat($registry_handle);
    die "registry changed during removal\n" unless @after
      && $before[0] == $after[0] && $before[1] == $after[1];
    unlink($registry) or die "cannot remove registry\n";
  ' "$registry_directory" "$registry_path" "$registry_lock" "$(id -u)" \
    || fail "could not remove the trusted Git registry safely."
  if [[ "$registry_was_present" == true ]]; then
    printf 'Removed %s\n' "$registry_path"
    printf '%s\n' 'The protected Git trust state was intentionally retained. After reinstalling, run: macop ssh git-client reset'
  fi
}

if [[ ! -e "$bin_dir" ]]; then
  if [[ "$delete_managed_keychain" == true ]]; then
    fail "cannot delete managed Keychain items because $bin_dir does not exist."
  fi
  remove_machine_local_data
  remove_managed_path
  printf 'Nothing to uninstall: %s does not exist.\n' "$bin_dir"
  exit 0
fi
[[ -d "$bin_dir" ]] || fail "install path is not a directory: $bin_dir"
[[ "$(stat -f '%u' "$bin_dir")" == "$(id -u)" ]] \
  || fail "install directory must be owned by the current user."

if [[ "${MACOP_INSTALL_TEST_MODE:-0}" == "1" ]]; then
  canonical_test_bin_dir="$(cd -- "$bin_dir" 2>/dev/null && pwd -P)" \
    || fail "MACOP_INSTALL_TEST_MODE requires an existing real directory."
  [[ "$canonical_test_bin_dir" == /private/tmp/macop-install-test-*/* ]] \
    || fail "MACOP_INSTALL_TEST_MODE requires --bin-dir beneath /private/tmp/macop-install-test-*."
  [[ ! -L "$bin_dir" && "$(stat -f '%u:%Lp' "$bin_dir")" == "$(id -u):700" ]] \
    || fail "MACOP_INSTALL_TEST_MODE requires an owner-only non-symlink destination."
  state_dir="$bin_dir/.macop-install-state"
else
  state_dir="$HOME/Library/Application Support/macop/install-state"
fi
if [[ ! -e "$state_dir" && ! -L "$state_dir" ]]; then
  if [[ "${MACOP_INSTALL_TEST_MODE:-0}" == "1" ]]; then
    bin_id="$(python3 "$install_fs" id "$bin_dir")" \
      || fail "cannot retain install directory identity."
    python3 "$install_fs" mkdir "$bin_dir" "$bin_id" .macop-install-state 700 \
      || fail "cannot create uninstall state for a legacy installation."
  else
    state_parent="$(dirname "$state_dir")"
    if [[ ! -e "$state_parent" && ! -L "$state_parent" ]]; then
      install -d -m 700 "$state_parent" \
        || fail "cannot create uninstall state parent for a legacy installation."
    fi
    [[ ! -L "$state_parent" && -d "$state_parent" \
        && "$(stat -f '%u:%Lp' "$state_parent")" == "$(id -u):700" ]] \
      || fail "uninstall state parent must be current-user-owned, owner-only, and not a symlink: $state_parent"
    state_parent_id="$(python3 "$install_fs" id "$state_parent")" \
      || fail "cannot retain uninstall state parent identity."
    python3 "$install_fs" mkdir "$state_parent" "$state_parent_id" install-state 700 \
      || fail "cannot create uninstall state for a legacy installation."
  fi
fi
[[ ! -L "$state_dir" && -d "$state_dir" && "$(stat -f '%u:%Lp' "$state_dir")" == "$(id -u):700" ]] \
  || fail "installer state directory must be current-user-owned, owner-only, and not a symlink: $state_dir"
state_id="$(python3 "$install_fs" id "$state_dir")" || fail "cannot validate installer state directory."
uninstall_lock_id=""
release_uninstall_lock_pause() {
  local point="$1"
  [[ "${MACOP_INSTALL_TEST_MODE:-0}" == "1" && "${MACOP_INSTALL_TEST_RELEASE_PAUSE_AT:-}" == "uninstaller-$point" ]] || return 0
  printf 'macop uninstall test: pause at uninstaller-%s\n' "$point" >&2
  sleep "${MACOP_INSTALL_TEST_RELEASE_PAUSE_SECONDS:-2}"
}
owner_record_pause() {
  local point="$1"
  [[ "${MACOP_INSTALL_TEST_MODE:-0}" == "1" && "${MACOP_INSTALL_TEST_LOCK_OWNER_PAUSE_AT:-}" == "uninstaller-$point" ]] || return 0
  printf 'macop uninstall test: pause at uninstaller-%s\n' "$point" >&2
  sleep "${MACOP_INSTALL_TEST_LOCK_OWNER_PAUSE_SECONDS:-2}"
}
release_uninstall_lock() {
  local retired_lock_leaf
  [[ -n "$uninstall_lock_id" ]] || return
  # The original PID remains in the visible lock through the atomic handoff.
  # That prevents a concurrent installer from reclaiming it as PID-less before
  # this process has bound cleanup to its own retired directory identity.
  release_uninstall_lock_pause retire-before
  retired_lock_leaf="$(python3 "$install_fs" retire-child "$state_dir" "$state_id" lock "$uninstall_lock_id" retired-lock.)" \
    || return
  release_uninstall_lock_pause retire-after
  python3 "$install_fs" remove-child "$state_dir" "$state_id" "$retired_lock_leaf" "$uninstall_lock_id" pid file >/dev/null 2>&1 || return
  python3 "$install_fs" rmdir-child "$state_dir" "$state_id" "$retired_lock_leaf" "$uninstall_lock_id" >/dev/null 2>&1 || return
  uninstall_lock_id=""
}

if ! python3 "$install_fs" mkdir "$state_dir" "$state_id" lock 700 2>/dev/null; then
  lock_id="$(python3 "$install_fs" child-id "$state_dir" "$state_id" lock dir)" \
    || fail "refusing to inspect an unsafe installer lock."
  if ! lock_pid="$(python3 "$install_fs" read-child "$state_dir" "$state_id" lock "$lock_id" pid 2>/dev/null)"; then
    if python3 "$install_fs" absent-child "$state_dir" "$state_id" lock "$lock_id" pid >/dev/null 2>&1; then
      fail "installer lock is missing its owner PID record; manual recovery is required: $state_dir/lock"
    fi
    fail "refusing to inspect an unsafe installer lock."
  fi
  if [[ "$lock_pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
    fail "a macop install transaction is active (pid $lock_pid)."
  fi
  [[ "$lock_pid" =~ ^[1-9][0-9]*$ ]] \
    || fail "installer lock PID record is malformed; manual recovery is required: $state_dir/lock"
  retired_lock_leaf="$(python3 "$install_fs" retire-child "$state_dir" "$state_id" lock "$lock_id" retired-lock.)" \
    || fail "cannot retire stale installer lock: $state_dir/lock"
  python3 "$install_fs" remove-child "$state_dir" "$state_id" "$retired_lock_leaf" "$lock_id" pid file \
    || fail "cannot remove stale installer PID record: $state_dir/lock"
  python3 "$install_fs" rmdir-child "$state_dir" "$state_id" "$retired_lock_leaf" "$lock_id" \
    || fail "cannot recover stale installer lock: $state_dir/lock"
  python3 "$install_fs" mkdir "$state_dir" "$state_id" lock 700 \
    || fail "cannot acquire uninstall lock after stale-lock recovery."
fi
owner_record_pause after-lock-mkdir
uninstall_lock_id="$(python3 "$install_fs" child-id "$state_dir" "$state_id" lock dir)" \
  || fail "cannot validate uninstall lock."
python3 "$install_fs" record-child "$state_dir" "$state_id" lock "$uninstall_lock_id" pid "$$"$'\n' \
  || fail "cannot create uninstall lock."
trap release_uninstall_lock EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# Never interpret missing or malformed recovery evidence as permission to
# delete a generation. These checks keep the state directory as their
# authority and inspect only direct leaves through its validated descriptor.
python3 "$install_fs" absent "$state_dir" "$state_id" pending \
  || fail "transaction recovery is required before uninstalling: $state_dir/pending"
for journal in "$state_dir"/journal.*; do
  [[ -e "$journal" || -L "$journal" ]] || continue
  [[ ! -L "$journal" && -d "$journal" \
      && "$(stat -f '%u:%Lp' "$journal")" == "$(id -u):700" ]] \
    || fail "transaction recovery is required before uninstalling: unsafe transaction journal $journal"
  terminal_marker=""
  terminal_value=""
  if [[ -e "$journal/COMMITTED" ]]; then
    terminal_marker="COMMITTED"
    terminal_value="committed"
  fi
  if [[ -e "$journal/ROLLED_BACK" ]]; then
    [[ -z "$terminal_marker" ]] \
      || fail "transaction recovery is required before uninstalling: conflicting terminal markers in $journal"
    terminal_marker="ROLLED_BACK"
    terminal_value="rolled-back"
  fi
  [[ -n "$terminal_marker" && ! -e "$journal/ROLLBACK_INCOMPLETE" \
      && ! -L "$journal/$terminal_marker" && -f "$journal/$terminal_marker" \
      && "$(stat -f '%u:%Lp' "$journal/$terminal_marker")" == "$(id -u):600" \
      && "$(cat "$journal/$terminal_marker")" == "$terminal_value" ]] \
    || fail "transaction recovery is required before uninstalling: retained transaction journal in $state_dir"
  python3 "$install_fs" remove "$state_dir" "$state_id" "$(basename "$journal")" dir \
    || fail "cannot remove completed transaction journal before uninstalling: $journal"
done
python3 "$install_fs" absent-prefix "$state_dir" "$state_id" journal. \
  || fail "transaction recovery is required before uninstalling: retained transaction journal in $state_dir"

remove_machine_local_data

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

install_manifest="$bin_dir/macop-install-manifest.json"
if [[ -e "$install_manifest" || -L "$install_manifest" ]]; then
  if [[ ! -L "$install_manifest" && -f "$install_manifest" ]] \
      && grep -Fqx '  "schema_version": 1,' "$install_manifest" \
      && { grep -Fqx '  "broker_protocol_version": 7,' "$install_manifest" \
        || grep -Fqx '  "broker_protocol_version": 8,' "$install_manifest" \
        || grep -Fqx '  "broker_protocol_version": 9,' "$install_manifest"; }; then
    rm -f -- "$install_manifest"
    printf 'Removed %s\n' "$install_manifest"
  else
    printf 'Preserved unrecognized generation manifest: %s\n' "$install_manifest"
  fi
fi
remove_managed_path

if [[ "$delete_managed_keychain" == true ]]; then
  printf '%s\n' 'Preserved macop configuration, CTK identities, and the install directory.'
else
  printf '%s\n' 'Preserved macop configuration, Keychain items, CTK identities, and the install directory.'
fi
