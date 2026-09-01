#!/bin/bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
install_fs="$script_dir/install-fs.py"
[[ -x "$install_fs" || -f "$install_fs" ]] || { printf 'macop install: missing installer filesystem helper\n' >&2; exit 1; }
bin_dir="${MACOP_BIN_DIR:-$HOME/.local/bin}"
configuration="release"
run_checks=false
skip_build=false
with_op_symlink=false
configure_path=false
shell_profile="${MACOP_SHELL_PROFILE:-}"
signing_identity="${MACOP_SIGNING_IDENTITY:-}"
test_mode="${MACOP_INSTALL_TEST_MODE:-0}"
prepared_test_dir="${MACOP_INSTALL_TEST_PREPARED_DIR:-}"

usage() {
  cat <<'EOF'
Usage: scripts/build-install.sh [options]

Build, sign, verify, and install macop, macop-agent, and MacopAuth.app.

Options:
  --bin-dir <directory>       Install directory (default: ~/.local/bin)
  --configuration <value>    release or debug (default: release)
  --check                    Run make ci before building
  --skip-build               Install existing build artifacts
  --with-op-symlink          Create an op -> macop symlink if no op exists
  --configure-path           Add the install directory to the shell PATH
  --shell-profile <file>     Profile to manage (default: shell-specific)
  --signing-identity <name>  Required production certificate identity
  --help                     Show this help

Production installs require MACOP_SIGNING_IDENTITY (or --signing-identity)
and a regular matching MACOP_PROVISIONING_PROFILE. Ad-hoc signing is test-only.
MACOP_BIN_DIR and MACOP_SHELL_PROFILE may be used instead of their options.
EOF
}

fail() {
  printf 'macop install: %s\n' "$1" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)
      [[ $# -ge 2 ]] || fail "--bin-dir requires a value."
      bin_dir="$2"
      shift 2
      ;;
    --configuration)
      [[ $# -ge 2 ]] || fail "--configuration requires a value."
      configuration="$2"
      shift 2
      ;;
    --check)
      run_checks=true
      shift
      ;;
    --skip-build)
      skip_build=true
      shift
      ;;
    --with-op-symlink)
      with_op_symlink=true
      shift
      ;;
    --configure-path)
      configure_path=true
      shift
      ;;
    --shell-profile)
      [[ $# -ge 2 ]] || fail "--shell-profile requires a value."
      shell_profile="$2"
      shift 2
      ;;
    --signing-identity)
      [[ $# -ge 2 ]] || fail "--signing-identity requires a value."
      signing_identity="$2"
      shift 2
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

if [[ -n "$shell_profile" && "$configure_path" == false ]]; then
  fail "--shell-profile requires --configure-path."
fi

[[ "$(uname -s)" == "Darwin" ]] || fail "macOS is required."
[[ "$configuration" == "release" || "$configuration" == "debug" ]] \
  || fail "--configuration must be release or debug."
[[ "$bin_dir" == /* ]] || fail "the install directory must be an absolute path."
[[ "$bin_dir" != "/" && "$bin_dir" != "$HOME" ]] \
  || fail "refusing to use a broad install directory."
if [[ -n "$signing_identity" ]]; then
  [[ "$signing_identity" != "-" && "$signing_identity" != -* ]] \
    || fail "--signing-identity requires a named or hash codesigning identity, not ad-hoc signing."
fi

for command in awk chmod codesign cp date dirname find grep head id install kill make mkdir mktemp mv \
  ps python3 readlink rm rmdir sed shasum stat tr uuidgen; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done

resolve_shell_profile() {
  if [[ -z "$shell_profile" ]]; then
    case "${SHELL##*/}" in
      zsh) shell_profile="$HOME/.zprofile" ;;
      bash) shell_profile="$HOME/.bash_profile" ;;
      *) fail "unable to select a shell profile; pass --shell-profile explicitly." ;;
    esac
  fi
  [[ "$shell_profile" == /* ]] || fail "the shell profile must be an absolute path."
  [[ ! -L "$shell_profile" ]] || fail "refusing to edit a symlinked shell profile: $shell_profile"
  [[ ! -e "$shell_profile" || -f "$shell_profile" ]] \
    || fail "shell profile is not a regular file: $shell_profile"
  local profile_directory
  profile_directory="$(dirname "$shell_profile")"
  [[ -d "$profile_directory" ]] || fail "shell profile directory does not exist: $profile_directory"
  [[ "$(stat -f '%u' "$profile_directory")" == "$(id -u)" ]] \
    || fail "shell profile directory must be owned by the current user."
}

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

validate_shell_profile_markers() {
  if [[ -e "$shell_profile" ]] && ! strip_managed_path_block "$shell_profile" /dev/null; then
    fail "managed PATH markers are malformed in $shell_profile"
  fi
}

configure_shell_path() {
  local profile_directory temporary_profile original_mode quoted_bin_dir
  profile_directory="$(dirname "$shell_profile")"
  temporary_profile="$(mktemp "$profile_directory/.macop-profile.XXXXXX")"
  original_mode="600"
  if [[ -e "$shell_profile" ]]; then
    original_mode="$(stat -f '%Lp' "$shell_profile")"
    if ! strip_managed_path_block "$shell_profile" "$temporary_profile"; then
      rm -f "$temporary_profile"
      fail "managed PATH markers are malformed in $shell_profile"
    fi
  fi
  printf -v quoted_bin_dir '%q' "$bin_dir"
  printf "\n%s\nexport PATH=%s:\"\$PATH\"\n%s\n" \
    '# >>> macop PATH >>>' "$quoted_bin_dir" '# <<< macop PATH <<<' \
    >>"$temporary_profile"
  chmod "$original_mode" "$temporary_profile"
  mv -f "$temporary_profile" "$shell_profile"
  printf 'Configured PATH in %s\n' "$shell_profile"
}

if [[ "$configure_path" == true ]]; then
  resolve_shell_profile
  validate_shell_profile_markers
fi

if [[ "$run_checks" == true ]]; then
  make -C "$repo_root" ci
fi

if [[ "$skip_build" == false ]]; then
  if [[ "$configuration" == "release" ]]; then
    make -C "$repo_root" release-build-install-products
  else
    make -C "$repo_root" build-install-products
  fi
fi

build_dir="$repo_root/.build/$configuration"
codesign_identity="${signing_identity:--}"
reuse_prepared_signatures=false
if [[ -n "$prepared_test_dir" ]]; then
  [[ "$test_mode" == "1" && "$skip_build" == true ]] \
    || fail "MACOP_INSTALL_TEST_PREPARED_DIR requires test mode and --skip-build."
  [[ "$prepared_test_dir" == /* && ! -L "$prepared_test_dir" && -d "$prepared_test_dir" ]] \
    || fail "MACOP_INSTALL_TEST_PREPARED_DIR must be an absolute non-symlink directory."
  canonical_prepared_test_dir="$(cd -- "$prepared_test_dir" 2>/dev/null && pwd -P)" \
    || fail "cannot canonicalize MACOP_INSTALL_TEST_PREPARED_DIR."
  [[ "$canonical_prepared_test_dir" == /private/tmp/macop-install-test-*/* \
      && "$(stat -f '%u:%Lp' "$prepared_test_dir")" == "$(id -u):700" ]] \
    || fail "MACOP_INSTALL_TEST_PREPARED_DIR must be owner-only beneath a real installer test root."
  source_macop="$prepared_test_dir/macop"
  source_agent="$prepared_test_dir/macop-agent"
  source_auth_app="$prepared_test_dir/MacopAuth.app"
  reuse_prepared_signatures=true
else
  MACOP_SIGNING_IDENTITY="$codesign_identity" bash "$repo_root/scripts/build-auth-app.sh" "$configuration"
  source_macop="$build_dir/macop"
  source_agent="$build_dir/macop-agent"
  source_auth_app="$build_dir/MacopAuth.app"
fi
[[ -x "$source_macop" ]] || fail "missing build artifact: $source_macop"
[[ -x "$source_agent" ]] || fail "missing build artifact: $source_agent"
[[ -d "$source_auth_app" ]] || fail "missing app bundle: $source_auth_app"

if [[ ! -e "$bin_dir" ]]; then
  if [[ "${MACOP_INSTALL_TEST_MODE:-0}" == "1" ]]; then
    install -d -m 700 "$bin_dir"
  else
    install -d -m 755 "$bin_dir"
  fi
fi
[[ -d "$bin_dir" ]] || fail "install path is not a directory: $bin_dir"
[[ "$(stat -f '%u' "$bin_dir")" == "$(id -u)" ]] \
  || fail "install directory must be owned by the current user."
bin_dir_id="$(python3 "$install_fs" id "$bin_dir")" || fail "cannot retain install directory identity."

destination_macop="$bin_dir/macop"
destination_agent="$bin_dir/macop-agent"
destination_auth_app="$bin_dir/MacopAuth.app"
destination_manifest="$bin_dir/macop-install-manifest.json"
if [[ "${MACOP_INSTALL_TEST_MODE:-0}" == "1" ]]; then
  state_dir="$bin_dir/.macop-install-state"
else
  state_dir="$HOME/Library/Application Support/macop/install-state"
fi
if [[ ! -e "$state_dir" ]]; then
  if [[ "${MACOP_INSTALL_TEST_MODE:-0}" == "1" ]]; then
    python3 "$install_fs" mkdir "$bin_dir" "$bin_dir_id" .macop-install-state 700 \
      || fail "cannot create test install state directory."
  else
    state_parent="$(dirname "$state_dir")"
    state_parent_created=false
    if [[ ! -e "$state_parent" && ! -L "$state_parent" ]]; then
      install -d -m 700 "$state_parent" \
        || fail "cannot create install state parent."
      state_parent_created=true
    fi
    [[ ! -L "$state_parent" && -d "$state_parent" \
        && "$(stat -f '%u:%Lp' "$state_parent")" == "$(id -u):700" ]] \
      || fail "install state parent must be current-user-owned, owner-only, and not a symlink."
    state_parent_id="$(python3 "$install_fs" id "$state_parent")" \
      || fail "cannot retain install state parent identity."
    if [[ "$state_parent_created" == true ]]; then
      state_grandparent="$(dirname "$state_parent")"
      state_grandparent_id="$(python3 "$install_fs" id "$state_grandparent")" \
        || fail "cannot retain install state grandparent identity."
      python3 "$install_fs" sync "$state_grandparent" "$state_grandparent_id" \
        "$(basename "$state_parent")" dir \
        || fail "cannot make install state parent durable."
    fi
    python3 "$install_fs" mkdir "$state_parent" "$state_parent_id" "$(basename "$state_dir")" 700 \
      || fail "cannot create durable install state directory."
  fi
fi
[[ ! -L "$state_dir" && -d "$state_dir" && "$(stat -f '%u:%Lp' "$state_dir")" == "$(id -u):700" ]] \
  || fail "install state directory must be owner-only and not a symlink."
state_dir_id="$(python3 "$install_fs" id "$state_dir")" || fail "cannot retain install state directory identity."
canonical_bin_dir="$(cd -- "$bin_dir" && pwd -P)" || fail "cannot canonicalize install directory."
canonical_state_dir="$(cd -- "$state_dir" && pwd -P)" || fail "cannot canonicalize install state directory."
state_device="${state_dir_id%%:*}"
state_inode="${state_dir_id#*:}"
pending_marker="$state_dir/pending"
op_path="$bin_dir/op"

for destination in "$destination_macop" "$destination_agent" "$destination_manifest"; do
  [[ ! -L "$destination" ]] || fail "refusing to replace a symlink: $destination"
  [[ ! -e "$destination" || -f "$destination" ]] \
    || fail "refusing to replace a non-file: $destination"
done
if [[ -e "$destination_auth_app" ]]; then
  [[ ! -L "$destination_auth_app" && -d "$destination_auth_app" ]] \
    || fail "refusing to replace a symlink or non-directory: $destination_auth_app"
  installed_auth_identifier="$(codesign -d --verbose=4 "$destination_auth_app" 2>&1 | sed -n 's/^Identifier=//p' | head -n 1)"
  [[ "$installed_auth_identifier" == "io.github.slashkiko.macop.auth" ]] \
    || fail "refusing to replace an app with an unexpected code-signing identifier: $destination_auth_app"
fi

if [[ "$with_op_symlink" == true ]]; then
  if [[ -L "$op_path" ]]; then
    op_target="$(readlink "$op_path")"
    [[ "$op_target" == "macop" || "$op_target" == "$destination_macop" ]] \
      || fail "refusing to replace an op symlink that does not target macop: $op_path"
  elif [[ -e "$op_path" ]]; then
    fail "refusing to replace an existing op command: $op_path"
  fi
fi

# The lock is intentionally a sibling of the install generation.  mkdir is
# atomic on APFS; its PID record lets a later installer recover only locks held
# by a process that is definitely gone.  Test mode is deliberately constrained
# to a temporary root so failpoints can never target ~/.local/bin or /Applications.
if [[ "$test_mode" == "1" ]]; then
  # Tests must use the real system temporary volume. Never trust a caller's
  # TMPDIR/HOME as an authority for installer capability or destination scope.
  canonical_bin_dir="$(cd -- "$bin_dir" 2>/dev/null && pwd -P)" \
    || fail "MACOP_INSTALL_TEST_MODE requires an existing real directory."
  [[ "$canonical_bin_dir" == /private/tmp/macop-install-test-*/* ]] \
    || fail "MACOP_INSTALL_TEST_MODE requires --bin-dir beneath /private/tmp/macop-install-test-*."
  [[ ! -L "$bin_dir" && "$(stat -f '%u:%Lp' "$bin_dir")" == "$(id -u):700" ]] \
    || fail "MACOP_INSTALL_TEST_MODE requires an owner-only non-symlink destination."
elif [[ -n "${MACOP_INSTALL_FAILPOINT:-}${MACOP_INSTALL_TEST_HANDSHAKE:-}${MACOP_INSTALL_TEST_SKIP_FSYNC:-}${MACOP_INSTALL_TEST_PREPARED_DIR:-}" ]]; then
  fail "installer failpoints and test-only overrides require MACOP_INSTALL_TEST_MODE=1."
fi

if [[ "$test_mode" != "1" ]]; then
  [[ -n "$signing_identity" ]] \
    || fail "production installation requires --signing-identity; ad-hoc signing is build/test only."
  [[ -n "${MACOP_PROVISIONING_PROFILE:-}" && -f "${MACOP_PROVISIONING_PROFILE}" \
      && ! -L "${MACOP_PROVISIONING_PROFILE}" ]] \
    || fail "production installation requires a regular MACOP_PROVISIONING_PROFILE."
fi

lock_dir="$state_dir/lock"
journal_dir=""
journal_dir_id=""
lock_dir_id=""
staged_macop=""
staged_agent=""
staged_auth_app=""
staged_manifest=""
transaction_armed=false
transaction_committing=false
rollback_running=false
installer_verification_fd=""

# Journal records are crash-durable before a subsequent rename can alter an
# installed component.  `rename` is atomic, but not durable until both the
# record and its containing directory have been fsync'd.  This deliberately
# does not claim to survive every power-loss/cache failure; recovery rejects
# every ambiguous journal instead of guessing a destructive target.
atomic_record() {
  local path="$1" value="$2" directory leaf directory_id
  directory="$(dirname "$path")"; leaf="$(basename "$path")"
  directory_id="$(directory_identity "$directory")" || return 1
  python3 "$install_fs" record "$directory" "$directory_id" "$leaf" "$value"
}

directory_identity() {
  case "$1" in
    "$bin_dir") printf '%s\n' "$bin_dir_id" ;;
    "$state_dir") printf '%s\n' "$state_dir_id" ;;
    "$journal_dir") [[ -n "$journal_dir_id" ]] && printf '%s\n' "$journal_dir_id" ;;
    "$lock_dir") [[ -n "$lock_dir_id" ]] && printf '%s\n' "$lock_dir_id" ;;
    *) return 1 ;;
  esac
}

assert_retained_directories() {
  python3 "$install_fs" assert "$bin_dir" "$bin_dir_id" \
    && python3 "$install_fs" assert "$state_dir" "$state_dir_id" \
    && { [[ -z "$journal_dir" ]] || python3 "$install_fs" assert "$journal_dir" "$journal_dir_id"; }
}

# Fixture-only rendezvous for out-of-process pathname substitution tests.  The
# retained directory identities are checked both before and after the pause.
phase_guard() {
  local phase="$1"
  assert_retained_directories || fail "install root changed before $phase"
  if [[ "$test_mode" == "1" && "${MACOP_INSTALL_TEST_PAUSE_AT:-}" == "$phase" ]]; then
    printf 'macop install test: pause at %s\n' "$phase" >&2
    sleep "${MACOP_INSTALL_TEST_PAUSE_SECONDS:-2}"
  fi
  assert_retained_directories || fail "install root changed during $phase"
}

create_record() {
  local directory="$1" leaf="$2" value="$3"
  [[ "$leaf" != */* && -n "$leaf" ]] || return 1
  local directory_id
  directory_id="$(directory_identity "$directory")" || return 1
  python3 "$install_fs" record "$directory" "$directory_id" "$leaf" "$value"
}

remove_record() {
  local directory="$1" leaf="$2"
  [[ "$leaf" != */* && -n "$leaf" ]] || return 1
  local directory_id
  directory_id="$(directory_identity "$directory")" || return 1
  python3 "$install_fs" remove "$directory" "$directory_id" "$leaf" file
}

read_record() {
  local directory="$1" leaf="$2" directory_id
  directory_id="$(directory_identity "$directory")" || return 1
  python3 "$install_fs" read "$directory" "$directory_id" "$leaf"
}

safe_remove_file() {
  local path="$1"
  local directory leaf directory_id
  directory="$(dirname "$path")"; leaf="$(basename "$path")"
  directory_id="$(directory_identity "$directory")" || return 1
  python3 "$install_fs" remove "$directory" "$directory_id" "$leaf" file
}

safe_remove_directory() {
  local path="$1"
  local directory leaf directory_id
  directory="$(dirname "$path")"; leaf="$(basename "$path")"
  directory_id="$(directory_identity "$directory")" || return 1
  python3 "$install_fs" remove "$directory" "$directory_id" "$leaf" dir
}

release_lock_pause() {
  local point="$1"
  [[ "$test_mode" == "1" && "${MACOP_INSTALL_TEST_RELEASE_PAUSE_AT:-}" == "installer-$point" ]] || return 0
  printf 'macop install test: pause at installer-%s\n' "$point" >&2
  sleep "${MACOP_INSTALL_TEST_RELEASE_PAUSE_SECONDS:-2}"
}

# Fixture-only pause at the sole interval between atomically creating the
# visible lock directory and recording its owner. This proves that a PID-less
# lock is retained as recovery evidence rather than being claimed by another
# transaction.
owner_record_pause() {
  local point="$1"
  [[ "$test_mode" == "1" && "${MACOP_INSTALL_TEST_LOCK_OWNER_PAUSE_AT:-}" == "installer-$point" ]] || return 0
  printf 'macop install test: pause at installer-%s\n' "$point" >&2
  sleep "${MACOP_INSTALL_TEST_LOCK_OWNER_PAUSE_SECONDS:-2}"
}

release_lock() {
  local retired_lock_leaf
  if [[ -n "$lock_dir_id" ]]; then
    python3 "$install_fs" assert "$state_dir" "$state_dir_id" >/dev/null 2>&1 || return
    # Keep the PID in the visible lock until it is atomically renamed to an
    # unguessable retired leaf. Removing the PID first would let a concurrent
    # installer reclaim a PID-less lock and have its new lock recursively
    # removed by this cleanup trap.
    release_lock_pause retire-before
    retired_lock_leaf="$(python3 "$install_fs" retire-child "$state_dir" "$state_dir_id" lock "$lock_dir_id" retired-lock.)" \
      || return
    release_lock_pause retire-after
    python3 "$install_fs" remove-child "$state_dir" "$state_dir_id" "$retired_lock_leaf" "$lock_dir_id" pid file >/dev/null 2>&1 || return
    python3 "$install_fs" rmdir-child "$state_dir" "$state_dir_id" "$retired_lock_leaf" "$lock_dir_id" >/dev/null 2>&1 || return
    lock_dir_id=""
  fi
}

acquire_lock() {
  assert_retained_directories || fail "install root changed before lock acquisition."
  if ! python3 "$install_fs" mkdir "$state_dir" "$state_dir_id" lock 700 2>/dev/null; then
    # Do not publish an existing lock's identity to the EXIT cleanup trap.  A
    # competing installer that exits at either fail-closed branch below must
    # never retire the lock it merely inspected.  `lock_dir_id` becomes owned
    # only after this process has made a fresh visible lock and will write its
    # own PID record to it.
    local existing_lock_id
    existing_lock_id="$(python3 "$install_fs" child-id "$state_dir" "$state_dir_id" lock dir)" \
      || fail "install lock identity is unsafe: $lock_dir"
    local holder retired_lock_leaf
    if ! holder="$(python3 "$install_fs" read-child "$state_dir" "$state_dir_id" lock "$existing_lock_id" pid 2>/dev/null)"; then
      if python3 "$install_fs" absent-child "$state_dir" "$state_dir_id" lock "$existing_lock_id" pid >/dev/null 2>&1; then
        fail "installer lock is missing its owner PID record; manual recovery is required: $lock_dir"
      fi
      fail "install lock has unsafe PID record: $lock_dir"
    fi
    if [[ "$holder" =~ ^[1-9][0-9]*$ ]] && kill -0 "$holder" 2>/dev/null; then
      fail "another macop installer is active for $bin_dir (pid $holder)."
    fi
    # Only a validated numeric record for a dead process is stale. A missing
    # or malformed owner record may be an owner still in the mkdir-to-record
    # interval, so it must remain for explicit manual recovery.
    [[ "$holder" =~ ^[1-9][0-9]*$ ]] || fail "install lock PID record is malformed: $lock_dir"
    retired_lock_leaf="$(python3 "$install_fs" retire-child "$state_dir" "$state_dir_id" lock "$existing_lock_id" retired-lock.)" \
      || fail "cannot retire stale installer lock: $lock_dir"
    python3 "$install_fs" remove-child "$state_dir" "$state_dir_id" "$retired_lock_leaf" "$existing_lock_id" pid file \
      || fail "cannot remove stale installer PID record: $lock_dir"
    python3 "$install_fs" rmdir-child "$state_dir" "$state_dir_id" "$retired_lock_leaf" "$existing_lock_id" \
      || fail "cannot recover stale installer lock: $lock_dir"
    python3 "$install_fs" mkdir "$state_dir" "$state_dir_id" lock 700 || fail "cannot acquire installer lock: $lock_dir"
  fi
  owner_record_pause after-lock-mkdir
  lock_dir_id="$(python3 "$install_fs" child-id "$state_dir" "$state_dir_id" lock dir)" || fail "cannot retain installer lock identity."
  python3 "$install_fs" record-child "$state_dir" "$state_dir_id" lock "$lock_dir_id" pid "$$"$'\n' \
    || fail "cannot create installer PID record."
}

failpoint() {
  local point="$1"
  [[ "$test_mode" == "1" ]] || return 0
  local configured=",${MACOP_INSTALL_FAILPOINT:-},"
  if [[ "$configured" == *",$point,"* ]]; then
    printf 'macop install: injected failpoint: %s\n' "$point" >&2
    return 97
  fi
  local signal_point="${MACOP_INSTALL_SIGNAL_FAILPOINT:-}"
  if [[ "$signal_point" == "$point" ]]; then
    local signal_name="${MACOP_INSTALL_SIGNAL:-TERM}"
    kill -s "$signal_name" "$$"
  fi
}

record_initial_state() {
  local name="$1" destination="$2"
  if [[ -e "$destination" ]]; then
    create_record "$journal_dir" "$name.initial" $'present\n'
  else
    create_record "$journal_dir" "$name.initial" $'absent\n'
  fi
}

backup_path_for() {
  local name="$1"
  printf '%s/backup-%s\n' "$journal_dir" "$name"
}

remove_destination() {
  local name="$1" destination="$2"
  local leaf
  leaf="$(basename "$destination")"
  assert_retained_directories || return 1
  python3 "$install_fs" exists "$bin_dir" "$bin_dir_id" "$leaf" "$( [[ "$name" == auth_app ]] && printf dir || printf file )" >/dev/null 2>&1 || return 0
  case "$name" in
    auth_app) python3 "$install_fs" remove "$bin_dir" "$bin_dir_id" "$leaf" dir ;;
    *) python3 "$install_fs" remove "$bin_dir" "$bin_dir_id" "$leaf" file ;;
  esac
}

rollback_transaction() {
  [[ "$transaction_armed" == true && "$rollback_running" == false ]] || return 0
  rollback_running=true
  set +e
  local failures=() name destination backup initial
  for name in manifest auth_app agent macop; do
    phase_guard "rollback-$name"
    case "$name" in
      macop) destination="$destination_macop" ;;
      agent) destination="$destination_agent" ;;
      auth_app) destination="$destination_auth_app" ;;
      manifest) destination="$destination_manifest" ;;
    esac
    backup="$(read_record "$journal_dir" "$name.backup" 2>/dev/null | sed -n '1p')"
    initial="$(read_record "$journal_dir" "$name.initial" 2>/dev/null | sed -n '1p')"
    if [[ "$backup" != "-" ]]; then
      [[ "$backup" == "$journal_dir/backup-$name" && ! -L "$backup" ]] \
        || { failures+=("$destination (unsafe backup path)"); continue; }
    fi
    if [[ -n "$backup" && -e "$backup" ]]; then
      remove_destination "$name" "$destination" || failures+=("$destination (cannot remove published component)")
      if ! failpoint "rollback-restore-$name-before"; then
        failures+=("$destination (backup retained at $backup)")
      elif [[ ! -e "$destination" ]] \
        && python3 "$install_fs" rename "$journal_dir" "$journal_dir_id" "backup-$name" "$bin_dir" "$bin_dir_id" "$(basename "$destination")"; then :; else
        failures+=("$destination (backup retained at $backup)")
      fi
    elif [[ "$initial" == "absent" ]]; then
      remove_destination "$name" "$destination" || failures+=("$destination (cannot remove newly published component)")
    elif [[ "$initial" == "present" ]]; then
      # A signal/failpoint can land after the durable initial marker but before
      # the first rename. The still-present destination is authoritative then.
      [[ -e "$destination" ]] || failures+=("$destination (missing backup; retained for recovery)")
    fi
  done
  if ((${#failures[@]})); then
    printf 'macop install: rollback incomplete: %s\n' "${failures[*]}" >&2
    create_record "$journal_dir" ROLLBACK_INCOMPLETE $'rollback-incomplete\n' || true
  else
    create_record "$journal_dir" ROLLED_BACK $'rolled-back\n' \
      || failures+=("$journal_dir/ROLLED_BACK (cannot record completed rollback)")
    if ((${#failures[@]} == 0)); then
      remove_record "$state_dir" pending || failures+=("$pending_marker (cannot remove public pending marker)")
      remove_record "$journal_dir" PENDING || failures+=("$journal_dir/PENDING (cannot remove journal pending marker)")
    fi
    if ((${#failures[@]} == 0)); then
      safe_remove_directory "$journal_dir" || failures+=("$journal_dir (cannot remove completed rollback journal)")
    fi
  fi
  transaction_armed=false
  if ((${#failures[@]})); then
    printf 'macop install: rollback cleanup incomplete: %s\n' "${failures[*]}" >&2
  else
    journal_dir=""
    journal_dir_id=""
  fi
  set -e
  return 1
}

recover_interrupted_transactions() {
  local candidate marker terminal_marker terminal_value pending_value canonical_candidate
  validate_interrupted_journal() {
    local candidate="$1" name entry initial backup expected_backup phase phase_rank required_rank transaction_record
    [[ "$(stat -f '%u:%Lp' "$candidate")" == "$(id -u):700" ]] || return 1
    transaction_record="$(read_record "$candidate" transaction)" || return 1
    [[ "$transaction_record" == $'schema_version=2\nwire_protocol=7\ncomponents=macop,agent,auth_app,manifest' \
        || "$transaction_record" == $'schema_version=2\nwire_protocol=8\ncomponents=macop,agent,auth_app,manifest' \
        || "$transaction_record" == $'schema_version=2\nwire_protocol=9\ncomponents=macop,agent,auth_app,manifest' ]] \
      || return 1
    [[ "$(read_record "$candidate" PENDING)" == "pending" ]] || return 1
    phase="$(read_record "$candidate" phase)" || return 1
    case "$phase" in
      initialized|backup:macop:prepared|backup:macop:done|backup:agent:prepared|backup:agent:done|backup:auth_app:prepared|backup:auth_app:done|backup:manifest:prepared|backup:manifest:done|publish:macop:prepared|publish:macop:done|publish:agent:prepared|publish:agent:done|publish:auth_app:prepared|publish:auth_app:done|publish:manifest:prepared|publish:manifest:done|verification:prepared) ;;
      *) return 1 ;;
    esac
    case "$phase" in
      initialized) phase_rank=0 ;;
      backup:macop:prepared) phase_rank=1 ;; backup:macop:done) phase_rank=2 ;;
      backup:agent:prepared) phase_rank=3 ;; backup:agent:done) phase_rank=4 ;;
      backup:auth_app:prepared) phase_rank=5 ;; backup:auth_app:done) phase_rank=6 ;;
      backup:manifest:prepared) phase_rank=7 ;; backup:manifest:done|publish:*|verification:prepared) phase_rank=8 ;;
    esac
    for name in macop agent auth_app manifest; do
      initial="$(read_record "$candidate" "$name.initial")" || return 1
      backup="$(read_record "$candidate" "$name.backup")" || return 1
      [[ "$initial" == present || "$initial" == absent ]] || return 1
      expected_backup="$candidate/backup-$name"
      if [[ "$initial" == present ]]; then
        [[ "$backup" == "$expected_backup" ]] || return 1
        case "$name" in macop) required_rank=2 ;; agent) required_rank=4 ;; auth_app) required_rank=6 ;; manifest) required_rank=8 ;; esac
        if (( phase_rank >= required_rank )); then
          case "$name" in
            auth_app) python3 "$install_fs" exists "$candidate" "$journal_dir_id" "backup-$name" dir >/dev/null || return 1 ;;
            *) python3 "$install_fs" exists "$candidate" "$journal_dir_id" "backup-$name" file >/dev/null || return 1 ;;
          esac
        fi
        # Once a completed backup transition is durable, later publish states
        # may not treat a destination as a substitute for the old generation.
        : # the fd-relative check above is authoritative for completed backups
      else
        [[ "$backup" == "-" ]] || return 1
        python3 "$install_fs" absent "$candidate" "$journal_dir_id" "backup-$name" || return 1
      fi
    done
    # Closed schema: a truncated record or an unknown leaf is not evidence
    # from which recovery may infer a destination to delete.
    while IFS= read -r entry; do
      case "${entry##*/}" in
        transaction|PENDING|phase|INSTALLER_CAPABILITY|macop.initial|agent.initial|auth_app.initial|manifest.initial|macop.backup|agent.backup|auth_app.backup|manifest.backup|backup-macop|backup-agent|backup-auth_app|backup-manifest) ;;
        *) return 1 ;;
      esac
    done < <(find "$candidate" -mindepth 1 -maxdepth 1 -print)
  }
  for candidate in "$state_dir"/journal.*; do
    python3 "$install_fs" assert "$state_dir" "$state_dir_id" || fail "install state directory changed during recovery."
    [[ -e "$candidate" ]] || continue
    [[ ! -L "$candidate" && -d "$candidate" ]] \
      || fail "refusing unsafe interrupted transaction journal: $candidate"
    [[ "$(stat -f '%u:%Lp' "$candidate")" == "$(id -u):700" ]] \
      || fail "interrupted transaction journal has unsafe ownership or mode: $candidate"
    terminal_marker=""
    terminal_value=""
    if [[ -e "$candidate/COMMITTED" ]]; then
      terminal_marker="COMMITTED"
      terminal_value="committed"
    fi
    if [[ -e "$candidate/ROLLED_BACK" ]]; then
      [[ -z "$terminal_marker" ]] \
        || fail "transaction journal has conflicting terminal markers: $candidate"
      terminal_marker="ROLLED_BACK"
      terminal_value="rolled-back"
    fi
    if [[ -n "$terminal_marker" ]]; then
      [[ ! -L "$candidate/$terminal_marker" && -f "$candidate/$terminal_marker" \
          && "$(stat -f '%u:%Lp' "$candidate/$terminal_marker")" == "$(id -u):600" \
          && "$(cat "$candidate/$terminal_marker")" == "$terminal_value" ]] \
        || fail "transaction terminal marker is unsafe or malformed: $candidate/$terminal_marker"
      [[ ! -e "$candidate/ROLLBACK_INCOMPLETE" ]] \
        || fail "terminal transaction journal also reports an incomplete rollback: $candidate"
      canonical_candidate="$(cd -- "$candidate" && pwd -P)" \
        || fail "cannot canonicalize terminal transaction journal: $candidate"
      if [[ -e "$state_dir/pending" ]]; then
        pending_value="$(read_record "$state_dir" pending)" \
          || fail "public pending marker is unsafe during terminal recovery: $state_dir/pending"
        [[ "$pending_value" == *$'\njournal='"$canonical_candidate"$'\n'* \
            || "$pending_value" == journal="$canonical_candidate"$'\n'* ]] \
          || fail "public pending marker does not belong to terminal transaction: $candidate"
        remove_record "$state_dir" pending \
          || fail "cannot remove terminal transaction pending marker: $state_dir/pending"
      fi
      journal_dir="$candidate"
      journal_dir_id="$(python3 "$install_fs" id "$journal_dir")" \
        || fail "terminal journal identity changed before cleanup."
      safe_remove_directory "$candidate" \
        || fail "cannot remove terminal transaction journal: $candidate"
      journal_dir=""
      journal_dir_id=""
      continue
    fi
    marker="$candidate/PENDING"
    if [[ -e "$marker" ]]; then
      [[ ! -L "$marker" && -f "$marker" ]] || fail "interrupted transaction marker is unsafe: $marker"
      journal_dir="$candidate"
      journal_dir_id="$(python3 "$install_fs" id "$journal_dir")" || fail "interrupted journal identity changed before recovery."
      validate_interrupted_journal "$candidate" \
        || fail "interrupted transaction journal is malformed or ambiguous; refusing recovery: $candidate"
      transaction_armed=true
      rollback_running=false
      rollback_transaction || true
      [[ ! -e "$candidate" ]] \
        || fail "interrupted transaction recovery is incomplete; backups were retained in $candidate"
      transaction_armed=false
      journal_dir=""
      journal_dir_id=""
    elif [[ -e "$candidate/ROLLBACK_INCOMPLETE" ]]; then
      fail "previous rollback is incomplete; recover retained backups in $candidate before installing"
    fi
  done
}

cleanup() {
  local status=$?
  if [[ "$transaction_armed" == true && "$transaction_committing" == false ]]; then
    rollback_transaction || true
    status=1
  fi
  [[ -z "$staged_macop" || ! -e "$staged_macop" ]] || safe_remove_file "$staged_macop" || true
  [[ -z "$staged_agent" || ! -e "$staged_agent" ]] || safe_remove_file "$staged_agent" || true
  [[ -z "$staged_manifest" || ! -e "$staged_manifest" ]] || safe_remove_file "$staged_manifest" || true
  [[ -z "$staged_auth_app" || ! -e "$staged_auth_app" ]] || safe_remove_directory "$staged_auth_app" || true
  release_lock
  exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

acquire_lock
recover_interrupted_transactions
if [[ "$test_mode" == "1" && "${MACOP_INSTALL_TEST_HOLD_LOCK_SECONDS:-0}" =~ ^[1-9][0-9]*$ ]]; then
  sleep "$MACOP_INSTALL_TEST_HOLD_LOCK_SECONDS"
fi
journal_leaf="$(python3 "$install_fs" mktemp "$state_dir" "$state_dir_id" journal. dir)" \
  || fail "cannot create transaction journal"
journal_dir="$state_dir/$journal_leaf"
journal_dir_id="$(python3 "$install_fs" id "$journal_dir")" || fail "cannot retain transaction journal identity."
journal_device="${journal_dir_id%%:*}"
journal_inode="${journal_dir_id#*:}"
canonical_journal_dir="$(cd -- "$journal_dir" && pwd -P)" || fail "cannot canonicalize transaction journal."
create_record "$journal_dir" transaction $'schema_version=2\nwire_protocol=9\ncomponents=macop,agent,auth_app,manifest\n'
for component in macop agent auth_app manifest; do
  case "$component" in
    macop) record_initial_state "$component" "$destination_macop" ;;
    agent) record_initial_state "$component" "$destination_agent" ;;
    auth_app) record_initial_state "$component" "$destination_auth_app" ;;
    manifest) record_initial_state "$component" "$destination_manifest" ;;
  esac
  initial="$(read_record "$journal_dir" "$component.initial")"
  if [[ "$initial" == present ]]; then
    create_record "$journal_dir" "$component.backup" "$(backup_path_for "$component")"$'\n'
  else
    create_record "$journal_dir" "$component.backup" $'-\n'
  fi
done
create_record "$journal_dir" phase $'initialized\n'
installer_nonce="$(uuidgen | tr '[:upper:]' '[:lower:]')"
[[ "$installer_nonce" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
  || fail "cannot create installer capability nonce."
installer_capability=$'schema=1\nstate='"$canonical_state_dir"$'\nstate_device='"$state_device"$'\nstate_inode='"$state_inode"$'\njournal='"$canonical_journal_dir"$'\njournal_device='"$journal_device"$'\njournal_inode='"$journal_inode"$'\nnonce='"$installer_nonce"$'\noperations=generation,broker,auth-probe\nmacop_executable='"$canonical_bin_dir/macop"$'\nauth_executable='"$canonical_bin_dir/MacopAuth.app/Contents/MacOS/MacopAuth"$'\n'
create_record "$journal_dir" INSTALLER_CAPABILITY "$installer_capability"
create_record "$journal_dir" PENDING $'pending\n'
pending_capability=$'schema=1\nnonce='"$installer_nonce"$'\njournal='"$canonical_journal_dir"$'\nstate_device='"$state_device"$'\nstate_inode='"$state_inode"$'\n'
create_record "$state_dir" pending "$pending_capability"
transaction_armed=true

staged_macop="$bin_dir/$(python3 "$install_fs" mktemp "$bin_dir" "$bin_dir_id" .macop.install. file)"
staged_agent="$bin_dir/$(python3 "$install_fs" mktemp "$bin_dir" "$bin_dir_id" .macop-agent.install. file)"
staged_auth_app="$bin_dir/$(python3 "$install_fs" mktemp "$bin_dir" "$bin_dir_id" .MacopAuth.install. dir)"
staged_manifest="$bin_dir/$(python3 "$install_fs" mktemp "$bin_dir" "$bin_dir_id" .macop-install-manifest.install. file)"
phase_guard staging

install -m 755 "$source_macop" "$staged_macop"
install -m 755 "$source_agent" "$staged_agent"
cp -R "$source_auth_app/Contents" "$staged_auth_app/Contents"
if [[ "$reuse_prepared_signatures" == false ]]; then
  codesign --force --options runtime --sign "$codesign_identity" --identifier macop "$staged_macop"
  codesign --force --options runtime --sign "$codesign_identity" --identifier macop-agent "$staged_agent"
fi
codesign --verify --strict "$staged_macop"
codesign --verify --strict "$staged_agent"
codesign --verify --deep --strict "$staged_auth_app"

read_identifier() {
  codesign -d --verbose=4 "$1" 2>&1 | sed -n 's/^Identifier=//p' | head -n 1
}

read_team_id() {
  codesign -d --verbose=4 "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -n 1
}

read_cdhash() {
  codesign -d --verbose=4 "$1" 2>&1 | sed -n 's/^CDHash=//p' | head -n 1
}

require_hardened_runtime() {
  local target="$1"
  local flags
  flags="$(codesign -d --verbose=4 "$target" 2>&1 \
    | sed -n 's/^CodeDirectory .* flags=\(0x[0-9A-Fa-f]*\).*/\1/p' \
    | head -n 1)"
  [[ "$flags" =~ ^0x[0-9A-Fa-f]+$ ]] \
    || fail "unable to read code-signing flags from $target"
  (( (flags & 0x10000) != 0 )) \
    || fail "hardened runtime readback failed for $target"
  if codesign -d --entitlements :- "$target" 2>/dev/null \
      | grep -Fq 'com.apple.security.cs.disable-library-validation'; then
    fail "library validation must not be disabled for $target"
  fi
}

[[ "$(read_identifier "$staged_macop")" == "macop" ]] || fail "macop identifier readback failed."
[[ "$(read_identifier "$staged_agent")" == "macop-agent" ]] || fail "macop-agent identifier readback failed."
[[ "$(read_identifier "$staged_auth_app")" == "io.github.slashkiko.macop.auth" ]] \
  || fail "MacopAuth identifier readback failed."
require_hardened_runtime "$staged_macop"
require_hardened_runtime "$staged_agent"
require_hardened_runtime "$staged_auth_app"
if [[ -n "$signing_identity" ]]; then
  macop_team="$(read_team_id "$staged_macop")"
  agent_team="$(read_team_id "$staged_agent")"
  auth_team="$(read_team_id "$staged_auth_app")"
  [[ -n "$macop_team" && "$macop_team" != "not set" && "$macop_team" == "$agent_team" \
      && "$macop_team" == "$auth_team" ]] \
    || fail "macop, macop-agent, and MacopAuth must have the same non-empty Team ID."
  if [[ -e "$destination_auth_app" ]]; then
    installed_auth_team="$(read_team_id "$destination_auth_app")"
    [[ -n "$installed_auth_team" && "$installed_auth_team" != "not set" \
        && "$auth_team" == "$installed_auth_team" ]] \
      || fail "MacopAuth update must preserve the installed companion Team ID."
  fi
fi

sha256() { shasum -a 256 "$1" | awk '{ print $1 }'; }

build_generation="${MACOP_INSTALL_BUILD_GENERATION:-$(git -C "$repo_root" rev-parse --verify --short=12 HEAD 2>/dev/null || date -u +%Y%m%dT%H%M%SZ)}"
[[ "$build_generation" =~ ^[A-Za-z0-9._-]+$ ]] || fail "build generation contains unsupported characters."
manifest_component() {
  local name="$1" signed_path="$2" hash_path="$3" identifier="$4" team cdhash
  team="$(read_team_id "$signed_path")"
  cdhash="$(read_cdhash "$signed_path")"
  [[ -n "$team" ]] || team="not set"
  [[ "$cdhash" =~ ^[0-9a-fA-F]{40}$ ]] || fail "cannot read CodeDirectory hash for $name"
  printf '    "%s": {"sha256":"%s","cdhash":"%s","identifier":"%s","team":"%s"}' \
    "$name" "$(sha256 "$hash_path")" "$cdhash" "$identifier" "$team"
}

{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "build_generation": "%s",\n' "$build_generation"
  printf '  "broker_protocol_version": 9,\n'
  printf '  "components": {\n'
  manifest_component "macop" "$staged_macop" "$staged_macop" "macop"; printf ',\n'
  manifest_component "agent" "$staged_agent" "$staged_agent" "macop-agent"; printf ',\n'
  manifest_component "auth_app" "$staged_auth_app" "$staged_auth_app/Contents/MacOS/MacopAuth" "io.github.slashkiko.macop.auth"; printf '\n'
  printf '  }\n}\n'
} >"$staged_manifest"
python3 "$install_fs" sync "$bin_dir" "$bin_dir_id" "$(basename "$staged_macop")" file \
  || fail "cannot durably stage macop."
python3 "$install_fs" sync "$bin_dir" "$bin_dir_id" "$(basename "$staged_agent")" file \
  || fail "cannot durably stage macop-agent."
python3 "$install_fs" sync "$bin_dir" "$bin_dir_id" "$(basename "$staged_auth_app")" dir \
  || fail "cannot durably stage MacopAuth.app."
python3 "$install_fs" sync "$bin_dir" "$bin_dir_id" "$(basename "$staged_manifest")" file \
  || fail "cannot durably stage the generation manifest."

verify_generation() {
  local root="$1"
  local manifest="$root/macop-install-manifest.json"
  [[ ! -L "$manifest" && -f "$manifest" ]] || return 1
  grep -Fqx '  "schema_version": 1,' "$manifest" || return 1
  grep -Fqx '  "broker_protocol_version": 9,' "$manifest" || return 1
  local name path hash_path expected_hash expected_identifier actual_hash actual_identifier
  for name in macop agent auth_app; do
    case "$name" in
      macop) path="$root/macop" ; hash_path="$path" ; expected_identifier="macop" ;;
      agent) path="$root/macop-agent" ; hash_path="$path" ; expected_identifier="macop-agent" ;;
      auth_app) path="$root/MacopAuth.app" ; hash_path="$path/Contents/MacOS/MacopAuth" ; expected_identifier="io.github.slashkiko.macop.auth" ;;
    esac
    [[ ! -L "$path" && -e "$path" ]] || return 1
    expected_hash="$(sed -n "s/.*\"$name\": {\"sha256\":\"\([0-9a-f]*\)\".*/\1/p" "$manifest" | head -n 1)"
    [[ "$expected_hash" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ -f "$hash_path" ]] || return 1
    actual_hash="$(sha256 "$hash_path")" || return 1
    [[ "$actual_hash" == "$expected_hash" ]] || return 1
    actual_identifier="$(read_identifier "$path")"
    [[ "$actual_identifier" == "$expected_identifier" ]] || return 1
  done
}

# macop-agent is one-shot, not a launchd daemon.  It has no resumable daemon
# state to restart, so an active authenticated session blocks publication
# rather than being killed underneath its caller.  A later invocation starts a
# new session from the fully installed generation.
quiesce_agent() {
  local pids=() pid executable expected start_token current_token expected_team
  expected="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$destination_agent")"
  expected_team="$(read_team_id "$destination_agent" 2>/dev/null || true)"
  if [[ "$test_mode" == "1" && -n "${MACOP_INSTALL_TEST_AGENT_PIDS:-}" ]]; then
    read -r -a pids <<<"${MACOP_INSTALL_TEST_AGENT_PIDS}"
  else
    while read -r pid executable; do
      [[ "$executable" == /* ]] || continue
      [[ "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$executable" 2>/dev/null || true)" == "$expected" ]] \
        && pids+=("$pid")
    done < <(ps -axo pid=,comm= 2>/dev/null)
  fi
  ((${#pids[@]})) || return 0
  for pid in "${pids[@]}"; do
    executable="$(ps -p "$pid" -o comm= 2>/dev/null | sed -n '1p' | awk '{$1=$1; print}')"
    [[ -n "$executable" ]] || continue
    [[ "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$executable" 2>/dev/null || true)" == "$expected" ]] || continue
    [[ "$(read_identifier "$executable" 2>/dev/null || true)" == "macop-agent" ]] || continue
    [[ -z "$expected_team" || "$expected_team" == "not set" || "$(read_team_id "$executable" 2>/dev/null || true)" == "$expected_team" ]] || continue
    # PID reuse is checked immediately before the refusal/signal decision.
    start_token="$(ps -p "$pid" -o lstart= 2>/dev/null | sed -n '1p')"
    current_token="$(ps -p "$pid" -o lstart= 2>/dev/null | sed -n '1p')"
    [[ -n "$start_token" && "$start_token" == "$current_token" ]] || continue
    fail "an active installed macop-agent session (pid $pid) prevents update; retry after its command exits."
  done
}

publish_component() {
  local name="$1" staged="$2" destination="$3"
  phase_guard "publish-$name"
  failpoint "publish-$name-before" || fail "injected publish failure"
  atomic_record "$journal_dir/phase" "publish:$name:prepared"$'\n'
  python3 "$install_fs" rename "$bin_dir" "$bin_dir_id" "$(basename "$staged")" \
    "$bin_dir" "$bin_dir_id" "$(basename "$destination")" \
    || fail "refusing unsafe publish of $name"
  atomic_record "$journal_dir/phase" "publish:$name:done"$'\n'
  case "$name" in
    macop) staged_macop="" ;;
    agent) staged_agent="" ;;
    auth_app) staged_auth_app="" ;;
    manifest) staged_manifest="" ;;
  esac
  failpoint "publish-$name-after" || fail "injected publish failure"
}

backup_component() {
  local name="$1" destination="$2"
  local backup initial
  phase_guard "backup-$name"
  initial="$(read_record "$journal_dir" "$name.initial")"
  backup="$(read_record "$journal_dir" "$name.backup")"
  atomic_record "$journal_dir/phase" "backup:$name:prepared"$'\n'
  if [[ -e "$destination" ]]; then
    [[ "$initial" == present && "$backup" == "$(backup_path_for "$name")" ]] \
      || fail "journal backup state is inconsistent for $name"
    failpoint "backup-$name-before" || fail "injected backup failure"
    python3 "$install_fs" rename "$bin_dir" "$bin_dir_id" "$(basename "$destination")" \
      "$journal_dir" "$journal_dir_id" "backup-$name" \
      || fail "refusing unsafe backup of $name"
    atomic_record "$journal_dir/phase" "backup:$name:done"$'\n'
    failpoint "backup-$name-after" || fail "injected backup failure"
  else
    [[ "$initial" == absent && "$backup" == "-" ]] \
      || fail "journal destination disappeared before backup: ${name:-unknown}"
  fi
}

quiesce_agent
phase_guard transaction
failpoint "transaction-before" || fail "injected transaction failure"
backup_component macop "$destination_macop"
backup_component agent "$destination_agent"
backup_component auth_app "$destination_auth_app"
backup_component manifest "$destination_manifest"
publish_component macop "$staged_macop" "$destination_macop"
publish_component agent "$staged_agent" "$destination_agent"
publish_component auth_app "$staged_auth_app" "$destination_auth_app"
publish_component manifest "$staged_manifest" "$destination_manifest"

phase_guard verification
verify_generation "$bin_dir" || fail "published generation manifest verification failed; rollback is required."
atomic_record "$journal_dir/phase" $'verification:prepared\n'
failpoint "manifest-after" || fail "injected manifest failure"

# A full noninteractive live broker handshake needs a credentialed companion
# session. Production performs an installed-runtime doctor probe here. Test
# fixtures exercise real generation publication and rollback boundaries but do
# not emulate a signed macOS companion process.
if [[ "$test_mode" != "1" ]]; then
  # Pass a descriptor, not a caller-forgeable VERIFY_* blanket bypass.  The
  # executable binds its contents to the exact installed path and only accepts
  # the two exact `doctor` invocations while the pending marker exists.
  # macOS ships Bash 3.2, which does not support dynamically allocated shell
  # descriptors. Use a dedicated numeric descriptor for the short-lived probes.
  installer_verification_fd=9
  exec 9<"$journal_dir/INSTALLER_CAPABILITY"
  MACOP_INSTALL_VERIFY_MODE=generation MACOP_INSTALL_VERIFY_FD="$installer_verification_fd" "$destination_macop" doctor >/dev/null \
    || fail "installed runtime generation verification failed; rollback is required."
  MACOP_INSTALL_VERIFY_MODE=broker MACOP_INSTALL_VERIFY_FD="$installer_verification_fd" "$destination_macop" doctor >/dev/null \
    || fail "installed broker peer/capability handshake failed; rollback is required."
  exec 9<&-
  installer_verification_fd=""
fi
failpoint "handshake-after" || fail "injected handshake failure"

phase_guard cleanup
transaction_committing=true
create_record "$journal_dir" COMMITTED $'committed\n'
transaction_armed=false
transaction_committing=false
remove_record "$state_dir" pending
remove_record "$journal_dir" PENDING
for name in macop agent auth_app manifest; do
  phase_guard "cleanup-$name"
  backup="$(read_record "$journal_dir" "$name.backup" 2>/dev/null || true)"
  if [[ "$backup" != "-" && -e "$backup" ]]; then
    case "$name" in
      auth_app) safe_remove_directory "$backup" || fail "cannot remove verified backup: $backup" ;;
      *) safe_remove_file "$backup" || fail "cannot remove verified backup: $backup" ;;
    esac
  fi
done
safe_remove_directory "$journal_dir" || fail "cannot remove completed transaction journal: $journal_dir"
journal_dir=""
journal_dir_id=""

if [[ "$with_op_symlink" == true && ! -L "$op_path" ]]; then
  ln -s macop "$op_path"
fi

if [[ "$configure_path" == true ]]; then
  configure_shell_path
fi

printf 'Installed macop, macop-agent, and MacopAuth.app in %s\n' "$bin_dir"
if [[ "$with_op_symlink" == true ]]; then
  printf 'Installed op symlink: %s -> macop\n' "$op_path"
else
  printf 'The op symlink was not changed; use --with-op-symlink to create it safely.\n'
fi
if [[ -n "$signing_identity" ]]; then
  printf 'Installed binaries and MacopAuth.app were signed with %s. Reuse the same identity after updates to preserve their designated requirements.\n' \
    "$signing_identity"
  if [[ -n "${MACOP_PROVISIONING_PROFILE:-}" ]]; then
    printf '%s\n' 'Managed Keychain capability is enabled by the embedded provisioning profile.'
  else
    printf '%s\n' 'Managed Keychain capability is disabled; set MACOP_PROVISIONING_PROFILE to a matching profile to enable it.'
  fi
else
  printf '%s\n' 'Installed test-fixture artifacts are ad-hoc signed; production installation requires certificate-backed signatures and a profile.'
fi
if [[ "$configure_path" == true ]]; then
  printf 'Restart the shell or run: source %q\n' "$shell_profile"
fi
