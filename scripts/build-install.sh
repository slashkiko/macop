#!/bin/bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
bin_dir="${MACOP_BIN_DIR:-$HOME/.local/bin}"
configuration="release"
run_checks=false
skip_build=false
with_op_symlink=false
configure_path=false
shell_profile="${MACOP_SHELL_PROFILE:-}"
signing_identity="${MACOP_SIGNING_IDENTITY:-}"

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
  --signing-identity <name>  Use a stable codesigning identity instead of ad-hoc signing
  --help                     Show this help

MACOP_BIN_DIR, MACOP_SHELL_PROFILE, MACOP_SIGNING_IDENTITY, and
MACOP_PROVISIONING_PROFILE may be used
instead of their options.
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

for command in awk chmod codesign cp dirname grep head id install make mktemp mv readlink rm rmdir sed stat; do
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
    make -C "$repo_root" release-build
  else
    make -C "$repo_root" build
  fi
fi

build_dir="$repo_root/.build/$configuration"
codesign_identity="${signing_identity:--}"
MACOP_SIGNING_IDENTITY="$codesign_identity" bash "$repo_root/scripts/build-auth-app.sh" "$configuration"
source_macop="$build_dir/macop"
source_agent="$build_dir/macop-agent"
source_auth_app="$build_dir/MacopAuth.app"
[[ -x "$source_macop" ]] || fail "missing build artifact: $source_macop"
[[ -x "$source_agent" ]] || fail "missing build artifact: $source_agent"
[[ -d "$source_auth_app" ]] || fail "missing app bundle: $source_auth_app"

if [[ ! -e "$bin_dir" ]]; then
  install -d -m 755 "$bin_dir"
fi
[[ -d "$bin_dir" ]] || fail "install path is not a directory: $bin_dir"
[[ "$(stat -f '%u' "$bin_dir")" == "$(id -u)" ]] \
  || fail "install directory must be owned by the current user."

destination_macop="$bin_dir/macop"
destination_agent="$bin_dir/macop-agent"
destination_auth_app="$bin_dir/MacopAuth.app"
op_path="$bin_dir/op"

for destination in "$destination_macop" "$destination_agent"; do
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

staged_macop="$(mktemp "$bin_dir/.macop.install.XXXXXX")"
staged_agent="$(mktemp "$bin_dir/.macop-agent.install.XXXXXX")"
staged_auth_app="$(mktemp -d "$bin_dir/.MacopAuth.install.XXXXXX")"
auth_backup=""
cleanup() {
  [[ -z "$staged_macop" ]] || rm -f "$staged_macop"
  [[ -z "$staged_agent" ]] || rm -f "$staged_agent"
  [[ -z "$staged_auth_app" || ! -e "$staged_auth_app" ]] || rm -rf "$staged_auth_app"
  if [[ -n "$auth_backup" && -e "$auth_backup" && ! -e "$destination_auth_app" ]]; then
    mv "$auth_backup" "$destination_auth_app"
    auth_backup=""
  fi
  [[ -z "$auth_backup" || ! -e "$auth_backup" ]] || rm -rf "$auth_backup"
}
trap cleanup EXIT

install -m 755 "$source_macop" "$staged_macop"
install -m 755 "$source_agent" "$staged_agent"
cp -R "$source_auth_app/Contents" "$staged_auth_app/Contents"
codesign --force --sign "$codesign_identity" --identifier macop "$staged_macop"
codesign --force --sign "$codesign_identity" --identifier macop-agent "$staged_agent"
codesign --verify --strict "$staged_macop"
codesign --verify --strict "$staged_agent"
codesign --verify --strict "$staged_auth_app"

read_identifier() {
  codesign -d --verbose=4 "$1" 2>&1 | sed -n 's/^Identifier=//p' | head -n 1
}

read_team_id() {
  codesign -d --verbose=4 "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -n 1
}

[[ "$(read_identifier "$staged_macop")" == "macop" ]] || fail "macop identifier readback failed."
[[ "$(read_identifier "$staged_agent")" == "macop-agent" ]] || fail "macop-agent identifier readback failed."
[[ "$(read_identifier "$staged_auth_app")" == "io.github.slashkiko.macop.auth" ]] \
  || fail "MacopAuth identifier readback failed."
if [[ -n "$signing_identity" ]]; then
  macop_team="$(read_team_id "$staged_macop")"
  agent_team="$(read_team_id "$staged_agent")"
  auth_team="$(read_team_id "$staged_auth_app")"
  [[ -n "$macop_team" && "$macop_team" != "not set" && "$macop_team" == "$agent_team" \
      && "$macop_team" == "$auth_team" ]] \
    || fail "macop, macop-agent, and MacopAuth must have the same non-empty Team ID."
fi

mv -f "$staged_macop" "$destination_macop"
staged_macop=""
mv -f "$staged_agent" "$destination_agent"
staged_agent=""
if [[ -e "$destination_auth_app" ]]; then
  auth_backup="$(mktemp -d "$bin_dir/.MacopAuth.backup.XXXXXX")"
  rmdir "$auth_backup"
  mv "$destination_auth_app" "$auth_backup"
fi
mv "$staged_auth_app" "$destination_auth_app"
staged_auth_app=""
if [[ -n "$auth_backup" ]]; then
  rm -rf "$auth_backup"
  auth_backup=""
fi

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
  printf '%s\n' 'Installed artifacts are ad-hoc signed; native approval capabilities require certificate-backed same-Team signatures.'
fi
if [[ "$configure_path" == true ]]; then
  printf 'Restart the shell or run: source %q\n' "$shell_profile"
fi
