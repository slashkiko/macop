#!/bin/bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
canonical_repository="https://github.com/slashkiko/macop.git"
secure_temp_base="/private/tmp"
state_dir="$HOME/Library/Application Support/macop"
identity_path="$state_dir/personal-signing-identity"
profile_path="$state_dir/MacopAuth.provisionprofile"
profile_helper="$script_dir/create-development-profile.sh"
installer="$script_dir/build-install.sh"

fail() {
  printf 'macop personal install: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  scripts/personal-install.sh identities
  scripts/personal-install.sh setup [setup-options] [install-options]
  scripts/personal-install.sh update [install-options]

Use an Apple Development certificate for a source-built personal installation.
The setup command records only the selected certificate's SHA-1 fingerprint;
the private key remains in the macOS Keychain. The update command renews the
matching development profile and reuses that exact certificate.

Setup options:
  --signing-identity <sha1>  Select non-interactively instead of showing a menu
  --replace-identity         Replace a saved certificate after successful install
  --no-configure-path        Do not add the install directory to the shell PATH

Install options:
  --with-op-symlink          Create op -> macop if no op command exists
  --configure-path           Add the install directory to the shell PATH
  --bin-dir <directory>      Install somewhere other than ~/.local/bin
  --shell-profile <file>     Profile to manage with --configure-path

Setup asks which Apple Development certificate to use and configures PATH by
default. Update fresh-clones the official main branch into a temporary directory,
then rebuilds with the saved certificate. GitHub Actions is the source CI gate;
the personal updater does not rerun the repository's local CI suite.
EOF
}

list_identities() {
  security find-identity -v -p codesigning \
    | awk '/"Apple Development: / { print }'
}

normalize_identity() {
  local identity="$1"
  [[ "$identity" =~ ^[[:xdigit:]]{40}$ ]] \
    || fail "--signing-identity must be an exact 40-character SHA-1 fingerprint."
  printf '%s' "$identity" | tr '[:lower:]' '[:upper:]'
}

choose_identity() {
  local available line fingerprint identity_count selection
  local -a identity_fingerprints
  available="$(list_identities)"
  [[ -n "$available" ]] \
    || fail "no Apple Development certificate is available; create one in Xcode first."
  [[ -t 0 ]] \
    || fail "setup needs an interactive terminal to choose a certificate; pass --signing-identity for non-interactive use."

  printf 'Choose the Apple Development certificate for macop:\n' >&2
  identity_count=0
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    fingerprint="$(printf '%s\n' "$line" | awk '{ print $2 }')"
    [[ "$fingerprint" =~ ^[[:xdigit:]]{40}$ ]] || continue
    identity_count=$((identity_count + 1))
    identity_fingerprints[$identity_count]="$(normalize_identity "$fingerprint")"
    printf '  %d. %s\n' "$identity_count" "$line" >&2
  done <<<"$available"
  (( identity_count > 0 )) \
    || fail "no Apple Development certificate is available; create one in Xcode first."

  printf 'Certificate number: ' >&2
  IFS= read -r selection \
    || fail "certificate selection was cancelled."
  [[ "$selection" =~ ^[0-9]+$ ]] \
    || fail "certificate selection must be a number from the list."
  (( selection >= 1 && selection <= identity_count )) \
    || fail "certificate selection is outside the displayed range."
  printf '%s' "${identity_fingerprints[$selection]}"
}

identity_label() {
  local identity="$1"
  security find-identity -v -p codesigning \
    | awk -v wanted="$identity" '
        BEGIN { wanted = toupper(wanted) }
        toupper($2) == wanted && match($0, /"[^"]+"/) {
          print substr($0, RSTART + 1, RLENGTH - 2)
          matches++
        }
        END { if (matches != 1) exit 1 }
      '
}

ensure_state_directory() {
  local create_if_missing="$1"
  if [[ ! -e "$state_dir" ]]; then
    if [[ "$create_if_missing" == true ]]; then
      install -d -m 700 "$state_dir"
    else
      fail "no saved signing identity; run the setup command first."
    fi
  fi
  [[ -d "$state_dir" && ! -L "$state_dir" ]] \
    || fail "state directory must be a real directory: $state_dir"
  [[ "$(stat -f '%u' "$state_dir")" == "$(id -u)" ]] \
    || fail "state directory must be owned by the current user."
  local directory_mode
  directory_mode="$(stat -f '%Lp' "$state_dir")"
  [[ "$directory_mode" =~ ^[0-7]{3,4}$ ]] \
    || fail "unable to validate state directory permissions."
  (( (8#$directory_mode & 8#22) == 0 )) \
    || fail "state directory must not be group- or world-writable."
}

read_saved_identity() {
  [[ -f "$identity_path" && ! -L "$identity_path" ]] \
    || fail "no saved signing identity; run the setup command first."
  [[ "$(stat -f '%u' "$identity_path")" == "$(id -u)" ]] \
    || fail "saved signing identity must be owned by the current user."
  [[ "$(stat -f '%Lp' "$identity_path")" == "600" ]] \
    || fail "saved signing identity must have mode 0600."
  [[ "$(stat -f '%l' "$identity_path")" == "1" ]] \
    || fail "saved signing identity must not have additional hard links."
  local saved
  saved="$(<"$identity_path")"
  normalize_identity "$saved"
}

write_saved_identity() {
  local identity="$1"
  local staged
  staged="$(mktemp "$state_dir/.personal-signing-identity.XXXXXX")"
  cleanup_identity_stage() {
    [[ ! -e "$staged" ]] || rm -f "$staged"
  }
  trap cleanup_identity_stage EXIT
  printf '%s\n' "$identity" >"$staged"
  chmod 600 "$staged"
  mv -f "$staged" "$identity_path"
  staged=""
  trap - EXIT
}

install_saved_update_from_clone() {
  local temp_base update_root cloned_installer
  temp_base="$secure_temp_base"
  update_root="$(mktemp -d "$temp_base/macop-personal-update.XXXXXX")"
  cleanup_update_clone() {
    if [[ -n "$update_root" \
      && "$update_root" == "$temp_base"/macop-personal-update.* \
      && -d "$update_root" \
      && ! -L "$update_root" ]]; then
      rm -rf -- "$update_root"
    fi
  }
  trap cleanup_update_clone EXIT

  printf 'Cloning %s (main)...\n' "$canonical_repository"
  TMPDIR="$secure_temp_base" \
    git clone --depth 1 --branch main --single-branch -- \
    "$canonical_repository" "$update_root/repository"
  cloned_installer="$update_root/repository/scripts/personal-install.sh"
  [[ -f "$cloned_installer" && ! -L "$cloned_installer" ]] \
    || fail "the fresh clone does not contain a regular personal installer."

  TMPDIR="$secure_temp_base" \
  MACOP_PERSONAL_UPDATE_FROM_CLONE=1 \
    bash "$cloned_installer" _install-saved "$@"

  cleanup_update_clone
  trap - EXIT
}

[[ $# -gt 0 ]] || { usage >&2; exit 2; }
command_name="$1"
shift

case "$command_name" in
  --help|-h)
    usage
    exit 0
    ;;
  identities)
    [[ $# -eq 0 ]] || fail "identities does not accept options."
    command -v security >/dev/null 2>&1 || fail "required command is unavailable: security"
    list_identities
    exit 0
    ;;
  setup|update) ;;
  _install-saved)
    [[ "${MACOP_PERSONAL_UPDATE_FROM_CLONE:-}" == "1" ]] \
      || fail "internal update command cannot be invoked directly."
    ;;
  *) fail "unknown command: $command_name" ;;
esac

for required in awk bash chmod id install mktemp mv rm security stat tr; do
  command -v "$required" >/dev/null 2>&1 || fail "required command is unavailable: $required"
done
if [[ "$command_name" == "update" ]]; then
  command -v git >/dev/null 2>&1 || fail "required command is unavailable: git"
fi

requested_identity=""
replace_identity=false
configure_path=false
if [[ "$command_name" == "setup" ]]; then
  configure_path=true
fi
installer_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --signing-identity)
      [[ "$command_name" == "setup" ]] \
        || fail "--signing-identity is accepted only by setup."
      [[ $# -ge 2 ]] || fail "--signing-identity requires a value."
      requested_identity="$2"
      shift 2
      ;;
    --replace-identity)
      [[ "$command_name" == "setup" ]] \
        || fail "--replace-identity is accepted only by setup."
      replace_identity=true
      shift
      ;;
    --with-op-symlink)
      installer_args+=("$1")
      shift
      ;;
    --configure-path)
      configure_path=true
      shift
      ;;
    --no-configure-path)
      [[ "$command_name" == "setup" ]] \
        || fail "--no-configure-path is accepted only by setup."
      configure_path=false
      shift
      ;;
    --bin-dir|--shell-profile)
      [[ $# -ge 2 ]] || fail "$1 requires a value."
      installer_args+=("$1" "$2")
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) fail "unsupported option: $1" ;;
  esac
done

if [[ "$configure_path" == true ]]; then
  installer_args+=("--configure-path")
fi

if [[ "$command_name" == "update" ]]; then
  ensure_state_directory false
  selected_identity="$(read_saved_identity)"
  identity_label "$selected_identity" >/dev/null \
    || fail "the saved signing identity is not available in the macOS Keychain."
  install_saved_update_from_clone ${installer_args[@]+"${installer_args[@]}"}
  exit 0
fi

[[ -x "$profile_helper" ]] || fail "profile helper is unavailable: $profile_helper"
[[ -x "$installer" ]] || fail "installer is unavailable: $installer"

if [[ "$command_name" == "setup" ]]; then
  if [[ -z "$requested_identity" ]]; then
    requested_identity="$(choose_identity)"
  fi
  selected_identity="$(normalize_identity "$requested_identity")"
  ensure_state_directory true
  if [[ -e "$identity_path" ]]; then
    saved_identity="$(read_saved_identity)"
    if [[ "$saved_identity" != "$selected_identity" && "$replace_identity" == false ]]; then
      fail "a different identity is already saved; pass --replace-identity to rotate it."
    fi
  fi
else
  ensure_state_directory false
  selected_identity="$(read_saved_identity)"
fi

if ! selected_label="$(identity_label "$selected_identity")"; then
  fail "the selected signing identity is not available in the macOS Keychain."
fi
case "$selected_label" in
  'Apple Development: '*) ;;
  *) fail "the selected identity is not an Apple Development certificate." ;;
esac

TMPDIR="$secure_temp_base" bash "$profile_helper" \
  --signing-identity "$selected_identity" \
  --output "$profile_path"

TMPDIR="$secure_temp_base" \
MACOP_SIGNING_IDENTITY="$selected_identity" \
MACOP_PROVISIONING_PROFILE="$profile_path" \
  bash "$installer" ${installer_args[@]+"${installer_args[@]}"}

if [[ "$command_name" == "setup" ]]; then
  write_saved_identity "$selected_identity"
  printf 'Saved personal signing identity in %s\n' "$identity_path"
fi
if [[ "$command_name" == "_install-saved" ]]; then
  printf 'Personal update completed with %s\n' "$selected_label"
else
  printf 'Personal %s completed with %s\n' "$command_name" "$selected_label"
fi
