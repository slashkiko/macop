#!/bin/bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
signing_identity="${MACOP_SIGNING_IDENTITY:-}"
output_path="${MACOP_PROVISIONING_PROFILE_OUTPUT:-$HOME/Library/Application Support/macop/MacopAuth.provisionprofile}"
bundle_identifier="io.github.slashkiko.macop.auth"
ssh_access_group_suffix=".ssh"

fail() {
  printf 'macop development profile: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: scripts/create-development-profile.sh --signing-identity <name-or-sha1> [--output <absolute-path>]

Create or renew a Personal Team macOS development provisioning profile for
MacopAuth.app using Xcode automatic signing. This may register the bundle ID
and this Mac with the selected Apple Development team. The profile is written
outside the repository with mode 0600.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --signing-identity)
      [[ $# -ge 2 ]] || fail "--signing-identity requires a value."
      signing_identity="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || fail "--output requires a value."
      output_path="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) fail "unknown option: $1" ;;
  esac
done

[[ -n "$signing_identity" && "$signing_identity" != "-" && "$signing_identity" != -* ]] \
  || fail "an Apple Development identity name or SHA-1 hash is required."
[[ "$output_path" == /* && "$output_path" != "/" && "$output_path" != "$HOME" ]] \
  || fail "--output must be a specific absolute path."
[[ ! -L "$output_path" ]] || fail "refusing to replace a symlinked output path."
if [[ -e "$output_path" ]]; then
  [[ -f "$output_path" ]] || fail "output path must be a regular file."
fi

for command in awk cp date dirname id install mktemp mv openssl plutil rm security sed stat tr xcodebuild; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done

normalized_request="$(printf '%s' "$signing_identity" | tr '[:lower:]' '[:upper:]')"
selected_hash=""
while IFS= read -r identity_line; do
  [[ "$identity_line" == *\"*\"* ]] || continue
  identity_hash="$(printf '%s\n' "$identity_line" | awk '{print $2}')"
  identity_label="${identity_line#*\"}"
  identity_label="${identity_label%%\"*}"
  if [[ "$normalized_request" == "$identity_hash" || "$signing_identity" == "$identity_label" ]]; then
    [[ -z "$selected_hash" ]] || fail "signing identity is ambiguous; pass its SHA-1 hash."
    selected_hash="$identity_hash"
  fi
done < <(security find-identity -v -p codesigning)
[[ -n "$selected_hash" ]] || fail "the selected codesigning identity was not found."

certificate_subject="$(
  security find-certificate -a -Z -p \
    | awk -v wanted="$selected_hash" '
        BEGIN { wanted = toupper(wanted) }
        /^SHA-1 hash: / { selected = (toupper($3) == wanted); next }
        selected && /^-----BEGIN CERTIFICATE-----$/ { emit = 1 }
        emit { print }
        emit && /^-----END CERTIFICATE-----$/ { exit }
      ' \
    | openssl x509 -noout -subject -nameopt RFC2253
)" || fail "unable to read the selected signing certificate."
team_id="$(printf '%s\n' "$certificate_subject" \
  | awk -F, '{ for (i = 1; i <= NF; i++) if ($i ~ /^OU=/) { sub(/^OU=/, "", $i); print $i; exit } }')"
[[ "$team_id" =~ ^[A-Z0-9]+$ ]] || fail "the signing certificate does not contain a valid Team ID."

output_directory="$(dirname "$output_path")"
if [[ ! -e "$output_directory" ]]; then
  install -d -m 700 "$output_directory"
fi
[[ -d "$output_directory" && ! -L "$output_directory" ]] \
  || fail "output directory must be a real directory."
[[ "$(stat -f '%u' "$output_directory")" == "$(id -u)" ]] \
  || fail "output directory must be owned by the current user."

temporary_root="$(mktemp -d /private/tmp/macop-profile.XXXXXX)"
staged_output="$(mktemp "$output_directory/.MacopAuth.provisionprofile.XXXXXX")"
cleanup() {
  [[ ! -e "$temporary_root" ]] || rm -rf "$temporary_root"
  [[ ! -e "$staged_output" ]] || rm -f "$staged_output"
}
trap cleanup EXIT

cp -R "$repo_root/Resources/ProfileBootstrap/." "$temporary_root/"
derived_data="$temporary_root/DerivedData"
build_log="$temporary_root/xcodebuild.log"
set +e
xcodebuild \
  -project "$temporary_root/MacopProfileBootstrap.xcodeproj" \
  -scheme MacopProfileBootstrap \
  -configuration Debug \
  -destination "platform=macOS,arch=$(uname -m)" \
  -derivedDataPath "$derived_data" \
  -allowProvisioningUpdates \
  -allowProvisioningDeviceRegistration \
  DEVELOPMENT_TEAM="$team_id" \
  CODE_SIGN_STYLE=Automatic \
  CODE_SIGN_IDENTITY="Apple Development" \
  build >"$build_log" 2>&1
build_status=$?
set -e
if [[ $build_status -ne 0 ]]; then
  sed -E \
    -e 's/Apple Development: [^"]+/Apple Development: <redacted>/g' \
    -e "s/$selected_hash/<IDENTITY>/g" \
    -e "s/$team_id/<TEAM>/g" \
    -e 's/[[:alnum:]_.%+-]+@[[:alnum:].-]+/<email>/g' \
    "$build_log" >&2
  fail "Xcode automatic signing failed."
fi

profile_path="$derived_data/Build/Products/Debug/MacopProfileBootstrap.app/Contents/embedded.provisionprofile"
[[ -f "$profile_path" ]] || fail "Xcode did not embed a provisioning profile."
decoded_profile="$temporary_root/profile.plist"
security cms -D -i "$profile_path" >"$decoded_profile"
profile_team="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$decoded_profile")"
application_identifier="$(/usr/libexec/PlistBuddy \
  -c 'Print :Entitlements:com.apple.application-identifier' "$decoded_profile")"
profile_authorizes_access_group() {
  local expected_group="$1"
  local index=0
  local candidate
  while candidate="$(/usr/libexec/PlistBuddy \
    -c "Print :Entitlements:keychain-access-groups:$index" "$decoded_profile" 2>/dev/null)"; do
    if [[ "$candidate" == "$expected_group" || "$candidate" == "$team_id.*" ]]; then
      return 0
    fi
    index=$((index + 1))
  done
  return 1
}
platform="$(/usr/libexec/PlistBuddy -c 'Print :Platform:0' "$decoded_profile")"
expiration="$(plutil -extract ExpirationDate raw "$decoded_profile")"
expiration_epoch="$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$expiration" '+%s')"
[[ "$profile_team" == "$team_id" ]] || fail "profile Team ID does not match the signing identity."
[[ "$application_identifier" == "$team_id.$bundle_identifier" ]] \
  || fail "profile application identifier does not match MacopAuth."
profile_authorizes_access_group "$application_identifier" \
  || fail "profile does not authorize the MacopAuth managed Keychain access group."
profile_authorizes_access_group "$application_identifier$ssh_access_group_suffix" \
  || fail "profile does not authorize the MacopAuth SSH Keychain access group."
[[ "$platform" == "OSX" || "$platform" == "macOS" ]] || fail "profile is not for macOS."
[[ "$expiration_epoch" -gt "$(date -u '+%s')" ]] || fail "profile is already expired."

install -m 600 "$profile_path" "$staged_output"
mv -f "$staged_output" "$output_path"
staged_output=""
printf 'Created %s\n' "$output_path"
printf 'Expires %s\n' "$expiration"
