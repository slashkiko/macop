#!/bin/bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
configuration="${1:-debug}"
signing_identity="${MACOP_SIGNING_IDENTITY:--}"
provisioning_profile="${MACOP_PROVISIONING_PROFILE:-}"
bundle_identifier="io.github.slashkiko.macop.auth"

fail() {
  printf 'macop auth bundle: %s\n' "$1" >&2
  exit 1
}

[[ "$configuration" == "debug" || "$configuration" == "release" ]] \
  || fail "configuration must be debug or release."
if [[ "$signing_identity" != "-" ]]; then
  [[ -n "$signing_identity" && "$signing_identity" != -* ]] \
    || fail "MACOP_SIGNING_IDENTITY must name a certificate-backed identity or be unset."
fi

for command in awk codesign cp head install mktemp mv openssl plutil rm rmdir security sed tr; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done

resolve_team_id() {
  local requested_identity="$1"
  local normalized_request identity_line identity_hash identity_label selected_hash certificate_subject resolved_team_id
  normalized_request="$(printf '%s' "$requested_identity" | tr '[:lower:]' '[:upper:]')"
  selected_hash=""

  while IFS= read -r identity_line; do
    [[ "$identity_line" == *\"*\"* ]] || continue
    identity_hash="$(printf '%s\n' "$identity_line" | awk '{print $2}')"
    identity_label="${identity_line#*\"}"
    identity_label="${identity_label%%\"*}"
    if [[ "$normalized_request" == "$identity_hash" || "$requested_identity" == "$identity_label" ]]; then
      [[ -z "$selected_hash" ]] || fail "signing identity is ambiguous. Pass its SHA-1 hash."
      selected_hash="$identity_hash"
    fi
  done < <(security find-identity -v -p codesigning)

  [[ -n "$selected_hash" ]] \
    || fail "unable to resolve the Team ID for MACOP_SIGNING_IDENTITY. Pass an exact identity name or SHA-1 hash."
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
  resolved_team_id="$(printf '%s\n' "$certificate_subject" \
    | awk -F, '{ for (i = 1; i <= NF; i++) if ($i ~ /^OU=/) { sub(/^OU=/, "", $i); print $i; exit } }')"
  [[ "$resolved_team_id" =~ ^[A-Z0-9]+$ ]] \
    || fail "the selected signing certificate does not contain a valid Team ID."
  printf '%s\n' "$resolved_team_id"
}

build_dir="$repo_root/.build/$configuration"
source_executable="$build_dir/MacopAuth"
destination="$build_dir/MacopAuth.app"
info_plist="$repo_root/Resources/MacopAuth/Info.plist"
entitlements_template="$repo_root/Resources/MacopAuth/MacopAuth.entitlements.in"
[[ -x "$source_executable" ]] || fail "missing build artifact: $source_executable"
plutil -lint "$info_plist" >/dev/null
plutil -lint "$entitlements_template" >/dev/null
if [[ -n "$provisioning_profile" ]]; then
  [[ "$provisioning_profile" == /* && -f "$provisioning_profile" && ! -L "$provisioning_profile" ]] \
    || fail "MACOP_PROVISIONING_PROFILE must be an absolute path to a regular file."
fi

staged="$(mktemp -d "$build_dir/.MacopAuth.app.XXXXXX")"
backup=""
generated_entitlements=""
entitlements_readback=""
team_id=""
cleanup() {
  if [[ -n "$backup" && -e "$backup" && ! -e "$destination" ]]; then
    mv "$backup" "$destination"
    backup=""
  fi
  [[ ! -e "$staged" ]] || rm -rf "$staged"
  [[ -z "$backup" || ! -e "$backup" ]] || rm -rf "$backup"
  [[ -z "$generated_entitlements" || ! -e "$generated_entitlements" ]] || rm -f "$generated_entitlements"
  [[ -z "$entitlements_readback" || ! -e "$entitlements_readback" ]] || rm -f "$entitlements_readback"
}
trap cleanup EXIT

install -d -m 755 "$staged/Contents/MacOS"
install -m 644 "$info_plist" "$staged/Contents/Info.plist"
install -m 755 "$source_executable" "$staged/Contents/MacOS/MacopAuth"
if [[ -n "$provisioning_profile" ]]; then
  install -m 644 "$provisioning_profile" "$staged/Contents/embedded.provisionprofile"
fi
# SwiftPM may ad-hoc sign the executable. Remove that signature from the staged
# bundle so the final app signature is created cleanly in a single operation.
codesign --remove-signature "$staged" >/dev/null 2>&1 || true
if [[ "$signing_identity" != "-" && -n "$provisioning_profile" ]]; then
  team_id="$(resolve_team_id "$signing_identity")"
  generated_entitlements="$(mktemp "$build_dir/.MacopAuth.entitlements.XXXXXX")"
  sed "s/__TEAM_ID__/$team_id/g" "$entitlements_template" >"$generated_entitlements"
  plutil -lint "$generated_entitlements" >/dev/null
  codesign --force --options runtime --entitlements "$generated_entitlements" \
    --sign "$signing_identity" --identifier "$bundle_identifier" "$staged"
  rm -f "$generated_entitlements"
  generated_entitlements=""
else
  codesign --force --options runtime --sign "$signing_identity" \
    --identifier "$bundle_identifier" "$staged"
fi
codesign --verify --strict "$staged"
actual_identifier="$(codesign -d --verbose=4 "$staged" 2>&1 | sed -n 's/^Identifier=//p' | head -n 1)"
[[ "$actual_identifier" == "$bundle_identifier" ]] || fail "signed bundle identifier readback failed."
if [[ "$signing_identity" != "-" && -n "$provisioning_profile" ]]; then
  entitlements_readback="$(mktemp "$build_dir/.MacopAuth.entitlements-readback.XXXXXX")"
  codesign -d --entitlements :- "$staged" >"$entitlements_readback" 2>/dev/null
  actual_app_identifier="$(plutil -extract 'com\.apple\.application-identifier' raw "$entitlements_readback")"
  actual_access_group="$(plutil -extract 'keychain-access-groups.0' raw "$entitlements_readback")"
  [[ "$actual_app_identifier" == "$team_id.$bundle_identifier" ]] \
    || fail "application identifier entitlement readback failed."
  [[ "$actual_access_group" == "$actual_app_identifier" ]] \
    || fail "Keychain access group entitlement readback failed."
  if [[ "$configuration" == "release" ]] \
      && plutil -extract 'com\.apple\.security\.get-task-allow' raw "$entitlements_readback" >/dev/null 2>&1; then
    fail "release app must not contain get-task-allow."
  fi
  rm -f "$entitlements_readback"
  entitlements_readback=""
fi

if [[ -e "$destination" ]]; then
  [[ ! -L "$destination" && -d "$destination" ]] || fail "refusing to replace a symlink or non-directory: $destination"
  backup="$(mktemp -d "$build_dir/.MacopAuth.backup.XXXXXX")"
  rmdir "$backup"
  mv "$destination" "$backup"
fi
mv "$staged" "$destination"
staged=""
if [[ -n "$backup" ]]; then
  rm -rf "$backup"
  backup=""
fi

printf 'Built %s\n' "$destination"
