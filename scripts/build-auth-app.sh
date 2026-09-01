#!/bin/bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
configuration="${1:-debug}"
signing_identity="${MACOP_SIGNING_IDENTITY:--}"
provisioning_profile="${MACOP_PROVISIONING_PROFILE:-}"
bundle_identifier="io.github.slashkiko.macop.auth"
ssh_access_group_suffix=".ssh"

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

for command in awk codesign cp date head iconutil install mktemp mv openssl plutil rm rmdir security sed tr; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done
[[ -x /usr/libexec/PlistBuddy ]] || fail "required command is unavailable: /usr/libexec/PlistBuddy"

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
localization_root="$repo_root/Resources/MacopAuth"
iconset="$repo_root/Resources/MacopAuth/MacopAuth.iconset"
[[ -x "$source_executable" ]] || fail "missing build artifact: $source_executable"
plutil -lint "$info_plist" >/dev/null
[[ -d "$iconset" && ! -L "$iconset" ]] || fail "missing or unsafe icon set: $iconset"
for slot in 16x16 16x16@2x 32x32 32x32@2x 128x128 128x128@2x 256x256 256x256@2x 512x512 512x512@2x; do
  slot_file="$iconset/icon_$slot.png"
  [[ -f "$slot_file" && ! -L "$slot_file" ]] || fail "missing or unsafe icon slot: $slot_file"
done
plutil -lint "$entitlements_template" >/dev/null
for language in ja en; do
  strings_file="$localization_root/$language.lproj/Localizable.strings"
  [[ -f "$strings_file" && ! -L "$strings_file" ]] \
    || fail "missing or unsafe localization: $strings_file"
  plutil -lint "$strings_file" >/dev/null
done
if [[ -n "$provisioning_profile" ]]; then
  [[ "$provisioning_profile" == /* && -f "$provisioning_profile" && ! -L "$provisioning_profile" ]] \
    || fail "MACOP_PROVISIONING_PROFILE must be an absolute path to a regular file."
fi

staged="$(mktemp -d "$build_dir/.MacopAuth.app.XXXXXX")"
backup=""
generated_entitlements=""
entitlements_readback=""
decoded_profile=""
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
  [[ -z "$decoded_profile" || ! -e "$decoded_profile" ]] || rm -f "$decoded_profile"
}
trap cleanup EXIT

install -d -m 755 "$staged/Contents/MacOS"
install -m 644 "$info_plist" "$staged/Contents/Info.plist"
install -m 755 "$source_executable" "$staged/Contents/MacOS/MacopAuth"
install -d -m 755 "$staged/Contents/Resources"
# Every slot is rendered from design/icon at its own size, so the .icns is
# assembled here rather than checked in as a binary.
iconutil --convert icns --output "$staged/Contents/Resources/MacopAuth.icns" "$iconset"
chmod 644 "$staged/Contents/Resources/MacopAuth.icns"
for language in ja en; do
  install -d -m 755 "$staged/Contents/Resources/$language.lproj"
  install -m 644 \
    "$localization_root/$language.lproj/Localizable.strings" \
    "$staged/Contents/Resources/$language.lproj/Localizable.strings"
done
if [[ -n "$provisioning_profile" ]]; then
  install -m 644 "$provisioning_profile" "$staged/Contents/embedded.provisionprofile"
fi
# SwiftPM may ad-hoc sign the executable. Remove that signature from the staged
# bundle so the final app signature is created cleanly in a single operation.
codesign --remove-signature "$staged" >/dev/null 2>&1 || true
if [[ "$signing_identity" != "-" && -n "$provisioning_profile" ]]; then
  team_id="$(resolve_team_id "$signing_identity")"
  decoded_profile="$(mktemp "$build_dir/.MacopAuth.profile.XXXXXX")"
  security cms -D -i "$provisioning_profile" >"$decoded_profile" \
    || fail "MACOP_PROVISIONING_PROFILE is not a valid signed profile."
  profile_team="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$decoded_profile")"
  profile_app_identifier="$(/usr/libexec/PlistBuddy \
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
  profile_platform="$(/usr/libexec/PlistBuddy -c 'Print :Platform:0' "$decoded_profile")"
  profile_expiration="$(plutil -extract ExpirationDate raw "$decoded_profile")"
  profile_expiration_epoch="$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$profile_expiration" '+%s')"
  [[ "$profile_team" == "$team_id" ]] || fail "provisioning profile Team ID does not match the identity."
  [[ "$profile_app_identifier" == "$team_id.$bundle_identifier" ]] \
    || fail "provisioning profile does not authorize the MacopAuth application identifier."
  profile_authorizes_access_group "$profile_app_identifier" \
    || fail "provisioning profile does not authorize the MacopAuth managed Keychain access group."
  profile_authorizes_access_group "$profile_app_identifier$ssh_access_group_suffix" \
    || fail "provisioning profile does not authorize the MacopAuth SSH Keychain access group."
  [[ "$profile_platform" == "OSX" || "$profile_platform" == "macOS" ]] \
    || fail "provisioning profile is not for macOS."
  [[ "$profile_expiration_epoch" -gt "$(date -u '+%s')" ]] || fail "provisioning profile is expired."
  rm -f "$decoded_profile"
  decoded_profile=""
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
  actual_managed_access_group="$(plutil -extract 'keychain-access-groups.0' raw "$entitlements_readback")"
  actual_ssh_access_group="$(plutil -extract 'keychain-access-groups.1' raw "$entitlements_readback")"
  [[ "$actual_app_identifier" == "$team_id.$bundle_identifier" ]] \
    || fail "application identifier entitlement readback failed."
  [[ "$actual_managed_access_group" == "$actual_app_identifier" ]] \
    || fail "managed Keychain access group entitlement readback failed."
  [[ "$actual_ssh_access_group" == "$actual_app_identifier$ssh_access_group_suffix" ]] \
    || fail "SSH Keychain access group entitlement readback failed."
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
