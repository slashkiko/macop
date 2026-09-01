#!/bin/bash
set -euo pipefail

fixture_root="$(mktemp -d /private/tmp/macop-install-test-installation.XXXXXX)"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cleanup() { rm -rf "$fixture_root"; }
trap cleanup EXIT

bin_dir="$fixture_root/bin"
test_home="$fixture_root/home"
shell_profile="$test_home/.zprofile"
config_marker="$test_home/Library/Application Support/macop/config.json"
mkdir -p "$(dirname "$config_marker")" "$test_home"
printf '%s\n' '{"version":1}' >"$config_marker"
printf '%s\n' 'export EXISTING_SETTING=preserved' >"$shell_profile"
export HOME="$test_home"
export SHELL=/bin/zsh

# An existing unrelated `op` must be detected before either binary is
# installed, so opting into compatibility never replaces another CLI.
mkdir -p "$bin_dir"
chmod 700 "$fixture_root" "$bin_dir"
ln -s /usr/bin/true "$bin_dir/op"
set +e
MACOP_INSTALL_TEST_MODE=1 bash scripts/build-install.sh \
  --configuration debug \
  --skip-build \
  --bin-dir "$bin_dir" \
  --with-op-symlink \
  >"$fixture_root/foreign-op.stdout" 2>"$fixture_root/foreign-op.stderr"
foreign_op_status=$?
set -e
test "$foreign_op_status" -ne 0
grep -F 'refusing to replace an op symlink that does not target macop' "$fixture_root/foreign-op.stderr"
test ! -e "$bin_dir/macop"
test ! -e "$bin_dir/macop-agent"
test ! -e "$bin_dir/MacopAuth.app"
test "$(readlink "$bin_dir/op")" = "/usr/bin/true"
rm -f "$bin_dir/op"

# A partial or duplicated managed block must fail before installation rather
# than dropping the remainder of a user-owned profile.
printf '%s\n' \
  'export EXISTING_SETTING=preserved' \
  '# >>> macop PATH >>>' \
  'export MUST_NOT_BE_REMOVED=yes' \
  >"$shell_profile"
set +e
MACOP_INSTALL_TEST_MODE=1 bash scripts/build-install.sh \
  --configuration debug \
  --skip-build \
  --bin-dir "$bin_dir" \
  --configure-path \
  --shell-profile "$shell_profile" \
  >"$fixture_root/malformed-profile.stdout" 2>"$fixture_root/malformed-profile.stderr"
malformed_profile_status=$?
set -e
test "$malformed_profile_status" -ne 0
grep -F 'managed PATH markers are malformed' "$fixture_root/malformed-profile.stderr"
test ! -e "$bin_dir/macop"
test ! -e "$bin_dir/macop-agent"
test ! -e "$bin_dir/MacopAuth.app"
grep -Fqx 'export MUST_NOT_BE_REMOVED=yes' "$shell_profile"
printf '%s\n' 'export EXISTING_SETTING=preserved' >"$shell_profile"

# A request for stable signing must name a real identity rather than silently
# falling back to an ad-hoc signature.
set +e
MACOP_INSTALL_TEST_MODE=1 bash scripts/build-install.sh \
  --configuration debug \
  --skip-build \
  --bin-dir "$bin_dir" \
  --signing-identity - \
  >"$fixture_root/invalid-signing.stdout" 2>"$fixture_root/invalid-signing.stderr"
invalid_signing_status=$?
set -e
test "$invalid_signing_status" -ne 0
grep -F 'requires a named or hash codesigning identity' "$fixture_root/invalid-signing.stderr"
test ! -e "$bin_dir/macop"
test ! -e "$bin_dir/macop-agent"
test ! -e "$bin_dir/MacopAuth.app"

# A pathname collision at the generation manifest must fail before journaling
# or moving the unrelated directory into installer-owned cleanup state.
manifest_collision="$bin_dir/macop-install-manifest.json"
mkdir "$manifest_collision"
printf 'must survive\n' >"$manifest_collision/sentinel"
set +e
MACOP_INSTALL_TEST_MODE=1 bash scripts/build-install.sh \
  --configuration debug \
  --skip-build \
  --bin-dir "$bin_dir" \
  >"$fixture_root/manifest-directory.stdout" 2>"$fixture_root/manifest-directory.stderr"
manifest_directory_status=$?
set -e
test "$manifest_directory_status" -ne 0
grep -F 'refusing to replace a non-file' "$fixture_root/manifest-directory.stderr"
test "$(cat "$manifest_collision/sentinel")" = 'must survive'
rm "$manifest_collision/sentinel"
rmdir "$manifest_collision"

MACOP_INSTALL_TEST_MODE=1 bash scripts/build-install.sh \
  --configuration debug \
  --skip-build \
  --bin-dir "$bin_dir" \
  --with-op-symlink \
  --configure-path \
  --shell-profile "$shell_profile"

test -x "$bin_dir/macop"
test -x "$bin_dir/macop-agent"
test -x "$bin_dir/MacopAuth.app/Contents/MacOS/MacopAuth"
for language in ja en; do
  strings_file="$bin_dir/MacopAuth.app/Contents/Resources/$language.lproj/Localizable.strings"
  test -f "$strings_file"
  plutil -lint "$strings_file" >/dev/null
done
test -f "$bin_dir/MacopAuth.app/Contents/Resources/MacopAuth.icns"
test "$(plutil -extract 'CFBundleIconFile' raw "$bin_dir/MacopAuth.app/Contents/Info.plist")" = "MacopAuth"
test "$(plutil -extract 'LSUIElement' raw "$bin_dir/MacopAuth.app/Contents/Info.plist")" = "false"
test "$(plutil -extract 'CFBundleLocalizations.0' raw "$bin_dir/MacopAuth.app/Contents/Info.plist")" = "ja"
test "$(plutil -extract 'CFBundleLocalizations.1' raw "$bin_dir/MacopAuth.app/Contents/Info.plist")" = "en"
test -f "$bin_dir/macop-install-manifest.json"
grep -Fqx '  "broker_protocol_version": 9,' "$bin_dir/macop-install-manifest.json"
test -L "$bin_dir/op"
test "$(readlink "$bin_dir/op")" = "macop"
test "$(codesign -d --verbose=4 "$bin_dir/macop" 2>&1 | sed -n 's/^Identifier=//p')" = "macop"
test "$(codesign -d --verbose=4 "$bin_dir/macop-agent" 2>&1 | sed -n 's/^Identifier=//p')" = "macop-agent"
test "$(codesign -d --verbose=4 "$bin_dir/MacopAuth.app" 2>&1 | sed -n 's/^Identifier=//p')" = \
  "io.github.slashkiko.macop.auth"
macop_flags="$(codesign -d --verbose=4 "$bin_dir/macop" 2>&1 \
  | sed -n 's/^CodeDirectory .* flags=\(0x[0-9A-Fa-f]*\).*/\1/p')"
agent_flags="$(codesign -d --verbose=4 "$bin_dir/macop-agent" 2>&1 \
  | sed -n 's/^CodeDirectory .* flags=\(0x[0-9A-Fa-f]*\).*/\1/p')"
(( (macop_flags & 0x10000) != 0 ))
(( (agent_flags & 0x10000) != 0 ))
! codesign -d --entitlements :- "$bin_dir/macop" 2>/dev/null \
  | grep -Fq 'com.apple.security.cs.disable-library-validation'
! codesign -d --entitlements :- "$bin_dir/macop-agent" 2>/dev/null \
  | grep -Fq 'com.apple.security.cs.disable-library-validation'
grep -Fqx '# >>> macop PATH >>>' "$shell_profile"
grep -Fqx "export PATH=$bin_dir:\"\$PATH\"" "$shell_profile"
grep -Fqx 'export EXISTING_SETTING=preserved' "$shell_profile"

# The transaction guard must preserve the complete published generation, not
# just whichever executable happens to be checked first.
snapshot_generation() {
  local destination="$1"
  {
    shasum "$bin_dir/macop"
    shasum "$bin_dir/macop-agent"
    shasum "$bin_dir/macop-install-manifest.json"
    find "$bin_dir/MacopAuth.app" -type f -exec shasum {} \;
  } >"$destination"
}

assert_generation_matches() {
  local expected="$1" actual="$fixture_root/generation.actual"
  snapshot_generation "$actual"
  cmp -s "$expected" "$actual"
}

# Uninstall shares the installer transaction authority. While a real installer
# holds the lock, uninstall must reject without changing components, the
# manifest, pending state, or the installer's lock record.
state_dir="$bin_dir/.macop-install-state"
MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_TEST_HOLD_LOCK_SECONDS=2 bash scripts/build-install.sh \
  --configuration debug \
  --skip-build \
  --bin-dir "$bin_dir" \
  >"$fixture_root/held-installer.out" 2>&1 &
installer_pid=$!
for _ in {1..100}; do
  if [[ -f "$state_dir/lock/pid" ]] && [[ "$(tr -d '\n' <"$state_dir/lock/pid")" == "$installer_pid" ]]; then
    break
  fi
  sleep 0.1
done
test -f "$state_dir/lock/pid"
test "$(tr -d '\n' <"$state_dir/lock/pid")" = "$installer_pid"
test ! -e "$state_dir/pending"
snapshot_generation "$fixture_root/generation.before-lock"
set +e
MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$fixture_root/locked-uninstall.out" 2>&1
status=$?
set -e
test "$status" -ne 0
grep -Fq 'a macop install transaction is active' "$fixture_root/locked-uninstall.out"
assert_generation_matches "$fixture_root/generation.before-lock"
test ! -e "$state_dir/pending"
test "$(tr -d '\n' <"$state_dir/lock/pid")" = "$installer_pid"
set +e
wait "$installer_pid"
installer_status=$?
set -e
if [[ "$installer_status" -ne 0 ]]; then
  cat "$fixture_root/held-installer.out" >&2
  exit "$installer_status"
fi

# PENDING, ROLLBACK_INCOMPLETE, and every malformed/ambiguous retained journal
# are evidence that only the installer may resolve. Uninstall keeps that
# evidence and the generation intact. The journals live under the same state
# root the installer acquired above; a separate test root is covered below.
snapshot_generation "$fixture_root/generation.before-evidence"
printf 'pending evidence\n' >"$state_dir/pending"
set +e
MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$fixture_root/state-pending-uninstall.out" 2>&1
status=$?
set -e
test "$status" -ne 0
assert_generation_matches "$fixture_root/generation.before-evidence"
test -f "$state_dir/pending"
rm -f "$state_dir/pending"
for journal_kind in pending incomplete malformed; do
  journal="$state_dir/journal.uninstall-$journal_kind"
  mkdir -m 700 "$journal"
  case "$journal_kind" in
    pending) printf 'pending\n' >"$journal/PENDING" ;;
    incomplete) printf 'rollback-incomplete\n' >"$journal/ROLLBACK_INCOMPLETE" ;;
    malformed) printf 'unknown\n' >"$journal/UNKNOWN" ;;
  esac
  set +e
  MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$fixture_root/$journal_kind-uninstall.out" 2>&1
  status=$?
  set -e
  test "$status" -ne 0
  assert_generation_matches "$fixture_root/generation.before-evidence"
  test -e "$journal"
  case "$journal_kind" in
    pending) test -f "$journal/PENDING" ;;
    incomplete) test -f "$journal/ROLLBACK_INCOMPLETE" ;;
    malformed) test -f "$journal/UNKNOWN" ;;
  esac
  rm -rf "$journal"
done

# Completed transaction journals from an older installer are safe cleanup
# work and must not permanently block uninstall.
for terminal_kind in COMMITTED ROLLED_BACK; do
  case "$terminal_kind" in
    COMMITTED) terminal_leaf="committed" ;;
    ROLLED_BACK) terminal_leaf="rolled-back" ;;
  esac
  journal="$state_dir/journal.uninstall-terminal-$terminal_leaf"
  mkdir -m 700 "$journal"
  case "$terminal_kind" in
    COMMITTED) printf 'committed\n' >"$journal/$terminal_kind" ;;
    ROLLED_BACK) printf 'rolled-back\n' >"$journal/$terminal_kind" ;;
  esac
  chmod 600 "$journal/$terminal_kind"
done

# Test-mode authority stays entirely within its selected root. Recovery
# evidence in another test root must not block this uninstall, and the normal
# Application Support state namespace remains untouched.
other_bin_dir="$fixture_root/other-root/bin"
other_state_dir="$other_bin_dir/.macop-install-state"
mkdir -p "$other_state_dir/journal.other-root"
chmod 700 "$fixture_root/other-root" "$other_bin_dir" "$other_state_dir" "$other_state_dir/journal.other-root"
printf 'other root evidence\n' >"$other_state_dir/journal.other-root/PENDING"
production_state_dir="$test_home/Library/Application Support/macop/install-state"
mkdir -p "$production_state_dir"
chmod 700 "$production_state_dir"
printf 'production state must remain untouched\n' >"$production_state_dir/sentinel"

MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$bin_dir" --shell-profile "$shell_profile"

test ! -e "$bin_dir/macop"
test ! -e "$bin_dir/macop-agent"
test ! -e "$bin_dir/MacopAuth.app"
test ! -e "$bin_dir/macop-install-manifest.json"
test ! -e "$bin_dir/op"
test -d "$bin_dir"
test -f "$config_marker"
test -f "$other_state_dir/journal.other-root/PENDING"
test "$(cat "$production_state_dir/sentinel")" = 'production state must remain untouched'
if grep -Fq '# >>> macop PATH >>>' "$shell_profile"; then
  exit 1
fi
grep -Fqx 'export EXISTING_SETTING=preserved' "$shell_profile"

# Pre-transaction releases had no install-state directory. The current
# uninstaller creates only its owner-only coordination state and then removes
# the recognized signed generation normally.
legacy_bin_dir="$fixture_root/legacy-uninstall/bin"
mkdir -p "$legacy_bin_dir"
chmod 700 "$fixture_root/legacy-uninstall" "$legacy_bin_dir"
cp "$repo_root/.build/debug/macop" "$legacy_bin_dir/macop"
cp "$repo_root/.build/debug/macop-agent" "$legacy_bin_dir/macop-agent"
cp -R "$repo_root/.build/debug/MacopAuth.app" "$legacy_bin_dir/MacopAuth.app"
codesign --force --options runtime --sign - --identifier macop "$legacy_bin_dir/macop"
codesign --force --options runtime --sign - --identifier macop-agent "$legacy_bin_dir/macop-agent"
MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$legacy_bin_dir" --keep-path
test ! -e "$legacy_bin_dir/macop"
test ! -e "$legacy_bin_dir/macop-agent"
test ! -e "$legacy_bin_dir/MacopAuth.app"
test -d "$legacy_bin_dir/.macop-install-state"

MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --help | grep -Fq -- '--delete-managed-keychain'
if MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh \
  --bin-dir "$bin_dir" \
  --shell-profile "$shell_profile" \
  --delete-managed-keychain >/dev/null 2>&1; then
  exit 1
fi

ln -s /usr/bin/true "$bin_dir/op"
MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$bin_dir" --shell-profile "$shell_profile"
test "$(readlink "$bin_dir/op")" = "/usr/bin/true"

printf '%s\n' 'build/install/uninstall fixture passed'
