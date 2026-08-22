#!/bin/bash
set -euo pipefail

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/macop-installation.XXXXXX")"
cleanup() { rm -rf "$fixture_root"; }
trap cleanup EXIT

bin_dir="$fixture_root/bin"
test_home="$fixture_root/home"
shell_profile="$test_home/.zprofile"
config_marker="$fixture_root/Library/Application Support/macop/config.json"
mkdir -p "$(dirname "$config_marker")" "$test_home"
printf '%s\n' '{"version":1}' >"$config_marker"
printf '%s\n' 'export EXISTING_SETTING=preserved' >"$shell_profile"

# An existing unrelated `op` must be detected before either binary is
# installed, so opting into compatibility never replaces another CLI.
mkdir -p "$bin_dir"
ln -s /usr/bin/true "$bin_dir/op"
set +e
bash scripts/build-install.sh \
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
bash scripts/build-install.sh \
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
grep -Fqx 'export MUST_NOT_BE_REMOVED=yes' "$shell_profile"
printf '%s\n' 'export EXISTING_SETTING=preserved' >"$shell_profile"

bash scripts/build-install.sh \
  --configuration debug \
  --skip-build \
  --bin-dir "$bin_dir" \
  --with-op-symlink \
  --configure-path \
  --shell-profile "$shell_profile"

test -x "$bin_dir/macop"
test -x "$bin_dir/macop-agent"
test -L "$bin_dir/op"
test "$(readlink "$bin_dir/op")" = "macop"
test "$(codesign -d --verbose=4 "$bin_dir/macop" 2>&1 | sed -n 's/^Identifier=//p')" = "macop"
test "$(codesign -d --verbose=4 "$bin_dir/macop-agent" 2>&1 | sed -n 's/^Identifier=//p')" = "macop-agent"
grep -Fqx '# >>> macop PATH >>>' "$shell_profile"
grep -Fqx "export PATH=$bin_dir:\"\$PATH\"" "$shell_profile"
grep -Fqx 'export EXISTING_SETTING=preserved' "$shell_profile"

bash scripts/uninstall.sh --bin-dir "$bin_dir" --shell-profile "$shell_profile"

test ! -e "$bin_dir/macop"
test ! -e "$bin_dir/macop-agent"
test ! -e "$bin_dir/op"
test -d "$bin_dir"
test -f "$config_marker"
if grep -Fq '# >>> macop PATH >>>' "$shell_profile"; then
  exit 1
fi
grep -Fqx 'export EXISTING_SETTING=preserved' "$shell_profile"

ln -s /usr/bin/true "$bin_dir/op"
bash scripts/uninstall.sh --bin-dir "$bin_dir"
test "$(readlink "$bin_dir/op")" = "/usr/bin/true"

printf '%s\n' 'build/install/uninstall fixture passed'
