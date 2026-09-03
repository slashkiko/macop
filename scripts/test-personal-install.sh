#!/bin/bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
personal_install="$script_dir/personal-install.sh"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/macop-personal-install.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT

assert_fails_with() {
  local expected="$1"
  shift
  local output status
  set +e
  output="$(HOME="$fixture_root/home" "$personal_install" "$@" 2>&1)"
  status=$?
  set -e
  [[ $status -ne 0 ]]
  printf '%s\n' "$output" | grep -F "$expected" >/dev/null
}

mkdir -p "$fixture_root/home"
bash -n "$personal_install"
"$personal_install" --help >/dev/null

assert_fails_with \
  'must be an exact 40-character SHA-1 fingerprint.' \
  setup --signing-identity invalid
assert_fails_with \
  'unsupported option: --skip-build' \
  setup --signing-identity 0000000000000000000000000000000000000000 --skip-build
assert_fails_with \
  'unsupported option: --check' \
  setup --signing-identity 0000000000000000000000000000000000000000 --check
assert_fails_with \
  'no saved signing identity; run the setup command first.' \
  update
assert_fails_with \
  'internal update command cannot be invoked directly.' \
  _install-saved

state_dir="$fixture_root/home/Library/Application Support/macop"
install -d -m 700 "$state_dir"
printf '%s\n' 0000000000000000000000000000000000000000 \
  >"$state_dir/personal-signing-identity"
chmod 644 "$state_dir/personal-signing-identity"
assert_fails_with \
  'saved signing identity must have mode 0600.' \
  update

chmod 600 "$state_dir/personal-signing-identity"
assert_fails_with \
  'the saved signing identity is not available in the macOS Keychain.' \
  update

fixture_repo="$fixture_root/repo"
fixture_scripts="$fixture_repo/scripts"
fixture_bin="$fixture_root/bin"
fixture_home="$fixture_root/success-home"
events="$fixture_root/events"
fixture_identity=1111111111111111111111111111111111111111
replacement_identity=2222222222222222222222222222222222222222
mkdir -p "$fixture_scripts" "$fixture_bin" "$fixture_home"
cp "$personal_install" "$fixture_scripts/personal-install.sh"

cat >"$fixture_bin/security" <<'EOF'
#!/bin/bash
if [[ "$*" == "find-identity -v -p codesigning" ]]; then
  printf '  1) %s "Apple Development: Fixture (TEAM123456)"\n' "$MACOP_TEST_IDENTITY"
  printf '  2) %s "Apple Development: Replacement (TEAM123456)"\n' "$MACOP_TEST_REPLACEMENT_IDENTITY"
  printf '  3) %s "Developer ID Application: Not Listed (TEAM123456)"\n' 3333333333333333333333333333333333333333
  printf '     3 valid identities found\n'
  exit 0
fi
exit 64
EOF

cat >"$fixture_bin/git" <<'EOF'
#!/bin/bash
set -euo pipefail
[[ "${1:-}" == "clone" ]] || exit 64
arguments=" $* "
[[ "$arguments" == *' --depth 1 '* ]]
[[ "$arguments" == *' --branch main '* ]]
[[ "$arguments" == *' --single-branch '* ]]
destination=""
repository=""
for argument in "$@"; do
  destination="$argument"
  case "$argument" in
    https://*) repository="$argument" ;;
  esac
done
[[ "$repository" == "https://github.com/slashkiko/macop.git" ]]
printf 'clone:%s\n' "$repository" >>"$MACOP_TEST_EVENTS"
printf 'clone-destination:%s\n' "$destination" >>"$MACOP_TEST_EVENTS"
printf 'git-tmpdir:%s\n' "${TMPDIR:-}" >>"$MACOP_TEST_EVENTS"
printf 'clone-root-mode:%s\n' "$(stat -f '%Lp' "$(dirname "$destination")")" \
  >>"$MACOP_TEST_EVENTS"
[[ "${MACOP_TEST_GIT_FAIL:-0}" != "1" ]]
mkdir -p "$destination"
cp -R "$MACOP_TEST_CLONE_SOURCE/." "$destination/"
case "${MACOP_TEST_CLONE_VARIANT:-regular}" in
  regular) ;;
  missing) rm -f "$destination/scripts/personal-install.sh" ;;
  symlink)
    rm -f "$destination/scripts/personal-install.sh"
    ln -s /bin/true "$destination/scripts/personal-install.sh"
    ;;
  *) exit 64 ;;
esac
EOF

cat >"$fixture_scripts/create-development-profile.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
output=""
identity=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --signing-identity) identity="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    *) exit 64 ;;
  esac
done
printf 'profile:%s\n' "$identity" >>"$MACOP_TEST_EVENTS"
printf 'profile-tmpdir:%s\n' "${TMPDIR:-}" >>"$MACOP_TEST_EVENTS"
mkdir -p "$(dirname "$output")"
printf 'fixture profile\n' >"$output"
chmod 600 "$output"
EOF

cat >"$fixture_scripts/build-install.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
[[ -n "${MACOP_SIGNING_IDENTITY:-}" ]]
[[ -f "${MACOP_PROVISIONING_PROFILE:-}" ]]
printf 'install:%s:%s\n' "$MACOP_SIGNING_IDENTITY" "$*" >>"$MACOP_TEST_EVENTS"
printf 'install-tmpdir:%s\n' "${TMPDIR:-}" >>"$MACOP_TEST_EVENTS"
[[ "${MACOP_TEST_INSTALL_FAIL:-0}" != "1" ]]
EOF
chmod 755 "$fixture_bin/security" "$fixture_bin/git" "$fixture_scripts/"*.sh

run_fixture() {
  HOME="$fixture_home" \
  PATH="$fixture_bin:$PATH" \
  MACOP_TEST_IDENTITY="$fixture_identity" \
  MACOP_TEST_REPLACEMENT_IDENTITY="$replacement_identity" \
  MACOP_TEST_EVENTS="$events" \
  MACOP_TEST_CLONE_SOURCE="$fixture_repo" \
  MACOP_TEST_CLONE_VARIANT="${MACOP_TEST_CLONE_VARIANT:-regular}" \
  TMPDIR="${MACOP_TEST_TMPDIR:-${TMPDIR:-/tmp}}" \
    "$fixture_scripts/personal-install.sh" "$@"
}

identities_output="$(run_fixture identities)"
printf '%s\n' "$identities_output" | grep -F 'Apple Development: Fixture' >/dev/null
printf '%s\n' "$identities_output" | grep -F 'Apple Development: Replacement' >/dev/null
if printf '%s\n' "$identities_output" | grep -F 'Developer ID Application' >/dev/null; then
  printf 'identities unexpectedly included a non-development identity\n' >&2
  exit 1
fi

set +e
selection_output="$(run_fixture setup 2>&1)"
selection_status=$?
set -e
[[ $selection_status -ne 0 ]]
printf '%s\n' "$selection_output" \
  | grep -F 'setup needs an interactive terminal to choose a certificate' >/dev/null

run_fixture setup --signing-identity "$fixture_identity" >/dev/null
fixture_state="$fixture_home/Library/Application Support/macop/personal-signing-identity"
[[ "$(<"$fixture_state")" == "$fixture_identity" ]]
[[ "$(stat -f '%Lp' "$fixture_state")" == "600" ]]
grep -Fx "profile:$fixture_identity" "$events" >/dev/null
grep -Fx "install:$fixture_identity:--configure-path" "$events" >/dev/null
grep -Fx 'profile-tmpdir:/private/tmp' "$events" >/dev/null
grep -Fx 'install-tmpdir:/private/tmp' "$events" >/dev/null

: >"$events"
run_fixture setup \
  --signing-identity "$fixture_identity" \
  --no-configure-path >/dev/null
grep -Fx "install:$fixture_identity:" "$events" >/dev/null
if grep -F -- '--configure-path' "$events" >/dev/null; then
  printf '%s\n' '--no-configure-path unexpectedly reached the installer as --configure-path' >&2
  exit 1
fi

: >"$events"
run_fixture update >/dev/null
grep -Fx 'clone:https://github.com/slashkiko/macop.git' "$events" >/dev/null
clone_destination="$(sed -n 's/^clone-destination://p' "$events")"
[[ "$clone_destination" == /private/tmp/macop-personal-update.*/repository ]]
[[ ! -e "$(dirname "$clone_destination")" ]]
grep -Fx 'git-tmpdir:/private/tmp' "$events" >/dev/null
grep -Fx 'clone-root-mode:700' "$events" >/dev/null
grep -Fx 'profile-tmpdir:/private/tmp' "$events" >/dev/null
grep -Fx 'install-tmpdir:/private/tmp' "$events" >/dev/null
grep -Fx "profile:$fixture_identity" "$events" >/dev/null
grep -Fx "install:$fixture_identity:" "$events" >/dev/null

attacker_temp="$fixture_root/attacker-controlled-temp"
mkdir -p "$attacker_temp"
printf 'preserve me\n' >"$attacker_temp/sentinel"
ln -s "$attacker_temp" "$fixture_root/attacker-temp-link"
for hostile_temp in "$attacker_temp" "$fixture_root/attacker-temp-link/"; do
  : >"$events"
  MACOP_TEST_TMPDIR="$hostile_temp" run_fixture update >/dev/null
  clone_destination="$(sed -n 's/^clone-destination://p' "$events")"
  [[ "$clone_destination" == /private/tmp/macop-personal-update.*/repository ]]
  [[ "$clone_destination" != "$attacker_temp"/* ]]
  grep -Fx 'git-tmpdir:/private/tmp' "$events" >/dev/null
  grep -Fx 'clone-root-mode:700' "$events" >/dev/null
  grep -Fx 'profile-tmpdir:/private/tmp' "$events" >/dev/null
done
grep -Fx 'preserve me' "$attacker_temp/sentinel" >/dev/null

for clone_variant in missing symlink; do
  : >"$events"
  set +e
  malformed_output="$(MACOP_TEST_CLONE_VARIANT="$clone_variant" run_fixture update 2>&1)"
  malformed_status=$?
  set -e
  [[ $malformed_status -ne 0 ]]
  printf '%s\n' "$malformed_output" \
    | grep -F 'the fresh clone does not contain a regular personal installer' >/dev/null
  clone_destination="$(sed -n 's/^clone-destination://p' "$events")"
  [[ ! -e "$(dirname "$clone_destination")" ]]
  [[ "$(grep -c '^install:' "$events" || true)" == "0" ]]
done

: >"$events"
set +e
MACOP_TEST_GIT_FAIL=1 run_fixture update >/dev/null 2>&1
clone_failure_status=$?
set -e
[[ $clone_failure_status -ne 0 ]]
[[ "$(<"$fixture_state")" == "$fixture_identity" ]]
grep -Fx 'clone:https://github.com/slashkiko/macop.git' "$events" >/dev/null
clone_destination="$(sed -n 's/^clone-destination://p' "$events")"
[[ ! -e "$(dirname "$clone_destination")" ]]
[[ "$(grep -c '^install:' "$events" || true)" == "0" ]]

set +e
MACOP_TEST_INSTALL_FAIL=1 run_fixture setup \
  --signing-identity "$replacement_identity" \
  --replace-identity >/dev/null 2>&1
replacement_status=$?
set -e
[[ $replacement_status -ne 0 ]]
[[ "$(<"$fixture_state")" == "$fixture_identity" ]]

: >"$events"
run_fixture setup \
  --signing-identity "$replacement_identity" \
  --replace-identity \
  --no-configure-path >/dev/null
[[ "$(<"$fixture_state")" == "$replacement_identity" ]]
grep -Fx "profile:$replacement_identity" "$events" >/dev/null
grep -Fx "install:$replacement_identity:" "$events" >/dev/null

failed_home="$fixture_root/failed-home"
mkdir -p "$failed_home"
set +e
HOME="$failed_home" \
PATH="$fixture_bin:$PATH" \
MACOP_TEST_IDENTITY="$fixture_identity" \
MACOP_TEST_REPLACEMENT_IDENTITY="$replacement_identity" \
MACOP_TEST_EVENTS="$events" \
MACOP_TEST_INSTALL_FAIL=1 \
  "$fixture_scripts/personal-install.sh" setup \
    --signing-identity "$fixture_identity" >/dev/null 2>&1
failed_status=$?
set -e
[[ $failed_status -ne 0 ]]
[[ ! -e "$failed_home/Library/Application Support/macop/personal-signing-identity" ]]

printf 'Personal signing wrapper validation passed.\n'
