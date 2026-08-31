#!/bin/bash
set -euo pipefail

if [[ "${0##*/}" == "make" ]]; then
  printf '%s\n' "$*"
  exit 37
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/macop-build-install-products.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT

git_environment='GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.bareRepository GIT_CONFIG_VALUE_0=all'

assert_plan() {
  local target="$1"
  local expected="$2"
  local actual
  actual="$(make -C "$repo_root" --no-print-directory -n "$target")"
  [[ "$actual" == "$expected" ]] || {
    printf 'unexpected %s plan:\n%s\n' "$target" "$actual" >&2
    exit 1
  }
}

assert_plan build "$git_environment swift build"
assert_plan release-build "$git_environment swift build -c release"
assert_plan build-install-products "$git_environment swift build --product macop
$git_environment swift build --product macop-agent
$git_environment swift build --product MacopAuth"
assert_plan release-build-install-products "$git_environment swift build -c release --product macop
$git_environment swift build -c release --product macop-agent
$git_environment swift build -c release --product MacopAuth"

ln -s "$repo_root/scripts/test-build-install-products.sh" "$fixture_root/make"

assert_installer_route() {
  local configuration="$1"
  local expected_target="$2"
  local output status
  set +e
  output="$(
    PATH="$fixture_root:$PATH" bash "$repo_root/scripts/build-install.sh" \
      --configuration "$configuration" --bin-dir "$fixture_root/bin" 2>&1
  )"
  status=$?
  set -e
  [[ "$status" -eq 37 ]] || {
    printf 'installer %s routing probe exited with %s:\n%s\n' \
      "$configuration" "$status" "$output" >&2
    exit 1
  }
  [[ "$output" == "-C $repo_root $expected_target" ]] || {
    printf 'unexpected installer %s route:\n%s\n' "$configuration" "$output" >&2
    exit 1
  }
}

assert_installer_route debug build-install-products
assert_installer_route release release-build-install-products

printf 'build-install product routing tests passed\n'
