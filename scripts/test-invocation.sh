#!/bin/bash
set -euo pipefail

# Exercise the documented alias and symlink installation modes without touching
# the user's PATH directory or shell configuration.
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/macop-invocation.XXXXXX")"
cleanup() { rm -rf "$fixture_root"; }
trap cleanup EXIT

bin_dir="$fixture_root/bin"
legacy_dir="$fixture_root/legacy"
mkdir -p "$bin_dir" "$legacy_dir"
install -m 755 .build/debug/macop "$bin_dir/macop"
ln -s macop "$bin_dir/op"
printf '%s\n' '#!/bin/sh' 'exit 99' >"$legacy_dir/op"
chmod 755 "$legacy_dir/op"

assert_json_schema() {
  /usr/bin/python3 -c '
import json, sys
payload = json.load(sys.stdin)
assert payload["schema_version"] == 3, payload
assert isinstance(payload["entries"], list) and payload["entries"], payload
'
}

# A real shell alias is intentionally tested through zsh. The flags occur on
# both sides of the command, matching the public parser contract.
ALIAS_BEFORE="$fixture_root/alias-before.json" \
ALIAS_AFTER="$fixture_root/alias-after.json" \
PATH="$bin_dir:$legacy_dir:$PATH" zsh -fc '
  alias op=macop
  op --format=json compatibility > "$ALIAS_BEFORE"
  op compatibility --format=json > "$ALIAS_AFTER"
'
assert_json_schema <"$fixture_root/alias-before.json"
assert_json_schema <"$fixture_root/alias-after.json"

# The symlink must win over a later, unrelated `op` on PATH and preserve the
# same compatibility and global-flag behavior when argv[0] is literally `op`.
PATH="$bin_dir:$legacy_dir:$PATH" op --format=json compatibility \
  | assert_json_schema
PATH="$bin_dir:$legacy_dir:$PATH" op compatibility --format=json \
  | assert_json_schema
test "$(PATH="$bin_dir:$legacy_dir:$PATH" command -v op)" = "$bin_dir/op"
test "$(PATH="$bin_dir:$legacy_dir:$PATH" op --version)" = "macop 0.1.0"

# Keep stdin open while a non-inject command contains the literal argument
# "inject". The CLI must parse the selected command instead of blocking on
# unrelated argv text.
MACOP_PATH="$bin_dir/macop" /usr/bin/python3 - <<'PY'
import os
import subprocess

process = subprocess.Popen(
    [os.environ["MACOP_PATH"], "item", "get", "inject"],
    stdin=subprocess.PIPE,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    process.wait(timeout=1)
except subprocess.TimeoutExpired:
    process.terminate()
    process.wait()
    raise AssertionError("an argument named inject must not make the CLI read stdin")
PY

printf '%s\n' 'alias and op symlink invocation fixture passed'
