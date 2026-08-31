#!/bin/bash
set -euo pipefail

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/macop-agent-helper.XXXXXX")"
active_helper=""
active_group=""
cleanup() {
  if [[ -n "$active_group" ]]; then kill -KILL "-$active_group" 2>/dev/null || true; fi
  if [[ -n "$active_helper" ]]; then kill -KILL "$active_helper" 2>/dev/null || true; fi
  rm -rf "$fixture_root"
}
trap cleanup EXIT

install -m 755 .build/debug/macop "$fixture_root/macop"
install -m 755 .build/debug/macop-agent "$fixture_root/macop-agent"
codesign --force --options runtime --sign - --identifier macop "$fixture_root/macop"
codesign --force --options runtime --sign - --identifier macop-agent "$fixture_root/macop-agent"

stdout_file="$fixture_root/stdout"
stderr_file="$fixture_root/stderr"
set +e
/usr/bin/env PATH="$fixture_root:${PATH:-/usr/bin:/bin}" macop --format=json --debug \
  ssh agent shell macop-helper-fixture-missing-identity -- /bin/true \
  >"$stdout_file" 2>"$stderr_file"
status=$?
set -e

test ! -s "$stdout_file"
test "$status" -eq 3
/usr/bin/python3 - "$stderr_file" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
payload = json.loads(text)
error = payload.get("error", {})
assert error.get("code") == "unsupported_command", payload
assert "debug" in error, payload
message = error.get("message", "")
assert "team-signed" in message and "ad-hoc" in message, payload
PY

set +e
/usr/bin/env PATH="$fixture_root:${PATH:-/usr/bin:/bin}" macop --debug \
  ssh agent shell macop-helper-fixture-missing-identity -- /bin/true \
  >"$stdout_file" 2>"$stderr_file"
status=$?
set -e

test ! -s "$stdout_file"
test "$status" -eq 3
test "$(grep -Ec '^macop: debug exit_code=[0-9]+ command=ssh$' "$stderr_file")" -eq 1

# Exercise macop-agent's direct human error renderer too. The top-level macop
# wrapper deliberately delegates its debug line to the helper, so either path
# must emit exactly one safe line and never a secret-bearing argv.
set +e
MACOP_AGENT_DEBUG=1 MACOP_AGENT_FORMAT=human "$fixture_root/macop-agent" \
  >"$stdout_file" 2>"$stderr_file"
status=$?
set -e

test ! -s "$stdout_file"
test "$status" -eq 2
test "$(grep -Ec '^macop: debug exit_code=2 command=ssh$' "$stderr_file")" -eq 1

MACOP_AGENT_RUN_LIFECYCLE_FIXTURES=1 "$fixture_root/macop-agent"
/usr/bin/script -q /dev/null env MACOP_AGENT_RUN_LIFECYCLE_FIXTURES=1 "$fixture_root/macop-agent"
MACOP_AGENT_RUN_GIT_SUSPENDED_FIXTURE=1 "$fixture_root/macop-agent"
MACOP_AGENT_RUN_SHELL_DEFERRED_FIXTURE=1 "$fixture_root/macop-agent"

assert_signal_cleanup() {
  local signal_name="$1"
  local expected_status="$2"
  local iteration="$3"
  local fixture_kind="${4:-shell}"
  local child_file="$fixture_root/signal-child-$signal_name-$iteration"
  rm -f "$child_file"
  if [[ "$fixture_kind" == "application" ]]; then
    MACOP_AGENT_RUN_APPLICATION_SIGNAL_FIXTURE=1 MACOP_AGENT_SIGNAL_CHILD_FILE="$child_file" \
      "$fixture_root/macop-agent" >"$stdout_file" 2>"$stderr_file" &
  else
    MACOP_AGENT_RUN_SIGNAL_FIXTURE=1 MACOP_AGENT_SIGNAL_CHILD_FILE="$child_file" \
      "$fixture_root/macop-agent" >"$stdout_file" 2>"$stderr_file" &
  fi
  local helper_pid=$!
  active_helper="$helper_pid"
  for _ in $(seq 1 100); do
    test -s "$child_file" && break
    sleep 0.02
  done
  test -s "$child_file"
  local child_pid
  child_pid="$(tr -d '[:space:]' <"$child_file")"
  active_group="$(ps -o pgid= -p "$child_pid" | tr -d '[:space:]')"
  kill "-$signal_name" "$helper_pid"
  ( sleep 15; kill -KILL "-$active_group" 2>/dev/null || true; kill -KILL "$helper_pid" 2>/dev/null || true ) &
  local watchdog_pid=$!
  set +e
  wait "$helper_pid"
  local result_code=$?
  set -e
  kill "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  test "$result_code" -eq "$expected_status"
  ! kill -0 "$child_pid" 2>/dev/null
  active_helper=""
  active_group=""
}

for iteration in $(seq 1 20); do
  assert_signal_cleanup TERM 143 "$iteration"
  assert_signal_cleanup INT 130 "$iteration"
done

assert_signal_cleanup TERM 143 application-term application
assert_signal_cleanup INT 130 application-int application

printf '%s\n' 'agent helper PATH fixture passed'
