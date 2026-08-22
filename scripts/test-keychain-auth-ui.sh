#!/bin/bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
reference="${MACOP_KEYCHAIN_AUTH_REFERENCE:-}"
executable="${MACOP_KEYCHAIN_AUTH_EXECUTABLE:-$repo_root/.build/debug/macop}"

if [[ -z "$reference" ]]; then
  echo "Set MACOP_KEYCHAIN_AUTH_REFERENCE to an existing ACL-protected op:// or keychain:// reference." >&2
  exit 2
fi
case "$reference" in
  op://* | keychain://*) ;;
  *)
    echo "MACOP_KEYCHAIN_AUTH_REFERENCE must use op:// or keychain://." >&2
    exit 2
    ;;
esac
if [[ ! -x "$executable" ]]; then
  echo "MACOP_KEYCHAIN_AUTH_EXECUTABLE is not executable: $executable" >&2
  exit 2
fi

echo "Approve the Keychain read, count the authentication dialogs, and do not choose Always Allow." >&2
"$executable" read --no-newline "$reference" >/dev/null

if [[ ! -r /dev/tty ]]; then
  echo "A controlling terminal is required to confirm the dialog count." >&2
  exit 2
fi
read -r -p "Did exactly one authentication dialog appear? [y/N] " answer </dev/tty
case "$answer" in
  y | Y | yes | YES)
    echo "Keychain authentication UI fixture passed."
    ;;
  *)
    echo "Keychain authentication UI fixture failed: expected exactly one dialog." >&2
    exit 1
    ;;
esac
