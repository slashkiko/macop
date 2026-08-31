#!/bin/bash
set -euo pipefail

# This fixture exercises the installer only below mktemp's root.  Its explicit
# test-mode gate is part of the production script, not a convention here.
fixture_root="$(mktemp -d /private/tmp/macop-install-test-transaction.XXXXXX)"
agent_fixture_pid=""
cleanup() {
  [[ -z "$agent_fixture_pid" ]] || kill -KILL "$agent_fixture_pid" 2>/dev/null || true
  rm -rf -- "$fixture_root"
}
trap cleanup EXIT

# macOS ships Bash 3.2. Dynamic descriptor allocation (`exec {name}<file`)
# parses there as an attempt to execute a command and breaks the production
# broker probe even though test mode skips that branch.
if grep -Eq 'exec[[:space:]]+\{[[:alnum:]_]+\}[[:space:]]*[<>]' scripts/build-install.sh; then
  echo "production installer uses Bash 4-only dynamic FD allocation" >&2
  exit 1
fi

bin_dir="$fixture_root/bin"
export HOME="$fixture_root/home"
export SHELL=/bin/zsh
mkdir -p "$HOME" "$bin_dir"
chmod 700 "$fixture_root" "$bin_dir"

# Recursive removal atomically retires the public leaf and traverses only the
# opened inode. Darwin cannot unlink an opened directory by descriptor, so the
# safe terminal state is an empty random tombstone rather than a pathname-based
# final rmdir that could target a replacement.
install_fs_root="$fixture_root/install-fs"
mkdir -p "$install_fs_root/tree/child"
printf 'payload\n' >"$install_fs_root/tree/child/file"
install_fs_root_id="$(python3 scripts/install-fs.py id "$install_fs_root")"
python3 scripts/install-fs.py remove "$install_fs_root" "$install_fs_root_id" tree dir
test ! -e "$install_fs_root/tree"
install_fs_tombstone="$(find "$install_fs_root" -mindepth 1 -maxdepth 1 -name '.remove-*' -type d -print -quit)"
test -n "$install_fs_tombstone"
if find "$install_fs_tombstone" -type f -o -type l | grep -q .; then
  echo 'fd-relative recursive removal retained a non-directory payload' >&2
  exit 1
fi

install_generation() {
  local generation="$1"
  MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION="$generation" \
    bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir"
}

assert_generation() {
  local expected="$1" manifest="$bin_dir/macop-install-manifest.json"
  test -f "$manifest"
  grep -Fqx "  \"build_generation\": \"$expected\"," "$manifest"
  grep -Fqx '  "broker_protocol_version": 8,' "$manifest"
  local name path expected_hash actual_hash
  for name in macop agent auth_app; do
    case "$name" in
      macop) path="$bin_dir/macop" ;;
      agent) path="$bin_dir/macop-agent" ;;
      auth_app) path="$bin_dir/MacopAuth.app/Contents/MacOS/MacopAuth" ;;
    esac
    test -f "$path"
    expected_hash="$(sed -n "s/.*\"$name\": {\"sha256\":\"\([0-9a-f]*\)\".*/\1/p" "$manifest")"
    actual_hash="$(shasum -a 256 "$path" | awk '{print $1}')"
    test "$actual_hash" = "$expected_hash"
  done
}

assert_capability_contract() {
  local root="$1" state capability journal pending expected_state_device expected_state_inode expected_journal_device expected_journal_inode
  state="$root/.macop-install-state"
  capability="$(find "$state" -mindepth 2 -maxdepth 2 -name INSTALLER_CAPABILITY -type f -print -quit)"
  test -n "$capability"
  journal="$(dirname "$capability")"
  pending="$state/pending"
  expected_state_device="$(stat -f '%d' "$state")"
  expected_state_inode="$(stat -f '%i' "$state")"
  expected_journal_device="$(stat -f '%d' "$journal")"
  expected_journal_inode="$(stat -f '%i' "$journal")"
  test "$(wc -l <"$capability" | tr -d ' ')" = 11
  test "$(sed -n '1p' "$capability")" = 'schema=1'
  test "$(sed -n '2p' "$capability")" = "state=$(cd "$state" && pwd -P)"
  test "$(sed -n '3p' "$capability")" = "state_device=$expected_state_device"
  test "$(sed -n '4p' "$capability")" = "state_inode=$expected_state_inode"
  test "$(sed -n '5p' "$capability")" = "journal=$(cd "$journal" && pwd -P)"
  test "$(sed -n '6p' "$capability")" = "journal_device=$expected_journal_device"
  test "$(sed -n '7p' "$capability")" = "journal_inode=$expected_journal_inode"
  sed -n '8p' "$capability" | grep -E '^nonce=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  test "$(sed -n '9p' "$capability")" = 'operations=generation,broker,auth-probe'
  test "$(sed -n '10p' "$capability")" = "macop_executable=$(cd "$root" && pwd -P)/macop"
  # The Auth executable is carried in the final field; keep the field count
  # deliberately closed so stale, permissive capability schemas cannot pass.
  test "$(sed -n '11p' "$capability")" = "auth_executable=$(cd "$root" && pwd -P)/MacopAuth.app/Contents/MacOS/MacopAuth"
  test "$(wc -l <"$pending" | tr -d ' ')" = 5
  test "$(sed -n '1p' "$pending")" = 'schema=1'
  test "$(sed -n '2p' "$pending")" = "$(sed -n '8p' "$capability")"
  test "$(sed -n '3p' "$pending")" = "journal=$(cd "$journal" && pwd -P)"
  test "$(sed -n '4p' "$pending")" = "state_device=$expected_state_device"
  test "$(sed -n '5p' "$pending")" = "state_inode=$expected_state_inode"
}

install_generation old
assert_generation old

# Refusing an update while the installed one-shot agent is active must unwind
# the already-created transaction markers. Otherwise every entry point remains
# blocked even though no component was ever published.
agent_child_file="$fixture_root/active-agent-child"
MACOP_AGENT_RUN_SIGNAL_FIXTURE=1 MACOP_AGENT_SIGNAL_CHILD_FILE="$agent_child_file" \
  "$bin_dir/macop-agent" >"$fixture_root/active-agent.out" 2>&1 &
agent_fixture_pid=$!
for _ in $(seq 1 100); do
  [[ -f "$agent_child_file" ]] && break
  sleep 0.05
done
test -f "$agent_child_file"
set +e
MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION=active-agent-refused \
  MACOP_INSTALL_TEST_AGENT_PIDS="$agent_fixture_pid" \
  bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" \
    >"$fixture_root/active-agent-install.out" 2>&1
status=$?
set -e
test "$status" -ne 0
grep -Fq 'active installed macop-agent session' "$fixture_root/active-agent-install.out"
test ! -e "$bin_dir/.macop-install-state/pending"
if find "$bin_dir/.macop-install-state" -mindepth 1 -maxdepth 1 -name 'journal.*' -print -quit | grep -q .; then
  echo 'active-agent refusal retained a completed transaction journal' >&2
  exit 1
fi
assert_generation old
kill -TERM "$agent_fixture_pid"
wait "$agent_fixture_pid" || true
agent_fixture_pid=""

# Legacy v4/v5/v7 manifests are update inputs, never a publish target: a v8
# install replaces the complete old generation rather than accepting a mixed
# wire contract.
for legacy_protocol in 4 5 7; do
  sed "s/\"broker_protocol_version\": 8/\"broker_protocol_version\": $legacy_protocol/" \
    "$bin_dir/macop-install-manifest.json" >"$fixture_root/legacy-manifest.json"
  mv -- "$fixture_root/legacy-manifest.json" "$bin_dir/macop-install-manifest.json"
  install_generation "upgraded-v$legacy_protocol"
  assert_generation "upgraded-v$legacy_protocol"
  grep -Fqx '  "broker_protocol_version": 8,' "$bin_dir/macop-install-manifest.json"
  install_generation old
  assert_generation old
done

# Every mutation boundary must restore the old generation.  This includes the
# absent/present distinction because the first failed run is performed against
# a fully present generation; a separate fresh-root case covers absence below.
for point in \
  backup-macop-before backup-macop-after publish-macop-before publish-macop-after \
  backup-agent-before backup-agent-after publish-agent-before publish-agent-after \
  backup-auth_app-before backup-auth_app-after publish-auth_app-before publish-auth_app-after \
  backup-manifest-before backup-manifest-after publish-manifest-before publish-manifest-after \
  manifest-after handshake-after; do
  set +e
  MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION=new \
    MACOP_INSTALL_FAILPOINT="$point" \
    bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" \
      >"$fixture_root/$point.out" 2>"$fixture_root/$point.err"
  status=$?
  set -e
  test "$status" -ne 0
  assert_generation old
done

# HUP, INT, and TERM at a publish boundary all take the EXIT rollback path.
for signal_name in HUP INT TERM; do
  set +e
  MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION=new \
  MACOP_INSTALL_SIGNAL_FAILPOINT=publish-agent-after \
    MACOP_INSTALL_SIGNAL="$signal_name" bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" \
    >"$fixture_root/signal-$signal_name.out" 2>"$fixture_root/signal-$signal_name.err"
  status=$?
  set -e
  test "$status" -ne 0
  assert_generation old
done

# An absent destination must be removed, not recreated, if its first install
# fails after publication.
absent_bin="$fixture_root/absent/bin"
mkdir -p "$absent_bin"
chmod 700 "$fixture_root/absent" "$absent_bin"
set +e
MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION=new \
MACOP_INSTALL_FAILPOINT=publish-agent-after \
  bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$absent_bin" \
  >"$fixture_root/absent.out" 2>"$fixture_root/absent.err"
status=$?
set -e
test "$status" -ne 0
test ! -e "$absent_bin/macop" && test ! -e "$absent_bin/macop-agent" \
  && test ! -e "$absent_bin/MacopAuth.app" && test ! -e "$absent_bin/macop-install-manifest.json"

# Lock records are fixed leaves, never paths followed through a symlink.  An
# attacker-controlled PID target must fail closed before the transaction can
# publish into the generation directory.
mkdir "$bin_dir/.macop-install-state/lock"
printf 'not-a-pid\n' >"$fixture_root/foreign-pid"
ln -s "$fixture_root/foreign-pid" "$bin_dir/.macop-install-state/lock/pid"
set +e
install_generation lock-symlink >"$fixture_root/lock-symlink.out" 2>&1
status=$?
set -e
test "$status" -ne 0
grep -Fq 'unsafe PID record' "$fixture_root/lock-symlink.out"
assert_generation old
rm -rf -- "$bin_dir/.macop-install-state/lock"

# A held lock rejects an overlapping transaction without replacing anything.
MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION=locked \
  MACOP_INSTALL_TEST_HOLD_LOCK_SECONDS=2 \
  bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" &
holder=$!
sleep 1
set +e
MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION=other \
  bash scripts/build-install.sh \
    --configuration debug --skip-build --bin-dir "$bin_dir" >"$fixture_root/concurrent.out" 2>&1
status=$?
set -e
test "$status" -ne 0
grep -Fq 'another macop installer is active' "$fixture_root/concurrent.out"
wait "$holder"
assert_generation locked

# Releasing a lock is a handoff, not a delete-by-name. Exercise both owners at
# the boundary: before retirement a second transaction must see the original
# active PID; after retirement it may acquire a new lock, and the old owner's
# cleanup must not remove that new lock. A third transaction then proves the
# new lock remains authoritative until its owner releases it.
wait_for_release_pause() {
  local log="$1" marker="$2" ready=false
  # Building and ad-hoc signing the fixture can exceed 20 seconds on a cold or
  # contended runner. The log marker is the synchronization barrier; this loop
  # only bounds how long the test waits for that deterministic state.
  for _ in $(seq 1 600); do
    if grep -Fq "$marker" "$log" 2>/dev/null; then
      ready=true
      break
    fi
    sleep 0.1
  done
  if [[ "$ready" != true ]]; then
    tail -40 "$log" >&2 || true
    printf 'release handoff fixture did not reach %s\n' "$marker" >&2
    return 1
  fi
}

start_release_owner() {
  local owner="$1" point="$2" seconds="$3" generation="$4" log="$5"
  if [[ "$owner" == installer ]]; then
    MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION="$generation" \
      MACOP_INSTALL_TEST_RELEASE_PAUSE_AT="installer-$point" \
      MACOP_INSTALL_TEST_RELEASE_PAUSE_SECONDS="$seconds" \
      bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" >"$log" 2>&1 &
  else
    MACOP_INSTALL_TEST_MODE=1 \
      MACOP_INSTALL_TEST_RELEASE_PAUSE_AT="uninstaller-$point" \
      MACOP_INSTALL_TEST_RELEASE_PAUSE_SECONDS="$seconds" \
      bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$log" 2>&1 &
  fi
  release_owner_pid=$!
}

assert_release_handoff() {
  local owner="$1" case_root case_state log before_log after_log contender_log third_log state_id new_lock_id new_lock_pid
  case_root="$fixture_root/release-handoff-$owner"
  mkdir -p "$case_root/bin"
  chmod 700 "$case_root" "$case_root/bin"
  saved_bin_dir="$bin_dir"
  bin_dir="$case_root/bin"
  install_generation "handoff-$owner-initial"
  case_state="$bin_dir/.macop-install-state"

  # The visible lock still contains the owner's PID at retire-before.
  before_log="$fixture_root/release-handoff-$owner-before.out"
  start_release_owner "$owner" retire-before 3 "handoff-$owner-before" "$before_log"
  wait_for_release_pause "$before_log" "pause at $owner-retire-before"
  set +e
  MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$fixture_root/release-handoff-$owner-before-contender.out" 2>&1
  status=$?
  set -e
  test "$status" -ne 0
  grep -Fq 'transaction is active' "$fixture_root/release-handoff-$owner-before-contender.out"
  wait "$release_owner_pid"

  # An uninstaller needs a new generation after its retire-before run.
  if [[ "$owner" == uninstaller ]]; then
    install_generation "handoff-$owner-rebased"
  fi

  # The owner atomically retired its old lock. A new uninstaller acquires the
  # visible lock and pauses before its own retirement, while the original
  # owner removes only the retained retired-lock leaf.
  after_log="$fixture_root/release-handoff-$owner-after.out"
  # Keep the original owner paused long enough for the contender to acquire
  # and reach its own release pause even on a cold test fixture.
  start_release_owner "$owner" retire-after 15 "handoff-$owner-after" "$after_log"
  wait_for_release_pause "$after_log" "pause at $owner-retire-after"
  contender_log="$fixture_root/release-handoff-$owner-contender.out"
  MACOP_INSTALL_TEST_MODE=1 \
    MACOP_INSTALL_TEST_RELEASE_PAUSE_AT=uninstaller-retire-before \
    MACOP_INSTALL_TEST_RELEASE_PAUSE_SECONDS=30 \
    bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$contender_log" 2>&1 &
  contender_pid=$!
  wait_for_release_pause "$contender_log" 'pause at uninstaller-retire-before'
  wait "$release_owner_pid"
  state_id="$(python3 scripts/install-fs.py id "$case_state")"
  new_lock_id="$(python3 scripts/install-fs.py child-id "$case_state" "$state_id" lock dir)"
  new_lock_pid="$(python3 scripts/install-fs.py read-child "$case_state" "$state_id" lock "$new_lock_id" pid)"
  test "$new_lock_pid" = "$contender_pid"
  third_log="$fixture_root/release-handoff-$owner-third.out"
  set +e
  MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$third_log" 2>&1
  status=$?
  set -e
  test "$status" -ne 0
  grep -Fq 'transaction is active' "$third_log"
  wait "$contender_pid"
  test -z "$(find "$case_state" -mindepth 1 -maxdepth 1 -name 'retired-lock.*' -print -quit)"
  install_generation "handoff-$owner-restored"
  assert_generation "handoff-$owner-restored"
  bin_dir="$saved_bin_dir"
}

start_owner_record_window() {
  local owner="$1" seconds="$2" generation="$3" log="$4"
  if [[ "$owner" == installer ]]; then
    MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION="$generation" \
      MACOP_INSTALL_TEST_LOCK_OWNER_PAUSE_AT=installer-after-lock-mkdir \
      MACOP_INSTALL_TEST_LOCK_OWNER_PAUSE_SECONDS="$seconds" \
      bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" >"$log" 2>&1 &
  else
    MACOP_INSTALL_TEST_MODE=1 \
      MACOP_INSTALL_TEST_LOCK_OWNER_PAUSE_AT=uninstaller-after-lock-mkdir \
      MACOP_INSTALL_TEST_LOCK_OWNER_PAUSE_SECONDS="$seconds" \
      bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$log" 2>&1 &
  fi
  owner_record_pid=$!
}

# mkdir publishes a lock before its PID record can be written. That interval is
# not a stale-lock recovery opportunity: contender transactions must retain the
# empty lock as evidence until the creating process records its ownership.
assert_pidless_lock_window() {
  local owner="$1" case_root case_state owner_log installer_log uninstaller_log state_id lock_id
  case_root="$fixture_root/pidless-lock-$owner"
  mkdir -p "$case_root/bin"
  chmod 700 "$case_root" "$case_root/bin"
  saved_bin_dir="$bin_dir"
  bin_dir="$case_root/bin"
  install_generation "pidless-$owner-initial"
  case_state="$bin_dir/.macop-install-state"

  owner_log="$fixture_root/pidless-lock-$owner-owner.out"
  start_owner_record_window "$owner" 45 "pidless-$owner-owner" "$owner_log"
  wait_for_release_pause "$owner_log" "pause at $owner-after-lock-mkdir"
  assert_generation "pidless-$owner-initial"
  state_id="$(python3 scripts/install-fs.py id "$case_state")"
  lock_id="$(python3 scripts/install-fs.py child-id "$case_state" "$state_id" lock dir)"
  python3 scripts/install-fs.py absent-child "$case_state" "$state_id" lock "$lock_id" pid

  installer_log="$fixture_root/pidless-lock-$owner-installer-contender.out"
  set +e
  MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION="pidless-$owner-contender" \
    bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" >"$installer_log" 2>&1
  status=$?
  set -e
  test "$status" -ne 0
  grep -Fq 'installer lock is missing its owner PID record; manual recovery is required' "$installer_log"

  uninstaller_log="$fixture_root/pidless-lock-$owner-uninstaller-contender.out"
  set +e
  MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$uninstaller_log" 2>&1
  status=$?
  set -e
  test "$status" -ne 0
  grep -Fq 'installer lock is missing its owner PID record; manual recovery is required' "$uninstaller_log"
  python3 scripts/install-fs.py absent-child "$case_state" "$state_id" lock "$lock_id" pid

  wait "$owner_record_pid"
  if [[ "$owner" == installer ]]; then
    assert_generation "pidless-$owner-owner"
  else
    test ! -e "$bin_dir/macop" && test ! -e "$bin_dir/macop-agent" \
      && test ! -e "$bin_dir/MacopAuth.app" && test ! -e "$bin_dir/macop-install-manifest.json"
  fi
  python3 scripts/install-fs.py absent "$case_state" "$state_id" lock
  install_generation "pidless-$owner-next"
  assert_generation "pidless-$owner-next"
  python3 scripts/install-fs.py absent "$case_state" "$state_id" lock
  bin_dir="$saved_bin_dir"
}

assert_release_handoff installer
assert_release_handoff uninstaller
assert_pidless_lock_window installer
assert_pidless_lock_window uninstaller

# SIGKILL during the uninstaller's release trap leaves a complete numeric PID
# record. The next uninstaller must retire that exact dead-owner lock and
# finish normally without weakening the PID-less fail-closed window above.
assert_stale_uninstaller_lock_recovery() {
  local case_root case_state log owner_pid saved_bin_dir
  case_root="$fixture_root/stale-uninstaller-lock"
  mkdir -p "$case_root/bin"
  chmod 700 "$case_root" "$case_root/bin"
  saved_bin_dir="$bin_dir"
  bin_dir="$case_root/bin"
  install_generation stale-uninstaller-initial
  case_state="$bin_dir/.macop-install-state"
  log="$fixture_root/stale-uninstaller-lock.out"
  MACOP_INSTALL_TEST_MODE=1 \
    MACOP_INSTALL_TEST_RELEASE_PAUSE_AT=uninstaller-retire-before \
    MACOP_INSTALL_TEST_RELEASE_PAUSE_SECONDS=30 \
    bash scripts/uninstall.sh --bin-dir "$bin_dir" >"$log" 2>&1 &
  owner_pid=$!
  wait_for_release_pause "$log" 'pause at uninstaller-retire-before'
  kill -KILL "$owner_pid"
  set +e
  wait "$owner_pid"
  status=$?
  set -e
  test "$status" -ne 0
  test "$(tr -d '\n' <"$case_state/lock/pid")" = "$owner_pid"

  MACOP_INSTALL_TEST_MODE=1 bash scripts/uninstall.sh --bin-dir "$bin_dir" \
    >"$fixture_root/stale-uninstaller-lock-recovery.out" 2>&1
  test ! -e "$case_state/lock"
  test ! -e "$bin_dir/macop"
  test ! -e "$bin_dir/macop-agent"
  test ! -e "$bin_dir/MacopAuth.app"
  test ! -e "$bin_dir/macop-install-manifest.json"
  bin_dir="$saved_bin_dir"
}

assert_stale_uninstaller_lock_recovery

# SIGKILL bypasses traps. A subsequent installer reclaims the stale lock and
# recovers the durable journal before publishing one complete generation.
set +e
MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION=new \
  MACOP_INSTALL_SIGNAL_FAILPOINT=backup-agent-after \
  MACOP_INSTALL_SIGNAL=KILL bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" \
  >"$fixture_root/signal-KILL.out" 2>"$fixture_root/signal-KILL.err"
status=$?
set -e
test "$status" -ne 0
set +e
install_generation after-kill
status=$?
set -e
test "$status" -eq 0
assert_generation after-kill

# Terminal journals are cleanup work, not recovery ambiguity. A committed
# journal may coexist with its still-public pending marker if power is lost in
# the narrow commit-cleanup window; the next installer must finish that commit.
terminal_state="$bin_dir/.macop-install-state"
terminal_journal="$terminal_state/journal.committed-fixture"
mkdir -m 700 "$terminal_journal"
printf 'committed\n' >"$terminal_journal/COMMITTED"
chmod 600 "$terminal_journal/COMMITTED"
printf 'schema=1\nnonce=test\njournal=%s\nstate_device=%s\nstate_inode=%s\n' \
  "$(cd "$terminal_journal" && pwd -P)" "$(stat -f '%d' "$terminal_state")" "$(stat -f '%i' "$terminal_state")" \
  >"$terminal_state/pending"
chmod 600 "$terminal_state/pending"
install_generation after-committed-recovery
assert_generation after-committed-recovery
test ! -e "$terminal_journal"
test ! -e "$terminal_state/pending"

terminal_journal="$terminal_state/journal.rolled-back-fixture"
mkdir -m 700 "$terminal_journal"
printf 'rolled-back\n' >"$terminal_journal/ROLLED_BACK"
chmod 600 "$terminal_journal/ROLLED_BACK"
install_generation after-rolled-back-recovery
assert_generation after-rolled-back-recovery
test ! -e "$terminal_journal"

# A pathname swap between phase checks must not authorize a mutation in the
# replacement tree.  Exercise staging, backup, publish, rollback, and cleanup
# with both the install root and its state-directory parent.  The interrupted
# journal and pending marker remain with the retained tree; after restoring
# it, the next installer performs normal journal recovery.
exercise_substitution() {
  local phase="$1" target="$2" failpoint="${3:-}" case_root case_bin retained retained_pending sentinel_path log pid ready=false
  case_root="$fixture_root/substitution-${phase//[:]/-}-${target}"
  case_bin="$case_root/bin"
  mkdir -p "$case_bin"
  chmod 700 "$case_root" "$case_bin"
  saved_bin_dir="$bin_dir"
  bin_dir="$case_bin"
  install_generation "substitute-${phase}-old"
  log="$fixture_root/substitution-${phase//[:]/-}-${target}.out"
  MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION="substitute-${phase}-new" \
    MACOP_INSTALL_TEST_PAUSE_AT="$phase" MACOP_INSTALL_TEST_PAUSE_SECONDS=4 \
    MACOP_INSTALL_FAILPOINT="$failpoint" \
    bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" >"$log" 2>&1 &
  pid=$!
  for _ in $(seq 1 600); do
    if grep -Fq "macop install test: pause at $phase" "$log" 2>/dev/null; then
      ready=true
      break
    fi
    sleep 0.1
  done
  test "$ready" = true
  if [[ "$phase" == staging ]]; then
    assert_capability_contract "$case_bin"
  fi
  if [[ "$target" == root ]]; then
    mv -- "$case_bin" "$case_root/bin-retained"
    mkdir "$case_bin"
    chmod 700 "$case_bin"
    sentinel_path="$case_bin/sentinel"
    printf 'replacement must remain untouched\n' >"$sentinel_path"
    retained="$case_root/bin-retained"
    retained_pending="$retained/.macop-install-state/pending"
  else
    mv -- "$case_bin/.macop-install-state" "$case_root/state-retained"
    mkdir "$case_bin/.macop-install-state"
    chmod 700 "$case_bin/.macop-install-state"
    sentinel_path="$case_bin/.macop-install-state/sentinel"
    printf 'replacement state must remain untouched\n' >"$sentinel_path"
    retained="$case_root/state-retained"
    retained_pending="$retained/pending"
  fi
  set +e
  wait "$pid"
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then printf 'substitution %s/%s unexpectedly succeeded\n' "$phase" "$target" >&2; exit 1; fi
  if [[ ! -f "$sentinel_path" ]]; then printf 'substitution %s/%s modified replacement\n' "$phase" "$target" >&2; exit 1; fi
  if [[ ! -f "$retained_pending" ]]; then printf 'substitution %s/%s cleared retained pending\n' "$phase" "$target" >&2; exit 1; fi
  if [[ "$target" == root ]]; then
    if [[ -e "$case_bin/macop" ]]; then printf 'substitution %s/root published into replacement\n' "$phase" >&2; exit 1; fi
    rm -rf -- "$case_bin"
    mv -- "$retained" "$case_bin"
  else
    rm -rf -- "$case_bin/.macop-install-state"
    mv -- "$retained" "$case_bin/.macop-install-state"
  fi
  install_generation "substitute-${phase}-recovered"
  assert_generation "substitute-${phase}-recovered"
  bin_dir="$saved_bin_dir"
}

run_substitution_case() { [[ -z "${MACOP_INSTALL_TEST_ONLY_SUBSTITUTION:-}" || "$1" == "$MACOP_INSTALL_TEST_ONLY_SUBSTITUTION" ]]; }
run_substitution_case staging && exercise_substitution staging root
run_substitution_case backup-macop && exercise_substitution backup-macop state
run_substitution_case publish-macop && exercise_substitution publish-macop root
run_substitution_case rollback-manifest && exercise_substitution rollback-manifest state publish-macop-after
run_substitution_case cleanup && exercise_substitution cleanup root

# A crash after one or more rollback restores is intentionally not guessed at:
# its publish phase no longer identifies which backups remain authoritative.
# Keep the pending evidence and reject every future installer attempt until a
# human repairs it, rather than deleting a possibly new destination.
rollback_partial_bin="$fixture_root/rollback-partial/bin"
mkdir -p "$rollback_partial_bin"
chmod 700 "$fixture_root/rollback-partial" "$rollback_partial_bin"
saved_bin_dir="$bin_dir"
bin_dir="$rollback_partial_bin"
install_generation rollback-partial-old
MACOP_INSTALL_TEST_MODE=1 MACOP_INSTALL_BUILD_GENERATION=rollback-partial-new \
  MACOP_INSTALL_FAILPOINT=publish-macop-after MACOP_INSTALL_TEST_PAUSE_AT=rollback-macop \
  MACOP_INSTALL_TEST_PAUSE_SECONDS=4 \
  bash scripts/build-install.sh --configuration debug --skip-build --bin-dir "$bin_dir" \
    >"$fixture_root/rollback-partial.out" 2>&1 &
rollback_partial_pid=$!
rollback_partial_ready=false
for _ in $(seq 1 600); do
  if grep -Fq 'macop install test: pause at rollback-macop' "$fixture_root/rollback-partial.out" 2>/dev/null; then
    rollback_partial_ready=true
    break
  fi
  sleep 0.1
done
if [[ "$rollback_partial_ready" != true ]]; then
  set +e
  wait "$rollback_partial_pid"
  status=$?
  set -e
  tail -40 "$fixture_root/rollback-partial.out" >&2 || true
  printf 'rollback-partial fixture did not reach rollback-macop pause (exit %s)\n' "$status" >&2
  exit 1
fi
# Kill at the paused restore boundary: this is the ambiguous journal state the
# recovery matrix must retain for manual repair, never guess through.
kill -KILL "$rollback_partial_pid"
set +e
wait "$rollback_partial_pid"
status=$?
set -e
test "$status" -ne 0
test -f "$bin_dir/.macop-install-state/pending"
set +e
install_generation rollback-partial-retry >"$fixture_root/rollback-partial-retry.out" 2>&1
status=$?
set -e
test "$status" -ne 0
grep -Fq 'interrupted transaction journal is malformed or ambiguous' "$fixture_root/rollback-partial-retry.out"
test -f "$bin_dir/.macop-install-state/pending"
bin_dir="$saved_bin_dir"

# A caller-controlled VERIFY_* environment never bypasses a pending marker;
# only the inherited installer descriptor can run its exact doctor probe. With
# no live installer lock, the operator is told to recover instead of waiting.
printf 'pending\n' >"$bin_dir/.macop-install-state/pending"
printf 'state=%s\nexecutable=%s\nnonce=test\n' "$bin_dir/.macop-install-state" "$bin_dir/macop" \
  >"$bin_dir/.macop-install-state/guard-capability"
guard_fd=9
exec 9<"$bin_dir/.macop-install-state/guard-capability"
set +e
MACOP_INSTALL_VERIFY_FD="$guard_fd" "$bin_dir/macop" doctor >"$fixture_root/guard.out" 2>&1
status=$?
set -e
test "$status" -ne 0
grep -Fq 'installation recovery is required' "$fixture_root/guard.out"
exec 9<&-
rm -f -- "$bin_dir/.macop-install-state/guard-capability"
rm -f -- "$bin_dir/.macop-install-state/pending"

# Recovery never guesses from an incomplete, unknown, or truncated schema.
# The existing generation is left untouched and the pending evidence remains
# for manual repair rather than authorizing a destructive rollback.
saved_bin_dir="$bin_dir"
bin_dir="$fixture_root/corrupt/bin"
mkdir -p "$bin_dir"
chmod 700 "$fixture_root/corrupt" "$bin_dir"
install_generation corrupt-old
mkdir "$bin_dir/.macop-install-state/journal.corrupt"
chmod 700 "$bin_dir/.macop-install-state/journal.corrupt"
printf 'pending\n' >"$bin_dir/.macop-install-state/journal.corrupt/PENDING"
printf 'pending\n' >"$bin_dir/.macop-install-state/pending"
set +e
install_generation corrupt-new >"$fixture_root/corrupt.out" 2>&1
status=$?
set -e
test "$status" -ne 0
assert_generation corrupt-old
test -f "$bin_dir/.macop-install-state/journal.corrupt/PENDING"
test -f "$bin_dir/.macop-install-state/pending"
bin_dir="$saved_bin_dir"

printf '%s\n' 'installer transaction failpoint fixture passed'
