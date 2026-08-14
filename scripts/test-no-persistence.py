#!/usr/bin/env python3
"""Check fake-Keychain run/inject secrets stay out of argv and artifacts."""

import os
import hashlib
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SELFTEST = ROOT / ".build" / "debug" / "macop-selftest"


def fail(message: str) -> None:
    raise RuntimeError(message)


def descendants(pid: int) -> list[int]:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid="], check=True, capture_output=True, text=True
    )
    parents: dict[int, list[int]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2:
            parents.setdefault(int(fields[1]), []).append(int(fields[0]))
    found: list[int] = []
    pending = [pid]
    while pending:
        pending = [child for parent in pending for child in parents.get(parent, [])]
        found.extend(pending)
    return found


def command_line(pid: int) -> bytes:
    return subprocess.run(
        ["/bin/ps", "-ww", "-o", "command=", "-p", str(pid)], check=False, capture_output=True
    ).stdout


def scan_tree(root: Path, secret: bytes) -> None:
    for path in root.rglob("*"):
        if path.is_file() and secret in path.read_bytes():
            fail(f"fake-Keychain secret persisted in fixture artifact {path.name}")


def fixture_environment(root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update({
        "HOME": str(root / "home"),
        "TMPDIR": str(root / "tmp"),
        "TMP": str(root / "tmp"),
        "TEMP": str(root / "tmp"),
        "MACOP_SELFTEST_RUN_REFERENCE": "op://Local/Acceptance/token",
    })
    return environment


def main() -> int:
    if not SELFTEST.is_file():
        fail("missing selftest executable")
    with tempfile.TemporaryDirectory(prefix="macop-no-persistence-") as temporary:
        root = Path(temporary)
        secret = secrets.token_bytes(32).hex().encode("ascii")
        home = root / "home"
        temporary_root = root / "tmp"
        config_root = root / "config"
        log_root = root / "log"
        for directory in (home, temporary_root, config_root, log_root):
            directory.mkdir(mode=0o700)
        config = config_root / "config.json"
        config.write_text(
            '{"version":1,"items":{"Local/Acceptance":'
            '{"provider":"keychain-generic","service":"macop-acceptance",'
            '"account":"runtime","fields":["token"]}}}\n'
        )
        config.chmod(0o600)
        environment = fixture_environment(root)
        ready = temporary_root / "child-ready"
        stop = temporary_root / "child-stop"
        environment_hash = temporary_root / "child-environment.sha256"
        script = (
            'printf %s "$GH_TOKEN" | /usr/bin/shasum -a 256 | /usr/bin/cut -d " " -f 1 > "$3"; '
            'printf ready > "$1"; while test ! -f "$2"; do sleep 0.05; done'
        )
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, secret)
        os.close(write_descriptor)
        run_environment = environment | {"MACOP_SELFTEST_FAKE_SECRET_FD": str(read_descriptor)}
        process = subprocess.Popen(
            [
                str(SELFTEST), "--pty-run", "--debug", "--config", str(config_root),
                "run", "--no-masking", "--", "/bin/sh", "-c", script,
                "macop-no-persistence", str(ready), str(stop), str(environment_hash),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=run_environment,
            pass_fds=(read_descriptor,),
        )
        os.close(read_descriptor)
        run_stdout = b""
        run_stderr = b""
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            if not ready.exists():
                fail("fake-Keychain run child did not become observable")
            child_commands = [command_line(pid) for pid in descendants(process.pid)]
            child_commands = [command for command in child_commands if command]
            if not child_commands:
                fail("fake-Keychain run has no observable child")
            if any(secret in command for command in child_commands):
                fail("fake-Keychain secret appeared in a child argv")
            expected_hash = hashlib.sha256(secret).hexdigest()
            if environment_hash.read_text().strip() != expected_hash:
                fail("fake-Keychain run child did not receive the exact resolved environment value")
            scan_tree(root, secret)
        finally:
            # Always release the controlled child first, including assertion
            # failures. This lets its shell close inherited pipes naturally
            # before bounded TERM/KILL fallbacks target the exact selftest PID.
            try:
                stop.touch()
            except OSError:
                pass
            try:
                run_stdout, run_stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    run_stdout, run_stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    run_stdout, run_stderr = process.communicate(timeout=5)
        if process.returncode != 0:
            fail(f"fake-Keychain run exited with {process.returncode}")
        if secret in run_stdout or secret in run_stderr:
            fail("fake-Keychain secret appeared in run stdout/debug stderr")
        if b"macop: debug exit_code=0 command=run" not in run_stderr:
            fail("fake-Keychain run did not emit the expected safe debug record")

        # Inject resolves the same config mapping. Expanded output is verified
        # in a pipe and discarded without writing it under any scan root.
        read_descriptor, write_descriptor = os.pipe()
        os.write(write_descriptor, secret)
        os.close(write_descriptor)
        inject_environment = environment | {"MACOP_SELFTEST_FAKE_SECRET_FD": str(read_descriptor)}
        try:
            injected = subprocess.run(
                [
                    str(SELFTEST), "--inject-stdin", "--debug", "--config", str(config_root),
                ],
                input=b"token=op://Local/Acceptance/token\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                env=inject_environment,
                pass_fds=(read_descriptor,),
            )
        finally:
            os.close(read_descriptor)
        if injected.stdout != b"token=" + secret + b"\n":
            fail("fake-Keychain inject fixture did not produce the expected in-memory result")
        if secret in injected.stderr:
            fail("fake-Keychain secret appeared in inject debug stderr")
        if b"macop: debug exit_code=0 command=inject" not in injected.stderr:
            fail("fake-Keychain inject did not emit the expected safe debug record")
        del injected
        scan_tree(root, secret)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"no-persistence fixture failed: {error}", file=sys.stderr)
        raise SystemExit(1)
