#!/usr/bin/env python3
"""Deterministic integration checks for macop's interactive PTY relay.

This script owns both ends of the outer PTY and the process groups it starts.
Keeping that responsibility out of a background shell is important: POSIX shells
may inherit SIGINT as ignored for asynchronous jobs, and cannot reliably undo
that disposition before executing the relay under test.
"""

import errno
import fcntl
import os
import pty
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SELFTEST = ROOT / ".build" / "debug" / "macop-selftest"
TIMEOUT_SECONDS = 10.0
POLL_SECONDS = 0.02


class HarnessFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise HarnessFailure(message)


def wait_for_path(path: Path, description: str, timeout: float = TIMEOUT_SECONDS) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(POLL_SECONDS)
    fail(f"timed out waiting for {description}")


def set_window_size(fd: int, rows: int, columns: int) -> None:
    size = rows.to_bytes(2, sys.byteorder) + columns.to_bytes(2, sys.byteorder) + b"\0" * 4
    fcntl.ioctl(fd, termios.TIOCSWINSZ, size)


def establish_controlling_terminal() -> None:
    """Make the already-duplicated slave the session leader's controlling TTY."""
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def drain_pty(master: int, process: subprocess.Popen[bytes], timeout: float) -> tuple[int, bytes]:
    """Read the master until the child exits and the slave side closes."""
    deadline = time.monotonic() + timeout
    output = bytearray()
    eof = False
    while not eof:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail(f"timed out waiting for pid {process.pid}")
        readable, _, _ = select.select([master], [], [], min(remaining, POLL_SECONDS))
        if readable:
            try:
                chunk = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    eof = True
                    continue
                raise
            if chunk:
                output.extend(chunk)
            else:
                eof = True
        if process.poll() is not None and not readable:
            # A PTY master returns EIO once every slave descriptor is closed.
            # Probe it promptly instead of waiting for a further select edge.
            try:
                chunk = os.read(master, 65536)
            except BlockingIOError:
                continue
            except OSError as error:
                if error.errno == errno.EIO:
                    eof = True
                    continue
                raise
            if chunk:
                output.extend(chunk)
            else:
                eof = True
    return process.wait(timeout=max(0.1, deadline - time.monotonic())), bytes(output)


class PTYProcess:
    def __init__(self, arguments: list[str], mode: str = "--pty-run"):
        self.master, slave = pty.openpty()
        self.initial_termios = termios.tcgetattr(slave)
        set_window_size(self.master, 24, 80)
        # The controller itself must use default signal dispositions so the
        # process under test does not inherit SIGINT ignored from a caller.
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        self.process = subprocess.Popen(
            [str(SELFTEST), mode, *arguments],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            # `start_new_session=True` alone does not acquire a controlling
            # terminal. The pre-exec hook makes this slave the session's TTY,
            # while still giving the controller an isolated process group.
            preexec_fn=establish_controlling_terminal,
            close_fds=True,
        )
        os.close(slave)

    def signal_group(self, signum: int) -> None:
        os.killpg(self.process.pid, signum)

    def finish(self, timeout: float = TIMEOUT_SECONDS) -> tuple[int, bytes]:
        return drain_pty(self.master, self.process, timeout)

    def close(self) -> None:
        try:
            if self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                self.process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                fail(f"could not reap process group {self.process.pid}")
        finally:
            os.close(self.master)


def run_pty(arguments: list[str], timeout: float = TIMEOUT_SECONDS) -> tuple[int, bytes, list[object]]:
    harness = PTYProcess(arguments)
    try:
        status, output = harness.finish(timeout)
        final_termios = termios.tcgetattr(harness.master)
        return status, output, final_termios
    finally:
        harness.close()


def normalized(output: bytes) -> str:
    return output.decode("utf-8").replace("\r", "")


def require_equal(actual: object, expected: object, description: str) -> None:
    if actual != expected:
        fail(f"{description}: expected {expected!r}, got {actual!r}")


def check_basic_pty() -> None:
    status, output, _ = run_pty([
        "run", "--", "/bin/sh", "-c",
        "test -t 0 && test -t 1 && dd if=/dev/tty of=/dev/null bs=1 count=0 >/dev/null 2>&1 "
        "&& printf pty-check >/dev/tty; exit 7",
    ])
    require_equal(status, 7, "PTY child exit status")
    if "pty-check" not in normalized(output):
        fail("PTY child could not write to its controlling terminal")
    status, output, _ = run_pty([
        "run", "--", "/bin/sh", "-c",
        'test -t 0 && test -t 1 && test "$1" = --stdin && test "$2" = --stdin=value '
        '&& printf child-stdin-argv',
        "marker", "--stdin", "--stdin=value",
    ])
    require_equal(status, 0, "child --stdin argv PTY selection status")
    require_equal(normalized(output), "child-stdin-argv", "child --stdin argv must retain PTY")
    # Macop changes its inner PTY mode while relaying. The outer caller's
    # terminal mode must remain unchanged when it returns.
    harness = PTYProcess(["run", "--", "/usr/bin/true"])
    try:
        initial = harness.initial_termios
        status, _ = harness.finish()
        require_equal(status, 0, "termios probe exit status")
        require_equal(termios.tcgetattr(harness.master), initial, "outer PTY termios restoration")
    finally:
        harness.close()


def check_masking() -> None:
    status, output, _ = run_pty(["run", "--", "/bin/sh", "-c", 'printf "%s" "$GH_TOKEN"'])
    require_equal(status, 0, "masked PTY exit status")
    require_equal(normalized(output), "<concealed by macop>", "masked PTY transcript")
    status, output, _ = run_pty(["run", "--no-masking", "--", "/bin/sh", "-c", 'printf "%s" "$GH_TOKEN"'])
    require_equal(status, 0, "unmasked PTY exit status")
    require_equal(normalized(output), "test-secret", "unmasked PTY transcript")
    status, output, _ = run_pty(["run", "--debug", "--", "/usr/bin/true"])
    require_equal(status, 0, "debug PTY exit status")
    require_equal(normalized(output), "macop: debug exit_code=0 command=run\n", "interactive debug transcript")


def check_signal_forwarding(tmpdir: Path, signum: int, expected: int) -> None:
    name = signal.Signals(signum).name.removeprefix("SIG")
    marker = tmpdir / name
    ready = tmpdir / f"{name}.ready"
    command = (
        f'trap "echo {name} > {shlex.quote(str(marker))}; exit {expected}" {name}; '
        f"echo ready > {shlex.quote(str(ready))}; while :; do sleep 1; done"
    )
    harness = PTYProcess(["run", "--", "/bin/sh", "-c", command])
    try:
        wait_for_path(ready, f"{name} relay readiness")
        harness.signal_group(signum)
        status, _ = harness.finish()
        require_equal(status, expected, f"{name} forwarded exit status")
        require_equal(marker.read_text().strip(), name, f"{name} forwarding marker")
    finally:
        harness.close()


def check_window_size(tmpdir: Path) -> None:
    size_file = tmpdir / "winch-size"
    ready = tmpdir / "winch-size.ready"
    command = (
        f'trap "stty size > {shlex.quote(str(size_file))}; exit 0" WINCH; '
        f"echo ready > {shlex.quote(str(ready))}; while :; do sleep 1; done"
    )
    harness = PTYProcess(["run", "--", "/bin/sh", "-c", command])
    try:
        wait_for_path(ready, "WINCH relay readiness")
        set_window_size(harness.master, 40, 120)
        harness.signal_group(signal.SIGWINCH)
        status, _ = harness.finish()
        require_equal(status, 0, "SIGWINCH forwarded exit status")
        require_equal(size_file.read_text().strip(), "40 120", "SIGWINCH PTY size")
    finally:
        harness.close()


def check_delayed_inject() -> None:
    process = subprocess.Popen(
        [str(SELFTEST), "--inject-stdin"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert process.stdin is not None
    try:
        process.stdin.write(b"first=")
        process.stdin.flush()
        time.sleep(0.05)
        process.stdin.write(b"keychain://generic/service/account\n")
        process.stdin.close()
        stdout, stderr = process.communicate(timeout=TIMEOUT_SECONDS)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    require_equal(process.returncode, 0, "delayed inject exit status")
    require_equal(stderr, b"", "delayed inject stderr")
    require_equal(stdout, b"first=test-secret\n", "delayed inject output")


def check_injected_stdin_on_outer_pty() -> None:
    status, output, _ = run_pty([
        "run", "--stdin", "keychain://generic/service/account", "--", "/bin/cat",
    ])
    require_equal(status, 0, "outer PTY injected stdin exit status")
    require_equal(normalized(output), "<concealed by macop>", "outer PTY injected stdin EOF output")

    harness = PTYProcess([
        "run", "--stdin", "keychain://generic/service/account", "--", "/bin/cat",
    ], mode="--pty-run-large-stdin")
    try:
        status, output = harness.finish()
        require_equal(status, 0, "outer PTY large injected stdin exit status")
        require_equal(normalized(output), "<concealed by macop>", "outer PTY large stdin EOF output")
    finally:
        harness.close()

    status, output, _ = run_pty([
        "run", "--stdin", "keychain://generic/service/account", "--", "/usr/bin/true",
    ])
    require_equal(status, 0, "outer PTY early-close injected stdin exit status")
    require_equal(output, b"", "outer PTY early-close injected stdin output")


def main() -> int:
    if not SELFTEST.is_file():
        fail(f"missing selftest executable: {SELFTEST}")
    with tempfile.TemporaryDirectory(prefix="macop-pty-") as temporary:
        tmpdir = Path(temporary)
        check_basic_pty()
        check_masking()
        check_signal_forwarding(tmpdir, signal.SIGINT, 41)
        check_signal_forwarding(tmpdir, signal.SIGTERM, 42)
        check_window_size(tmpdir)
        check_delayed_inject()
        check_injected_stdin_on_outer_pty()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessFailure as error:
        print(f"PTY selftest failed: {error}", file=sys.stderr)
        raise SystemExit(1)
