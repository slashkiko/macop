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
    def __init__(self, arguments: list[str], mode: str = "--pty-run", pass_fds: tuple[int, ...] = (), env: dict[str, str] | None = None):
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
            pass_fds=pass_fds,
            env=env,
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

    sentinel = os.open("/dev/null", os.O_RDONLY)
    try:
        flags = fcntl.fcntl(sentinel, fcntl.F_GETFD)
        fcntl.fcntl(sentinel, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
        environment = os.environ | {"MACOP_SENTINEL_FD": str(sentinel)}
        harness = PTYProcess(
            ["run", "--", "/bin/sh", "-c", "test ! -e /dev/fd/$MACOP_SENTINEL_FD"],
            pass_fds=(sentinel,), env=environment
        )
        try:
            status, _ = harness.finish()
            require_equal(status, 0, "PTY child must not inherit an ambient non-CLOEXEC FD")
        finally:
            harness.close()
    finally:
        os.close(sentinel)


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


def check_suspended_interactive_lifecycle(tmpdir: Path) -> None:
    for signum, expected_status in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
        validation_ready = tmpdir / f"validation-ready-{signum}"
        cancelled_side_effect = tmpdir / f"validation-side-effect-{signum}"
        environment = os.environ.copy()
        environment["MACOP_SUSPENDED_VALIDATION_READY"] = str(validation_ready)
        environment["MACOP_SUSPENDED_VALIDATION_DELAY_US"] = "250000"
        harness = PTYProcess(
            ["/usr/bin/touch", str(cancelled_side_effect)],
            mode="--suspended-interactive",
            env=environment,
        )
        try:
            wait_for_path(validation_ready, "delayed suspended validation")
            os.kill(harness.process.pid, signum)
            status, _ = harness.finish()
            require_equal(status, expected_status, "pre-resume cancellation status")
            if cancelled_side_effect.exists():
                fail("interactive child cancelled during validation was resumed")
        finally:
            harness.close()

    identity = tmpdir / "suspended-identity"
    ready = tmpdir / "suspended-ready"
    command = (
        f'test -t 0 && test -t 1 || exit 90; '
        f'printf "%s %s\\n" "$$" "$(ps -o pgid= -p $$ | tr -d " ")" > {shlex.quote(str(identity))}; '
        f'trap "exit 130" INT; echo ready > {shlex.quote(str(ready))}; while :; do sleep 1; done'
    )
    harness = PTYProcess(["/bin/sh", "-c", command], mode="--suspended-interactive")
    try:
        wait_for_path(ready, "suspended helper readiness")
        child_pid_text, child_group_text = identity.read_text().split()
        child_pid = int(child_pid_text)
        require_equal(int(child_group_text), os.getpgid(harness.process.pid), "helper inherited foreground pgrp")
        harness.signal_group(signal.SIGINT)
        status, _ = harness.finish()
        require_equal(status, 130, "foreground-group SIGINT status")
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            pass
        else:
            fail("SIGINT helper child remained alive")
    finally:
        harness.close()

    term_ready = tmpdir / "suspended-term-ready"
    term_pid = tmpdir / "suspended-term-pid"
    term_command = (
        f'echo $$ > {shlex.quote(str(term_pid))}; trap "exit 143" TERM; '
        f'echo ready > {shlex.quote(str(term_ready))}; while :; do sleep 1; done'
    )
    harness = PTYProcess(["/bin/sh", "-c", term_command], mode="--suspended-interactive")
    try:
        wait_for_path(term_ready, "direct TERM helper readiness")
        child_pid = int(term_pid.read_text().strip())
        os.kill(harness.process.pid, signal.SIGTERM)
        status, _ = harness.finish()
        require_equal(status, 143, "direct wrapper TERM forwarding status")
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            pass
        else:
            fail("direct wrapper TERM orphaned the helper child")
    finally:
        harness.close()

    check_non_orphaned_job_control(tmpdir)


def check_non_orphaned_job_control(tmpdir: Path) -> None:
    """Act as a shell parent in the same session so SIGTSTP cannot be discarded."""
    ready = tmpdir / "job-control-ready"
    identity = tmpdir / "job-control-identity"
    read_result, write_result = os.pipe()
    master, slave = pty.openpty()
    os.set_blocking(master, False)
    initial_termios = termios.tcgetattr(slave)
    controller = os.fork()
    if controller == 0:
        os.close(read_result)
        os.close(master)
        macop_pid = -1
        try:
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            controller_group = os.getpgrp()
            macop_pid = os.fork()
            if macop_pid == 0:
                os.setpgid(0, 0)
                os.dup2(slave, 0)
                os.dup2(slave, 1)
                os.dup2(slave, 2)
                command = (
                    f'printf "%s %s\\n" "$$" "$(ps -o pgid= -p $$ | tr -d " ")" '
                    f'> {shlex.quote(str(identity))}; trap "exit 143" TERM; '
                    f'echo ready > {shlex.quote(str(ready))}; while :; do sleep 1; done'
                )
                os.execve(
                    str(SELFTEST),
                    [str(SELFTEST), "--suspended-interactive", "/bin/sh", "-c", command],
                    os.environ,
                )
            try:
                os.setpgid(macop_pid, macop_pid)
            except PermissionError:
                if os.getpgid(macop_pid) != macop_pid:
                    raise
            previous_ttou = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            os.tcsetpgrp(slave, macop_pid)
            wait_for_path(ready, "non-orphaned job-control readiness")
            helper_pid_text, helper_group_text = identity.read_text().split()
            helper_pid = int(helper_pid_text)
            require_equal(int(helper_group_text), macop_pid, "non-orphaned helper pgrp")
            os.killpg(macop_pid, signal.SIGTSTP)
            waited, wait_status = os.waitpid(macop_pid, os.WUNTRACED)
            require_equal(waited, macop_pid, "stopped wrapper pid")
            if not os.WIFSTOPPED(wait_status) or os.WSTOPSIG(wait_status) != signal.SIGTSTP:
                fail("wrapper did not stop under shell-style SIGTSTP job control")
            helper_state = subprocess.check_output(
                ["/bin/ps", "-o", "state=", "-p", str(helper_pid)], text=True
            ).strip()
            if not helper_state.startswith("T"):
                fail(f"helper did not stop with wrapper: state={helper_state!r}")
            os.tcsetpgrp(slave, controller_group)
            os.tcsetpgrp(slave, macop_pid)
            os.killpg(macop_pid, signal.SIGCONT)
            os.kill(macop_pid, signal.SIGTERM)
            _, final_status = os.waitpid(macop_pid, 0)
            require_equal(os.waitstatus_to_exitcode(final_status), 143, "fg-resumed helper TERM status")
            os.tcsetpgrp(slave, controller_group)
            require_equal(termios.tcgetattr(slave), initial_termios, "job-control terminal restoration")
            signal.signal(signal.SIGTTOU, previous_ttou)
            os.write(write_result, b"ok")
            os._exit(0)
        except BaseException as error:
            if macop_pid > 0:
                try:
                    os.killpg(macop_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            os.write(write_result, f"error:{error}".encode())
            os._exit(1)

    os.close(write_result)
    os.close(slave)
    try:
        deadline = time.monotonic() + TIMEOUT_SECONDS
        result = b""
        while time.monotonic() < deadline:
            readable, _, _ = select.select([read_result], [], [], POLL_SECONDS)
            if readable:
                result += os.read(read_result, 4096)
                if result:
                    break
            try:
                while os.read(master, 4096):
                    pass
            except (BlockingIOError, OSError):
                pass
        waited = 0
        controller_status = 0
        while waited == 0 and time.monotonic() < deadline:
            waited, controller_status = os.waitpid(controller, os.WNOHANG)
            if waited == 0:
                time.sleep(POLL_SECONDS)
        if waited == 0:
            os.kill(controller, signal.SIGKILL)
            waited, controller_status = os.waitpid(controller, 0)
            fail("timed out waiting for job-control controller")
        require_equal(waited, controller, "job-control controller pid")
        require_equal(os.waitstatus_to_exitcode(controller_status), 0, "job-control controller status")
        require_equal(result, b"ok", "job-control controller result")
    finally:
        os.close(read_result)
        os.close(master)


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
        check_suspended_interactive_lifecycle(tmpdir)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessFailure as error:
        print(f"PTY selftest failed: {error}", file=sys.stderr)
        raise SystemExit(1)
