"""Process-group lifecycle tests for issue #6 (POSIX/Linux)."""

from __future__ import annotations

import contextlib
import os
import signal
import sys
import time

import pytest

from codecell import IpcSubprocessRuntime, NullValidator, SubprocessRuntime

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="assertions read /proc for liveness"
)


def _runtime(kind: str):
    validator = NullValidator("python")
    return (
        SubprocessRuntime(validator) if kind == "subprocess" else IpcSubprocessRuntime(validator)
    )


def _spawn_code(pidfile: str, *, exit_code: int | None = None, linger: bool = True) -> str:
    """Code that spawns a detached grandchild, records its pid, then acts.

    The grandchild's stdout/stderr are devnull so it cannot hold the cell's
    pipes open and turn a normal return into a timeout.
    """
    lines = [
        "import os, subprocess, sys, time",
        "p = subprocess.Popen(",
        "    [sys.executable, '-c', 'import time; time.sleep(60)'],",
        "    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,",
        ")",
        f"open({pidfile!r}, 'w').write(str(p.pid))",
    ]
    if exit_code is not None:
        lines.append(f"os._exit({exit_code})")
    elif linger:
        lines.append("time.sleep(60)")
    return "\n".join(lines)


def _read_pid(path: str, timeout: float = 5.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path) as fh:
                text = fh.read().strip()
        except FileNotFoundError:
            text = ""
        if text:
            return int(text)
        time.sleep(0.02)
    raise AssertionError("grandchild pid was not recorded")


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


def _wait_gone(pid: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.02)
    return False


def _cleanup(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, 9)


@pytest.mark.parametrize("kind", ["subprocess", "ipc"])
def test_timeout_kills_grandchild(kind, tmp_path):
    pidfile = str(tmp_path / "pid")
    runtime = _runtime(kind)
    try:
        result = runtime.execute(_spawn_code(pidfile), timeout=1)
        assert result.timed_out is True
        pid = _read_pid(pidfile)
        assert _wait_gone(pid), f"grandchild {pid} survived a timeout"
    finally:
        if os.path.exists(pidfile):
            with open(pidfile) as fh:
                _cleanup(int(fh.read()))


@pytest.mark.parametrize("kind", ["subprocess", "ipc"])
def test_normal_return_kills_leftover_grandchild(kind, tmp_path):
    pidfile = str(tmp_path / "pid")
    runtime = _runtime(kind)
    code = _spawn_code(pidfile, linger=False)
    try:
        start = time.monotonic()
        result = runtime.execute(code, timeout=10)
        elapsed = time.monotonic() - start
        assert result.return_code == 0
        pid = _read_pid(pidfile)
        assert _wait_gone(pid), f"grandchild {pid} outlived a normal return"
        # A welded-shut SIGTERM guard burns the full 1 s grace period.
        assert elapsed < 0.75, f"teardown waited {elapsed:.2f}s for a group kill"
    finally:
        if os.path.exists(pidfile):
            with open(pidfile) as fh:
                _cleanup(int(fh.read()))


@pytest.mark.parametrize("kind", ["subprocess", "ipc"])
def test_crash_kills_leftover_grandchild(kind, tmp_path):
    pidfile = str(tmp_path / "pid")
    runtime = _runtime(kind)
    try:
        start = time.monotonic()
        result = runtime.execute(_spawn_code(pidfile, exit_code=3), timeout=10)
        elapsed = time.monotonic() - start
        assert result.return_code == 3
        pid = _read_pid(pidfile)
        assert _wait_gone(pid), f"grandchild {pid} survived a crash"
        assert elapsed < 0.75, f"teardown waited {elapsed:.2f}s for a group kill"
    finally:
        if os.path.exists(pidfile):
            with open(pidfile) as fh:
                _cleanup(int(fh.read()))


def test_timeout_output_is_not_duplicated():
    code = (
        "import sys, time\nsys.stdout.write('PARTIAL-LINE\\n')\nsys.stdout.flush()\ntime.sleep(60)"
    )
    result = SubprocessRuntime(NullValidator("python")).execute(code, timeout=1)
    assert result.timed_out is True
    assert result.stdout.count("PARTIAL-LINE") == 1, result.stdout


@pytest.mark.parametrize("kind", ["subprocess", "ipc"])
def test_timeout_zero_is_immediate(kind):
    start = time.monotonic()
    result = _runtime(kind).execute("import time; time.sleep(5)", timeout=0)
    elapsed = time.monotonic() - start
    assert result.timed_out is True
    assert elapsed < 3, f"timeout=0 took {elapsed:.2f}s"


def _raise_keyboard_interrupt(signum, frame):
    raise KeyboardInterrupt


@pytest.mark.parametrize("kind", ["subprocess", "ipc"])
def test_keyboard_interrupt_tears_down_group(kind, tmp_path):
    """Cancellation must not leave detached descendants behind."""
    pidfile = str(tmp_path / "pid")
    previous = signal.signal(signal.SIGALRM, _raise_keyboard_interrupt)
    signal.setitimer(signal.ITIMER_REAL, 2.0)
    try:
        with pytest.raises(KeyboardInterrupt):
            _runtime(kind).execute(_spawn_code(pidfile), timeout=30)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    try:
        pid = _read_pid(pidfile)
        assert _wait_gone(pid), f"grandchild {pid} survived cancellation"
    finally:
        if os.path.exists(pidfile):
            with open(pidfile) as fh:
                _cleanup(int(fh.read()))


def test_sigterm_ignoring_child_is_sigkilled():
    code = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(60)"
    start = time.monotonic()
    result = SubprocessRuntime(NullValidator("python")).execute(code, timeout=0.5)
    elapsed = time.monotonic() - start
    assert result.timed_out is True
    assert elapsed < 10, f"teardown took {elapsed:.2f}s"
