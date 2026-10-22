"""Process-group lifecycle guarantees (issue #6).

Before this, a timeout or a cancellation killed only the direct child, so
anything the executed code spawned outlived ``execute()``.  Every scenario here
reproduced as a leak.

POSIX only: Windows has no process groups, so only the direct child can be
terminated there.
"""

from __future__ import annotations

import contextlib
import os
import signal
import threading
import time

import pytest

from codecell import IpcSubprocessRuntime, NullValidator, SubprocessRuntime

pytestmark = pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-only")

# Spawns a grandchild, records its pid, then keeps running.
SPAWN_GRANDCHILD = """
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open({pidfile!r}, "w") as fh:
    fh.write(str(child.pid))
time.sleep(60)
"""

# Spawns a grandchild, records its pid, then returns immediately.
SPAWN_GRANDCHILD_AND_EXIT = """
import subprocess, sys
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open({pidfile!r}, "w") as fh:
    fh.write(str(child.pid))
print("spawned", child.pid)
"""

IGNORE_SIGTERM_AND_SLEEP = """
import os, signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open({pidfile!r}, "w") as fh:
    fh.write(str(os.getpid()))
time.sleep(60)
"""


def _read_pid(path, timeout: float = 10.0) -> int:
    """Wait for the executed code to report a pid."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            text = path.read_text().strip()
            if text:
                return int(text)
        time.sleep(0.01)
    raise AssertionError(f"{path} was never written")


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie is dead, it just has not been reaped yet.
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            fields = fh.read().split(b") ", 1)
    except FileNotFoundError:
        return True
    return len(fields) == 2 and not fields[1].startswith(b"Z")


def _assert_gone(pid: int, timeout: float = 10.0) -> None:
    """Assert the process is gone, killing it on failure so CI stays clean."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _is_alive(pid):
            return
        time.sleep(0.02)
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, 9)
    raise AssertionError(f"process {pid} outlived execute()")


def _cancel_once_spawned(pidfile, timeout: float = 10.0):
    """Raise ``KeyboardInterrupt`` in the main thread once the grandchild exists.

    SIGALRM is used because a handler that raises interrupts a blocking
    ``select``/lock wait immediately, which ``_thread.interrupt_main`` does not
    (it is only serviced at the next bytecode boundary).
    """

    def _handler(signum, frame):
        raise KeyboardInterrupt

    def _arm() -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not pidfile.exists():
            time.sleep(0.01)
        if pidfile.exists():
            os.kill(os.getpid(), signal.SIGALRM)

    previous = signal.signal(signal.SIGALRM, _handler)
    armer = threading.Thread(target=_arm, daemon=True)
    armer.start()

    def _restore() -> None:
        armer.join(timeout=timeout)
        signal.signal(signal.SIGALRM, previous)

    return _restore


class TestSubprocessRuntimeLifecycle:
    def setup_method(self):
        self.runtime = SubprocessRuntime(NullValidator("python"))

    def test_timeout_kills_grandchild(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        result = self.runtime.execute(SPAWN_GRANDCHILD.format(pidfile=str(pidfile)), timeout=1.0)

        assert result.timed_out is True
        assert result.return_code == -1
        _assert_gone(_read_pid(pidfile))

    def test_sigterm_ignoring_child_is_sigkilled(self, tmp_path):
        pidfile = tmp_path / "child.pid"
        started = time.monotonic()
        result = self.runtime.execute(
            IGNORE_SIGTERM_AND_SLEEP.format(pidfile=str(pidfile)), timeout=0.5
        )
        elapsed = time.monotonic() - started

        assert result.timed_out is True
        # 0.5s of runtime, then the SIGTERM grace period, then SIGKILL.
        assert elapsed < 10
        _assert_gone(_read_pid(pidfile))

    def test_cancellation_kills_child_and_grandchild(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        started = time.monotonic()
        restore = _cancel_once_spawned(pidfile)
        try:
            with pytest.raises(KeyboardInterrupt):
                self.runtime.execute(SPAWN_GRANDCHILD.format(pidfile=str(pidfile)), timeout=30)
        finally:
            restore()

        # A missed signal would show up as the 30s timeout instead.
        assert time.monotonic() - started < 10
        _assert_gone(_read_pid(pidfile))

    def test_descendant_holding_pipes_is_bounded_by_timeout(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        started = time.monotonic()
        result = self.runtime.execute(
            SPAWN_GRANDCHILD_AND_EXIT.format(pidfile=str(pidfile)), timeout=2.0
        )
        elapsed = time.monotonic() - started

        # The child exits at once, but its grandchild keeps the capture pipes
        # open, so ``communicate()`` never reaches EOF: the timeout bounds the
        # wait and the group kill then removes the grandchild.  Capturing output
        # in that case without reporting a timeout is the transport work in #10.
        assert result.timed_out is True
        assert elapsed < 8
        _assert_gone(_read_pid(pidfile))

    def test_timeout_zero_is_immediate(self):
        started = time.monotonic()
        result = self.runtime.execute("while True:\n    pass", timeout=0)
        elapsed = time.monotonic() - started

        assert result.timed_out is True
        assert result.return_code == -1
        assert elapsed < 5

    def test_large_stderr_does_not_deadlock(self):
        result = self.runtime.execute(
            "import sys\nsys.stderr.write('x' * 300_000)\nprint('done')", timeout=30
        )

        assert result.timed_out is False
        assert result.return_code == 0
        assert "done" in result.stdout
        assert "output truncated" in result.stderr

    def test_infinite_loop_times_out(self):
        result = self.runtime.execute("while True:\n    pass", timeout=0.5)

        assert result.timed_out is True
        assert result.return_code == -1


class TestIpcSubprocessRuntimeLifecycle:
    def setup_method(self):
        self.runtime = IpcSubprocessRuntime(NullValidator("python"))

    def test_timeout_kills_grandchild(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        result = self.runtime.execute(SPAWN_GRANDCHILD.format(pidfile=str(pidfile)), timeout=1.0)

        assert result.timed_out is True
        assert result.return_code == -1
        _assert_gone(_read_pid(pidfile))

    def test_normal_return_kills_leftover_grandchild(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        result = self.runtime.execute(
            SPAWN_GRANDCHILD_AND_EXIT.format(pidfile=str(pidfile)), timeout=30
        )

        assert result.timed_out is False
        assert result.return_code == 0
        _assert_gone(_read_pid(pidfile))

    def test_sigterm_ignoring_child_is_sigkilled(self, tmp_path):
        pidfile = tmp_path / "child.pid"
        started = time.monotonic()
        result = self.runtime.execute(
            IGNORE_SIGTERM_AND_SLEEP.format(pidfile=str(pidfile)), timeout=0.5
        )
        elapsed = time.monotonic() - started

        assert result.timed_out is True
        assert elapsed < 10
        _assert_gone(_read_pid(pidfile))

    def test_cancellation_kills_child_and_grandchild(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        started = time.monotonic()
        restore = _cancel_once_spawned(pidfile)
        try:
            with pytest.raises(KeyboardInterrupt):
                self.runtime.execute(SPAWN_GRANDCHILD.format(pidfile=str(pidfile)), timeout=30)
        finally:
            restore()

        # A missed signal would show up as the 30s timeout instead.
        assert time.monotonic() - started < 10
        _assert_gone(_read_pid(pidfile))

    def test_timeout_zero_is_immediate(self):
        started = time.monotonic()
        result = self.runtime.execute("while True:\n    pass", timeout=0)
        elapsed = time.monotonic() - started

        assert result.timed_out is True
        assert result.return_code == -1
        assert elapsed < 5

    def test_tools_still_work_after_group_cleanup(self):
        calls = []
        result = self.runtime.execute(
            "print(add(a=1, b=2))", namespace={"add": lambda a, b: calls.append((a, b)) or a + b}
        )

        assert result.return_code == 0
        assert result.stdout.strip() == "3"
        assert calls == [(1, 2)]
