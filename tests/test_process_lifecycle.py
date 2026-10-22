"""Process-group lifecycle guarantees (issue #6).

Every scenario in this module reproduced as a leak before 0.3.0: a timeout or a
normal return left grandchildren of the executed code running.
"""

from __future__ import annotations

import _thread
import contextlib
import os
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


class TestSubprocessRuntimeLifecycle:
    def setup_method(self):
        self.runtime = SubprocessRuntime(NullValidator("python"))

    def test_timeout_kills_grandchild(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        result = self.runtime.execute(SPAWN_GRANDCHILD.format(pidfile=str(pidfile)), timeout=1.0)

        assert result.timed_out is True
        assert result.return_code == -1
        _assert_gone(_read_pid(pidfile))

    def test_normal_return_kills_leftover_grandchild(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        started = time.monotonic()
        result = self.runtime.execute(
            SPAWN_GRANDCHILD_AND_EXIT.format(pidfile=str(pidfile)), timeout=30
        )
        elapsed = time.monotonic() - started

        assert result.timed_out is False
        assert result.return_code == 0
        # A leftover descendant holding the pipes must not stall the wait.
        assert elapsed < 10
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

    def test_keyboard_interrupt_kills_child_and_grandchild(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        code = SPAWN_GRANDCHILD.format(pidfile=str(pidfile))
        interrupted_at = threading.Timer(0.5, _thread.interrupt_main)
        interrupted_at.start()
        try:
            with pytest.raises(KeyboardInterrupt):
                self.runtime.execute(code, timeout=30)
        finally:
            interrupted_at.cancel()

        _assert_gone(_read_pid(pidfile))

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

    def test_tools_still_work_after_group_cleanup(self):
        calls = []
        result = self.runtime.execute(
            "print(add(a=1, b=2))", namespace={"add": lambda a, b: calls.append((a, b)) or a + b}
        )

        assert result.return_code == 0
        assert result.stdout.strip() == "3"
        assert calls == [(1, 2)]
