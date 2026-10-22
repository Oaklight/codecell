"""Process-group lifecycle guarantees (issue #6).

Before this, killing was limited to the direct child, so whatever the executed
code spawned outlived ``execute()``.  Every scenario here reproduced as a leak.

Linux only: the assertions read ``/proc`` to tell a zombie from a live process.
Windows has no process groups at all, and only the direct child can be killed
there.
"""

from __future__ import annotations

import contextlib
import os
import platform
import signal
import threading
import time

import pytest

from codecell import IpcSubprocessRuntime, NullValidator, SubprocessRuntime

pytestmark = pytest.mark.skipif(
    os.name != "posix" or platform.system() != "Linux",
    reason="process-group assertions read /proc; POSIX and Linux only",
)

# Spawns a grandchild, records its pid, then keeps running.
SPAWN_GRANDCHILD = """
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open({pidfile!r}, "w") as fh:
    fh.write(str(child.pid))
time.sleep(60)
"""

# Spawns a grandchild that does NOT share our pipes, records its pid, then exits.
# ``communicate()`` never sees this descendant, so only a group kill reaches it.
SPAWN_DETACHED_AND_EXIT = """
import subprocess, sys
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(60)"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
with open({pidfile!r}, "w") as fh:
    fh.write(str(child.pid))
sys.exit({rc})
"""

# Spawns a grandchild that keeps our pipe open, records its pid, then exits.
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

# Writes to stdout, flushes, then blocks past the deadline.
WRITE_THEN_HANG = """
import sys, time
sys.stdout.write('hello-partial\\n')
sys.stdout.flush()
time.sleep(60)
"""

# Pids the current test is responsible for.  The autouse fixture kills them even
# when an assertion fails, so a regression cannot leave a 60 s sleeper in CI.
_WATCHED: list[int] = []


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            fields = fh.read().split(b") ", 1)
    except FileNotFoundError:
        # The entry vanished mid-check: the process is gone.
        return False
    # A zombie is dead, it just has not been reaped yet.
    return len(fields) == 2 and not fields[1].startswith(b"Z")


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


def _watch(pidfile) -> int:
    """Return the pid the cell reported, registered for teardown cleanup."""
    pid = _read_pid(pidfile)
    _WATCHED.append(pid)
    return pid


def _assert_gone(pid: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _is_alive(pid):
            return
        time.sleep(0.02)
    raise AssertionError(f"process {pid} outlived execute()")


@pytest.fixture(autouse=True)
def _kill_survivors():
    """Kill anything a test reported, so a failure cannot leak into CI."""
    _WATCHED.clear()
    yield
    for pid in _WATCHED:
        deadline = time.monotonic() + 10
        while _is_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


def _cancel_once_spawned(pidfile, timeout: float = 10.0):
    """Raise ``KeyboardInterrupt`` in the main thread once the grandchild exists.

    ``pthread_kill`` names the main thread explicitly: a signal sent with
    ``os.kill`` can be delivered to any thread, and ``_thread.interrupt_main`` is
    only serviced at the next bytecode boundary, which never arrives while the
    caller is blocked in ``communicate()``.
    """

    def _handler(signum, frame):
        raise KeyboardInterrupt

    def _arm() -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not pidfile.exists():
            time.sleep(0.01)
        main = threading.main_thread().ident
        if pidfile.exists() and main is not None:
            signal.pthread_kill(main, signal.SIGALRM)

    previous = signal.signal(signal.SIGALRM, _handler)
    armer = threading.Thread(target=_arm, daemon=True)
    armer.start()

    def _restore() -> None:
        armer.join(timeout=timeout)
        signal.signal(signal.SIGALRM, previous)

    return _restore


RUNTIMES = pytest.mark.parametrize(
    "make_runtime",
    [
        pytest.param(lambda: SubprocessRuntime(NullValidator("python")), id="subprocess"),
        pytest.param(lambda: IpcSubprocessRuntime(NullValidator("python")), id="ipc"),
    ],
)


@RUNTIMES
class TestLifecycle:
    """Behaviour both runtimes must guarantee."""

    def test_timeout_kills_grandchild(self, make_runtime, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        result = make_runtime().execute(SPAWN_GRANDCHILD.format(pidfile=str(pidfile)), timeout=1.0)
        pid = _watch(pidfile)

        assert result.timed_out is True
        assert result.return_code == -1
        _assert_gone(pid)

    @pytest.mark.parametrize("rc", [0, 3], ids=["normal-exit", "crash-exit"])
    def test_detached_grandchild_dies_on_exit(self, make_runtime, tmp_path, rc):
        pidfile = tmp_path / "grandchild.pid"
        result = make_runtime().execute(
            SPAWN_DETACHED_AND_EXIT.format(pidfile=str(pidfile), rc=rc), timeout=30
        )
        pid = _watch(pidfile)

        # The descendant holds none of our pipes, so the child's exit is prompt.
        assert result.timed_out is False
        assert result.return_code == rc
        _assert_gone(pid)

    def test_sigterm_ignoring_child_is_sigkilled(self, make_runtime, tmp_path):
        pidfile = tmp_path / "child.pid"
        started = time.monotonic()
        result = make_runtime().execute(
            IGNORE_SIGTERM_AND_SLEEP.format(pidfile=str(pidfile)), timeout=0.5
        )
        elapsed = time.monotonic() - started
        pid = _watch(pidfile)

        assert result.timed_out is True
        # 0.5s of runtime, then the SIGTERM grace period, then SIGKILL.
        assert elapsed < 10
        _assert_gone(pid)

    def test_cancellation_kills_child_and_grandchild(self, make_runtime, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        started = time.monotonic()
        restore = _cancel_once_spawned(pidfile)
        try:
            with pytest.raises(KeyboardInterrupt):
                make_runtime().execute(SPAWN_GRANDCHILD.format(pidfile=str(pidfile)), timeout=30)
        finally:
            restore()
        pid = _watch(pidfile)

        # A missed signal would show up as the 30s timeout instead.
        assert time.monotonic() - started < 10
        _assert_gone(pid)

    def test_timeout_zero_is_immediate(self, make_runtime):
        started = time.monotonic()
        result = make_runtime().execute("while True:\n    pass", timeout=0)
        elapsed = time.monotonic() - started

        assert result.timed_out is True
        assert result.return_code == -1
        assert elapsed < 5


class TestSubprocessRuntime:
    """Behaviour specific to the pipe-captured runtime."""

    def setup_method(self):
        self.runtime = SubprocessRuntime(NullValidator("python"))

    def test_partial_output_survives_timeout(self):
        result = self.runtime.execute(WRITE_THEN_HANG, timeout=1.0)

        assert result.timed_out is True
        assert "hello-partial" in result.stdout

    def test_descendant_holding_pipes_is_bounded_by_timeout(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        started = time.monotonic()
        result = self.runtime.execute(
            SPAWN_GRANDCHILD_AND_EXIT.format(pidfile=str(pidfile)), timeout=2.0
        )
        elapsed = time.monotonic() - started
        pid = _watch(pidfile)

        # The child exits at once, but its grandchild keeps the capture pipes
        # open, so ``communicate()`` never reaches EOF: the timeout bounds the
        # wait and the group kill then removes the grandchild.  Capturing output
        # in that case without reporting a timeout is the transport work in #10.
        assert result.timed_out is True
        assert elapsed < 8
        _assert_gone(pid)

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


class TestIpcSubprocessRuntime:
    """Behaviour specific to the dispatch-loop runtime."""

    def setup_method(self):
        self.runtime = IpcSubprocessRuntime(NullValidator("python"))

    def test_normal_return_kills_pipe_holding_grandchild(self, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        started = time.monotonic()
        result = self.runtime.execute(
            SPAWN_GRANDCHILD_AND_EXIT.format(pidfile=str(pidfile)), timeout=30
        )
        elapsed = time.monotonic() - started
        pid = _watch(pidfile)

        # The `done` frame ends the loop without waiting for pipe EOF, so the
        # grandchild is still alive when the group is torn down.
        assert result.timed_out is False
        assert result.return_code == 0
        assert elapsed < 10
        _assert_gone(pid)

    def test_tools_still_work_after_group_cleanup(self):
        calls = []
        result = self.runtime.execute(
            "print(add(a=1, b=2))", namespace={"add": lambda a, b: calls.append((a, b)) or a + b}
        )

        assert result.return_code == 0
        assert result.stdout.strip() == "3"
        assert calls == [(1, 2)]
