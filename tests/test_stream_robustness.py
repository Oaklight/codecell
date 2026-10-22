"""Regressions for the review findings on the stream/lifecycle rework (#15).

Each test names the failure it reproduces, not the fix that prevents it.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time

import pytest

from codecell import IpcSubprocessRuntime, NullValidator, SubprocessRuntime, _runtime

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-only")
LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="reads /proc for descriptors")


def _py_runtime() -> SubprocessRuntime:
    return SubprocessRuntime(NullValidator("python"))


def _ipc_runtime() -> IpcSubprocessRuntime:
    return IpcSubprocessRuntime(NullValidator("python"))


def _kill(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)


@POSIX_ONLY
def test_invalid_utf8_in_stdout_does_not_kill_the_drain():
    """One invalid byte must not stop the drain: the child would block forever."""
    code = (
        "import sys\n"
        "sys.stdout.buffer.write(b'\\xff')\n"
        "sys.stdout.write('x' * 200_000)\n"
        "sys.stdout.flush()\n"
    )
    result = _py_runtime().execute(code, timeout=20)

    assert result.timed_out is False
    assert result.return_code == 0
    # A dead drain thread would leave the rest of the output unread.
    assert result.stdout.count("x") > 60_000
    assert "output truncated" in result.stdout
    assert "\ufffd" in result.stdout


@POSIX_ONLY
def test_invalid_utf8_in_ipc_stderr_does_not_kill_the_drain():
    code = "import sys\nsys.stderr.buffer.write(b'\\xff' * 100_000)\nprint('ok')\n"
    result = _ipc_runtime().execute(code, timeout=20)

    assert result.timed_out is False
    assert result.return_code == 0
    assert "ok" in result.stdout
    assert "\ufffd" in result.stderr


@POSIX_ONLY
def test_windows_fallback_force_kill_does_not_need_sigkill(monkeypatch):
    """The non-POSIX branch must not touch ``signal.SIGKILL`` (absent on Windows)."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    monkeypatch.setattr(_runtime, "_IS_POSIX", False)
    monkeypatch.delattr(signal, "SIGKILL", raising=False)
    try:
        _runtime._terminate_process_group(proc, grace=0.2)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


@POSIX_ONLY
def test_escaped_descendant_marks_capture_as_partial(tmp_path):
    """Output before the child exits must not be dropped, and partial capture is
    reported instead of passing as complete."""
    pidfile = tmp_path / "child.pid"
    code = f"""
import subprocess, sys
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
)
with open({str(pidfile)!r}, "w") as fh:
    fh.write(str(child.pid))
print("hello")
"""
    started = time.monotonic()
    result = _py_runtime().execute(code, timeout=30)
    elapsed = time.monotonic() - started

    assert result.return_code == 0
    # Closing the pipe under a blocked reader used to hang until the escaped
    # descendant exited: the wait has to stay bounded instead.
    assert elapsed < 10, f"execute() took {elapsed:.1f}s"
    assert "hello" in result.stdout
    assert "output drain cut off" in result.stderr
    # The test escaped the group on purpose: clean it up ourselves.
    _kill(int(pidfile.read_text()))


@POSIX_ONLY
def test_ipc_dead_child_with_held_stderr_returns_promptly(tmp_path):
    """A descendant holding stderr open must not outlive the timeout budget."""
    pidfile = tmp_path / "child.pid"
    code = f"""
import os, subprocess, sys
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
with open({str(pidfile)!r}, "w") as fh:
    fh.write(str(child.pid))
os._exit(1)
"""
    started = time.monotonic()
    result = _ipc_runtime().execute(code, timeout=2)
    elapsed = time.monotonic() - started

    assert elapsed < 8, f"execute() took {elapsed:.1f}s, the stderr read blocked"
    assert result.timed_out is False
    assert result.return_code == 1
    _kill(int(pidfile.read_text()))


@LINUX_ONLY
def test_no_thread_or_fd_leak_across_executions():
    """Reader threads and pipes are released on every exit path."""

    def snapshot() -> tuple[int, int]:
        return threading.active_count(), len(os.listdir("/proc/self/fd"))

    runtimes = (_py_runtime(), _ipc_runtime())
    for runtime in runtimes:
        assert runtime.execute("print('warm')", timeout=30).return_code == 0

    baseline_threads, baseline_fds = snapshot()
    for _ in range(3):
        for runtime in runtimes:
            assert runtime.execute("print('x' * 100)", timeout=30).return_code == 0

    threads, fds = snapshot()
    assert threads <= baseline_threads, f"leaked threads: {baseline_threads} -> {threads}"
    assert fds <= baseline_fds, f"leaked fds: {baseline_fds} -> {fds}"
