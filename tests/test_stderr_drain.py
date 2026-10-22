"""Regression tests for issue #5: IPC stderr must be drained continuously."""

from __future__ import annotations

import threading
import time

import pytest

from codecell import IpcSubprocessRuntime, NullValidator
from codecell._runtime import MAX_OUTPUT_BYTES, TRUNCATION_MARKER


@pytest.fixture
def runtime():
    return IpcSubprocessRuntime(NullValidator("python"))


def test_large_stderr_completes_and_is_truncated(runtime):
    """More than a pipe buffer must not stall the child."""
    code = "import sys\nsys.stderr.write('x' * 1_000_000)\nsys.stderr.flush()\nprint('ok')"
    result = runtime.execute(code, timeout=10)
    assert result.timed_out is False
    assert result.return_code == 0
    assert result.stdout.strip() == "ok"
    assert result.stderr.startswith("x")
    assert result.stderr.endswith(TRUNCATION_MARKER)
    assert len(result.stderr.encode()) <= MAX_OUTPUT_BYTES + len(TRUNCATION_MARKER)


def test_stderr_is_returned_on_timeout(runtime):
    code = (
        "import sys, time\n"
        "sys.stderr.write('before-timeout\\n')\n"
        "sys.stderr.flush()\n"
        "time.sleep(60)"
    )
    result = runtime.execute(code, timeout=1)
    assert result.timed_out is True
    assert "before-timeout" in result.stderr


def test_timeout_fires_while_stderr_floods(runtime):
    """Draining must not make timeout enforcement depend on stderr volume."""
    code = "import sys\nwhile True:\n    sys.stderr.write('y' * 65_536)\n"
    start = time.monotonic()
    result = runtime.execute(code, timeout=1)
    elapsed = time.monotonic() - start
    assert result.timed_out is True
    assert elapsed < 3, f"timeout took {elapsed:.2f}s while stderr was flooding"


def test_stderr_is_returned_on_crash(runtime):
    code = "import os, sys\nsys.stderr.write('crash-note\\n')\nsys.stderr.flush()\nos._exit(3)"
    result = runtime.execute(code, timeout=10)
    assert result.timed_out is False
    assert result.return_code == 3
    assert "crash-note" in result.stderr


def test_user_stderr_precedes_in_band_traceback(runtime):
    code = "import sys\nsys.stderr.write('user-note\\n')\nsys.stderr.flush()\n1 / 0"
    result = runtime.execute(code, timeout=10)
    assert result.return_code == 1
    assert "user-note" in result.stderr
    assert "ZeroDivisionError" in result.stderr
    assert result.stderr.index("user-note") < result.stderr.index("ZeroDivisionError")


def test_drain_thread_does_not_leak(runtime):
    for _ in range(3):
        result = runtime.execute("print('ok')", timeout=10)
        assert result.return_code == 0
        assert not [
            thread for thread in threading.enumerate() if thread.name == "codecell-stderr-drain"
        ]
