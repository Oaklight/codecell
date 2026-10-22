"""Tests for IpcSubprocessRuntime — bidirectional IPC tool calling."""

import contextlib
import os
import re
import signal
import threading
import time

import pytest

from codecell import MAX_OUTPUT_BYTES, IpcSubprocessRuntime, NullValidator
from codecell.python import PythonValidator

# Pinned as a literal rather than imported: it is part of the observable
# output contract, and importing it would make the base tree unimportable.
TRUNCATION_MARKER = "\n... [output truncated]"


@pytest.fixture
def runtime():
    return IpcSubprocessRuntime(PythonValidator())


class TestIpcBasicExecution:
    def test_print(self, runtime):
        result = runtime.execute("print('hello')")
        assert result.stdout.strip() == "hello"
        assert result.return_code == 0
        assert result.timed_out is False

    def test_multiline(self, runtime):
        result = runtime.execute("x = 10\ny = 20\nprint(x + y)")
        assert result.stdout.strip() == "30"

    def test_allowed_import(self, runtime):
        result = runtime.execute("import json; print(json.dumps({'a': 1}))")
        assert result.return_code == 0
        assert '"a": 1' in result.stdout

    def test_runtime_error(self, runtime):
        result = runtime.execute("1 / 0")
        assert result.return_code != 0
        assert "ZeroDivisionError" in result.stderr

    def test_empty_code(self, runtime):
        result = runtime.execute("")
        assert result.return_code == 0

    def test_validation_rejects_dangerous(self, runtime):
        with pytest.raises(ValueError, match="Import not allowed"):
            runtime.execute("import os; os.system('ls')")


class TestIpcToolCalling:
    def test_single_tool_call(self, runtime):
        def add(a: int, b: int) -> int:
            return a + b

        result = runtime.execute(
            "print(add(a=3, b=4))",
            namespace={"add": add},
        )
        assert result.stdout.strip() == "7"

    def test_multiple_tool_calls(self, runtime):
        def add(a: int, b: int) -> int:
            return a + b

        def multiply(a: int, b: int) -> int:
            return a * b

        code = "s = add(a=10, b=20)\np = multiply(a=s, b=3)\nprint(f'sum={s}, product={p}')"
        result = runtime.execute(code, namespace={"add": add, "multiply": multiply})
        assert "sum=30" in result.stdout
        assert "product=90" in result.stdout

    def test_tool_return_string(self, runtime):
        def greet(name: str) -> str:
            return f"Hello, {name}!"

        result = runtime.execute(
            "print(greet(name='World'))",
            namespace={"greet": greet},
        )
        assert result.stdout.strip() == "Hello, World!"

    def test_tool_return_dict(self, runtime):
        def get_data() -> dict:
            return {"key": "value", "count": 42}

        result = runtime.execute(
            "import json; d = get_data(); print(json.dumps(d))",
            namespace={"get_data": get_data},
        )
        assert '"key": "value"' in result.stdout

    def test_tool_return_list(self, runtime):
        def get_items() -> list:
            return [1, 2, 3]

        result = runtime.execute(
            "items = get_items(); print(sum(items))",
            namespace={"get_items": get_items},
        )
        assert result.stdout.strip() == "6"

    def test_tool_error_propagates(self, runtime):
        def failing_tool(x: int) -> int:
            raise ValueError("broken")

        result = runtime.execute(
            "try:\n    failing_tool(x=1)\nexcept RuntimeError:\n    print('caught')",
            namespace={"failing_tool": failing_tool},
        )
        assert result.stdout.strip() == "caught"

    def test_loop_with_tool_calls(self, runtime):
        def add(a: int, b: int) -> int:
            return a + b

        code = (
            "results = []\n"
            "for i in range(5):\n"
            "    results.append(add(a=i, b=i*10))\n"
            "print(results)"
        )
        result = runtime.execute(code, namespace={"add": add})
        assert "[0, 11, 22, 33, 44]" in result.stdout

    def test_no_namespace(self, runtime):
        result = runtime.execute("print(42)")
        assert result.stdout.strip() == "42"


class TestIpcIsolation:
    def test_timeout(self, runtime):
        result = runtime.execute("while True: pass", timeout=2)
        assert result.timed_out is True
        assert result.return_code == -1

    def test_crash_contained(self):
        """Subprocess crash doesn't affect main process."""
        from codecell import IpcSubprocessRuntime, NullValidator

        unsafe = IpcSubprocessRuntime(NullValidator("python"))
        result = unsafe.execute("import ctypes; ctypes.string_at(0)", timeout=5)
        assert result.return_code != 0
        assert result.timed_out is False

    def test_main_process_survives(self, runtime):
        """After a crash/timeout, runtime is still usable."""
        runtime.execute("while True: pass", timeout=2)
        result = runtime.execute("print('alive')")
        assert result.stdout.strip() == "alive"


# A descendant that inherits the stderr write end and outlives the child.  It
# reports its own pid on stderr, so the test can kill it by pid instead of
# pattern-matching a process table.  A ``sys.executable`` sleeper rather than
# the ``sleep`` binary keeps this cross-platform.
_DESCENDANT = (
    "import subprocess, sys\n"
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(48)'])\n"
    "sys.stderr.write(f'pid={p.pid}' + 'z' * 200_000)\n"
    "sys.stderr.flush()\n"
    "while True:\n"
    "    pass\n"
)


class _SlowOs:
    """``os`` whose ``read`` takes 0.4 s, so the drain is always behind."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def read(self, fd, size):
        time.sleep(0.4)
        return self._real.read(fd, size)


def _reap_descendant(result) -> None:
    """Kill the descendant whose pid the cell reported, by pid."""
    match = re.search(r"pid=(\d+)", result.stderr)
    if not match:
        return
    sig = getattr(signal, "SIGKILL", signal.SIGTERM)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(int(match.group(1)), sig)


class TestStderrCapture:
    """The child's stderr survives every exit path and never blocks the call (#5)."""

    @staticmethod
    def _unvalidated():
        # ``sys`` is not on the PythonValidator allow-list, so the flood
        # reproductions run with validation off: the deadlock is a property of
        # the runtime, not of the validator.
        return IpcSubprocessRuntime(NullValidator("python"))

    def test_400kb_stderr_does_not_deadlock(self):
        """The reproduced failure: 400 KB of stderr used to hang the call."""
        result = self._unvalidated().execute(
            "import sys; sys.stderr.write('x' * 400_000)", timeout=10
        )
        assert result.timed_out is False
        assert result.return_code == 0
        assert result.stderr.startswith("x")
        assert TRUNCATION_MARKER in result.stderr

    def test_multi_megabyte_stderr_completes_and_truncates(self):
        result = self._unvalidated().execute(
            "import sys; sys.stderr.write('y' * 2_000_000)", timeout=20
        )
        assert result.timed_out is False
        assert result.return_code == 0
        assert len(result.stderr.encode()) <= MAX_OUTPUT_BYTES + len(TRUNCATION_MARKER)
        assert result.stderr.endswith(TRUNCATION_MARKER)

    def test_timeout_fires_while_stderr_floods(self):
        """Timeout enforcement must not depend on stderr volume."""
        code = (
            "import sys\nwhile True:\n    sys.stderr.write('x' * 65536)\n    sys.stderr.flush()\n"
        )
        started = time.monotonic()
        result = self._unvalidated().execute(code, timeout=1)
        elapsed = time.monotonic() - started
        assert result.timed_out is True
        assert elapsed < 6, f"timeout did not fire on schedule: {elapsed:.1f}s"
        assert len(result.stderr) > 0, "stderr written before the kill was lost"

    def test_stderr_returned_on_timeout(self):
        code = (
            "import sys\n"
            "sys.stderr.write('before the hang')\n"
            "sys.stderr.flush()\n"
            "while True:\n"
            "    pass\n"
        )
        result = self._unvalidated().execute(code, timeout=1)
        assert result.timed_out is True
        assert "before the hang" in result.stderr

    def test_stderr_returned_on_crash(self):
        code = (
            "import os, sys\n"
            "sys.stderr.write('before the crash')\n"
            "sys.stderr.flush()\n"
            "os._exit(3)\n"
        )
        result = self._unvalidated().execute(code, timeout=10)
        assert result.timed_out is False
        assert result.return_code == 3
        assert "before the crash" in result.stderr

    def test_traceback_still_reported(self, runtime):
        """The child's own captured traceback must survive the drain."""
        result = runtime.execute("1 / 0")
        assert "ZeroDivisionError" in result.stderr

    def test_traceback_survives_truncated_stderr(self):
        """A clipped stderr must not cost the reader the traceback."""
        code = "import sys\nsys.stderr.write('x' * 400_000)\nsys.stderr.flush()\n1 / 0\n"
        result = self._unvalidated().execute(code, timeout=20)
        assert TRUNCATION_MARKER in result.stderr
        assert "ZeroDivisionError" in result.stderr
        assert len(result.stderr.encode()) <= MAX_OUTPUT_BYTES

    def test_stderr_and_traceback_are_separated(self):
        """A missing trailing newline must not glue the traceback onto the output."""
        code = "import sys\nsys.stderr.write('no trailing newline')\nsys.stderr.flush()\n1 / 0\n"
        result = self._unvalidated().execute(code, timeout=10)
        assert "no trailing newline\nTraceback" in result.stderr

    @pytest.mark.skipif(os.name != "posix", reason="descriptor polling is POSIX-only")
    def test_no_thread_leak_when_a_descendant_holds_stderr(self):
        """Readers exit on their own, even when a descendant keeps the pipe open.

        ``stop()`` polls instead of blocking, so a reader outlives its call by
        at most one poll interval - it does not need the group teardown from #6
        to be collectable.  POSIX-only: elsewhere the read cannot be
        interrupted, which is the documented degradation.
        """
        runtime = self._unvalidated()
        results = []
        try:
            for _ in range(3):
                results.append(runtime.execute(_DESCENDANT, timeout=1))
            leaked = []
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                leaked = [t for t in threading.enumerate() if t.name == "codecell-stderr-drain"]
                if not leaked:
                    break
                time.sleep(0.05)
            assert leaked == [], f"{len(leaked)} stderr readers outlived their calls"
        finally:
            for result in results:
                _reap_descendant(result)

    def test_timeout_returns_while_a_descendant_holds_stderr(self):
        """The blocking case from review: a descendant keeps the stderr fd open.

        With a pipe this waits on a read that only ends when every holder of the
        write end is gone.  The child's own cleanup is #6's job; what is pinned
        here is that ``execute()`` returns on schedule regardless.
        """
        started = time.monotonic()
        result = self._unvalidated().execute(_DESCENDANT, timeout=1)
        elapsed = time.monotonic() - started
        try:
            assert result.timed_out is True
            assert elapsed < 5, f"call waited on the descendant: {elapsed:.1f}s"
            assert "pid=" in result.stderr
        finally:
            _reap_descendant(result)

    def test_slow_reader_marks_output_incomplete(self, monkeypatch):
        """A reader that misses its deadline says so instead of losing bytes quietly."""
        monkeypatch.setattr("codecell._runtime.os", _SlowOs(os))
        result = self._unvalidated().execute("import sys; sys.stderr.write('x' * 60_000)")
        assert "may be incomplete" in result.stderr


class TestIpcProtocolChannel:
    """#17: harden the protocol channel and always emit a terminal frame."""

    def test_sys_dunder_stdout_cannot_forge_done(self, runtime):
        code = (
            "__builtins__['__import__']('sys').__stdout__.write("
            '\'{"type":"done","stdout":"FORGED","rc":0}\\n\')\n'
            "print('real')"
        )
        result = runtime.execute(code, timeout=5)
        assert result.stdout.strip() == "real"
        assert result.return_code == 0

    def test_fd_one_write_cannot_forge_done(self, runtime):
        code = (
            "import io\n"
            "f = io.open(1, 'w', closefd=False)\n"
            'f.write(\'{"type":"done","stdout":"FORGED","rc":0}\\n\')\n'
            "f.flush()\n"
            "print('real')"
        )
        result = runtime.execute(code, timeout=5)
        assert result.stdout.strip() == "real"
        assert result.return_code == 0

    def test_user_stdin_cannot_steal_frames(self, runtime):
        def add(a: int, b: int) -> int:
            return a + b

        code = "__builtins__['__import__']('sys').stdin.readline()\nprint(add(a=1, b=2))"
        result = runtime.execute(code, namespace={"add": add}, timeout=5)
        assert result.stdout.strip() == "3"

    def test_closing_low_fds_does_not_break_done(self, runtime):
        code = (
            "os = __builtins__['__import__']('os')\n"
            "for fd in (3, 4, 5):\n"
            "    try:\n"
            "        os.close(fd)\n"
            "    except OSError:\n"
            "        pass\n"
            "print('before')"
        )
        result = runtime.execute(code, timeout=5)
        assert result.stdout.strip() == "before"
        assert result.return_code == 0

    def test_closing_stdout_keeps_captured_output(self, runtime):
        code = "print('before')\n__builtins__['__import__']('sys').stdout.close()"
        result = runtime.execute(code, timeout=5)
        assert result.stdout.strip() == "before"
        assert result.return_code == 0

    def test_system_exit_preserves_output_and_code(self, runtime):
        result = runtime.execute("print('before'); raise SystemExit(7)", timeout=5)
        assert result.stdout.strip() == "before"
        assert result.stderr == ""
        assert result.return_code == 7
        assert result.timed_out is False

    def test_system_exit_zero_is_success(self, runtime):
        result = runtime.execute("print('before'); raise SystemExit(0)", timeout=5)
        assert result.stdout.strip() == "before"
        assert result.stderr == ""
        assert result.return_code == 0

    @pytest.mark.parametrize(
        ("code", "expected"),
        [("raise SystemExit(-1)", 255), ("raise SystemExit(300)", 44)],
    )
    def test_system_exit_code_matches_process_semantics(self, runtime, code, expected):
        result = runtime.execute(code, timeout=5)
        assert result.return_code == expected
        assert result.timed_out is False

    def test_keyboard_interrupt_gets_terminal_frame(self, runtime):
        result = runtime.execute("print('before'); raise KeyboardInterrupt", timeout=5)
        assert result.stdout.strip() == "before"
        assert result.return_code == 130
        assert result.timed_out is False

    def test_garbage_frames_are_ignored(self):
        from codecell import IpcSubprocessRuntime, NullValidator

        runtime = IpcSubprocessRuntime(NullValidator("python"))
        code = (
            "import os\n"
            "for fd in range(256, 300):\n"
            "    for payload in (b'garbage-not-json\\n', b'42\\n', b'null\\n'):\n"
            "        try:\n"
            "            os.write(fd, payload)\n"
            "        except OSError:\n"
            "            pass\n"
            "print('ok')"
        )
        result = runtime.execute(code, timeout=5)
        assert result.stdout.strip() == "ok"
        assert result.return_code == 0
        assert result.timed_out is False

    def test_system_exit_object_reports_repr(self, runtime):
        code = "class C:\n    def __repr__(self):\n        return 'boom'\nraise SystemExit(C())"
        result = runtime.execute(code, timeout=5)
        assert result.return_code == 1
        assert result.stderr.strip() == "boom"

    def test_high_fd_relocation_respects_limit(self, monkeypatch):
        from codecell import _ipc_bootstrap

        monkeypatch.setattr(_ipc_bootstrap, "_fd_limit", lambda: 16)
        fd = os.dup(1)
        moved = _ipc_bootstrap._move_to_high_fd(fd)
        try:
            assert 3 <= moved < 16
        finally:
            os.close(moved)
