"""Base runtime and validator abstractions.

Defines the ABC for code execution runtimes and validators.
Language-specific implementations (Python, Bash) inherit from these
and provide their own validation logic and interpreter invocation.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import IO, Any

from ._types import CodeResult

# Maximum bytes kept for stdout / stderr to prevent memory exhaustion.
MAX_OUTPUT_BYTES = 65_536  # 64 KB

# Appended when captured output is clipped, so a caller can tell truncation
# from a program that genuinely ended there.
TRUNCATION_MARKER = "\n... [output truncated]"


def truncate(text: str, max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    """Truncate *text* to at most *max_bytes* UTF-8 bytes.

    If truncation occurs, a marker is appended so the caller knows the
    output was clipped.

    Args:
        text: The string to truncate.
        max_bytes: Maximum number of UTF-8 bytes allowed.

    Returns:
        The (possibly truncated) string.
    """
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated + TRUNCATION_MARKER


class _StderrDrain:
    """Read a child's stderr in the background into a bounded buffer.

    Draining must not depend on the child exiting.  Once the OS pipe buffer
    (~64 KiB) fills, a child blocks inside ``write()`` and never sends another
    protocol message, so a parent that only reads stderr after exit waits for
    a message that cannot arrive.

    The buffer is capped at *limit* bytes; further output is read and dropped
    so the child is never blocked by us.  Reading continues after the cap so a
    flooding child still makes progress.
    """

    def __init__(self, stream: IO[str], limit: int = MAX_OUTPUT_BYTES) -> None:
        self._stream = stream
        self._limit = limit
        self._buffer = bytearray()
        self._truncated = False
        self._captured: bytes | None = None
        self._lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._read_loop, name="codecell-stderr-drain", daemon=True
        )

    @property
    def truncated(self) -> bool:
        """Whether output beyond the buffer cap was dropped."""
        with self._lock:
            return self._truncated

    def start(self) -> None:
        """Begin draining.  Call once, immediately after the spawn."""
        self._thread.start()

    def _read_loop(self) -> None:
        # ``read1`` returns whatever is available instead of waiting for a
        # full buffer, so partial output survives a kill.
        raw: Any = getattr(self._stream, "buffer", self._stream)
        while True:
            try:
                chunk = raw.read1(8192)
            except (OSError, ValueError):
                return  # our own close(), or the child went away
            if not chunk:
                return
            data = chunk if isinstance(chunk, bytes) else chunk.encode("utf-8", "replace")
            with self._lock:
                room = self._limit - len(self._buffer)
                if room > 0:
                    self._buffer.extend(data[:room])
                if len(data) > max(room, 0):
                    self._truncated = True

    def stop(self, timeout: float = 2.0) -> bytes:
        """Stop reading and return the captured bytes (at most ``limit``).

        Blocks at most *timeout* seconds for the reader.  A descendant that
        inherited the pipe can keep it open after the direct child is gone,
        so the read end is closed rather than leaving a thread behind.
        """
        with self._lock:
            if self._captured is not None:
                return self._captured
        self._thread.join(timeout)
        if self._thread.is_alive():
            with contextlib.suppress(OSError, ValueError):
                self._stream.close()
            self._thread.join(1.0)
        with self._lock:
            self._captured = bytes(self._buffer)
            return self._captured


class Validator(ABC):
    """Base class for code validators.

    Each validator is the single source of truth for its language:
    it provides the language name, the interpreter command, and the
    validation logic.  The runtime infers everything from the validator.
    """

    @property
    @abstractmethod
    def lang(self) -> str:
        """Language identifier (e.g. ``"python"``, ``"bash"``)."""
        ...

    @property
    @abstractmethod
    def interpreter(self) -> list[str]:
        """Command to invoke the interpreter (e.g. ``[sys.executable, "-c"]``)."""
        ...

    @abstractmethod
    def validate(self, code: str) -> None:
        """Validate code before execution.

        Args:
            code: Source code string.

        Raises:
            ValueError: If the code contains dangerous constructs.
            SyntaxError: If the code cannot be parsed.
        """
        ...


class NullValidator(Validator):
    """Validator that allows everything.  For trusted code only.

    Forces callers to make a deliberate security decision::

        runtime = SubprocessRuntime(NullValidator("python"))
    """

    def __init__(self, lang: str = "python") -> None:
        self._lang = lang

    @property
    def lang(self) -> str:
        return self._lang

    @property
    def interpreter(self) -> list[str]:
        if self._lang == "python":
            return [sys.executable, "-c"]
        if self._lang == "bash":
            return ["bash", "-c"]
        return [self._lang, "-c"]

    def validate(self, code: str) -> None:
        pass


class BaseRuntime(ABC):
    """Abstract base for code execution runtimes.

    Subclasses decide the isolation strategy (subprocess, container,
    etc.) and how namespace callables are made available to the
    executed code.

    The ``namespace`` is a plain ``dict[str, Callable]`` — this
    package has no knowledge of ``ToolProjection`` or ``ToolRegistry``.
    """

    def __init__(self, validator: Validator) -> None:
        self._validator = validator

    @property
    def lang(self) -> str:
        """Language of this runtime, inferred from the validator."""
        return self._validator.lang

    @abstractmethod
    def execute(
        self,
        code: str,
        *,
        namespace: dict[str, Callable[..., Any]] | None = None,
        timeout: float | None = None,
    ) -> CodeResult:
        """Execute code and return structured output.

        Args:
            code: Source code to execute.
            namespace: Mapping of name -> callable to inject into the
                execution namespace.  Support varies by language and
                runtime implementation.
            timeout: Maximum wall-clock seconds.  ``None`` means no limit.

        Returns:
            A :class:`CodeResult` with captured stdout, stderr, and
            exit information.
        """
        ...


class SubprocessRuntime(BaseRuntime):
    """Execute code in a subprocess for crash isolation.

    The code is validated via the provided :class:`Validator`, then run
    in a fresh interpreter process.  Crashes, infinite loops, and
    resource exhaustion cannot affect the calling process.

    Usage::

        from codecell import SubprocessRuntime
        from codecell.python import PythonValidator

        runtime = SubprocessRuntime(PythonValidator())
        result = runtime.execute("print(1 + 2)", timeout=10)
    """

    def execute(
        self,
        code: str,
        *,
        namespace: dict[str, Callable[..., Any]] | None = None,
        timeout: float | None = None,
    ) -> CodeResult:
        """Execute code in a subprocess.

        Args:
            code: Source code to execute.
            namespace: Mapping of name -> callable.  Currently supported
                for Python (injected as stubs); raises ``NotImplementedError``
                for other languages.
            timeout: Maximum wall-clock seconds before kill.

        Returns:
            A :class:`CodeResult` with captured output.

        Raises:
            ValueError: If validation rejects the code.
            SyntaxError: If the code cannot be parsed.
            NotImplementedError: If namespace is passed for a language
                that doesn't support it.
        """
        self._validator.validate(code)

        script = self._build_script(code, namespace)

        try:
            result = subprocess.run(
                [*self._validator.interpreter, script],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return CodeResult(
                stdout=truncate(result.stdout),
                stderr=truncate(result.stderr),
                return_code=result.returncode,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout
            stderr = exc.stderr
            return CodeResult(
                stdout=truncate(stdout if isinstance(stdout, str) else ""),
                stderr=truncate(stderr if isinstance(stderr, str) else ""),
                return_code=-1,
                timed_out=True,
            )

    def _build_script(
        self,
        code: str,
        namespace: dict[str, Callable[..., Any]] | None,
    ) -> str:
        """Build the full script, prepending namespace stubs if needed."""
        if not namespace:
            return code

        if self.lang != "python":
            raise NotImplementedError(
                f"Namespace injection is not supported for {self.lang!r}. "
                "Only Python runtimes support callable namespace."
            )

        import json

        stubs: list[str] = []
        for name, fn in namespace.items():
            doc = getattr(fn, "__doc__", None) or f"Stub for {name}"
            doc_escaped = json.dumps(doc)
            stubs.append(
                f"def {name}(**kwargs):\n"
                f"    {doc_escaped}\n"
                f"    raise NotImplementedError("
                f"'Cannot call {name}() in subprocess mode')\n"
            )

        preamble = "\n".join(stubs)
        return preamble + "\n" + code


class IpcSubprocessRuntime(BaseRuntime):
    """Execute code in a subprocess with namespace callables via IPC.

    Unlike :class:`SubprocessRuntime` (which injects stubs that raise),
    this runtime establishes a bidirectional JSON pipe so the
    subprocess code can **actually call** the namespace functions.
    Tool execution always happens in the main process — only the
    LLM-generated code runs in the subprocess.

    Benefits over in-process ``exec()``:
        - Crash isolation (segfault, OOM, infinite loop)
        - No cloudpickle needed for tools
        - Tools retain access to main-process state (connections, env)

    Protocol (JSON lines over stdin/stdout pipe):

        Main → Sub:  ``{"type": "init", "tools": [...], "code": "..."}``
        Sub → Main:  ``{"type": "call", "tool": "name", "kwargs": {...}}``
        Main → Sub:  ``{"type": "result", "value": ...}``
        Sub → Main:  ``{"type": "done", "stdout": "...", "stderr": "...", "rc": 0}``

    Usage::

        from codecell import IpcSubprocessRuntime
        from codecell.python import PythonValidator

        runtime = IpcSubprocessRuntime(PythonValidator())
        result = runtime.execute(
            "print(add(a=1, b=2))",
            namespace={"add": lambda a, b: a + b},
        )
        assert result.stdout.strip() == "3"
    """

    def execute(
        self,
        code: str,
        *,
        namespace: dict[str, Callable[..., Any]] | None = None,
        timeout: float | None = None,
    ) -> CodeResult:
        """Execute code in a subprocess with IPC tool calling.

        Args:
            code: Source code to execute.
            namespace: Mapping of name -> callable.  These are callable
                from the subprocess code via IPC back to the main process.
            timeout: Maximum wall-clock seconds before kill.

        Returns:
            A :class:`CodeResult` with captured output.

        Raises:
            ValueError: If validation rejects the code.
            SyntaxError: If the code cannot be parsed.
            NotImplementedError: If namespace is passed for non-Python.
        """
        self._validator.validate(code)

        if namespace and self.lang != "python":
            raise NotImplementedError(
                f"IPC namespace is not supported for {self.lang!r}. "
                "Only Python runtimes support callable namespace."
            )

        # Build tool_docs: {name: docstring} for the subprocess stubs
        tool_docs: dict[str, str | None] = {}
        if namespace:
            for name, fn in namespace.items():
                tool_docs[name] = getattr(fn, "__doc__", None)

        # Spawn subprocess running the bootstrap script
        proc = subprocess.Popen(
            [sys.executable, "-m", "codecell._ipc_bootstrap"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stderr is not None

        # Start draining stderr before the first protocol byte moves.  Reading
        # it only after exit is the deadlock: a child that fills the pipe
        # buffer blocks in write() and stops sending protocol messages.
        drain = _StderrDrain(proc.stderr)
        drain.start()

        try:
            return self._dispatch_loop(proc, code, tool_docs, namespace or {}, timeout, drain)
        except Exception:
            proc.kill()
            raise
        finally:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            drain.stop()

    def _dispatch_loop(
        self,
        proc: subprocess.Popen,
        code: str,
        tool_docs: dict[str, str | None],
        namespace: dict[str, Callable[..., Any]],
        timeout: float | None,
        drain: _StderrDrain,
    ) -> CodeResult:
        """Main-process dispatch loop: forward tool calls, collect results.

        Uses a background thread for readline so that timeout can be
        enforced even when the subprocess is blocked (infinite loop).

        Every exit path goes through :meth:`_finish`, so stderr captured by
        *drain* is returned on success, crash and timeout alike, and the
        drain thread never outlives the call.
        """
        import json
        import queue
        import threading
        import time

        assert proc.stdin is not None
        assert proc.stdout is not None
        assert proc.stderr is not None

        # Send init message with tool docs for help() support
        init_msg = json.dumps({"type": "init", "tools": tool_docs, "code": code})
        proc.stdin.write(init_msg + "\n")
        proc.stdin.flush()

        # Background thread reads lines from subprocess stdout
        line_queue: queue.Queue[str | None] = queue.Queue()

        def _reader() -> None:
            try:
                for line in proc.stdout:  # ty: ignore[not-iterable]
                    line_queue.put(line)
            except ValueError:
                pass  # pipe closed
            line_queue.put(None)  # sentinel

        reader_thread = threading.Thread(target=_reader, daemon=True)
        reader_thread.start()

        deadline = time.monotonic() + timeout if timeout else None

        while True:
            # Calculate remaining time for queue.get
            if deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return self._timeout_result(proc, drain)
            else:
                remaining = None

            try:
                line = line_queue.get(timeout=remaining)
            except queue.Empty:
                return self._timeout_result(proc, drain)

            if line is None:
                # Subprocess died without sending ``done``: a crash, or the
                # bootstrap exited before the code ran.
                return self._finish(proc, drain, stdout="", return_code=None, timed_out=False)

            msg = json.loads(line)

            if msg["type"] == "done":
                # ``done`` is sent before the interpreter exits, so the tail of
                # the child's stderr may still be in the pipe: wait for the
                # exit (bounded) before collecting.  The traceback the child
                # captured itself is appended after the drained output.
                return self._finish(
                    proc,
                    drain,
                    stdout=msg.get("stdout", ""),
                    return_code=msg.get("rc", 0),
                    timed_out=False,
                    tail=msg.get("stderr", ""),
                )

            if msg["type"] == "call":
                tool_name = msg["tool"]
                kwargs = msg["kwargs"]

                fn = namespace.get(tool_name)
                if fn is None:
                    result_msg = json.dumps(
                        {
                            "type": "result",
                            "error": f"Unknown tool: {tool_name}",
                        }
                    )
                else:
                    try:
                        result = fn(**kwargs)
                        result_msg = json.dumps(
                            {
                                "type": "result",
                                "value": result,
                            }
                        )
                    except Exception as exc:
                        result_msg = json.dumps(
                            {
                                "type": "result",
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )

                proc.stdin.write(result_msg + "\n")
                proc.stdin.flush()

    def _timeout_result(self, proc: subprocess.Popen, drain: _StderrDrain) -> CodeResult:
        """Kill the child and return what was captured, stderr included."""
        proc.kill()
        return self._finish(proc, drain, stdout="", return_code=-1, timed_out=True)

    def _finish(
        self,
        proc: subprocess.Popen,
        drain: _StderrDrain,
        *,
        stdout: str,
        return_code: int | None,
        timed_out: bool,
        tail: str = "",
        wait: float = 2.0,
    ) -> CodeResult:
        """Collect the child's stderr and build the result.

        ``return_code=None`` means *whatever the process exited with*.  *wait*
        bounds the wait for exit, so a descendant holding the pipe open cannot
        hang the call; the stderr captured so far is returned regardless.
        """
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=wait)
        drained = drain.stop()
        text = drained.decode("utf-8", errors="ignore")
        # ``drained`` is already capped; only the child's own tail can push the
        # combination over, and it must not be capped twice (two markers).
        stderr = text + TRUNCATION_MARKER if drain.truncated else truncate(text + tail)
        rc = proc.returncode if return_code is None else return_code
        return CodeResult(
            stdout=truncate(stdout),
            stderr=stderr,
            return_code=rc if rc is not None else -1,
            timed_out=timed_out,
        )
