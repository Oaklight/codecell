"""Base runtime and validator abstractions.

Defines the ABC for code execution runtimes and validators.
Language-specific implementations (Python, Bash) inherit from these
and provide their own validation logic and interpreter invocation.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import IO, Any

from ._types import CodeResult

# Maximum bytes kept for stdout / stderr to prevent memory exhaustion.
MAX_OUTPUT_BYTES = 65_536  # 64 KB


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
    return truncated + "\n... [output truncated]"


# ---------------------------------------------------------------------------
# Process-group lifecycle
# ---------------------------------------------------------------------------
# Every child is spawned as the leader of its own process group (POSIX,
# ``start_new_session=True``) so that a timeout, a caller cancellation, or a
# crash tears down the whole descendant tree instead of just the direct child.
#
# On Windows there are no process groups: only the direct child can be
# signalled, so grandchildren may survive.  That is a weaker guarantee, and it
# is the reason POSIX is the supported platform for hard timeout semantics.

_IS_POSIX = os.name == "posix"

# Seconds a descendant gets to exit on SIGTERM before the group is SIGKILLed.
SIGTERM_GRACE_SECONDS = 1.0

_GROUP_POLL_INTERVAL = 0.02
_STREAM_CHUNK_CHARS = 8192


def _spawn_kwargs() -> dict[str, Any]:
    """Return ``Popen`` keyword arguments that isolate the child in its own group.

    On POSIX this requests a new session, which makes the child a process-group
    leader (``pgid == pid``); that group is what
    :func:`_terminate_process_group` signals.  On Windows nothing can be
    requested here, so the child shares the caller's group.
    """
    if _IS_POSIX:
        return {"start_new_session": True}
    return {}


def _signal_group(proc: subprocess.Popen[Any], sig: int) -> None:
    """Send *sig* to the child's process group, or to the child on Windows."""
    if _IS_POSIX:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, sig)
        return
    with contextlib.suppress(OSError, ValueError):
        proc.send_signal(sig)


def _group_alive(proc: subprocess.Popen[Any]) -> bool:
    """Whether any process of the child's process group still exists."""
    if not _IS_POSIX:
        return proc.poll() is None
    try:
        os.killpg(proc.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(
    proc: subprocess.Popen[Any], grace: float = SIGTERM_GRACE_SECONDS
) -> None:
    """Kill the child's whole process group: SIGTERM, grace period, then SIGKILL.

    Safe to call on an already-exited child: once the group is empty this is a
    no-op.  Any process the child left behind is cleaned up, including
    grandchildren that outlived it.
    """
    if proc.poll() is None or _group_alive(proc):
        _signal_group(proc, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            # Reap the leader first: its zombie would otherwise keep the group
            # non-empty and defeat the early exit below.  Reaping makes the pid
            # reusable in principle, but not while the group still has members:
            # the kernel keeps a pgid allocated as long as a process references
            # it, so signalling ``proc.pid`` below cannot reach a recycled group.
            proc.poll()
            if not _group_alive(proc):
                break
            time.sleep(_GROUP_POLL_INTERVAL)
        else:
            _signal_group(proc, signal.SIGKILL)

    if proc.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=grace)


def _read_stream(stream: IO[str], sink: list[str]) -> None:
    """Drain *stream* into *sink*, keeping a bounded amount of output.

    Draining must never stop early: a child that keeps writing would block as
    soon as the OS pipe buffer fills.  Output beyond ``MAX_OUTPUT_BYTES`` plus
    one chunk is discarded rather than buffered, so a chatty child cannot
    exhaust the caller's memory.  The extra chunk matters: :func:`truncate`
    needs to see that the output was clipped in order to append its marker.
    """
    limit = MAX_OUTPUT_BYTES + _STREAM_CHUNK_CHARS
    kept = 0
    try:
        while True:
            chunk = stream.read(_STREAM_CHUNK_CHARS)
            if not chunk:
                return
            if kept < limit:
                sink.append(chunk)
                kept += len(chunk)
    except (OSError, ValueError):
        return


def _collect_output(proc: subprocess.Popen[Any], timeout: float | None) -> tuple[str, str, bool]:
    """Wait for the child to exit while draining its output pipes.

    Waiting on the process rather than on the pipes is what makes the timeout
    reliable: a descendant that inherits ``stdout``/``stderr`` keeps the pipe
    open after the child is gone, so read-until-EOF would block.

    Args:
        proc: Child process, already spawned with :func:`_spawn_kwargs`.
        timeout: Maximum wall-clock seconds, or ``None`` for no limit.

    Returns:
        ``(stdout, stderr, timed_out)``.
    """
    assert proc.stdout is not None
    assert proc.stderr is not None

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    readers = [
        threading.Thread(target=_read_stream, args=(proc.stdout, stdout_chunks), daemon=True),
        threading.Thread(target=_read_stream, args=(proc.stderr, stderr_chunks), daemon=True),
    ]
    for thread in readers:
        thread.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True

    # Descendants that outlive the child are outside the contract: clear the
    # group so nothing survives ``execute()`` and the reader threads hit EOF.
    _terminate_process_group(proc)
    for thread in readers:
        thread.join(timeout=SIGTERM_GRACE_SECONDS)

    return "".join(stdout_chunks), "".join(stderr_chunks), timed_out


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

    Timeout and cancellation semantics:

    - The child is spawned as the leader of its own process group (POSIX), so a
      timeout, an exception, or a caller cancellation such as
      ``KeyboardInterrupt`` kills the child **and every descendant it spawned**:
      SIGTERM, a short grace period, then SIGKILL for anything still alive.
    - Descendants still running when the code finishes are killed before
      ``execute()`` returns.  Nothing outlives a call.
    - Output is drained while the child runs, so a child that writes more than
      the OS pipe buffer cannot deadlock, and a leftover descendant holding the
      pipes cannot stall the wait.
    - Windows has no process groups: only the direct child can be killed there,
      so its grandchildren may survive.  POSIX is required for the hard
      guarantee.

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

        # The child leads its own process group (POSIX) so the whole descendant
        # tree can be torn down if it times out, crashes, or the caller cancels.
        proc = subprocess.Popen(
            [*self._validator.interpreter, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **_spawn_kwargs(),
        )

        try:
            stdout, stderr, timed_out = _collect_output(proc, timeout)
        except BaseException:
            # Caller cancellation (e.g. KeyboardInterrupt) must not leak the
            # child or any of its descendants.
            _terminate_process_group(proc)
            raise

        return CodeResult(
            stdout=truncate(stdout),
            stderr=truncate(stderr),
            return_code=-1 if timed_out else proc.returncode,
            timed_out=timed_out,
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

    Timeout and cancellation semantics are the same as
    :class:`SubprocessRuntime`: the child leads its own process group (POSIX), and
    a timeout, an exception, or ``KeyboardInterrupt`` kills the child together
    with every descendant it spawned.  On Windows only the direct child can be
    killed, so grandchildren may survive.

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

        # Spawn subprocess running the bootstrap script.  The child leads its own
        # process group (POSIX) so its descendants can be killed with it.
        proc = subprocess.Popen(
            [sys.executable, "-m", "codecell._ipc_bootstrap"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **_spawn_kwargs(),
        )

        try:
            return self._dispatch_loop(proc, code, tool_docs, namespace or {}, timeout)
        except BaseException:
            # Includes KeyboardInterrupt: never leave the child or its
            # descendants running when the caller walks away.
            _terminate_process_group(proc)
            raise
        finally:
            # Reap the child and clear anything it left behind, so no process
            # outlives ``execute()``.
            _terminate_process_group(proc)

    def _dispatch_loop(
        self,
        proc: subprocess.Popen,
        code: str,
        tool_docs: dict[str, str | None],
        namespace: dict[str, Callable[..., Any]],
        timeout: float | None,
    ) -> CodeResult:
        """Main-process dispatch loop: forward tool calls, collect results.

        Uses a background thread for readline so that timeout can be
        enforced even when the subprocess is blocked (infinite loop).
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
                    # Kill the group, not just the direct child: a descendant may
                    # be what is keeping the child (or the pipe) alive.
                    _terminate_process_group(proc)
                    return CodeResult(
                        stdout="",
                        stderr="",
                        return_code=-1,
                        timed_out=True,
                    )
            else:
                remaining = None

            try:
                line = line_queue.get(timeout=remaining)
            except queue.Empty:
                # Timeout
                _terminate_process_group(proc)
                return CodeResult(
                    stdout="",
                    stderr="",
                    return_code=-1,
                    timed_out=True,
                )

            if line is None:
                # Subprocess died unexpectedly
                stderr = proc.stderr.read()
                return CodeResult(
                    stdout="",
                    stderr=truncate(stderr),
                    return_code=proc.wait(),
                    timed_out=False,
                )

            msg = json.loads(line)

            if msg["type"] == "done":
                return CodeResult(
                    stdout=truncate(msg.get("stdout", "")),
                    stderr=truncate(msg.get("stderr", "")),
                    return_code=msg.get("rc", 0),
                    timed_out=False,
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
