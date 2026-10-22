"""Base runtime and validator abstractions.

Defines the ABC for code execution runtimes and validators.
Language-specific implementations (Python, Bash) inherit from these
and provide their own validation logic and interpreter invocation.
"""

from __future__ import annotations

import contextlib
import os
import selectors
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

# Appended when captured output is clipped, so a caller can tell truncation
# from a program that genuinely ended there.
TRUNCATION_MARKER = "\n... [output truncated]"
# Appended when the reader could not hand over everything before its
# deadline.  Dropping bytes silently is worse than saying so: a partial
# traceback with no marker reads like a complete one.
_STDERR_INCOMPLETE_MARKER = "\n... [stderr may be incomplete: the reader was still draining]"


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


_STDERR_CHUNK_BYTES = 8192
# How often a blocked reader re-checks its stop flag.
_STDERR_POLL_SECONDS = 0.05
# Only POSIX pipes are pollable; on Windows ``selectors`` handles sockets.
_STDERR_POLLABLE = os.name == "posix"
# On stop the reader takes a bounded number of extra reads, so bytes already in
# the pipe are not lost without letting a descendant that keeps writing hold
# the thread open.  It is a count, not "until nothing is ready", because that
# condition never becomes true while the descendant runs.
_STDERR_CATCHUP_READS = 64
# One teardown budget, shared by the reap and the drain join, so a child that
# will not die costs this once instead of once per wait site.
_TEARDOWN_BUDGET = 5.0
_STDERR_HEAD_DROPPED_MARKER = "\n... [stderr head dropped]\n"


def _remaining(deadline: float) -> float:
    """Seconds left before *deadline*, never negative."""
    return max(0.0, deadline - time.monotonic())


def _clip(text: str, budget: int, marker: str, *, force: bool = False) -> str:
    """Fit *text* into *budget* UTF-8 bytes, with *marker* inside the budget.

    *force* applies the marker even when the text already fits: the buffer is
    capped at exactly ``MAX_OUTPUT_BYTES``, so a truncated stream can measure
    as "within budget" while still having dropped everything past the cap.
    """
    encoded = text.encode("utf-8", errors="replace")
    if not force and len(encoded) <= budget:
        return text
    keep = max(budget - len(marker.encode("utf-8")), 0)
    return encoded[:keep].decode("utf-8", errors="ignore") + marker


class _StderrDrain:
    """Read the child's stderr from its descriptor into a bounded buffer.

    Reading has to start at spawn, not after exit: once the OS pipe buffer
    fills, a child blocks inside ``write()`` and stops sending protocol
    messages, so a parent waiting for the next message waits forever.

    ``os.read`` on the raw descriptor, not ``read``/``read1`` on the
    ``TextIOWrapper``: the wrapper holds its buffer lock across a blocking
    read, so closing the stream from another thread waits on that lock instead
    of interrupting the read - which is how a drain becomes a hang.

    On POSIX the descriptor is polled, so the reader notices :meth:`stop`
    between reads whatever the writer is doing, including a descendant that
    never stops writing.  Windows cannot poll a pipe, so there the read blocks
    and the thread is left to die as a daemon: the guarantees this class
    documents are POSIX guarantees.
    """

    def __init__(self, stream: IO[str], limit: int = MAX_OUTPUT_BYTES) -> None:
        self._stream = stream  # kept alive: closing it would close the descriptor
        self._fd = stream.fileno()
        self._limit = limit
        self._buffer = bytearray()
        self._truncated = False
        self._eof = False
        self._error: str | None = None
        self._stop = threading.Event()
        self._stopped = False
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
        # Everything is inside the ``try``: a failure in selector setup, in the
        # poll, or in the read has to be recorded, because the alternative is a
        # dead thread that looks exactly like a clean EOF.
        try:
            if _STDERR_POLLABLE:
                self._read_pollable()
            else:
                self._read_blocking()
        except BaseException as exc:  # noqa: BLE001 - recorded, never swallowed
            self._error = f"{type(exc).__name__}: {exc}"

    def _read_pollable(self) -> None:
        """Poll the descriptor, so ``stop`` is honoured between reads.

        ``selectors`` rather than ``select``: the parent's read end can land
        above ``FD_SETSIZE`` (1024) in a process holding many descriptors, and
        ``select`` raises ``ValueError`` there - killing the reader while the
        child sits blocked on a full pipe.
        """
        with selectors.DefaultSelector() as selector:
            selector.register(self._fd, selectors.EVENT_READ)
            while True:
                if self._stop.is_set():
                    self._catch_up(selector)
                    return
                if not selector.select(_STDERR_POLL_SECONDS):
                    continue
                if not self._consume():
                    return

    def _catch_up(self, selector: selectors.BaseSelector) -> None:
        """Read what is already pending, then leave whatever is still coming.

        A descendant that keeps writing makes the descriptor permanently
        readable, so "read until nothing is ready" would not terminate.
        """
        for _ in range(_STDERR_CATCHUP_READS):
            if not selector.select(0):
                return
            if not self._consume():
                return

    def _read_blocking(self) -> None:
        """Non-POSIX fallback: a pipe cannot be polled, so the read blocks.

        Nothing here can interrupt it.  A descendant holding the write end keeps
        this thread blocked until that descendant exits, so ``stop`` reports
        that the reader did not finish and the result says the output may be
        short.  This path cannot be exercised on the Linux CI runner.
        """
        while self._consume():
            if self._stop.is_set():
                return

    def _consume(self) -> bool:
        """Read one chunk into the buffer.  ``False`` at EOF or on a dead fd."""
        try:
            chunk = os.read(self._fd, _STDERR_CHUNK_BYTES)
        except OSError:
            return False
        if not chunk:
            self._eof = True
            return False
        with self._lock:
            room = self._limit - len(self._buffer)
            if room > 0:
                self._buffer.extend(chunk[:room])
            if len(chunk) > max(room, 0):
                self._truncated = True
        return True

    def stop(self, timeout: float = 2.0) -> None:
        """Ask the reader to finish and wait for it, taking at most *timeout*.

        The join comes before the close on purpose: closing the stream while
        another thread is inside ``os.read`` on it does not interrupt the read,
        it invalidates the descriptor.
        """
        if self._stopped:
            return
        self._stop.set()
        self._thread.join(timeout)
        if not self._thread.is_alive():
            with contextlib.suppress(OSError, ValueError):
                self._stream.close()
        self._stopped = True

    def captured(self) -> bytes:
        """The captured bytes, at most ``limit``."""
        with self._lock:
            return bytes(self._buffer)

    def incomplete_reason(self) -> str | None:
        """Why the captured bytes may be short, or ``None`` when they are not.

        Reported instead of inferred from "the thread is not running": a dead
        worker and a clean EOF look identical from the outside, and treating
        them the same is how output disappears without a trace.
        """
        if self._error is not None:
            return f"the stderr reader failed ({self._error})"
        if not self._eof:
            return "the stderr reader was still draining"
        if self._thread.is_alive():
            return "the stderr reader did not stop"
        return None


def _compose_stderr(
    head: bytes, tail: str, truncated: bool, *, incomplete: str | None = None
) -> str:
    """Compose stderr from the drained bytes and the child's own traceback.

    *tail* is what the child sent in its ``done`` frame - the traceback of an
    exception it caught, which is the part a reader needs most.  Everything
    stays inside ``MAX_OUTPUT_BYTES``: the markers that report loss are part of
    the budget, so the cap is a cap rather than a suggestion.
    """
    suffix = "" if incomplete is None else f"\n... [stderr may be incomplete: {incomplete}]"
    body = _compose_body(head, tail, truncated, MAX_OUTPUT_BYTES - len(suffix.encode("utf-8")))
    return body + suffix


def _compose_body(head: bytes, tail: str, truncated: bool, budget: int) -> str:
    """Fit drained stderr and the child's traceback into *budget* bytes."""
    text = head.decode("utf-8", errors="ignore")
    head_clipped = truncated or len(head) > budget

    if not tail:
        return _clip(text, budget, TRUNCATION_MARKER, force=head_clipped)

    sep = "" if not text or text.endswith("\n") else "\n"
    tail_bytes = len(tail.encode("utf-8", errors="replace"))
    head_room = budget - tail_bytes - len(sep.encode("utf-8"))

    if head_room <= len(TRUNCATION_MARKER.encode("utf-8")):
        # The traceback alone fills the budget.  Dropping the head is fine; not
        # saying so is not, because a traceback with no program output above it
        # reads like a program that printed nothing.
        spare = budget - len(_STDERR_HEAD_DROPPED_MARKER.encode("utf-8"))
        return _STDERR_HEAD_DROPPED_MARKER + _clip(tail, spare, TRUNCATION_MARKER)

    head_part = text
    if head_clipped or len(text.encode("utf-8")) > head_room:
        head_part = _clip(text, head_room, TRUNCATION_MARKER, force=head_clipped)
    return head_part + sep + tail


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
    in a fresh interpreter process.  That boundary isolates crashes,
    interpreter state, and caller memory; it does not isolate resource
    use or adversaries.  Child memory, CPU, and disk use are not
    limited, output is buffered in full before truncation, and
    ``timeout=None`` can block indefinitely.  See ``THREAT_MODEL.md``.

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

    Contract (see ``RUNTIME_CONTRACT.md``): this runtime is transport
    only for **tool semantics** — it never filters, authorizes, caches,
    or logs a tool call; the caller owns that.  It does own the
    **execution lifecycle**: wire framing and ordering, blocking until
    a call is answered, stdout capture, output truncation, and killing
    the child.  Tool arguments are keyword-only in this version, and a
    non-JSON tool result is reported as a failure (#7).

    Benefits over in-process ``exec()``:
        - Crash isolation: a segfault or an uncaught exception cannot take
          down the caller
        - A wall-clock bound on the child when ``timeout`` is passed; with
          ``timeout=None`` an infinite loop blocks the dispatch loop
          indefinitely, and an OOM can still reach the host OOM killer
        - No cloudpickle needed for tools
        - Tools retain access to main-process state (connections, env)

    The wire protocol (``init`` / ``call`` / ``result`` / ``done``), its
    error semantics, and the backend compliance checklist are specified in
    ``RUNTIME_CONTRACT.md``, which is the single source of truth.  The
    bootstrap module docstring in ``codecell/_ipc_bootstrap.py`` repeats a
    summary and is not authoritative.

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

        proc = subprocess.Popen(
            [sys.executable, "-m", "codecell._ipc_bootstrap"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stderr is not None

        # Start draining before the first protocol byte moves.  Reading stderr
        # only after exit is the deadlock: a child that fills the pipe buffer
        # blocks in write() and stops sending protocol messages.
        drain = _StderrDrain(proc.stderr)
        drain.start()

        try:
            return self._dispatch_loop(proc, code, tool_docs, namespace or {}, timeout, drain)
        except BaseException:
            # Safety net only: failures inside the dispatch loop come back as a
            # CodeResult.  This covers a failure in teardown itself or an
            # interrupt in the parent, and must not wait a second time.
            proc.kill()
            drain.stop(_TEARDOWN_BUDGET)
            raise

    def _dispatch_loop(
        self,
        proc: subprocess.Popen,
        code: str,
        tool_docs: dict[str, str | None],
        namespace: dict[str, Callable[..., Any]],
        timeout: float | None,
        drain: _StderrDrain,
    ) -> CodeResult:
        """Dispatch, turning any escaping failure into a result.

        A child that dies mid-call makes ``proc.stdin.write`` raise
        ``BrokenPipeError``; the caller should get a ``CodeResult`` carrying the
        stderr captured so far, not a raw exception with the buffer thrown away.
        ``Exception`` rather than ``BaseException``: an interrupt aimed at the
        parent should stay an interrupt.
        """
        try:
            return self._dispatch(proc, code, tool_docs, namespace, timeout, drain)
        except Exception as exc:  # noqa: BLE001 - reported as a result
            return self._finish(
                proc,
                drain,
                stdout="",
                return_code=None,
                timed_out=False,
                tail=(
                    f"codecell: the call ended before a result frame: {type(exc).__name__}: {exc}"
                ),
            )

    def _dispatch(
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

        Every exit path goes through :meth:`_finish`, so the child's stderr is
        returned on success, crash and timeout alike.
        """
        import json
        import queue

        assert proc.stdin is not None
        assert proc.stdout is not None

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

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                # User code or an escaped descendant wrote to the channel.
                # Ignore garbage rather than failing the whole cell.
                continue
            if not isinstance(msg, dict):
                continue

            msg_type = msg.get("type")

            if msg_type == "done":
                stdout = msg.get("stdout", "")
                stderr = msg.get("stderr", "")
                rc = msg.get("rc", 0)
                # ``done`` is sent before the interpreter exits, so the tail of
                # the child's stderr may still be in the pipe: wait for the
                # exit (bounded) before collecting, then append the traceback
                # the child captured itself.
                return self._finish(
                    proc,
                    drain,
                    stdout=stdout if isinstance(stdout, str) else str(stdout),
                    return_code=rc if isinstance(rc, int) else 1,
                    timed_out=False,
                    tail=stderr if isinstance(stderr, str) else str(stderr),
                )

            if msg_type == "call":
                tool_name = msg.get("tool")
                kwargs = msg.get("kwargs", {})
                if not isinstance(tool_name, str) or not isinstance(kwargs, dict):
                    continue

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

    @staticmethod
    def _reap(proc: subprocess.Popen, budget: float) -> None:
        """Wait for the child within *budget*, then kill and reap it."""
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=budget)
        if proc.poll() is None:
            proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=budget)

    def _finish(
        self,
        proc: subprocess.Popen,
        drain: _StderrDrain,
        *,
        stdout: str,
        return_code: int | None,
        timed_out: bool,
        tail: str = "",
    ) -> CodeResult:
        """Collect the child's stderr and build the result.

        ``return_code=None`` means *whatever the process exited with*; otherwise
        the code came from the ``done`` frame.  The child is reaped within
        ``_TEARDOWN_BUDGET`` shared with the drain join - so a child that sent
        then lingers costs that once rather than once per wait site.  The drain
        is joined before its buffer is read: the interpreter flushes stderr on
        the way out, *after* the frame, and those bytes are part of the output.
        """
        deadline = time.monotonic() + _TEARDOWN_BUDGET
        self._reap(proc, _remaining(deadline))
        drain.stop(_remaining(deadline))
        rc = proc.returncode if return_code is None else return_code
        return CodeResult(
            stdout=truncate(stdout),
            stderr=_compose_stderr(
                drain.captured(),
                tail,
                drain.truncated,
                incomplete=drain.incomplete_reason(),
            ),
            return_code=rc if rc is not None else -1,
            timed_out=timed_out,
        )
