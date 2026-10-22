"""Base runtime and validator abstractions.

Defines the ABC for code execution runtimes and validators.
Language-specific implementations (Python, Bash) inherit from these
and provide their own validation logic and interpreter invocation.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import select
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
# Child-process lifecycle
# ---------------------------------------------------------------------------
# Every child is spawned as the leader of its own process group (POSIX,
# ``start_new_session=True``) so that a timeout, a caller cancellation, or a
# crash tears down the whole descendant tree instead of just the direct child.
#
# On Windows there are no process groups: only the direct child can be
# signalled, so grandchildren may survive.  That is a weaker guarantee, and it
# is the reason POSIX is the supported platform for hard timeout semantics.

_IS_POSIX = os.name == "posix"

# Seconds a descendant gets to exit on SIGTERM before the group is force-killed.
SIGTERM_GRACE_SECONDS = 1.0

# Seconds a drain thread gets to reach EOF before its pipe is closed under it.
DRAIN_JOIN_SECONDS = 1.0

_GROUP_POLL_INTERVAL = 0.02
_STREAM_CHUNK_BYTES = 8192

# Dispatch-loop outcomes, see ``IpcSubprocessRuntime._dispatch_loop``.
OUTCOME_DONE = "done"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_CRASH = "crash"

# How often the dispatch loop checks whether the child is still alive, and how
# long it keeps the door open for frames already read when the child exits.
_CHILD_POLL_INTERVAL = 0.1
_SELECT_INTERVAL = 0.1
_FRAME_FLUSH_SECONDS = 0.2


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


def _pin_pid(pid: int) -> int | None:
    """Pin *pid* so its number cannot be recycled while we may still signal it.

    An open pidfd holds a reference to the kernel's ``struct pid``, so the pid --
    and therefore the pgid -- stays allocated until the descriptor is closed.
    Without it, a group teardown that runs after the leader was reaped could in
    principle signal an unrelated group that recycled the id.

    Returns:
        The pidfd, or ``None`` where pidfds are unavailable (non-Linux, old
        kernels): callers then accept the (very small) recycling window.
    """
    opener = getattr(os, "pidfd_open", None)
    if opener is None:
        return None
    try:
        return opener(pid)
    except OSError:
        return None


def _close_fd(fd: int | None) -> None:
    """Close *fd* if it was opened."""
    if fd is None:
        return
    with contextlib.suppress(OSError):
        os.close(fd)


def _signal_group(proc: subprocess.Popen[Any], sig: int) -> None:
    """Send *sig* to the child's process group, or to the child on Windows."""
    if _IS_POSIX:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, sig)
        return
    with contextlib.suppress(OSError, ValueError):
        proc.send_signal(sig)


def _kill_group(proc: subprocess.Popen[Any]) -> None:
    """Forcefully kill the child's process group (the child alone on Windows)."""
    if _IS_POSIX:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        return
    with contextlib.suppress(OSError, ValueError):
        proc.kill()


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

    Safe to call on an already-exited child and safe to call twice: once the
    group is empty this is a no-op.  Anything the child left behind is cleaned
    up, including grandchildren that outlived it.  The child itself is reaped if
    it is still around, so callers never leak a zombie.
    """
    if proc.poll() is None or _group_alive(proc):
        _signal_group(proc, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            # Reap the leader first: its zombie would otherwise keep the group
            # non-empty and defeat the early exit below.
            proc.poll()
            if not _group_alive(proc):
                break
            time.sleep(_GROUP_POLL_INTERVAL)
        else:
            _kill_group(proc)

    if proc.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=grace)


class _StreamDrain:
    """Drain a child's output stream into a bounded buffer on a background thread.

    Draining runs for the child's whole lifetime, so a child that writes more
    than the OS pipe buffer can never block in ``write()``.  Bytes are read from
    the descriptor with ``os.read`` and decoded once, with ``errors="replace"``:
    a stray invalid byte must not kill the drain, which would deadlock a child
    that keeps writing into a full pipe.

    On POSIX the loop selects on the descriptor with a short timeout, so
    :meth:`stop` can interrupt it without closing the pipe under a blocked read.
    Closing a ``BufferedReader`` while another thread is blocked inside it waits
    for that read to return, which is exactly the hang this class must not have.
    """

    def __init__(
        self,
        stream: IO[bytes],
        limit: int = MAX_OUTPUT_BYTES + _STREAM_CHUNK_BYTES,
    ) -> None:
        self._stream = stream
        self._limit = limit
        self._chunks: list[bytes] = []
        self._kept = 0
        self._finished = False
        self._stop = threading.Event()
        self._fd = stream.fileno() if _IS_POSIX else None
        self._thread = threading.Thread(target=self._read_loop, daemon=True, name="codecell-drain")

    @property
    def finished(self) -> bool:
        """Whether the stream reached EOF on its own."""
        return self._finished

    def start(self) -> _StreamDrain:
        """Start draining in the background."""
        self._thread.start()
        return self

    def stop(self, timeout: float = DRAIN_JOIN_SECONDS) -> None:
        """Stop draining and release the pipe."""
        # Let the drain reach EOF on its own first: after the group teardown the
        # pipe closes immediately, and cutting the read short here would report
        # a clean run as partial output.
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            self._stop.set()
            self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            # Last resort (Windows has no selectable pipes): the reader is stuck
            # in a blocking read, and only closing the handle unblocks it.
            with contextlib.suppress(OSError, ValueError):
                self._stream.close()
            self._thread.join(timeout=timeout)
        with contextlib.suppress(OSError, ValueError):
            self._stream.close()

    def text(self) -> str:
        """Return everything captured so far, decoded leniently."""
        return b"".join(self._chunks).decode("utf-8", errors="replace")

    def _append(self, chunk: bytes) -> None:
        if self._kept < self._limit:
            self._chunks.append(chunk)
            self._kept += len(chunk)

    def _read_loop(self) -> None:
        if self._fd is None:
            self._read_blocking()
            return
        fd = self._fd
        while not self._stop.is_set():
            try:
                readable, _, _ = select.select([fd], [], [], _SELECT_INTERVAL)
            except (OSError, ValueError):
                return
            if not readable:
                continue
            try:
                chunk = os.read(fd, _STREAM_CHUNK_BYTES)
            except OSError:
                return
            if not chunk:
                self._finished = True
                return
            self._append(chunk)

    def _read_blocking(self) -> None:
        """Reader for platforms whose pipes cannot be selected on (Windows)."""
        read_chunk = getattr(self._stream, "read1", self._stream.read)
        try:
            while not self._stop.is_set():
                chunk = read_chunk(_STREAM_CHUNK_BYTES)
                if not chunk:
                    self._finished = True
                    return
                self._append(chunk)
        except (OSError, ValueError):
            return


class _LineFeed:
    """Read newline-delimited protocol frames from a child's stdout into a queue."""

    def __init__(self, stream: IO[bytes]) -> None:
        self._stream = stream
        self._fd = stream.fileno() if _IS_POSIX else None
        self._stop = threading.Event()
        self.frames: queue.Queue[bytes | None] = queue.Queue()
        self._thread = threading.Thread(
            target=self._read_loop, daemon=True, name="codecell-frames"
        )

    def start(self) -> _LineFeed:
        """Start reading frames in the background."""
        self._thread.start()
        return self

    def stop(self, timeout: float = DRAIN_JOIN_SECONDS) -> None:
        """Stop the reader and release the pipe."""
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            self._stop.set()
            self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            with contextlib.suppress(OSError, ValueError):
                self._stream.close()
            self._thread.join(timeout=timeout)
        with contextlib.suppress(OSError, ValueError):
            self._stream.close()

    def _read_loop(self) -> None:
        try:
            if self._fd is None:
                self._read_blocking()
            else:
                self._read_selected(self._fd)
        except (OSError, ValueError):
            pass
        finally:
            # Always wake the consumer, including when the pipe was closed
            # under us: the dispatch loop must never block on a dead pipe.
            self.frames.put(None)

    def _read_selected(self, fd: int) -> None:
        pending = b""
        while not self._stop.is_set():
            readable, _, _ = select.select([fd], [], [], _SELECT_INTERVAL)
            if not readable:
                continue
            chunk = os.read(fd, _STREAM_CHUNK_BYTES)
            if not chunk:
                break
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                self.frames.put(line)
        if pending.strip():
            self.frames.put(pending)

    def _read_blocking(self) -> None:
        """Reader for platforms whose pipes cannot be selected on (Windows)."""
        for frame in self._stream:
            self.frames.put(frame)
            if self._stop.is_set():
                return


def _collect_output(proc: subprocess.Popen[Any], timeout: float | None) -> tuple[str, str, bool]:
    """Wait for the child to exit while draining its output streams.

    Waiting on the process rather than on the pipes is what makes the timeout
    reliable: a descendant that inherits ``stdout``/``stderr`` keeps the pipe
    open after the child is gone, so read-until-EOF would block.

    Args:
        proc: Child process, already spawned with :func:`_spawn_kwargs`.
        timeout: Maximum wall-clock seconds, or ``None`` for no limit.

    Returns:
        ``(stdout, stderr, timed_out)``.  If a descendant held a pipe open, the
        capture is partial and ``stderr`` says so instead of pretending the
        output was complete.
    """
    assert proc.stdout is not None
    assert proc.stderr is not None

    pidfd = _pin_pid(proc.pid)
    stdout_drain = _StreamDrain(proc.stdout).start()
    stderr_drain = _StreamDrain(proc.stderr).start()
    drains = (stdout_drain, stderr_drain)

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        # Descendants that outlive the child are outside the contract: clear the
        # group so nothing survives ``execute()`` and the pipes hit EOF.
        _terminate_process_group(proc)
        for drain in drains:
            drain.stop()
        _close_fd(pidfd)

    stdout, stderr = stdout_drain.text(), stderr_drain.text()
    if not all(drain.finished for drain in drains):
        stderr += "\n... [output drain cut off: a descendant kept the pipe open]"
    return stdout, stderr, timed_out


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
        proc = subprocess.Popen[bytes](
            [*self._validator.interpreter, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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
        proc = subprocess.Popen[bytes](
            [sys.executable, "-m", "codecell._ipc_bootstrap"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **_spawn_kwargs(),
        )
        assert proc.stdin is not None
        assert proc.stdout is not None
        assert proc.stderr is not None

        pidfd = _pin_pid(proc.pid)
        stderr_drain = _StreamDrain(proc.stderr).start()
        frames = _LineFeed(proc.stdout).start()

        outcome = OUTCOME_CRASH
        frame: dict[str, Any] = {}
        drained_stderr = ""
        drain_complete = False
        try:
            outcome, frame = self._dispatch_loop(
                proc, frames.frames, code, tool_docs, namespace or {}, timeout
            )
        finally:
            # Single owner of teardown.  Every exit path -- done, timeout, crash,
            # KeyboardInterrupt -- kills the group, unblocks both readers, and
            # releases the pipes, so no thread or descriptor leaks into the next
            # call.  Killing first is what lets the drains reach EOF.
            _terminate_process_group(proc)
            stderr_drain.stop()
            frames.stop()
            with contextlib.suppress(OSError, ValueError):
                proc.stdin.close()
            _close_fd(pidfd)
            drained_stderr = stderr_drain.text()
            drain_complete = stderr_drain.finished

        if not drain_complete:
            drained_stderr += "\n... [stderr drain cut off: a descendant kept the pipe open]"

        if outcome == OUTCOME_DONE:
            return CodeResult(
                stdout=truncate(frame.get("stdout", "")),
                stderr=truncate(drained_stderr + frame.get("stderr", "")),
                return_code=frame.get("rc", 0),
                timed_out=False,
            )

        if outcome == OUTCOME_TIMEOUT:
            return CodeResult(
                stdout="",
                stderr=truncate(drained_stderr),
                return_code=-1,
                timed_out=True,
            )

        # The child's stdout closed without a ``done`` frame: it died, or the
        # pipe was cut.  The group is already down, so this cannot block.
        return_code = proc.returncode if proc.returncode is not None else -1
        return CodeResult(
            stdout="",
            stderr=truncate(drained_stderr),
            return_code=return_code,
            timed_out=False,
        )

    def _dispatch_loop(
        self,
        proc: subprocess.Popen[Any],
        frames: queue.Queue[bytes | None],
        code: str,
        tool_docs: dict[str, str | None],
        namespace: dict[str, Callable[..., Any]],
        timeout: float | None,
    ) -> tuple[str, dict[str, Any]]:
        """Forward tool calls and collect the child's completion frame.

        The child's stdout is read on its own thread (:class:`_LineFeed`), so the
        timeout is enforced even when the child is stuck in an infinite loop.

        Returns:
            ``(outcome, frame)`` with *outcome* one of :data:`OUTCOME_DONE`,
            :data:`OUTCOME_TIMEOUT` or :data:`OUTCOME_CRASH`.  Tearing the child
            down belongs to the caller: this method never kills or waits.
        """
        assert proc.stdin is not None

        # Send init message with tool docs for help() support
        init_msg = json.dumps({"type": "init", "tools": tool_docs, "code": code})
        try:
            proc.stdin.write((init_msg + "\n").encode("utf-8"))
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            return OUTCOME_CRASH, {}

        deadline = time.monotonic() + timeout if timeout else None
        # Set once the child is gone: already-read frames still get a moment to
        # arrive before the cell counts as crashed without a ``done`` frame.
        exit_seen_at: float | None = None

        while True:
            now = time.monotonic()
            if exit_seen_at is not None and now >= exit_seen_at + _FRAME_FLUSH_SECONDS:
                return OUTCOME_CRASH, {}
            if deadline is not None and now >= deadline:
                return OUTCOME_TIMEOUT, {}

            wait = _CHILD_POLL_INTERVAL
            if deadline is not None:
                wait = min(wait, deadline - now)
            if exit_seen_at is not None:
                wait = min(wait, exit_seen_at + _FRAME_FLUSH_SECONDS - now)

            try:
                raw = frames.get(timeout=max(wait, 0.0))
            except queue.Empty:
                # A descendant can keep the protocol pipe open after the child is
                # gone, so EOF alone cannot be trusted to detect the exit.
                if exit_seen_at is None and proc.poll() is not None:
                    exit_seen_at = time.monotonic()
                continue

            if raw is None:
                # The child's stdout closed: it exited, crashed, or was cut off.
                return OUTCOME_CRASH, {}

            try:
                msg = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                # Not one of our frames.  Executed code can write to the protocol
                # pipe; skip the garbage instead of failing the cell.
                continue

            if msg.get("type") == "done":
                return OUTCOME_DONE, msg

            if msg.get("type") == "call":
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

                try:
                    proc.stdin.write((result_msg + "\n").encode("utf-8"))
                    proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    return OUTCOME_CRASH, {}
