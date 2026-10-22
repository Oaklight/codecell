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
from typing import Any

from ._types import CodeResult
from ._wire import (
    MAX_TOOL_VALUE_BYTES,
    PROTOCOL_VERSION,
    CodecError,
    dumps,
    loads,
)

# Maximum bytes kept for stdout / stderr to prevent memory exhaustion.
MAX_OUTPUT_BYTES = 65_536  # 64 KB

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


_IS_POSIX = os.name == "posix"
_GRACE_SECONDS = 1.0
_ATEXIT_SECONDS = 2.0
_REAP_SECONDS = 5.0


def _spawn_kwargs() -> dict[str, Any]:
    """Return Popen kwargs that put the child in its own process group."""
    return {"start_new_session": True} if _IS_POSIX else {}


def _bootstrap_command() -> list[str]:
    """Run the IPC bootstrap from the parent's own package tree.

    ``python -m codecell._ipc_bootstrap`` resolves ``codecell`` from the
    child's cwd and ``PYTHONPATH``, which can point at a different
    checkout than the one the parent imported.  Pinning the parent's
    package root keeps both sides on the same protocol and codec.
    """
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = (
        "import sys; "
        f"sys.path.insert(0, {package_root!r}); "
        "from codecell._ipc_bootstrap import main; main()"
    )
    return [sys.executable, "-c", code]


def _pin_pidfd(pid: int) -> int | None:
    """Pin *pid* against reuse while the group is being torn down."""
    opener = getattr(os, "pidfd_open", None)
    if not _IS_POSIX or opener is None:
        return None
    try:
        return opener(pid)
    except OSError:
        return None


def _close_fd(fd: int | None) -> None:
    if fd is None:
        return
    with contextlib.suppress(OSError):
        os.close(fd)


def _group_alive(proc: subprocess.Popen[Any]) -> bool:
    """Return whether any process in the child's group still exists."""
    if not _IS_POSIX:
        return proc.poll() is None
    try:
        os.killpg(proc.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_group(proc: subprocess.Popen[Any], sig: int) -> None:
    """Signal the child's process group on POSIX, or the child elsewhere."""
    if _IS_POSIX:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, sig)
    else:
        with contextlib.suppress(OSError):
            proc.send_signal(sig)


def _terminate_group(proc: subprocess.Popen[Any], grace: float = _GRACE_SECONDS) -> None:
    """SIGTERM the child's group, wait, then SIGKILL survivors and reap.

    On Windows only the direct child is signalled; grandchildren may
    survive.  The leader's pid is pinned by the caller with
    :func:`_pin_pidfd` so the group id cannot be recycled during teardown.

    Liveness is decided on the *group*, not the leader: both runtimes reap
    the leader before teardown on normal and crash exits, while detached
    descendants keep the group alive.  Teardown also completes even when a
    second ``KeyboardInterrupt`` arrives during the grace period — SIGKILL
    still goes out, and the interrupt is re-raised afterwards so it is not
    swallowed.
    """
    kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    interrupted: BaseException | None = None
    try:
        if proc.poll() is None or _group_alive(proc):
            _signal_group(proc, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if proc.poll() is not None and not _group_alive(proc):
                break
            time.sleep(0.02)
    except BaseException as exc:  # noqa: BLE001 - finish teardown, then re-raise
        interrupted = exc
    finally:
        with contextlib.suppress(BaseException):
            if proc.poll() is None or _group_alive(proc):
                _signal_group(proc, kill_signal)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=_REAP_SECONDS)
    if interrupted is not None:
        raise interrupted


def _as_text(value: str | bytes | None) -> str:
    """Decode a communicate() payload, which is bytes on timeout."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


class _StderrDrain:
    """Continuously drain a child's stderr into a bounded buffer.

    The pipe must be read even when the caller does not want the bytes:
    once the OS pipe buffer fills, the child blocks in ``write``.  Only
    the first :data:`MAX_OUTPUT_BYTES` are retained; the remainder is
    drained and discarded.
    """

    def __init__(self, stream: Any) -> None:
        self._fd = stream.fileno()
        self._buffer = bytearray()
        self._total = 0
        self._lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._run, name="codecell-stderr-drain", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)

    def snapshot(self) -> tuple[str, bool]:
        """Return the retained text and whether later bytes were dropped."""
        with self._lock:
            raw = bytes(self._buffer)
            total = self._total
        return raw.decode("utf-8", errors="replace"), total > len(raw)

    def _run(self) -> None:
        while True:
            try:
                chunk = os.read(self._fd, 65_536)
            except OSError:
                return
            if not chunk:
                return
            with self._lock:
                self._total += len(chunk)
                room = MAX_OUTPUT_BYTES - len(self._buffer)
                if room > 0:
                    self._buffer.extend(chunk[:room])


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
            namespace: Mapping of name -> callable.  Not supported here:
                ``SubprocessRuntime`` has no call channel.  Use
                :class:`IpcSubprocessRuntime` for tool calls.
            timeout: Maximum wall-clock seconds before kill.  ``None`` is
                unbounded; ``0`` expires immediately.

        Returns:
            A :class:`CodeResult` with captured output.

        Raises:
            ValueError: If validation rejects the code.
            SyntaxError: If the code cannot be parsed.
            NotImplementedError: If ``namespace`` is passed; tool calls
                require :class:`IpcSubprocessRuntime`.
        """
        self._validator.validate(code)

        if namespace:
            raise NotImplementedError(
                "SubprocessRuntime does not execute tool calls; use "
                "IpcSubprocessRuntime for namespace injection."
            )

        proc = subprocess.Popen(
            [*self._validator.interpreter, code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **_spawn_kwargs(),
        )
        pidfd = _pin_pidfd(proc.pid)
        timed_out = False
        try:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_group(proc)
                # communicate() keeps its buffer across calls: the retry
                # returns everything already read, so it supersedes (not
                # extends) the TimeoutExpired payload.
                try:
                    stdout, stderr = proc.communicate(timeout=_REAP_SECONDS)
                except subprocess.TimeoutExpired as drain_exc:
                    stdout, stderr = drain_exc.stdout, drain_exc.stderr
                return CodeResult(
                    stdout=truncate(_as_text(stdout)),
                    stderr=truncate(_as_text(stderr)),
                    return_code=-1,
                    timed_out=True,
                )
            return CodeResult(
                stdout=truncate(_as_text(stdout)),
                stderr=truncate(_as_text(stderr)),
                return_code=proc.returncode,
                timed_out=False,
            )
        finally:
            try:
                if not timed_out:
                    # Kill descendants that outlived the leader.
                    _terminate_group(proc)
            finally:
                _close_fd(pidfd)


class IpcSubprocessRuntime(BaseRuntime):
    """Execute code in a subprocess with namespace callables via IPC.

    Unlike :class:`SubprocessRuntime`, which rejects namespace injection
    because it has no call channel, this runtime establishes a
    bidirectional JSON pipe so subprocess code can **actually call** the
    namespace functions.
    Tool execution always happens in the main process — only the
    LLM-generated code runs in the subprocess.

    Contract (see ``RUNTIME_CONTRACT.md``): this runtime is transport
    only for **tool semantics** — it never filters, authorizes, caches,
    or logs a tool call; the caller owns that.  It does own the
    **execution lifecycle**: wire framing and ordering, blocking until
    a call is answered, stdout capture, output truncation, and killing
    the child.  Tool arguments may be positional or keyword; arguments
    and results use the codec in :mod:`codecell._wire`.

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
                Arguments and results use the codec in :mod:`codecell._wire`;
                an unencodable value raises :class:`codecell.CodecError` at
                the call site.
            timeout: Maximum wall-clock seconds before kill.  ``None`` is
                unbounded; ``0`` expires immediately.

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

        # Build tool_docs: {name: docstring} for the IPC stubs
        tool_docs: dict[str, str | None] = {}
        if namespace:
            for name, fn in namespace.items():
                tool_docs[name] = getattr(fn, "__doc__", None)

        # Spawn subprocess running the bootstrap script
        proc = subprocess.Popen(
            _bootstrap_command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **_spawn_kwargs(),
        )
        pidfd = _pin_pidfd(proc.pid)
        assert proc.stderr is not None
        drain = _StderrDrain(proc.stderr)
        drain.start()

        result: CodeResult | None = None
        try:
            result = self._dispatch_loop(proc, code, tool_docs, namespace or {}, timeout)
        finally:
            # Give the leader a bounded chance to finish its own shutdown
            # (atexit handlers), then tear down anything left in the group.
            # The nested finally keeps teardown running even when the
            # exception that brought us here (e.g. KeyboardInterrupt) is
            # still in flight.
            try:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=_ATEXIT_SECONDS)
            finally:
                try:
                    _terminate_group(proc)
                finally:
                    try:
                        # Descendants may have inherited stderr; only after
                        # the group is gone is EOF guaranteed.
                        drain.join(_REAP_SECONDS)
                    finally:
                        _close_fd(pidfd)

        assert result is not None
        drained, clipped = drain.snapshot()
        if not drained and not clipped:
            return result
        combined = drained + result.stderr
        if clipped:
            combined += TRUNCATION_MARKER
        return CodeResult(
            stdout=result.stdout,
            stderr=truncate(combined),
            return_code=result.return_code,
            timed_out=result.timed_out,
        )

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
        import time

        assert proc.stdin is not None
        assert proc.stdout is not None
        assert proc.stderr is not None

        # Send init message with tool docs for help() support
        init_msg = dumps(
            {"type": "init", "protocol": PROTOCOL_VERSION, "tools": tool_docs, "code": code}
        )
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

        deadline = time.monotonic() + timeout if timeout is not None else None

        while True:
            # Calculate remaining time for queue.get
            if deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _terminate_group(proc)
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
                _terminate_group(proc)
                return CodeResult(
                    stdout="",
                    stderr="",
                    return_code=-1,
                    timed_out=True,
                )

            if line is None:
                # Subprocess died unexpectedly. Tear down any group members
                # first so descendants cannot keep stderr open; the drain
                # thread's buffer is merged in by execute().
                _terminate_group(proc)
                return CodeResult(
                    stdout="",
                    stderr="",
                    return_code=proc.returncode if proc.returncode is not None else -1,
                    timed_out=False,
                )

            try:
                msg = loads(line)
            except (json.JSONDecodeError, CodecError):
                # User code or an escaped descendant wrote to the channel.
                # Ignore garbage rather than failing the whole cell.
                continue
            if not isinstance(msg, dict):
                continue

            if msg.get("protocol") != PROTOCOL_VERSION:
                _terminate_group(proc)
                return CodeResult(
                    stdout="",
                    stderr=truncate(
                        f"Protocol mismatch: child sent {msg.get('protocol')!r}, "
                        f"expected {PROTOCOL_VERSION}\n"
                    ),
                    return_code=1,
                    timed_out=False,
                )

            msg_type = msg.get("type")

            if msg_type == "done":
                stdout = msg.get("stdout", "")
                stderr = msg.get("stderr", "")
                rc = msg.get("rc", 0)
                return CodeResult(
                    stdout=truncate(stdout if isinstance(stdout, str) else str(stdout)),
                    stderr=truncate(stderr if isinstance(stderr, str) else str(stderr)),
                    return_code=rc if isinstance(rc, int) else 1,
                    timed_out=False,
                )

            if msg_type == "call":
                tool_name = msg.get("tool")
                args = msg.get("args", [])
                kwargs = msg.get("kwargs", {})
                if (
                    not isinstance(tool_name, str)
                    or not isinstance(args, list)
                    or not isinstance(kwargs, dict)
                ):
                    continue

                fn = namespace.get(tool_name)
                if fn is None:
                    result_msg = dumps(
                        {
                            "type": "result",
                            "protocol": PROTOCOL_VERSION,
                            "error": f"Unknown tool: {tool_name}",
                        }
                    )
                else:
                    try:
                        result = fn(*args, **kwargs)
                        result_msg = dumps(
                            {
                                "type": "result",
                                "protocol": PROTOCOL_VERSION,
                                "value": result,
                            },
                            max_bytes=MAX_TOOL_VALUE_BYTES,
                        )
                    except CodecError as exc:
                        result_msg = dumps(
                            {
                                "type": "result",
                                "protocol": PROTOCOL_VERSION,
                                "error": str(exc),
                                "error_kind": "codec",
                            }
                        )
                    except Exception as exc:
                        result_msg = dumps(
                            {
                                "type": "result",
                                "protocol": PROTOCOL_VERSION,
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )

                proc.stdin.write(result_msg + "\n")
                proc.stdin.flush()
