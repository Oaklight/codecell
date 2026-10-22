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
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

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
# Process-group teardown
# ---------------------------------------------------------------------------
# Executed code routinely spawns processes of its own.  Killing only the direct
# child leaves that whole tree running after ``execute()`` returns, so every child
# is started as the leader of its own process group (POSIX) and the group is torn
# down on timeout, crash, or caller cancellation.
#
# Windows has no process groups, so only the direct child can be terminated
# there and grandchildren may survive.

_IS_POSIX = os.name == "posix"

# Seconds a process group gets to exit on SIGTERM before it is SIGKILLed.
SIGTERM_GRACE_SECONDS = 1.0

# Seconds allowed to collect output already buffered in the pipes after the group
# was killed.  A process that left the group while holding a pipe can keep it open
# indefinitely, so capture is bounded instead of waited on.
POST_KILL_DRAIN_SECONDS = 1.0

_GROUP_POLL_INTERVAL = 0.02


def _spawn_kwargs() -> dict[str, Any]:
    """Extra ``Popen`` kwargs that put the child in its own process group."""
    return {"start_new_session": True} if _IS_POSIX else {}


def _signal_group(proc: subprocess.Popen[Any], sig: int) -> None:
    """Send *sig* to the child's process group (POSIX) or to the child alone."""
    if proc.pid <= 1:  # never signal our own group
        return
    with contextlib.suppress(OSError):
        if _IS_POSIX:
            os.killpg(proc.pid, sig)
        else:
            proc.send_signal(sig)


def _group_alive(proc: subprocess.Popen[Any]) -> bool:
    """Whether the child's process group still has a live member."""
    if not _IS_POSIX:
        return proc.poll() is None
    if proc.pid <= 1:
        return False
    try:
        os.killpg(proc.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_group(proc: subprocess.Popen[Any]) -> None:
    """SIGKILL the child's process group (POSIX) or the child itself."""
    if _IS_POSIX:
        _signal_group(proc, signal.SIGKILL)
    else:
        with contextlib.suppress(OSError):
            proc.kill()


def _terminate_process_group(
    proc: subprocess.Popen[Any], grace: float = SIGTERM_GRACE_SECONDS
) -> None:
    """Reap *proc* and kill whatever it left running in its process group.

    Idempotent, and safe on an already-reaped child: the group is checked before
    anything is signalled, so our own group is never touched.  On the normal-exit
    path the leader has already been reaped by ``communicate()``, which leaves a
    theoretical pid-reuse race; it is narrowed to the microseconds between that
    reap and this call, and a signal only goes out if a group with that id still
    has a live member.
    """
    if _group_alive(proc):
        _signal_group(proc, signal.SIGTERM)
        deadline = time.monotonic() + grace
        # Wait on the leader instead of sleeping a fixed interval: it exits
        # within milliseconds, and sleeping cost ~20 ms on every call.  The
        # deadline is shared, so a child that ignores SIGTERM is still killed
        # after one grace period rather than two.
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            proc.wait(timeout=grace)
        while _group_alive(proc) and time.monotonic() < deadline:
            time.sleep(_GROUP_POLL_INTERVAL)
        if _group_alive(proc):
            _kill_group(proc)

    if proc.poll() is None:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            proc.wait(timeout=grace)


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

        # The child leads its own process group (POSIX) so a timeout or a caller
        # cancellation takes down the whole descendant tree, not just the child.
        proc = subprocess.Popen(
            [*self._validator.interpreter, script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **_spawn_kwargs(),
        )

        stdout = stderr = ""
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            # ``communicate`` raises with whatever it had already read.  Keep it:
            # the retry below is bounded, so it may be all the output there is.
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            _terminate_process_group(proc)
            with contextlib.suppress(subprocess.TimeoutExpired):
                # ``communicate`` accumulates across calls, so on success this is
                # the complete output, including the partial read above.
                stdout, stderr = proc.communicate(timeout=POST_KILL_DRAIN_SECONDS)
            return CodeResult(
                stdout=truncate(stdout),
                stderr=truncate(stderr),
                return_code=-1,
                timed_out=True,
            )
        except BaseException:
            _terminate_process_group(proc)
            raise

        # The child exiting says nothing about what it spawned: a descendant that
        # does not share our pipes is invisible to ``communicate``, so on the
        # normal and crash exit paths the tree would otherwise outlive the call.
        _terminate_process_group(proc)

        return CodeResult(
            stdout=truncate(stdout),
            stderr=truncate(stderr),
            return_code=proc.returncode,
            timed_out=False,
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

        # Spawn subprocess running the bootstrap script.  It leads its own
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
        finally:
            # Single owner of teardown: reap the child and clear anything it left
            # behind, on every path -- return, crash, timeout, or cancellation.
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

        # ``timeout=0`` means "fail immediately", as in SubprocessRuntime; only
        # ``None`` disables the deadline.
        deadline = time.monotonic() + timeout if timeout is not None else None

        while True:
            # Calculate remaining time for queue.get
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # Teardown belongs to execute()'s finally, not here.
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
                # Timeout; execute()'s finally tears the group down.
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
                return CodeResult(
                    stdout=truncate(stdout if isinstance(stdout, str) else str(stdout)),
                    stderr=truncate(stderr if isinstance(stderr, str) else str(stderr)),
                    return_code=rc if isinstance(rc, int) else 1,
                    timed_out=False,
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
