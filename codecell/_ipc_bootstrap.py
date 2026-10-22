"""Bootstrap script executed inside the IPC subprocess.

This module is invoked as ``python -m codecell._ipc_bootstrap`` by
:class:`IpcSubprocessRuntime`.  It receives tool specs and code over a
dedicated channel, builds stub functions that send IPC messages back to
the main process for real tool execution, then runs the code via
``exec()``.

Protocol (JSON messages):

    Main → Sub:  {"type": "init", "tools": {"add": "doc"}, "code": "..."}
    Sub → Main:  {"type": "call", "tool": "add", "kwargs": {"a": 1}}
    Main → Sub:  {"type": "result", "value": 3}
    Sub → Main:  {"type": "done", "stdout": "3\\n", "stderr": "", "rc": 0}

    On error:
    Main → Sub:  {"type": "result", "error": "ZeroDivisionError: ..."}
    Sub → Main:  {"type": "done", "stdout": "", "stderr": "...", "rc": 1}

Channel reservation
-------------------

The protocol uses duplicated descriptors relocated to high fd numbers,
and file descriptors 0 and 1 are redirected to ``os.devnull`` before any
user code runs.  The obvious handles (``sys.stdin``, ``sys.__stdout__``,
``io.open(1)``) therefore cannot read or forge protocol frames, and
closing the low fds does not break the channel.

This is hardening, not a same-process security boundary: a determined
program can enumerate ``/proc/self/fd`` or walk frames to reach the
writer.  Full enforcement needs a protocol shim in a separate process or
the container backend.

A ``done`` frame is sent on every Python exit path, including
``SystemExit`` and ``KeyboardInterrupt``.  ``os._exit`` and fatal signals
still terminate the process without a frame; the caller sees EOF.
"""

from __future__ import annotations

import io
import json
import os
import sys
import traceback
from collections.abc import Callable
from typing import Any

_HIGH_FD_START = 256
_HIGH_FD_SEARCH = 256


def _fd_limit() -> int:
    """Return the soft ``RLIMIT_NOFILE``, or a conservative fallback."""
    try:
        import resource
    except ImportError:  # Windows
        return 2048
    try:
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    except OSError:
        return 2048
    if soft == resource.RLIM_INFINITY:
        return 4096
    return int(soft)


def _move_to_high_fd(fd: int) -> int:
    """Relocate *fd* to a free descriptor above ``_HIGH_FD_START``.

    Predictable low descriptors (3, 4, ...) are easy for user code to
    close or write to; a high descriptor makes accidental interference
    unlikely.  Frame introspection can still reach the writer, so this is
    hardening rather than a boundary.  The search is bounded by the
    process's ``RLIMIT_NOFILE``; if no candidate is available the original
    descriptor is kept so the channel still works.
    """
    limit = _fd_limit()
    start = min(_HIGH_FD_START, max(3, limit // 2))
    end = min(start + _HIGH_FD_SEARCH, limit)
    for candidate in range(start, end):
        try:
            os.fstat(candidate)
        except OSError:
            try:
                os.dup2(fd, candidate)
            except OSError:
                continue
            os.close(fd)
            return candidate
    return fd


def _reserve_protocol_channel() -> tuple[io.TextIOWrapper, io.TextIOWrapper]:
    """Move protocol I/O off fds 0/1 and redirect those fds to devnull.

    The duplicates share the original open file descriptions, so the
    init line and later frames flow unchanged.  After this returns, user
    code that reaches fd 0/1 reads or writes ``os.devnull``.
    """
    in_fd = _move_to_high_fd(os.dup(0))
    out_fd = _move_to_high_fd(os.dup(1))
    devnull = os.open(os.devnull, os.O_RDWR)
    try:
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
    finally:
        os.close(devnull)
    return (
        os.fdopen(in_fd, "r", encoding="utf-8", newline="\n"),
        os.fdopen(out_fd, "w", encoding="utf-8", newline="\n", buffering=1),
    )


def _exit_code(exc: BaseException) -> int:
    """Map a caught ``BaseException`` to a process-style exit code.

    Integer codes are reduced modulo 256 to match how a real process
    exposes them; ``-1`` therefore becomes 255 and never collides with
    ``CodeResult``'s timeout sentinel.
    """
    if isinstance(exc, SystemExit):
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code % 256
        return 1
    if isinstance(exc, KeyboardInterrupt):
        return 130
    return 1


class _Capture(io.StringIO):
    """StringIO whose ``close()`` is a no-op.

    User code may close ``sys.stdout``; the captured output up to that
    point must still reach the caller.
    """

    def close(self) -> None:
        pass


def main() -> None:
    """Bootstrap entry point."""
    proto_in, proto_out = _reserve_protocol_channel()

    def send_to_main(msg: dict) -> None:
        proto_out.write(json.dumps(msg) + "\n")
        proto_out.flush()

    def recv_from_main() -> dict:
        line = proto_in.readline()
        if not line:
            raise EOFError("Main process closed pipe")
        return json.loads(line)

    init_line = proto_in.readline()
    if not init_line:
        sys.exit(1)
    init = json.loads(init_line)

    # tools can be a list of names (legacy) or a dict of name→doc
    raw_tools = init["tools"]
    if isinstance(raw_tools, dict):
        tool_docs: dict[str, str | None] = raw_tools
    else:
        tool_docs = {name: None for name in raw_tools}
    code: str = init["code"]

    captured_stdout = _Capture()
    sys.stdout = captured_stdout

    # Build stub namespace
    namespace: dict = {}
    for name, doc in tool_docs.items():

        def make_stub_fn(tool_name: str, tool_doc: str | None) -> Callable[..., Any]:
            def stub(**kwargs):
                send_to_main({"type": "call", "tool": tool_name, "kwargs": kwargs})
                resp = recv_from_main()
                if resp.get("error"):
                    raise RuntimeError(f"Tool {tool_name} failed: {resp['error']}")
                return resp["value"]

            stub.__name__ = tool_name
            stub.__qualname__ = tool_name
            stub.__doc__ = tool_doc
            return stub

        namespace[name] = make_stub_fn(name, doc)

    # Execute the code.  Catch BaseException so SystemExit and
    # KeyboardInterrupt still produce a terminal frame.
    import builtins

    exec_globals: dict = {"__builtins__": builtins.__dict__}
    exec_globals.update(namespace)

    rc = 0
    stderr_text = ""
    try:
        exec(compile(code, "<code_execution>", "exec"), exec_globals)
    except BaseException as exc:  # noqa: BLE001 - terminal frame is mandatory
        rc = _exit_code(exc)
        if isinstance(exc, SystemExit):
            # A clean exit is not an error; only a message is reported.
            if isinstance(exc.code, str):
                stderr_text = f"{exc.code}\n"
            elif exc.code is None or isinstance(exc.code, int):
                stderr_text = ""
            else:
                stderr_text = f"{exc.code!r}\n"
        else:
            stderr_text = traceback.format_exc()
    finally:
        stdout_text = captured_stdout.getvalue()
        send_to_main(
            {
                "type": "done",
                "stdout": stdout_text,
                "stderr": stderr_text,
                "rc": rc,
            }
        )


if __name__ == "__main__":
    main()
