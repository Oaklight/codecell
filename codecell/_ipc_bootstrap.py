"""Bootstrap script executed inside the IPC subprocess.

This module is invoked as ``python -m codecell._ipc_bootstrap`` by
:class:`IpcSubprocessRuntime`.  It receives tool specs and code over
a pipe, builds stub functions that send IPC messages back to the main
process for real tool execution, then runs the code via ``exec()``.

Protocol (JSON messages over stdin/stdout):

    Main → Sub:  {"type": "init", "tools": ["add", "mul"], "code": "..."}
    Sub → Main:  {"type": "call", "tool": "add", "kwargs": {"a": 1}}
    Main → Sub:  {"type": "result", "value": 3}
    Sub → Main:  {"type": "call", "tool": "mul", "kwargs": {"a": 3, "b": 2}}
    Main → Sub:  {"type": "result", "value": 6}
    Sub → Main:  {"type": "done", "stdout": "6\\n", "stderr": "", "rc": 0}

    On error:
    Main → Sub:  {"type": "result", "error": "ZeroDivisionError: ..."}
    Sub → Main:  {"type": "done", "stdout": "", "stderr": "...", "rc": 1}
"""

from __future__ import annotations

import io
import json
import sys
import traceback
from collections.abc import Callable
from typing import Any


def _send(msg: dict) -> None:
    """Send a JSON message to the main process via stdout."""
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _recv() -> dict:
    """Receive a JSON message from the main process via stdin."""
    line = sys.stdin.readline()
    if not line:
        raise EOFError("Main process closed pipe")
    return json.loads(line)


def _make_stub(tool_name: str) -> Callable[..., Any]:
    """Create a stub function that calls the tool via IPC."""

    def stub(**kwargs):
        _send({"type": "call", "tool": tool_name, "kwargs": kwargs})
        resp = _recv()
        if resp.get("error"):
            raise RuntimeError(f"Tool {tool_name} failed: {resp['error']}")
        return resp["value"]

    stub.__name__ = tool_name
    stub.__qualname__ = tool_name
    return stub


def main() -> None:
    """Bootstrap entry point."""
    # Redirect our stdout so print() in user code doesn't interfere
    # with the IPC protocol on real stdout.
    real_stdout = sys.stdout
    real_stdin = sys.stdin

    # Receive init message
    init_line = real_stdin.readline()
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

    # Rewire _send/_recv to use the real stdout/stdin
    # while user code gets a captured buffer.
    captured_stdout = io.StringIO()
    sys.stdout = captured_stdout

    # Override _send/_recv to use real pipes
    def send_to_main(msg: dict) -> None:
        real_stdout.write(json.dumps(msg) + "\n")
        real_stdout.flush()

    def recv_from_main() -> dict:
        line = real_stdin.readline()
        if not line:
            raise EOFError("Main process closed pipe")
        return json.loads(line)

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

    # Execute the code
    import builtins

    exec_globals: dict = {"__builtins__": builtins.__dict__}
    exec_globals.update(namespace)

    rc = 0
    stderr_text = ""
    try:
        exec(compile(code, "<code_execution>", "exec"), exec_globals)
    except Exception:
        rc = 1
        stderr_text = traceback.format_exc()

    stdout_text = captured_stdout.getvalue()

    # Send completion
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
