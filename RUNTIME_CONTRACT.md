# Runtime contract: transport, semantics, and the wire protocol

Status: describes the protocol **as implemented on `master` after #17**
(`IpcSubprocessRuntime`, including the channel hardening merged in #20), and the invariants
every future backend must satisfy. Protocol versioning, positional arguments, the result
codec, `stderr` handling, and process-group cleanup are still 0.3.0 work (#5, #6, #7);
frame integrity across a shared interpreter is #21 (0.4.0). §8 lists what changes and what
this document will then have to say.

## 1. The division of responsibility

codecell is a **transport** for tool calls and an **owner** of the execution lifecycle.
Those are different things and the distinction is the whole contract.

### codecell owns (runtime side)

| Responsibility | Status in 0.2.1 |
|---|---|
| Spawning the execution process | shipped |
| Framing and ordering of wire messages | shipped; channel handles hardened in #17 (#20), frame integrity is #21 |
| Terminal frame on every Python exit path | shipped (#17/#20): `BaseException` caught, `SystemExit` normalized mod 256 |
| Blocking until a tool call is answered | shipped |
| Capturing the code's `stdout`, returning `stdout`/`stderr`/`rc` | shipped; user `stderr` is discarded (§3) |
| Protocol versioning | **target — #7**; no version field exists today |
| Cancellation semantics | **target — #6**; today a timeout kills the direct child only |
| `stderr` drain | **target — #5**; today discarded, or it stalls the cell |
| Process-group cleanup | **target — #6**; today grandchildren survive |
| Result codec | **target — #7**; today JSON-only, and a non-JSON result is reported as a tool failure |

### The caller owns (semantic side)

- Which callables are exposed to the code — the namespace **is** the capability grant.
- Authorization, policy, rate limiting, and audit logging.
- Actually executing the tool.
- Mapping tool failures to user-facing messages.
- Retries, caching, and any other semantics above the wire.

Two invariants follow, and both are load-bearing:

1. **The runtime never interprets tool traffic.** It does not filter, authorize, cache,
   log, retry, or rewrite tool names, arguments, or results. It moves them.
2. **The caller never touches the wire.** It receives a call, applies semantics, and
   answers. It does not read or write protocol frames.

The second invariant is why "transport-only" does **not** mean "semantics-free about
lifecycle": a runtime that leaks processes, hangs on an undrained pipe, or lies about
how a cell ended has broken the contract just as badly as one that authorizes a tool
call. Lifecycle semantics belong to codecell; tool semantics belong to the caller.

## 2. What codecell will never do

- Inspect `kwargs` to decide whether a call is allowed.
- Add per-tool allow-lists, caching, or audit logging inside the runtime.
- Interpret a tool's return value beyond encoding it.
- Hide a tool failure by reporting success, or hide a success by reporting failure
  (0.2.1 violates this last one for non-JSON results — see §5).

If a feature needs any of these, it belongs in the caller, not in a backend.

## 3. Wire protocol (v0, as shipped in 0.2.1)

**Transport.** Newline-delimited UTF-8 JSON over the child's `stdin` (main → child) and
`stdout` (child → main). Exactly one JSON object per line, no pretty-printing.

The protocol channel is **reserved at the fd level** since #17 (#20). The bootstrap
duplicates fds 0/1, relocates the duplicates above fd 256, then points fds 0/1 at
`os.devnull` before any user code runs. Measured: a forged `done` written through
`sys.__stdout__`, `io.open(1)`, or `os.write(1, ...)` is discarded; a cell that closes fds
3–5 still returns its output; and the duplicates are non-inheritable, so a spawned child
cannot write them either (`os.write(256, ...)` in a grandchild → `EBADF`).

That is **hardening, not isolation**. User code shares the interpreter with the writer, so
frame introspection still reaches it —
`sys._getframe().f_back.f_locals['send_to_main']({...})` returns `stdout='FORGED'` today —
and `/proc/self/fd` still lists the relocated descriptors (measured:
`['0','1','2','256','257','3']`). The parent ignores malformed frames (§6) but cannot tell
a forged well-formed `done` from a genuine one. Full enforcement needs the writer in a
separate process: #21, 0.4.0.

Two consequences worth knowing: a cell that closes the relocated descriptors destroys its
own channel and is reported as `return_code=1` with a bootstrap traceback and empty output
(self-DoS, not forgery); and `print()` remains the only supported output path — it is
captured in the child and delivered inside `done`.

**Messages.** Four roles, in this order per execution:

| # | Direction | `type` | Fields | Meaning |
|---|---|---|---|---|
| 1 | main → child | `init` | `tools`: object mapping tool name → docstring or `null`; `code`: string | Start one execution. A legacy list of names is also accepted |
| 2 | child → main | `call` | `tool`: string; `kwargs`: object | Execute this tool with these **keyword** arguments. The child blocks immediately after sending |
| 3 | main → child | `result` | `value`: any JSON value **or** `error`: string | Exactly one answer per `call`; `value` and `error` are mutually exclusive |
| 4 | child → main | `done` | `stdout`: string; `stderr`: string; `rc`: integer | The code finished (normally or by raising). Terminal message |

**Ordering and lifecycle rules.**

- One `init` per execution. A terminal `done` is **guaranteed for every Python exit path**
  since #17: the bootstrap catches `BaseException`, so `SystemExit` and `KeyboardInterrupt`
  still produce a frame. Measured: `SystemExit(0)` → `rc=0`, `SystemExit(7)` → `rc=7`,
  `SystemExit(-1)` → `rc=255`, `SystemExit(300)` → `rc=44`, `SystemExit('bye')` → `rc=1`
  with `bye` on `stderr`, `KeyboardInterrupt` → `rc=130`; captured output survives in every
  case. `os._exit` and fatal signals still bypass the frame and surface as EOF (§6).
- `call` and `result` strictly alternate. The child has no other source of input while
  blocked, so a runtime that does not answer stalls the cell.
- `done` is produced only by the child finishing. A child killed on timeout sends
  nothing; the main process reports that as `timed_out=True, return_code=-1` with empty
  output.
- 0.2.1 has **no message ids and no version field**: concurrent calls from user threads
  interleave and corrupt the stream, and an old caller cannot detect a new child. Treat
  one runtime instance as single-threaded until #7 lands.
- User `sys.stderr` is **not** redirected and **not** captured. It goes to the OS
  `stderr` pipe, which 0.2.1 reads only when the child dies without sending `done`. On a
  normal finish those bytes are **discarded** (measured: `sys.stderr.write('hello')` then
  `print('ok')` returns `stderr=''`), and a write larger than the pipe buffer stalls the
  cell until the timeout (#5).

## 4. Errors on the wire

A `result` with `error` is the only in-band failure channel. The child turns it into a
`RuntimeError("Tool <name> failed: <error>")`, so tool failures are Python exceptions at
the call site rather than silent values.

| Cause | `result.error` | Code sees |
|---|---|---|
| Tool raised | `"<ExceptionType>: <message>"` | `RuntimeError` |
| A `call` names something not in the namespace | `"Unknown tool: <name>"` | Unreachable from user code: an unbound name is a plain `NameError` in the child before any IPC happens. The dispatcher keeps this as a defensive path |
| Tool returned a non-JSON value (0.2.1 defect) | `"TypeError: Object of type <T> is not JSON serializable"` | `RuntimeError` — a **successful** call reported as failure (#7) |

## 5. Result codec

- Values must be JSON-serializable. `str`, `int`, `float`, `bool`, `None`, lists, and
  dicts with string keys work.
- Non-JSON values (`set`, `bytes`, `datetime`, custom objects) currently fail as shown
  above. #7 defines the codec: deterministic encoding for common types or an explicit,
  documented codec error — never a generic "tool failed" for a successful call.
- Tool **arguments** are serialized in the child before any frame is sent, so they must be
  JSON-serializable as well. A non-JSON argument fails *before* the call reaches the
  caller: `f(x={1, 2})` raises `TypeError ... when serializing dict item 'kwargs'` as a
  child-side traceback (`return_code=1`), bypassing the `result.error` channel. #7 owns
  both directions.
- The returned `stdout`/`stderr` strings are truncated to 64 KiB per stream in the main
  process, after capture.

## 6. Failure modes as the caller sees them

| Situation | `CodeResult` |
|---|---|
| Code ran and returned | `return_code=0`, `timed_out=False` |
| Code raised | `return_code=1`, traceback in `stderr` (inside `done`) |
| Timeout | `timed_out=True`, `return_code=-1`, empty output |
| Code raised `SystemExit(n)` | `return_code = n % 256` (`0` for `None`); captured output kept; no traceback. `SystemExit('msg')` → `return_code=1` with `msg` on `stderr` |
| `os._exit`, a fatal signal, or a destroyed channel | `return_code` = child exit status (`1` if the channel died), `stderr` only; `stdout` may be lost |
| Malformed frame written to the channel | ignored: junk written to a protocol fd no longer fails the call (measured: `rc=0`, real output intact) |
| Tool failed | `return_code=1`, `RuntimeError` traceback in `stderr` |

A caller must treat `timed_out=True` as "the wrapper gave up", not "the work stopped":
0.2.1 kills only the direct child, so grandchildren survive (#6).

## 7. Backend compliance checklist

A new backend (`ContainerRuntime`, Wasm, remote sandbox) is contract-compliant when it:

- [ ] Implements the four message roles with the same field names and directions.
- [ ] Performs a version handshake and rejects an unknown protocol version with an
      actionable error (required from protocol v1).
- [ ] Makes the protocol channel **unreachable**, not merely hidden. Hiding the fds is not
      enough while executed code shares the interpreter with the writer: #17/#20 closed the
      obvious handles, and #21 owns the remaining frame-introspection route.
- [ ] Guarantees a terminal `done` frame on every Python exit path, including `SystemExit`
      and `KeyboardInterrupt`, and documents which exits still bypass it (`os._exit`,
      fatal signals).
- [ ] Preserves strict `call` → `result` alternation and blocks the code until answered.
- [ ] Distinguishes "code finished" (`done`) from "transport died" (EOF/exit) and
      reports both accurately.
- [ ] Implements cancellation as a lifecycle operation with defined semantics for
      in-flight calls, and terminates the whole process/container tree.
- [ ] Never interprets tool semantics (no filtering, authorization, caching, logging).
- [ ] Bounds every buffer the caller allocates with a ceiling that does not depend on how
      much the executed code writes.
- [ ] Truncates returned output consistently (64 KiB per stream).
- [ ] Keeps failures and successes distinct in both directions: a tool failure never
      arrives as a value, and a successful value never arrives as a failure (the defect
      #7 fixes).
- [ ] Propagates tool errors verbatim as `result.error` strings.
- [ ] Carries no state across executions: no module cache, variable, or namespace
      survives into the next call.
- [ ] Reports `rc`, `stdout`, `stderr`, and `timed_out` without deciding whether the
      outcome is acceptable.
- [ ] Documents any capability the channel adds or removes relative to the subprocess
      backend.

## 8. What changes in 0.3.0

| Change | Issue | Effect on this document |
|---|---|---|
| Protocol channel hardening and terminal frame | #17 / #20 | §3 flips from gap to enforced for fd handles and `BaseException`; the #21 residual is stated as a non-guarantee |
| `stderr` drained continuously | #5 | Removes the "stderr is unread until exit" caveat in §3 |
| Process-group kill on timeout/cancellation | #6 | Cancellation semantics become a defined lifecycle operation (§6, §7) |
| Positional args, result codec, `__name__`, `protocol` field | #7 | Replaces "v0" in §3 with protocol v1 and the version handshake |
| Transport/Protocol split | #10 | The four roles move behind an explicit `Protocol` object; the wire stays as specified here |
| Frame integrity across a shared interpreter | #21 (0.4.0) | Turns the §3 residual into an enforced guarantee by moving the writer out of the executed process |
| Container backend | 0.4.0 | First backend that must pass the §7 checklist under a hostile-code threat model |

## 9. Relation to ToolRegistry

ToolRegistry implements `registry.invoke()` as the canonical semantic handler. The
contract here is what codecell guarantees *to* such a caller: framed, ordered,
blocking tool calls and an honest execution result. `registry.invoke()` is what the
caller provides *back*: authorization, logging, execution, and error mapping. Neither
side reaches across the wire.
