# Runtime contract: transport, semantics, and the wire protocol

Status: describes the protocol **as implemented on `master` after #17**
(`IpcSubprocessRuntime`, including the channel hardening merged in #20), and the invariants
every future backend must satisfy. Protocol v1, positional arguments and the result codec
shipped in 0.3.0 (#7); process-group cleanup and continuous `stderr` draining shipped in
0.3.0 (#5, #6). Frame integrity across a shared interpreter is #21 (0.4.0). §8 lists what
changes and what this document will then have to say.

## 1. The division of responsibility

codecell is a **transport** for tool calls and an **owner** of the execution lifecycle.
Those are different things and the distinction is the whole contract.

### codecell owns (runtime side)

| Responsibility | Status (0.3.0-dev) |
|---|---|
| Spawning the execution process | shipped |
| Framing and ordering of wire messages | shipped; channel handles hardened in #17 (#20), frame integrity is #21 |
| Terminal frame on every exception-based exit path | shipped (#17/#20): `BaseException` caught, `SystemExit` normalized mod 256 |
| Blocking until a tool call is answered | shipped |
| Capturing the code's `stdout`, returning `stdout`/`stderr`/`rc` | shipped; user `stderr` is drained continuously (§3) |
| Protocol versioning | shipped in 0.3.0 (#7): `protocol: 1` on every frame, mismatch rejected with an actionable error |
| Cancellation semantics | shipped in 0.3.0 (#6): group SIGTERM→SIGKILL; direct child only on Windows |
| `stderr` drain | shipped in 0.3.0 (#5): bounded continuous drain, returned on every path |
| Process-group cleanup | shipped in 0.3.0 (#6) on POSIX; direct child only on Windows |
| Result codec | shipped in 0.3.0 (#7): JSON plus tagged common types and a size limit; unencodable values raise `CodecError` |

Rows marked *shipped* in the 0.3.0-dev column are **not** in the released 0.2.1: on the
`v0.2.1` tag, `SystemExit` returns without a terminal frame (`rc=0, stdout=''`), the protocol
fds are plain 0/1, and `stderr` is discarded.

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

## 3. Wire protocol (v1, with the #17 channel hardening on master)

Wire format v1 is the 0.3.0 protocol (#7). Every frame carries `protocol: 1`; a missing or
different version is rejected with an actionable error. The released 0.2.1 tag has no
version field, plain fds 0/1 as the protocol channel, no terminal frame on `SystemExit`, and
discarded `stderr`.

**Transport.** Newline-delimited UTF-8 JSON over the child's `stdin` (main → child) and
`stdout` (child → main). Exactly one JSON object per line, no pretty-printing. Frames are
encoded by `codecell._wire`: tool `args`, `kwargs` and result `value` use the codec in §5.

The protocol channel is **reserved at the fd level** since #17 (#20). The bootstrap
duplicates fds 0/1, relocates the duplicates to the first free descriptor at or above a
limit-derived threshold — `min(256, max(3, RLIMIT_NOFILE // 2))`, which is 256 under a
normal limit but 4 under `RLIMIT_NOFILE=8` — then points fds 0/1 at `os.devnull` before any
user code runs. If every candidate in that range is occupied, the bootstrap falls back to
the original descriptor, i.e. a low fd; `RLIMIT_NOFILE` is the only thing that bounds the
scan, and the close-fd hazard described below comes back in that degraded mode.

Measured under a normal limit: newline-terminated junk written through `sys.__stdout__`,
`io.open(1)`, or `os.write(1, ...)` is discarded, and a cell that closes fds 3–5 still
returns its output (the channel sits at 256/257 there). Discarding is line-based: a write
without a trailing newline coalesces with the genuine `done` line, which is then dropped, and
the call ends at EOF with `stdout=''` (§6).

The relocated descriptors are non-inheritable **since #23**: `os.dup2` is called with
`inheritable=False`, so they do not survive `exec`. Before #23, `os.dup2` kept
`inheritable=True` and a grandchild started with `close_fds=False` could write a forged
`done` to fd 257 — measured on `c2d7dd0`: `stdout='FORGED-BY-GRANDCHILD', rc=0`.

`FD_CLOEXEC` stops inheritance, not reopening. A grandchild that can read the parent's
procfs opens the same descriptor by path:

```python
open(f"/proc/{os.getppid()}/fd/257", "wb").write(b'{"type":"done",...}\n')
```

Measured on master after #23: `execute()` returns `stdout='FORGED_VIA_PROC', rc=0`. Nothing
in the same-uid case prevents it. This is the same-interpreter weakness in another form and
belongs to #21, not to #23.

That is **hardening, not isolation**. User code shares the interpreter with the writer, so
frame introspection still reaches it —
`sys._getframe().f_back.f_locals['send_to_main']({...})` returns `stdout='FORGED'` today —
and `/proc/self/fd` still lists the relocated descriptors (measured:
`['0','1','2','256','257','3']`). The parent ignores malformed frames and rejects frames
whose `protocol` is not 1 (§6), but a forged well-formed v1 `done` is still
indistinguishable from a genuine one. Full enforcement needs the writer in a separate
process: #21, 0.4.0.

Two consequences worth knowing: a cell that closes the relocated descriptors destroys its
own channel and is reported as `return_code=1` with a bootstrap traceback and empty output
(self-DoS, not forgery); and `print()` remains the only supported output path — it is
captured in the child and delivered inside `done`.

**Messages.** Four roles, in this order per execution:

| # | Direction | `type` | Fields | Meaning |
|---|---|---|---|---|
| 1 | main → child | `init` | `protocol`: integer; `tools`: object mapping tool name → docstring or `null`; `code`: string | Start one execution. A legacy list of names is also accepted |
| 2 | child → main | `call` | `protocol`: integer; `tool`: string; `args`: array; `kwargs`: object | Execute this tool with these positional and keyword arguments. The child blocks immediately after sending |
| 3 | main → child | `result` | `protocol`: integer; `value`: any codec value **or** `error`: string; `error_kind`: `"codec"` when the failure is encoding | Exactly one answer per `call`; `value` and `error` are mutually exclusive |
| 4 | child → main | `done` | `protocol`: integer; `stdout`: string; `stderr`: string; `rc`: integer | The code finished (normally or by raising). Terminal message |

**Ordering and lifecycle rules.**

- One `init` per execution. A terminal `done` is **guaranteed for every exit that unwinds
  through the interpreter** since #17: the bootstrap catches `BaseException`, so `SystemExit`
  and `KeyboardInterrupt` still produce a frame. Measured: `SystemExit(0)` → `rc=0`,
  `SystemExit(7)` → `rc=7`, `SystemExit(-1)` → `rc=255`, `SystemExit(300)` → `rc=44`,
  `SystemExit('bye')` → `rc=1` with `bye` on `stderr`, `KeyboardInterrupt` → `rc=130`;
  captured output survives in every case. Exits that bypass the interpreter are **not**
  covered: `os._exit(0)` looks exactly like an empty success (`rc=0, stdout=''`), and a
  fatal signal surfaces as a negative `return_code` (§6).
- `call` and `result` strictly alternate. The child has no other source of input while
  blocked, so a runtime that does not answer stalls the cell. `args` and `kwargs` are
  codec-encoded by the child and decoded by the caller before `fn(*args, **kwargs)` runs.
- `done` is produced only by the child finishing. A child killed on timeout sends
  nothing; the main process reports that as `timed_out=True, return_code=-1` with empty
  output.
- Since #7 every frame carries `protocol: 1`, and a missing or different version is
  rejected: the child emits a terminal `done` with an actionable message when `init` is
  wrong, and the parent fails the call when a child frame is wrong. Calls from user threads
  are serialized by a child-side lock, so one `call` is outstanding at a time. There are
  still no message ids; a custom transport must not multiplex frames from multiple
  executions onto one stream.
- User `sys.stderr` is **not** redirected: writes go to the OS `stderr` pipe. Since #5 the
  parent drains that pipe continuously into a bounded buffer (the first 64 KiB) and merges it
  into `CodeResult.stderr` on every path — normal `done`, timeout, and crash/EOF. On a normal
  finish the drained bytes precede the in-band `done.stderr` (traceback or `SystemExit`
  message), preserving their relative order. Bytes beyond the buffer are drained and
  discarded; the returned prefix ends with the truncation marker. Because the pipe is always
  read, a write of any size (measured: 1 MB) cannot stall the cell. The 0.2.1 behaviour was
  the opposite: `sys.stderr.write('hello')` then `print('ok')` returned `stderr=''`, and a
  write larger than the pipe buffer hung until the timeout.

## 4. Errors on the wire

A `result` with `error` is the only in-band failure channel. The child turns it into
`RuntimeError("Tool <name> failed: <error>")`, except when `error_kind` is `"codec"`: that
becomes `CodecError` (a `TypeError`) carrying the codec message, so a successful call whose
value cannot cross the wire is not reported as a tool failure.

| Cause | `result.error` | Code sees |
|---|---|---|
| Tool raised | `"<ExceptionType>: <message>"` | `RuntimeError` |
| A `call` names something not in the namespace | `"Unknown tool: <name>"` | Unreachable from user code: an unbound name is a plain `NameError` in the child before any IPC happens. The dispatcher keeps this as a defensive path |
| Tool returned an unencodable value | `"cannot encode <T> on the wire; ..."` | `CodecError` — the call succeeded; its value has no wire representation |
| Tool returned a value over the size limit | `"encoded payload is N bytes, limit is ..."` | `CodecError` |
| Tool **arguments** cannot be encoded | no frame is sent | `CodecError` in the child before the call reaches the caller; surfaces as a child-side traceback (`return_code=1`) |

## 5. Result codec

`codecell._wire` encodes both directions, so a value sent by the child and returned by the
caller round-trips to the same type.

- JSON-native values pass through: `str`, `int`, `float`, `bool`, `None`, lists, and
  dicts. Tuples are encoded as arrays and arrive as lists; dicts with non-string keys are
  converted by JSON.
- Tagged values use a reserved `{"$codecell": <tag>, "value": ...}` object:
  `datetime`/`date`/`time` → ISO 8601; `timedelta` → seconds; `Decimal`, `UUID`, `Path` →
  string; `set`/`frozenset` → a list sorted by `repr` (deterministic for the same set);
  `bytes`/`bytearray` → base64. A user dict with exactly that shape is decoded as the tag.
- Anything else raises `CodecError`, a `TypeError` subclass exported as
  `codecell.CodecError`, with the type name and the supported alternatives. It is never
  reported as "tool failed".
- Both tool arguments and tool results are limited to `MAX_TOOL_VALUE_BYTES` (1 MiB) of
  encoded JSON. The limit is configurable at the codec boundary
  (`_wire.dumps(value, max_bytes=...)`); exceeding it raises `CodecError`.
- The returned `stdout`/`stderr` strings are separately truncated to 64 KiB per stream in
  the main process, after capture.

## 6. Failure modes as the caller sees them

| Situation | `CodeResult` |
|---|---|
| Code ran and returned | `return_code=0`, `timed_out=False` |
| Code raised | `return_code=1`, traceback in `stderr` (inside `done`) |
| Timeout | `timed_out=True`, `return_code=-1`. Both runtimes return the `stderr` read before the deadline; `SubprocessRuntime` also returns the partial `stdout`, while `IpcSubprocessRuntime` returns empty `stdout`, because captured output only travels in `done` |
| Code raised `SystemExit(n)` | `return_code = n % 256` (`0` for `None`); captured output kept; no traceback. `SystemExit('msg')` → `return_code=1` with `msg` on `stderr` |
| `os._exit(n)` | `return_code = n`, `stdout=''` — captured output is always lost. `os._exit(0)` is byte-identical to an empty cell (`rc=0, stdout=''`), so "finished" cannot be distinguished from "transport died" without a terminal frame |
| Fatal signal | `return_code` is the **negative** signal number (`-15` `SIGTERM`, `-9` `SIGKILL`), not a 0–255 exit status; `stdout` lost. `SIGHUP` yields `-1`, which collides with the timeout sentinel — disambiguate with `timed_out` |
| Channel destroyed (the cell closed the relocated fds) | `return_code=1`, bootstrap traceback in `stderr`, `stdout` lost |
| Protocol mismatch | `return_code=1`; the child's actionable `done.stderr` when `init` is wrong, or `"Protocol mismatch: child sent ..., expected 1"` when a child frame is wrong |
| Malformed frame, newline-terminated | ignored when it is not a JSON object; a JSON object with a wrong or missing `protocol` fails the call as a protocol mismatch |
| Malformed frame without a trailing newline | coalesces with the genuine `done` line, which is then dropped; the call ends at EOF with `stdout=''` (measured) |
| Tool failed | `return_code=1`, `RuntimeError` traceback in `stderr` |
| Tool result unencodable | `CodecError` at the call site; uncaught, `return_code=1` with its traceback |

A caller must treat `timed_out=True` as "the wrapper gave up", not "the work stopped":
0.3.0 kills the process group on POSIX (#6); on Windows only the direct child is killed,
so grandchildren may survive.

## 7. Backend compliance checklist

A new backend (`ContainerRuntime`, Wasm, remote sandbox) is contract-compliant when it:

- [ ] Implements the four message roles with the same field names and directions.
- [ ] Performs a version handshake and rejects an unknown protocol version with an
      actionable error (protocol v1 does this).
- [ ] Round-trips the documented codec types, or rejects an unencodable argument or result
      with a distinct codec error — never as a tool failure.
- [ ] Serializes concurrent tool calls, or rejects them with a clear error.
- [ ] Makes the protocol channel **unreachable**, not merely hidden. Hiding the fds is not
      enough while executed code shares the interpreter with the writer: #17/#20 closed the
      obvious handles and #23 stopped `exec` inheritance, but frame introspection and
      reopening `/proc/<pid>/fd/<n>` both still reach the writer. #21 owns that.
- [ ] Guarantees a terminal `done` frame on every exception-based exit path, including
      `SystemExit` and `KeyboardInterrupt`, and documents which exits still bypass it
      (`os._exit`, fatal signals, a destroyed channel).
- [ ] Preserves strict `call` → `result` alternation and blocks the code until answered.
- [ ] Distinguishes "code finished" (`done`) from "transport died" (EOF/exit) and
      reports both accurately — including `os._exit(0)`, which is byte-identical to an
      empty success and must either be reported as unknown or documented as
      indistinguishable.
- [ ] Implements cancellation as a lifecycle operation with defined semantics for
      in-flight calls, and terminates the whole process/container tree.
- [ ] Never interprets tool semantics (no filtering, authorization, caching, logging).
- [ ] Bounds every buffer the caller allocates with a ceiling that does not depend on how
      much the executed code writes.
- [ ] Drains both child streams continuously, so neither pipe can backpressure the child.
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

## 8. What changes in this document

### Already shipped on master

| Change | Issue | Effect on this document |
|---|---|---|
| Protocol channel hardening and terminal frame | #17 / #20 / #23 | §3 moves from gap to **hardened** for fd handles and `BaseException`; full enforcement is #21, stated as a non-guarantee. The `/proc/<pid>/fd` reopen vector is explicitly listed as an open residual |
| Process-group kill on timeout/cancellation | #6 | Cancellation semantics are a defined lifecycle operation (§6, §7): group SIGTERM→SIGKILL on POSIX; direct child only on Windows |
| Continuous `stderr` drain | #5 | §3's `stderr` caveat becomes a guarantee: bounded buffer, returned on normal, timeout, and crash paths |
| Protocol v1, positional args, codec, `__name__`, call lock | #7 | §3 is v1 with a version field on every frame; §4/§5 define `CodecError` and the tagged codec; concurrency is serialized by the child |

### Remaining 0.3.0 work

| Change | Issue | Effect on this document |
|---|---|---|
| Transport/Protocol split | #10 | The four roles move behind an explicit `Protocol` object; the wire stays as specified here |
| Container backend | 0.4.0 | First backend that must pass the §7 checklist under a hostile-code threat model |

## 9. Relation to ToolRegistry

ToolRegistry implements `registry.invoke()` as the canonical semantic handler. The
contract here is what codecell guarantees *to* such a caller: framed, ordered,
blocking tool calls and an honest execution result. `registry.invoke()` is what the
caller provides *back*: authorization, logging, execution, and error mapping. Neither
side reaches across the wire.

### 0.4.0

| Change | Issue | Effect on this document |
|---|---|---|
| Frame integrity across a shared interpreter | #21 (0.4.0) | Turns the §3 residuals (frame introspection, `/proc/<pid>/fd` reopen) into an enforced guarantee by moving the writer out of the executed process |
