# Runtime contract

**Applies to:** codecell 0.3.0. **Companion documents:** `THREAT_MODEL.md` covers what
executed code can reach; this one covers who owns what between a runtime and its caller.

codecell runs code that a language model wrote and lets that code call functions the caller
injected. Two parties are involved in every one of those calls, and the failure mode this
document exists to prevent is each of them assuming the other does something.

## 1. The split

| Responsibility | Owner |
| --- | --- |
| Carry a call from the executed code to the caller | codecell |
| Serialise and deserialise the frames | codecell |
| Block until the result arrives | codecell |
| Terminate the execution and report its outcome | codecell |
| Decide whether a call is allowed | the caller |
| Authenticate, rate-limit, validate arguments, redact, audit | the caller |
| Execute the tool, with its credentials and connections | the caller |
| Decide what an outcome *means* | the caller |

> **Invariant:** a runtime is transport-only. It never interprets, filters, caches, retries,
> logs, rate-limits, or authorises a tool call.

The invariant is what makes N runtimes affordable. A subprocess backend, a container backend, a
Wasm backend and a remote backend all have to carry the same frames; if each also implements
policy, that policy exists N times and drifts. The caller implements it once.

## 2. Wire format, protocol v1

Four frame types, JSON objects, one per line.

**`init`** - caller to runtime, once per execution, first frame:

```json
{"type": "init", "tools": {"<name>": "<docstring or null>"}, "code": "<source>"}
```

An earlier spelling allowed `tools` to be a list of names; the bootstrap still accepts it.

**`call`** - runtime to caller, zero or more:

```json
{"type": "call", "tool": "<name>", "kwargs": {"<key>": "<value>"}}
```

**`result`** - caller to runtime, exactly one per `call`:

```json
{"type": "result", "value": "<any JSON value>"}
{"type": "result", "error": "<ExceptionType>: <message>"}
```

**`done`** - runtime to caller, exactly one, terminal:

```json
{"type": "done", "stdout": "<captured>", "stderr": "<traceback or empty>", "rc": 0}
```

Rules:

- One JSON object per line, UTF-8, newline-terminated. No pretty-printing, no multi-line frames.
- An unknown `type` is a protocol error, not something to ignore.
- `error` is a string. The runtime raises `RuntimeError("Tool <name> failed: <error>")` inside
the executed code, so a tool failure is catchable there and nowhere else.
- Calls are synchronous: the runtime blocks until the matching `result` arrives.
- v1 has no request IDs, so at most one call may be outstanding at a time.
- `done.stderr` carries only the traceback the runtime caught. Process stderr is a separate
channel and does not travel on the protocol.

## 3. What v1 leaves unspecified

Each row is a real gap with a tracked fix, not an oversight to be discovered by a backend author.

| Gap | What it costs | Tracked in |
| --- | --- | --- |
| No version field | A peer cannot detect an incompatible change; it fails on a malformed frame instead | #7 |
| `kwargs` only | `add(1, 2)` raises `TypeError` inside the executed code | #7 |
| JSON-only result codec | A successful tool returning `datetime` is reported as a tool failure | #7 |
| No call IDs | Concurrent calls interleave on one pipe and corrupt the stream | #7 |
| Unknown frame types are ignored, not rejected | A desync or a backend bug passes silently | #7 |
| Protocol shares fd 0 and fd 1 with executed code | Code can write a frame, forge a result, or inject a `done` | #17 |
| `SystemExit` skips the terminal frame | The caller sees EOF with no exit status | #17 |
| Process stderr is out of band | A runtime that does not drain it deadlocks at the pipe buffer (~64 KiB) | #5 |
| Tool bodies execute in the caller's process | The transport cannot observe or constrain them, by design | - |

## 4. Obligations on a runtime

A backend is contract-compliant when all ten hold. Each one is a test, not a guideline.

1. **Private channel.** The protocol must not share a stream with code the runtime executes.
   A backend whose frames travel on the same fd as `print()` output is corruptible by the code
   it is carrying.
2. **One terminal frame, always.** Crash, signal, `SystemExit`, timeout - the caller must be
   able to tell "finished with rc N" from "died without saying anything".
3. **Synchronous calls.** A call blocks until its result arrives. Never reorder, never drop,
   never coalesce.
4. **Bounded buffers.** Every buffer the caller allocates has a ceiling that does not depend on
   how much the executed code writes.
5. **No semantics.** No filtering, caching, retrying, rate-limiting, logging or authorising of
   tool calls. Not even as a convenience.
6. **Errors stay errors.** A tool failure must never arrive as a value, and a successful value
   must never arrive as a failure.
7. **Out-of-band diagnostics.** The runtime's own diagnostics (stderr) must not travel on the
   protocol channel, and must not be able to block it.
8. **Teardown.** On timeout or caller cancellation, everything the execution started can be
   terminated, and the runtime reports the outcome either way.
9. **No carry-over.** One execution per instance. No state, no module cache, no variable
   survives into the next call.
10. **Report, do not decide.** The runtime reports `rc`, `stdout`, `stderr` and `timed_out`; it
    never decides whether an outcome is acceptable.

## 5. Obligations on the caller

- **The namespace is the authority.** What you put in `namespace` is what the code can call.
  There is no second allow-list, and no name the code invents resolves.
- **Policy lives here.** Authentication, rate limits, argument validation, redaction and audit
  belong on this side of the channel, because this is the side that holds the credentials.
- **Arguments are untrusted input.** They were produced by generated code, not by the tool's
  schema. Validate them like any other external input.
- **Set a timeout.** `None` means unbounded, which is a footgun for agent code.
- **Treat stdout as untrusted too.** It becomes the next prompt.

## 6. Status against this contract

| Obligation | Today | Met |
| --- | --- | --- |
| 1. Private channel | Frames and `print()` share fd 1; `sys.__stdout__` and `sys.stdin` remain reachable | No - #17 |
| 2. Terminal frame | `done` on normal exit, EOF on crash, nothing on `SystemExit` | Partial - #17 |
| 3. Synchronous calls | Dispatch loop blocks per call; no IDs, so one at a time | Yes |
| 4. Bounded buffers | stdout is capped after buffering; stderr is capped in #14 (open); the child's own capture is unbounded | Partial |
| 5. No semantics | The dispatcher resolves a name and calls it | Yes |
| 6. Errors stay errors | A non-JSON result is reported as a tool error | No - #7 |
| 7. Out-of-band diagnostics | stderr moves to its own file in #14 (open) | After #14 |
| 8. Teardown | Only the direct child is killed | No - #6 |
| 9. No carry-over | One process per call | Yes |
| 10. Report, do not decide | `CodeResult` carries the facts | Yes |

## 7. Non-goals

- **Tool schemas and prompting.** ToolRegistry owns those; codecell only carries calls.
- **Isolation guarantees.** Those belong to `THREAT_MODEL.md`; a protocol cannot make a backend
  safe, and a safe backend cannot fix a protocol.
- **Multi-language backends.** The contract is language-agnostic, but only Python is implemented.
