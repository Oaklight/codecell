# Threat model and isolation guarantees

Status: describes **codecell 0.2.1** as measured, and the targets for 0.3.0 (issues
#5–#8). Evidence for every claim below was produced by running code, not by reading
it; the commands are in [Reproduced evidence](#reproduced-evidence).

This document exists because the README previously advertised Python validation as
*"Strong (AST analysis)"* and execution as *"only safe computation modules allowed"*.
Both statements are false as security claims. `PythonValidator` is bypassable in several
trivial ways, and `SubprocessRuntime` has the caller's uid, filesystem, network, and
environment. The correction is not a stronger validator — it is an honest statement of
what the kernel enforces and what it merely advises.

## 1. Scope

In scope: the execution path of `SubprocessRuntime` and `IpcSubprocessRuntime`, the
`PythonValidator` / `BashValidator` / `NullValidator` advisory checks, output capture and
truncation, and timeout/kill behaviour.

Out of scope for 0.3.0: `ContainerRuntime` (0.4.0), stateful sessions, remote sandboxes,
multi-language backends, and the bash deny list (0.3.0 removes the bash backend; policy
for shell execution lives in `Oaklight/bashtool` and `toolregistry-hub`).

## 2. Assets

| Asset | Why it matters |
|---|---|
| Host filesystem | Readable and writable as the calling process's uid (measured: any file the caller can touch) |
| Network | Unrestricted egress from the child (measured: outbound `connect()` succeeds) |
| Environment and secrets | Child inherits the full environment, including tokens and credentials (measured) |
| Tool credentials | Tools execute in the **main** process, so a tool call borrows its full authority |
| Agent availability | A hung or unkillable cell blocks the agent loop; orphaned children outlive the call (measured) |
| Output budget | Untrusted output is fed back into an LLM context |
| Host resources | CPU, memory, disk, and PIDs are not limited per cell (measured) |

## 3. Adversaries and trust tiers

| Tier | Who | Realistic attack |
|---|---|---|
| **T0** | The caller's own trusted code | Bugs, not attacks |
| **T1** | LLM-written code steered by a prompt-injected document or tool result | The dominant threat: the model is *trying* to reach the host, and will happily use `io`, `getattr`, or `__subclasses__` if the prompt suggests it |
| **T2** | Code from a hostile tenant / third-party agent sharing the deployment | Direct, informed attempts to read secrets or pivot |
| **T3** | A local attacker with a shell on the host | Irrelevant to this document; the process boundary is not a defence against the same uid |

codecell 0.3.0 can only claim soundness against **T0**. For **T1** it reduces accidents
and keeps the model's *output* parseable — it does not contain a determined attempt.
**T2** requires a container backend (0.4.0) or an external sandbox.

## 4. The rule this document follows

> A guarantee exists only if the operating system, kernel, or container runtime enforces
> it. A validator is advisory: it is a lint pass over text, and text is not a boundary.

Consequences that follow from the rule and are easy to get wrong:

- An allow-list of imports is not a capability restriction; `io` is on it, and `io.open`
  is `open`.
- Blocking *names* (`open`, `exec`, `__import__`) does not block *reachability*:
  `getattr(__builtins__, 'open')` and `(lambda: 0).__globals__['__builtins__'].open`
  are the same function.
- Killing the direct child is not killing the work: a child's children survive.
- A pipe that is never drained is a hang, not a stream.

## 5. What the runtime actually enforces (0.2.1)

Measured, not inferred. Everything not in this list is **not** enforced.

| Property | Enforced? | Mechanism |
|---|---|---|
| Crash isolation | Yes | Separate OS process (`subprocess.run` / `Popen`) |
| Interpreter/global-state isolation per call | Yes | Fresh interpreter per `execute()` |
| Output size cap | Yes | `truncate()` at 65 536 UTF-8 bytes per stream, in-process |
| Wall-clock bound on the **direct child** | Yes | `subprocess.run(timeout=…)` → `SIGKILL` to the direct child |
| Wall-clock bound on the process **tree** | **No** | No process group / no `setsid`; grandchildren survive (measured: `sleep 90` still alive after `timed_out=True`) |
| Filesystem, network, env, PID, resource limits | **No** | No namespace, seccomp, rlimit, cgroup, or uid change |
| Code validation | **Advisory** | `ast` walk (`PythonValidator`) or regex (`BashValidator`) |

## 6. Per-backend guarantee table

Legend — **ENFORCED(mechanism)**: the mechanism is an OS/container control.
**ADVISORY(check)**: a text check that a determined author bypasses.
**NONE**: nothing stands between the code and the asset.

| Capability | `SubprocessRuntime` + `NullValidator` | `SubprocessRuntime` + `PythonValidator` | `IpcSubprocessRuntime` (+ either validator) | `ContainerRuntime` (0.4.0 target) |
|---|---|---|---|---|
| **Code visibility** (can code read the caller's memory?) | NONE — separate process, no shared address space | Same | Same; code is sent over the pipe and `exec`'d in the child | ENFORCED — separate container filesystem/process namespace |
| **Injected tool namespace** | NONE — callables are not injected; stubs raise | NONE — same | ADVISORY — code can only call injected names, but each call runs with full main-process authority; no per-tool allow-list | ENFORCED (0.4.0, by absence of IPC channel), ADVISORY before that |
| **Host filesystem read** | NONE — child runs as caller uid | NONE — `import io` is allowed (`io` is on the allow-list) and `io.open` reads any readable path (measured) | NONE — same | ENFORCED — read-only or absent mounts, container rootfs |
| **Host filesystem write** | NONE | NONE — `io.open(path, 'w')` writes anywhere the caller can (measured) | NONE | ENFORCED — read-only mounts, no host bind by default |
| **Network egress** | NONE | NONE — `socket` reached via `getattr(__builtins__, '__import__')` (measured: connect attempt made) | NONE | ENFORCED — `network=none` / no interface |
| **Environment and secrets** | NONE — full env inherited | NONE — same env, reachable despite `os` being denied (measured: `HOME`, `USER`) | NONE — and tool calls additionally see main-process objects | ENFORCED — explicit, minimal env pass-through |
| **Process spawn** | NONE — `subprocess` reachable | NONE — reachable via the same escape (measured: pid-namespace not used) | NONE | ENFORCED — PID namespace, no host PIDs |
| **Resource exhaustion** | NONE — no rlimits (`Max address space`, `Max cpu time`, `Max file size` all `unlimited`; measured) | NONE | NONE | ENFORCED — cgroup memory/CPU/pids limits |
| **Timeout / kill semantics** | Partial — direct child `SIGKILL`ed; **tree leaks** (measured) | Partial — same | Partial — same, plus undrained `stderr` can stall the child until the deadline (measured: 200 KB write → hang until timeout) | ENFORCED — container stop kills the whole tree |
| **Tool access** (PTC namespace) | NONE — stubs raise `NotImplementedError` | NONE — same | ADVISORY — kwargs-only stubs, non-JSON results turn success into a traceback (measured) | ENFORCED by the tool layer, not by codecell |
| **Output containment** | ENFORCED(truncate, 64 KB per stream) — but the cap is applied after the child has already produced the bytes | Same | Same | Same |

Notes:

- The bash backend (`SubprocessRuntime` + `BashValidator`) is deliberately omitted from
the comparison: 0.3.0 removes it (no consumer, drifted from `Oaklight/bashtool`). Where
it existed, its guarantee was ADVISORY(regex deny list) over an otherwise identical
NONE-everything runtime — see §7.2 for a reproduced bypass.
- "ENFORCED" for `CodeResult` only covers output size. Truncation happens after capture,
  so a child can still emit unbounded data to its own pipes/disk; only the returned
  string is capped.

## 7. Known validator bypasses

### 7.1 `PythonValidator` (AST allow-list)

All of these execute successfully under `SubprocessRuntime(PythonValidator())` on 0.2.1
and read or write arbitrary host files. Verbatim outputs in
[Reproduced evidence](#reproduced-evidence).

| # | Bypass | Why the AST check misses it |
|---|---|---|
| 1 | `import io; io.open('/etc/hostname').read()` | `io` is on `ALLOWED_IMPORTS`; only the *name* `open` is blocked, not `io.open` |
| 2 | `getattr(__builtins__, 'open')(...)` | `getattr` is not blocked, and point 2 of §4 applies |
| 3 | `(lambda: 0).__globals__['__builtins__'].open(...)` | `__globals__` / `__builtins__` traversal is not modelled |
| 4 | `object.__subclasses__()` traversal | Blocked attributes are keyed on *names* (`os.`), not on reachability from builtins |

Also reachable through the same one-line escape, all measured: environment variables,
`subprocess`, `socket`, and any module Python can import. In practice the allow-list
constrains the *style* of code, not its authority. Any fix that keeps this an AST check
will be bypassable again; hardening of the validator is out of scope for 0.3.0 and the
README must not describe its result as a security boundary.

Because blocking is name-based, the validator also blocks legitimate code (`os.getcwd()`,
`import sys`) while missing the escapes above. That asymmetry is the point: it is a UX and
prompt-hygiene tool with a security-shaped API, which is why the docs must say so.

### 7.2 `BashValidator` (regex deny list)

Measured against the shipped deny list: `sudo id`, `rm -rf /`, and other literal forms are
blocked, but four of five obfuscated forms pass validation — `su''do id`, `s\udo id`,
`r''m -rf /tmp/whatever`, and `echo $(r''m -rf /tmp/whatever)`. The regex inspects raw
text; the shell performs quote removal after. The deny list is best-effort risk reduction
and remains so in `bashtool`; it is not a sandbox and never was.

## 8. Timeout and kill semantics

`SubprocessRuntime` kills only the direct child on timeout, and `IpcSubprocessRuntime`
additionally leaves the child blocked when `stderr` fills because the pipe is never
drained. Both are reproduced:

- A cell that spawns `sleep 90` and then idles returns `timed_out=True` after 3.0 s with
the grandchild (pid recorded by the cell itself) still running.
- A cell writing 200 000 bytes to `stderr` under `IpcSubprocessRuntime` produced no
`done` message and returned `timed_out=True` after 8.01 s with empty `stdout` — the child
was blocked on a full pipe the whole time.

Consequence for agents: a timeout tells you the wrapper gave up, **not** that the work
stopped. Do not treat `timed_out=True` as "the host is clean". Both behaviours are fixed
by the IPC lifecycle issues (#5–#7), not by the validator.

## 9. Resource limits

Measured inside a validated cell through `/proc/self/limits`: `Max cpu time unlimited`,
`Max file size unlimited`, `Max address space unlimited`, `Max processes 62282` (the
kernel's user-wide limit, not a per-cell one). A cell can therefore consume the host's
memory, disk, and CPU for as long as the timeout allows — and longer, if it spawns
children. `timeout` is the only bound; it is not a resource policy.

## 10. Where the boundary actually is (capability model)

In PTC and in the intended agentic framework, two things protect the host:

1. **The sandbox** — the process/container the code runs in. In 0.3.0 this is a plain
   subprocess with the caller's full authority, i.e. no boundary at all against T1/T2.
2. **The injected namespace** — the set of tools the code can call. Each call is executed
   in the main process with the caller's authority, so the namespace *is* the capability
   grant, and it must be curated as such.

The validator belongs to neither. Its legitimate jobs are: catching mistakes cheaply,
keeping obviously dangerous code out of the agent's feedback loop, and giving the model a
clear error message that steers it toward computation. It must never be cited as the
reason untrusted code is safe; the honest statement for 0.3.0 is *"untrusted code is not
isolated; run codecell with the privileges you would give that code"*.

## 11. Status and targets

| Change | Issue | Effect on this document |
|---|---|---|
| Container backend | 0.4.0 / `ContainerRuntime` | First backend permitted to claim T1/T2 isolation; the table gains an enforced column |
| stderr drain + process-group kill | #5 | Moves timeout/kill from *partial* to *tree-bounded* |
| tool-call ergonomics, result encoding | #6, #7 | Removes kwargs-only and non-JSON failure modes |
| bash backend removal | #8 | Deletes an ADVISORY-only surface, and the allow-list confusion that came with it |
| regression suite | #11 | Every reproduction in §7–§8 becomes an executable test |

Until `ContainerRuntime` ships, the sentence to repeat in docs and reviews is:
**codecell 0.3.0 isolates crashes, not adversaries.**

## Reproduced evidence

Environment: Linux 6.1.0-49-amd64, CPython 3.14.7, `PYTHONPATH=<repo>@master (e9d6a29)`.
Reproducers are kept out of `tests/` on purpose — they assert the buggy behaviour and
would have to be inverted once the fixes land (#11 owns that).

```python
from codecell import SubprocessRuntime
from codecell.python import PythonValidator

rt = SubprocessRuntime(PythonValidator())

# 7.1 / #1: io is allowed, io.open is open
rt.execute("import io; print(io.open('/etc/hostname').read())")
# stdout 'buttercup\n', return_code 0

# 7.1 / #2: getattr is unchecked
rt.execute("print(getattr(__builtins__, 'open')('/etc/hostname').read())")
# stdout 'buttercup\n', return_code 0

# 7.1 / #3: __globals__ traversal
rt.execute("print((lambda: 0).__globals__['__builtins__'].open('/etc/hostname').read())")
# stdout 'buttercup\n', return_code 0

# 7.1 / #4: subclass traversal is open
rt.execute("print(len(object.__subclasses__()), 'subclasses reachable')")
# stdout '174 subclasses reachable\n', return_code 0

# write anywhere the caller can (measured on /tmp)
rt.execute("import io; io.open('/tmp/codecell-probe-write.txt', 'w').write('written')")

# secrets: env is inherited and reachable through the escape
rt.execute("print((lambda: 0).__globals__['__builtins__'].__import__('os').environ['HOME'])")
# stdout '/home/elena\n'

# network: no egress restriction
rt.execute("s = getattr(__builtins__, '__import__')('socket').socket(); s.settimeout(1)\ntry:\n    s.connect(('127.0.0.1', 9))\nexcept Exception as e:\n    print('connect attempt made:', type(e).__name__)")
# stdout 'connect attempt made: ConnectionRefusedError\n' — the attempt left the process

# resources: no per-cell limits
rt.execute("import io; print([l for l in io.open('/proc/self/limits') if l.startswith('Max address')])")
# 'Max address space         unlimited            unlimited            bytes'
```

Process tree on timeout (`NullValidator`, so the cell may spawn): a cell that runs
`subprocess.Popen(['sleep', '90'])`, writes the pid to a file, then sleeps, returns
`timed_out=True, return_code=-1` after 3.0 s while `os.kill(pid, 0)` on the recorded
grandchild still succeeds.

`IpcSubprocessRuntime` stderr backpressure: `sys.stderr.write('x' * 200000)` returns
`timed_out=True` after 8.01 s with empty `stdout` and empty `stderr` — the child never
reached its `print`. A kwargs call (`add(a=1, b=2)`) returns `3`; the positional form
(`add(1, 2)`) raises `TypeError`; a tool returning a `set` fails with `return_code=1`
while a JSON-able `dict` returns `{'a': 1}`.
