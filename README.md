# codecell

Stateless, subprocess-isolated code execution for LLM agents. Zero dependencies.

> Unlike a Jupyter cell, there's no shared kernel — each call runs in a fresh subprocess with only the capabilities you explicitly route to it.

**Scope:** codecell is a small, stateless execution kernel: run one code string in a fresh subprocess, optionally expose callables as tools, and return structured output. It is not a sandbox. Read [THREAT_MODEL.md](THREAT_MODEL.md) before executing code you would not run yourself.

> **Security model:** codecell isolates crashes, not adversaries. A child process inherits your uid, filesystem, network, and environment; `PythonValidator` is an advisory AST check, not a boundary. Container-based isolation is targeted for 0.4.0, and only a container backend may be described as untrusted-code isolation.

## Quick start

```python
from codecell import SubprocessRuntime
from codecell.python import PythonValidator

runtime = SubprocessRuntime(PythonValidator())
result = runtime.execute("print(1 + 2)", timeout=10)
print(result.stdout)  # "3\n"
```

## Languages

### Python (AST-checked, advisory)

`PythonValidator` walks the AST and rejects imports outside an allow-list, blocked built-in calls, and a small set of `os.*` attributes. That catches accidents and keeps obviously destructive code out of the agent's loop, but it is **not** a security boundary: `import io; io.open('/etc/hostname').read()`, `getattr(__builtins__, 'open')(...)`, and `__subclasses__` traversal all execute. The reproduced list lives in [THREAT_MODEL.md](THREAT_MODEL.md#71-pythonvalidator-ast-allow-list).

```python
from codecell import SubprocessRuntime
from codecell.python import PythonValidator

py = SubprocessRuntime(PythonValidator())

# Computation works
py.execute("import math; print(math.sqrt(16))")

# Code blocked by the allow-list, not by isolation
py.execute("import os; os.system('rm -rf /')")  # raises ValueError
```

### Bash (deny-list, being removed)

Regex-based deny list blocks known-dangerous patterns. **Not a sandbox** — reduces risk but cannot guarantee safety, and quoting defeats it (`su''do id` passes). The backend has no consumer and is removed in 0.3.0; shell execution policy belongs to [`bashtool`](https://github.com/Oaklight/bashtool).

```python
from codecell import SubprocessRuntime
from codecell.bash import BashValidator

bash = SubprocessRuntime(BashValidator())
bash.execute("echo hello && ls -la")   # OK
bash.execute("rm -rf /")               # raises ValueError
```

### Trusted code (no validation)

```python
from codecell import SubprocessRuntime, NullValidator

unsafe = SubprocessRuntime(NullValidator("python"))
unsafe.execute("import os; print(os.getpid())")  # runs without validation
```

## Security model

Guarantees are per backend and only count when the OS enforces them. Full table, adversary tiers, and the reproduced bypasses: [THREAT_MODEL.md](THREAT_MODEL.md).

| Backend | Isolates | Does not isolate |
|---------|----------|------------------|
| `SubprocessRuntime` | Crashes, interpreter state (fresh process), caller memory (separate address space) | Filesystem, network, environment, uid, resource use, process tree on timeout, output volume (the returned string is truncated at 64 KB, but the whole stream is buffered in the parent first) |
| `IpcSubprocessRuntime` | Same | Same, and every tool call runs with the main process's full authority |
| `ContainerRuntime` — **target, 0.4.0, not shipped** | Nothing yet; the design targets filesystem, network, PIDs, and resource limits | — |

`Validator` implementations are advisory: they catch accidents and steer the model's behaviour, and a determined author bypasses them in one line. In PTC the capability boundary is the injected tool namespace plus the process or container the code runs in — never the code check.

## Namespace injection (Python only)

Inject callables into the execution namespace. In subprocess mode, they're available as stubs for discovery:

```python
def search(query: str) -> list:
    """Search for documents."""
    ...

result = py.execute(
    "print('search' in dir())",
    namespace={"search": search},
)
# stdout: "True"
```

## API

### `SubprocessRuntime(validator)`

Execute code in a subprocess. The validator provides language identity and code validation.

#### `runtime.execute(code, *, namespace=None, timeout=None) -> CodeResult`

| Parameter | Type | Description |
|-----------|------|-------------|
| `code` | `str` | Source code to execute |
| `namespace` | `dict[str, Callable] \| None` | Callables to inject (Python only) |
| `timeout` | `float \| None` | Max seconds before kill |

### `CodeResult`

| Field | Type | Description |
|-------|------|-------------|
| `stdout` | `str` | Captured standard output (truncated at 64 KB) |
| `stderr` | `str` | Captured standard error |
| `return_code` | `int` | Exit code, `-1` for timeout |
| `timed_out` | `bool` | Whether killed by timeout |

### Validators

| Validator | Security level | Language |
|-----------|---------------|----------|
| `PythonValidator` | Advisory (AST allow-list, bypassable) | Python |
| `BashValidator` | Advisory (regex deny-list); removed in 0.3.0 | Bash |
| `NullValidator(lang)` | None — trusted code only | Any |

## License

MIT
