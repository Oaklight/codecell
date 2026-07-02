# codecell

Stateless, subprocess-isolated code execution for LLM agents. Zero dependencies.

> Unlike a Jupyter cell, there's no shared kernel — each call runs in a fresh subprocess with only the tools you inject.

**Scope:** codecell is intentionally limited to sandboxed code evaluation — safe computation and namespace-based tool invocation. It is not a full runtime or a general-purpose execution engine. Features like stateful sessions, IPC-based tool calling, and container isolation may be added in future versions.

## Quick start

```python
from codecell import SubprocessRuntime
from codecell.python import PythonValidator

runtime = SubprocessRuntime(PythonValidator())
result = runtime.execute("print(1 + 2)", timeout=10)
print(result.stdout)  # "3\n"
```

## Languages

### Python (sandboxed)

AST-validated — blocks file I/O, network, command execution, dynamic imports. Only safe computation modules allowed.

```python
from codecell import SubprocessRuntime
from codecell.python import PythonValidator

py = SubprocessRuntime(PythonValidator())

# Safe computation works
py.execute("import math; print(math.sqrt(16))")

# Dangerous code is rejected before execution
py.execute("import os; os.system('rm -rf /')")  # raises ValueError
```

### Bash (deny-list)

Regex-based deny list blocks known-dangerous patterns. **Not a sandbox** — reduces risk but cannot guarantee safety.

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
| `PythonValidator` | Strong (AST analysis) | Python |
| `BashValidator` | Best-effort (regex deny-list) | Bash |
| `NullValidator(lang)` | None — trusted code only | Any |

## License

MIT
