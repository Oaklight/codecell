# Migration notes

## 0.3.0

### `codecell.bash` and `BashValidator` removed

The bash backend had no consumer and had drifted from
[`Oaklight/bashtool`](https://github.com/Oaklight/bashtool). Shell execution policy lives
there and in `toolregistry-hub`'s vendored copy. ToolRegistry core's `ptc` extra already
imports only `IpcSubprocessRuntime` and `PythonValidator`.

```python
# before
from codecell import SubprocessRuntime
from codecell.bash import BashValidator
runtime = SubprocessRuntime(BashValidator())

# after
from bashtool import ...  # or the toolregistry-hub wrapper
```

### `SubprocessRuntime` no longer injects namespace stubs

Passing `namespace` to `SubprocessRuntime` used to define stubs that raised
`NotImplementedError` when called. That half-mode is gone: the runtime now raises
`NotImplementedError` immediately with a pointer to the IPC runtime.

```python
# before: appeared to work, failed at call time
runtime = SubprocessRuntime(PythonValidator())
runtime.execute("search(query='x')", namespace={"search": search})

# after
runtime = IpcSubprocessRuntime(PythonValidator())
runtime.execute("search(query='x')", namespace={"search": search})
```

### IPC protocol is v1

Every frame carries `protocol: 1`; a custom protocol implementation must send it and
reject other versions. Tool calls accept positional and keyword arguments, and arguments
and results use the `codecell._wire` codec. Unencodable values raise `CodecError` (a
`TypeError` subclass) rather than reporting a successful tool call as failed.
