"""codecell — stateless, subprocess-isolated code execution for LLM agents.

Unlike a Jupyter cell, there's no shared kernel — each call runs in a
fresh subprocess with only the tools you inject.

Quick start::

    from codecell import SubprocessRuntime
    from codecell.python import PythonValidator

    runtime = SubprocessRuntime(PythonValidator())
    result = runtime.execute("print(1 + 2)", timeout=10)
    print(result.stdout)  # "3\\n"
"""

from ._runtime import (
    MAX_OUTPUT_BYTES,
    BaseRuntime,
    IpcSubprocessRuntime,
    NullValidator,
    SubprocessRuntime,
    Validator,
    truncate,
)
from ._types import CodeResult

__version__ = "0.2.0"

__all__ = [
    "BaseRuntime",
    "CodeResult",
    "IpcSubprocessRuntime",
    "MAX_OUTPUT_BYTES",
    "NullValidator",
    "SubprocessRuntime",
    "Validator",
    "__version__",
    "truncate",
]
