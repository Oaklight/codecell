"""Base runtime and validator abstractions.

Defines the ABC for code execution runtimes and validators.
Language-specific implementations (Python, Bash) inherit from these
and provide their own validation logic and interpreter invocation.
"""

from __future__ import annotations

import subprocess
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from ._types import CodeResult

# Maximum bytes kept for stdout / stderr to prevent memory exhaustion.
MAX_OUTPUT_BYTES = 65_536  # 64 KB


def truncate(text: str, max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    """Truncate *text* to at most *max_bytes* UTF-8 bytes.

    If truncation occurs, a marker is appended so the caller knows the
    output was clipped.

    Args:
        text: The string to truncate.
        max_bytes: Maximum number of UTF-8 bytes allowed.

    Returns:
        The (possibly truncated) string.
    """
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated + "\n... [output truncated]"


class Validator(ABC):
    """Base class for code validators.

    Each validator is the single source of truth for its language:
    it provides the language name, the interpreter command, and the
    validation logic.  The runtime infers everything from the validator.
    """

    @property
    @abstractmethod
    def lang(self) -> str:
        """Language identifier (e.g. ``"python"``, ``"bash"``)."""
        ...

    @property
    @abstractmethod
    def interpreter(self) -> list[str]:
        """Command to invoke the interpreter (e.g. ``[sys.executable, "-c"]``)."""
        ...

    @abstractmethod
    def validate(self, code: str) -> None:
        """Validate code before execution.

        Args:
            code: Source code string.

        Raises:
            ValueError: If the code contains dangerous constructs.
            SyntaxError: If the code cannot be parsed.
        """
        ...


class NullValidator(Validator):
    """Validator that allows everything.  For trusted code only.

    Forces callers to make a deliberate security decision::

        runtime = SubprocessRuntime(NullValidator("python"))
    """

    def __init__(self, lang: str = "python") -> None:
        self._lang = lang

    @property
    def lang(self) -> str:
        return self._lang

    @property
    def interpreter(self) -> list[str]:
        if self._lang == "python":
            return [sys.executable, "-c"]
        if self._lang == "bash":
            return ["bash", "-c"]
        return [self._lang, "-c"]

    def validate(self, code: str) -> None:
        pass


class BaseRuntime(ABC):
    """Abstract base for code execution runtimes.

    Subclasses decide the isolation strategy (subprocess, container,
    etc.) and how namespace callables are made available to the
    executed code.

    The ``namespace`` is a plain ``dict[str, Callable]`` — this
    package has no knowledge of ``ToolProjection`` or ``ToolRegistry``.
    """

    def __init__(self, validator: Validator) -> None:
        self._validator = validator

    @property
    def lang(self) -> str:
        """Language of this runtime, inferred from the validator."""
        return self._validator.lang

    @abstractmethod
    def execute(
        self,
        code: str,
        *,
        namespace: dict[str, Callable[..., Any]] | None = None,
        timeout: float | None = None,
    ) -> CodeResult:
        """Execute code and return structured output.

        Args:
            code: Source code to execute.
            namespace: Mapping of name -> callable to inject into the
                execution namespace.  Support varies by language and
                runtime implementation.
            timeout: Maximum wall-clock seconds.  ``None`` means no limit.

        Returns:
            A :class:`CodeResult` with captured stdout, stderr, and
            exit information.
        """
        ...


class SubprocessRuntime(BaseRuntime):
    """Execute code in a subprocess for crash isolation.

    The code is validated via the provided :class:`Validator`, then run
    in a fresh interpreter process.  Crashes, infinite loops, and
    resource exhaustion cannot affect the calling process.

    Usage::

        from codecell import SubprocessRuntime
        from codecell.python import PythonValidator

        runtime = SubprocessRuntime(PythonValidator())
        result = runtime.execute("print(1 + 2)", timeout=10)
    """

    def execute(
        self,
        code: str,
        *,
        namespace: dict[str, Callable[..., Any]] | None = None,
        timeout: float | None = None,
    ) -> CodeResult:
        """Execute code in a subprocess.

        Args:
            code: Source code to execute.
            namespace: Mapping of name -> callable.  Currently supported
                for Python (injected as stubs); raises ``NotImplementedError``
                for other languages.
            timeout: Maximum wall-clock seconds before kill.

        Returns:
            A :class:`CodeResult` with captured output.

        Raises:
            ValueError: If validation rejects the code.
            SyntaxError: If the code cannot be parsed.
            NotImplementedError: If namespace is passed for a language
                that doesn't support it.
        """
        self._validator.validate(code)

        script = self._build_script(code, namespace)

        try:
            result = subprocess.run(
                [*self._validator.interpreter, script],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return CodeResult(
                stdout=truncate(result.stdout),
                stderr=truncate(result.stderr),
                return_code=result.returncode,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout
            stderr = exc.stderr
            return CodeResult(
                stdout=truncate(stdout if isinstance(stdout, str) else ""),
                stderr=truncate(stderr if isinstance(stderr, str) else ""),
                return_code=-1,
                timed_out=True,
            )

    def _build_script(
        self,
        code: str,
        namespace: dict[str, Callable[..., Any]] | None,
    ) -> str:
        """Build the full script, prepending namespace stubs if needed."""
        if not namespace:
            return code

        if self.lang != "python":
            raise NotImplementedError(
                f"Namespace injection is not supported for {self.lang!r}. "
                "Only Python runtimes support callable namespace."
            )

        import json

        stubs: list[str] = []
        for name, fn in namespace.items():
            doc = getattr(fn, "__doc__", None) or f"Stub for {name}"
            doc_escaped = json.dumps(doc)
            stubs.append(
                f"def {name}(**kwargs):\n"
                f"    {doc_escaped}\n"
                f"    raise NotImplementedError("
                f"'Cannot call {name}() in subprocess mode')\n"
            )

        preamble = "\n".join(stubs)
        return preamble + "\n" + code
