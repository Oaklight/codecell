"""Shared result types for code execution."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CodeResult:
    """Structured result from code execution.

    Attributes:
        stdout: Captured standard output from the executed code.
        stderr: Content the code wrote to standard error during execution.
        return_code: Process exit code.  ``0`` for success, non-zero for
            failure, ``-1`` for timeout.
        timed_out: Whether the process was killed due to timeout.
    """

    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    timed_out: bool = False
