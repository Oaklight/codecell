"""Regex-based Bash command validator.

Checks commands against a deny list of known-dangerous patterns
before execution.  This is best-effort — it reduces risk but does
NOT provide sandbox-level guarantees.
"""

from __future__ import annotations

import re

from .._runtime import Validator

# Each entry is (compiled_regex, human-readable reason).
# Patterns are checked against each segment after splitting on
# shell operators (&&, ||, ;).
DANGER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # -- Destructive filesystem operations --
    (
        re.compile(
            r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+[/~*]"
            r"|\brm\s+.*-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+[/~*]"
        ),
        "Recursive forced deletion of root, home, or wildcard paths",
    ),
    (re.compile(r"\bmkfs\b"), "Filesystem formatting"),
    (re.compile(r"\bdd\s+.*\bif="), "Raw disk image write"),
    (re.compile(r">\s*/dev/sd[a-z]"), "Device overwrite"),
    # -- Privilege escalation --
    (re.compile(r"\bsudo\b"), "Privilege escalation via sudo"),
    (re.compile(r"\bsu\s+-"), "User switching via su"),
    (
        re.compile(r"\bchmod\s+.*-[a-zA-Z]*R.*\b777\b.*\s+/"),
        "Recursive world-writable permission on root",
    ),
    (re.compile(r"\bchown\s+.*-[a-zA-Z]*R"), "Recursive ownership change"),
    # -- Code injection --
    (re.compile(r"\beval\b"), "Arbitrary code evaluation"),
    (re.compile(r"\bexec\b"), "Process replacement via exec"),
    # -- Fork bomb --
    (re.compile(r":\(\)\s*\{.*:\|:.*\}"), "Fork bomb"),
    # -- Git destructive operations --
    (re.compile(r"\bgit\s+push\s+.*--force\b"), "Force push"),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "Hard reset"),
    (re.compile(r"\bgit\s+clean\s+.*-[a-zA-Z]*f"), "Force clean"),
    # -- System control --
    (re.compile(r"\bshutdown\b"), "System shutdown"),
    (re.compile(r"\breboot\b"), "System reboot"),
    (re.compile(r"\bhalt\b"), "System halt"),
    (re.compile(r"\bkill\s+.*-9\s+1\b"), "Killing init process"),
]

# Pipe-to-shell: checked on the full (unsplit) command.
_PIPE_EXEC_RE = re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:bash|sh|zsh|dash)\b")

# Shell operator split (&&, ||, ;).
_OPERATOR_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;)\s*")


class BashValidator(Validator):
    """Regex-based Bash command validator.

    Checks commands against a deny list of known-dangerous patterns.

    Warning:
        This is best-effort risk reduction, **not** a sandbox.  It
        blocks obvious destructive commands but cannot guarantee
        safety against all possible inputs.
    """

    @property
    def lang(self) -> str:
        return "bash"

    @property
    def interpreter(self) -> list[str]:
        return ["bash", "-c"]

    def validate(self, code: str) -> None:
        """Validate a shell command against the deny list.

        Args:
            code: Raw shell command string.

        Raises:
            ValueError: If the command matches a dangerous pattern.
        """
        # 1. Pipe-to-shell check on the full command
        if _PIPE_EXEC_RE.search(code):
            raise ValueError("Dangerous command blocked: pipe-to-shell execution detected")

        # 2. Segment by shell operators and check each part
        segments = _OPERATOR_SPLIT_RE.split(code)
        for segment in segments:
            stripped = segment.strip()
            if not stripped:
                continue
            for pattern, reason in DANGER_PATTERNS:
                if pattern.search(stripped):
                    raise ValueError(f"Dangerous command blocked: {reason}")
