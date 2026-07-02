"""Bash language support for codecell."""

from ._validator import DANGER_PATTERNS, BashValidator

__all__ = ["BashValidator", "DANGER_PATTERNS"]
