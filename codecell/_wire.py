"""Shared wire protocol constants and the tool-value codec.

Both sides of the IPC channel import this module, so a value encoded on
one side decodes to the same type on the other.  Only JSON-native values
are passed through untouched; a small set of common Python types gets a
tagged representation.  Anything else raises :class:`CodecError` instead
of being reported as a tool failure.
"""

from __future__ import annotations

import base64
import json
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

PROTOCOL_VERSION = 1

#: Largest encoded tool argument or result the wire accepts.
MAX_TOOL_VALUE_BYTES = 1_048_576

_TAG = "$codecell"
_ENCODABLE = "datetime, date, time, timedelta, Decimal, UUID, Path, set, frozenset, bytes"


class CodecError(TypeError):
    """A value cannot be represented on the wire."""


def _default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return {_TAG: "datetime", "value": obj.isoformat()}
    if isinstance(obj, date):
        return {_TAG: "date", "value": obj.isoformat()}
    if isinstance(obj, time):
        return {_TAG: "time", "value": obj.isoformat()}
    if isinstance(obj, timedelta):
        return {_TAG: "timedelta", "value": obj.total_seconds()}
    if isinstance(obj, Decimal):
        return {_TAG: "decimal", "value": str(obj)}
    if isinstance(obj, UUID):
        return {_TAG: "uuid", "value": str(obj)}
    if isinstance(obj, Path):
        return {_TAG: "path", "value": str(obj)}
    if isinstance(obj, frozenset):
        return {_TAG: "frozenset", "value": sorted(obj, key=repr)}
    if isinstance(obj, set):
        return {_TAG: "set", "value": sorted(obj, key=repr)}
    if isinstance(obj, bytearray):
        return {
            _TAG: "bytearray",
            "value": base64.b64encode(bytes(obj)).decode("ascii"),
        }
    if isinstance(obj, bytes):
        return {_TAG: "bytes", "value": base64.b64encode(obj).decode("ascii")}
    raise CodecError(
        f"cannot encode {type(obj).__name__} on the wire; "
        f"return a JSON-native value or one of: {_ENCODABLE}"
    )


def _hook(obj: dict[str, Any]) -> Any:
    tag = obj.get(_TAG)
    if not isinstance(tag, str) or set(obj) != {_TAG, "value"}:
        return obj
    value = obj["value"]
    try:
        if tag == "datetime":
            return datetime.fromisoformat(value)
        if tag == "date":
            return date.fromisoformat(value)
        if tag == "time":
            return time.fromisoformat(value)
        if tag == "timedelta":
            return timedelta(seconds=float(value))
        if tag == "decimal":
            return Decimal(value)
        if tag == "uuid":
            return UUID(value)
        if tag == "path":
            return Path(value)
        if tag == "frozenset":
            return frozenset(value)
        if tag == "set":
            return set(value)
        if tag == "bytearray":
            return bytearray(base64.b64decode(value))
        if tag == "bytes":
            return base64.b64decode(value)
    except (TypeError, ValueError) as exc:
        raise CodecError(f"invalid {tag} value on the wire: {exc}") from exc
    return obj


def dumps(value: Any, *, max_bytes: int | None = None) -> str:
    """Serialize *value* as one JSON line, enforcing an optional byte limit.

    The limit applies to tool arguments and results, not to protocol
    frames such as ``done`` that legitimately carry large captured output.
    """
    text = json.dumps(value, default=_default)
    if max_bytes is not None:
        size = len(text.encode("utf-8"))
        if size > max_bytes:
            raise CodecError(f"encoded payload is {size} bytes, limit is {max_bytes} bytes")
    return text


def loads(text: str) -> Any:
    """Parse one JSON line, restoring codec-tagged values."""
    return json.loads(text, object_hook=_hook)
