"""Tests for issue #7: positional args, codec, __name__, and protocol v1."""

from __future__ import annotations

import pytest

from codecell import (
    MAX_TOOL_VALUE_BYTES,
    CodecError,
    IpcSubprocessRuntime,
    NullValidator,
    SubprocessRuntime,
)


@pytest.fixture
def runtime():
    return IpcSubprocessRuntime(NullValidator("python"))


def test_positional_arguments(runtime):
    def add(a, b):
        return a + b

    result = runtime.execute("print(add(3, 4))", namespace={"add": add})
    assert result.return_code == 0
    assert result.stdout.strip() == "7"

    result = runtime.execute("print(add(3, b=4))", namespace={"add": add})
    assert result.return_code == 0
    assert result.stdout.strip() == "7"


def test_arguments_roundtrip_codec_types(runtime):
    def describe(when, tags):
        return [type(when).__name__, sorted(tags), when.year]

    code = "from datetime import datetime\nprint(describe(datetime(2026, 5, 6), {'b', 'a'}))"
    result = runtime.execute(code, namespace={"describe": describe})
    assert result.return_code == 0
    assert "datetime" in result.stdout
    assert "['a', 'b']" in result.stdout
    assert "2026" in result.stdout


def test_results_roundtrip_codec_types(runtime):
    def echo(*args):
        return list(args)

    code = (
        "from datetime import datetime, timedelta\n"
        "from decimal import Decimal\n"
        "from pathlib import Path\n"
        "from uuid import UUID\n"
        "vals = echo(\n"
        "    datetime(2026, 1, 2, 3, 4, 5),\n"
        "    timedelta(seconds=90),\n"
        "    Decimal('1.25'),\n"
        "    UUID('12345678-1234-5678-1234-567812345678'),\n"
        "    Path('/tmp/x'),\n"
        "    b'hi\\x00',\n"
        "    frozenset({1, 2}),\n"
        "    bytearray(b'ab'),\n"
        ")\n"
        "print([type(v).__name__ for v in vals])\n"
        "print(vals[0].isoformat(), vals[1].total_seconds(), str(vals[2]))\n"
        "print(str(vals[3]), str(vals[4]))\n"
        "print(vals[5] == b'hi\\x00', sorted(vals[6]), bytes(vals[7]))\n"
    )
    result = runtime.execute(code, namespace={"echo": echo}, timeout=10)
    assert result.return_code == 0, result.stderr
    assert "datetime" in result.stdout
    assert "timedelta" in result.stdout
    assert "Decimal" in result.stdout
    assert "UUID" in result.stdout
    assert "Path" in result.stdout
    assert "2026-01-02T03:04:05 90.0 1.25" in result.stdout
    assert "12345678-1234-5678-1234-567812345678 /tmp/x" in result.stdout
    assert "True [1, 2] b'ab'" in result.stdout


def test_unencodable_result_raises_codec_error(runtime):
    class Opaque:
        pass

    def make_opaque():
        return Opaque()

    code = (
        "try:\n"
        "    make_opaque()\n"
        "except Exception as exc:\n"
        "    print(type(exc).__name__)\n"
        "    print('cannot encode' in str(exc))\n"
    )
    result = runtime.execute(code, namespace={"make_opaque": make_opaque})
    assert result.return_code == 0, result.stderr
    assert "CodecError" in result.stdout
    assert "True" in result.stdout


def test_oversized_result_is_a_codec_error(runtime):
    def big():
        return "x" * (MAX_TOOL_VALUE_BYTES + 1)

    code = (
        "try:\n"
        "    big()\n"
        "except Exception as exc:\n"
        "    print(type(exc).__name__)\n"
        "    print('limit' in str(exc))\n"
    )
    result = runtime.execute(code, namespace={"big": big}, timeout=10)
    assert result.return_code == 0, result.stderr
    assert "CodecError" in result.stdout
    assert "True" in result.stdout


def test_oversized_argument_is_a_codec_error(runtime):
    def echo(value):
        return value

    code = (
        "try:\n"
        f"    echo('x' * {MAX_TOOL_VALUE_BYTES + 1})\n"
        "except Exception as exc:\n"
        "    print(type(exc).__name__)\n"
        "    print('limit' in str(exc))\n"
    )
    result = runtime.execute(code, namespace={"echo": echo}, timeout=10)
    assert result.return_code == 0, result.stderr
    assert "CodecError" in result.stdout
    assert "True" in result.stdout


@pytest.mark.parametrize("kind", ["subprocess", "ipc"])
def test_name_is_main(kind):
    if kind == "subprocess":
        runtime = SubprocessRuntime(NullValidator("python"))
    else:
        runtime = IpcSubprocessRuntime(NullValidator("python"))
    result = runtime.execute("print(__name__)")
    assert result.return_code == 0
    assert result.stdout.strip() == "__main__"


def test_protocol_mismatch_is_reported(monkeypatch):
    import codecell._runtime as runtime_module

    monkeypatch.setattr(runtime_module, "PROTOCOL_VERSION", 2)
    result = IpcSubprocessRuntime(NullValidator("python")).execute("print('never')")
    assert result.return_code == 1
    assert "Protocol mismatch" in result.stderr


def test_concurrent_tool_calls_are_serialized(runtime):
    def add(a, b):
        return a + b

    code = (
        "import threading\n"
        "out = []\n"
        "lock = threading.Lock()\n"
        "def worker(n):\n"
        "    for i in range(20):\n"
        "        value = add(a=n, b=i)\n"
        "        with lock:\n"
        "            out.append(value)\n"
        "threads = [threading.Thread(target=worker, args=(n,)) for n in range(2)]\n"
        "for thread in threads:\n"
        "    thread.start()\n"
        "for thread in threads:\n"
        "    thread.join()\n"
        "print(len(out), sum(out))\n"
    )
    result = runtime.execute(code, namespace={"add": add}, timeout=10)
    assert result.return_code == 0, result.stderr
    assert result.stdout.strip() == "40 400"


def test_codec_error_is_exported():
    assert issubclass(CodecError, TypeError)


def test_child_imports_parent_package_tree(monkeypatch, tmp_path):
    """A shadow package in the caller's cwd must not replace the bootstrap."""
    shadow = tmp_path / "codecell"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("raise RuntimeError('shadow codecell imported')\n")
    monkeypatch.chdir(tmp_path)
    result = IpcSubprocessRuntime(NullValidator("python")).execute("print('ok')")
    assert result.return_code == 0, result.stderr
    assert result.stdout.strip() == "ok"
