"""Tests for IpcSubprocessRuntime — bidirectional IPC tool calling."""

import pytest

from codecell import IpcSubprocessRuntime
from codecell.python import PythonValidator


@pytest.fixture
def runtime():
    return IpcSubprocessRuntime(PythonValidator())


class TestIpcBasicExecution:
    def test_print(self, runtime):
        result = runtime.execute("print('hello')")
        assert result.stdout.strip() == "hello"
        assert result.return_code == 0
        assert result.timed_out is False

    def test_multiline(self, runtime):
        result = runtime.execute("x = 10\ny = 20\nprint(x + y)")
        assert result.stdout.strip() == "30"

    def test_allowed_import(self, runtime):
        result = runtime.execute("import json; print(json.dumps({'a': 1}))")
        assert result.return_code == 0
        assert '"a": 1' in result.stdout

    def test_runtime_error(self, runtime):
        result = runtime.execute("1 / 0")
        assert result.return_code != 0
        assert "ZeroDivisionError" in result.stderr

    def test_empty_code(self, runtime):
        result = runtime.execute("")
        assert result.return_code == 0

    def test_validation_rejects_dangerous(self, runtime):
        with pytest.raises(ValueError, match="Import not allowed"):
            runtime.execute("import os; os.system('ls')")


class TestIpcToolCalling:
    def test_single_tool_call(self, runtime):
        def add(a: int, b: int) -> int:
            return a + b

        result = runtime.execute(
            "print(add(a=3, b=4))",
            namespace={"add": add},
        )
        assert result.stdout.strip() == "7"

    def test_multiple_tool_calls(self, runtime):
        def add(a: int, b: int) -> int:
            return a + b

        def multiply(a: int, b: int) -> int:
            return a * b

        code = "s = add(a=10, b=20)\np = multiply(a=s, b=3)\nprint(f'sum={s}, product={p}')"
        result = runtime.execute(code, namespace={"add": add, "multiply": multiply})
        assert "sum=30" in result.stdout
        assert "product=90" in result.stdout

    def test_tool_return_string(self, runtime):
        def greet(name: str) -> str:
            return f"Hello, {name}!"

        result = runtime.execute(
            "print(greet(name='World'))",
            namespace={"greet": greet},
        )
        assert result.stdout.strip() == "Hello, World!"

    def test_tool_return_dict(self, runtime):
        def get_data() -> dict:
            return {"key": "value", "count": 42}

        result = runtime.execute(
            "import json; d = get_data(); print(json.dumps(d))",
            namespace={"get_data": get_data},
        )
        assert '"key": "value"' in result.stdout

    def test_tool_return_list(self, runtime):
        def get_items() -> list:
            return [1, 2, 3]

        result = runtime.execute(
            "items = get_items(); print(sum(items))",
            namespace={"get_items": get_items},
        )
        assert result.stdout.strip() == "6"

    def test_tool_error_propagates(self, runtime):
        def failing_tool(x: int) -> int:
            raise ValueError("broken")

        result = runtime.execute(
            "try:\n    failing_tool(x=1)\nexcept RuntimeError:\n    print('caught')",
            namespace={"failing_tool": failing_tool},
        )
        assert result.stdout.strip() == "caught"

    def test_loop_with_tool_calls(self, runtime):
        def add(a: int, b: int) -> int:
            return a + b

        code = (
            "results = []\n"
            "for i in range(5):\n"
            "    results.append(add(a=i, b=i*10))\n"
            "print(results)"
        )
        result = runtime.execute(code, namespace={"add": add})
        assert "[0, 11, 22, 33, 44]" in result.stdout

    def test_no_namespace(self, runtime):
        result = runtime.execute("print(42)")
        assert result.stdout.strip() == "42"


class TestIpcIsolation:
    def test_timeout(self, runtime):
        result = runtime.execute("while True: pass", timeout=2)
        assert result.timed_out is True
        assert result.return_code == -1

    def test_crash_contained(self):
        """Subprocess crash doesn't affect main process."""
        from codecell import IpcSubprocessRuntime, NullValidator

        unsafe = IpcSubprocessRuntime(NullValidator("python"))
        result = unsafe.execute("import ctypes; ctypes.string_at(0)", timeout=5)
        assert result.return_code != 0
        assert result.timed_out is False

    def test_main_process_survives(self, runtime):
        """After a crash/timeout, runtime is still usable."""
        runtime.execute("while True: pass", timeout=2)
        result = runtime.execute("print('alive')")
        assert result.stdout.strip() == "alive"
