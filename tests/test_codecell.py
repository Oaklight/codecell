"""Tests for codecell package."""

import pytest

from codecell import CodeResult, NullValidator, SubprocessRuntime
from codecell.python import PythonValidator

# ---------------------------------------------------------------------------
# CodeResult
# ---------------------------------------------------------------------------


class TestCodeResult:
    def test_defaults(self):
        r = CodeResult()
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.return_code == 0
        assert r.timed_out is False

    def test_frozen(self):
        r = CodeResult()
        with pytest.raises(AttributeError):
            r.stdout = "mutate"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class TestValidators:
    def test_python_validator_lang(self):
        v = PythonValidator()
        assert v.lang == "python"
        assert "python" in v.interpreter[0] or v.interpreter[0].endswith("python3")

    def test_null_validator(self):
        v = NullValidator("python")
        assert v.lang == "python"
        v.validate("import os; os.system('rm -rf /')")  # no-op


# ---------------------------------------------------------------------------
# Python Runtime
# ---------------------------------------------------------------------------


class TestPythonRuntime:
    def setup_method(self):
        self.runtime = SubprocessRuntime(PythonValidator())

    def test_print(self):
        result = self.runtime.execute("print('hello')")
        assert result.stdout.strip() == "hello"
        assert result.return_code == 0

    def test_multiline(self):
        result = self.runtime.execute("x = 10\ny = 20\nprint(x + y)")
        assert result.stdout.strip() == "30"

    def test_allowed_import(self):
        result = self.runtime.execute("import json; print(json.dumps({'a': 1}))")
        assert result.return_code == 0
        assert '"a": 1' in result.stdout

    def test_math(self):
        result = self.runtime.execute("import math; print(math.pi)")
        assert "3.14" in result.stdout

    def test_runtime_error(self):
        result = self.runtime.execute("1 / 0")
        assert result.return_code != 0
        assert "ZeroDivisionError" in result.stderr

    def test_syntax_error(self):
        with pytest.raises(SyntaxError):
            self.runtime.execute("def")

    def test_timeout(self):
        result = self.runtime.execute("import time; time.sleep(10)", timeout=1)
        assert result.timed_out is True
        assert result.return_code == -1

    def test_empty_code(self):
        result = self.runtime.execute("")
        assert result.return_code == 0

    def test_function_definition(self):
        code = (
            "def fib(n):\n"
            "    a, b = 0, 1\n"
            "    for _ in range(n):\n"
            "        a, b = b, a+b\n"
            "    return a\n"
            "print(fib(10))"
        )
        result = self.runtime.execute(code)
        assert result.stdout.strip() == "55"

    def test_namespace_requires_ipc(self):
        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        with pytest.raises(NotImplementedError, match="IpcSubprocessRuntime"):
            self.runtime.execute("print('add' in dir())", namespace={"add": add})

    def test_truncation(self):
        result = self.runtime.execute("print('x' * 500_000)", timeout=5)
        assert "[output truncated]" in result.stdout


# ---------------------------------------------------------------------------
# Python validation
# ---------------------------------------------------------------------------


class TestPythonValidation:
    @pytest.mark.parametrize(
        "code",
        [
            "print(1 + 2)",
            "import math; print(math.sqrt(16))",
            "import json; print(json.dumps([1, 2]))",
            "x = [i**2 for i in range(10)]; print(x)",
            "open_file_count = 5; print(open_file_count)",
            "x = 'import os; os.system(rm)'; print(len(x))",
            "# open('/etc/passwd')\nprint('safe')",
        ],
    )
    def test_safe_code(self, code):
        PythonValidator().validate(code)

    @pytest.mark.parametrize(
        "code,reason",
        [
            ("open('/etc/passwd')", "Blocked built-in call: open"),
            ("exec('print(1)')", "Blocked built-in call: exec"),
            ("eval('1+1')", "Blocked built-in call: eval"),
            ("__import__('os')", "Blocked built-in call: __import__"),
            ("import os\nos.system('ls')", "Blocked"),
            ("import os", "Import not allowed: 'os'"),
            ("import sys", "Import not allowed: 'sys'"),
            ("import subprocess", "Import not allowed: 'subprocess'"),
            ("import socket", "Import not allowed: 'socket'"),
            ("import ctypes", "Import not allowed: 'ctypes'"),
        ],
    )
    def test_dangerous_code(self, code, reason):
        with pytest.raises(ValueError, match=reason):
            PythonValidator().validate(code)

    def test_multiple_violations(self):
        with pytest.raises(ValueError) as exc_info:
            PythonValidator().validate("import os\nimport subprocess\nopen('x')")
        msg = str(exc_info.value)
        assert "os" in msg
        assert "subprocess" in msg
        assert "open" in msg


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


class TestIsolation:
    def test_infinite_loop(self):
        runtime = SubprocessRuntime(PythonValidator())
        result = runtime.execute("while True: pass", timeout=1)
        assert result.timed_out is True

    def test_lang_inferred(self):
        py = SubprocessRuntime(PythonValidator())
        assert py.lang == "python"
