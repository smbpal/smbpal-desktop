r"""Checks on the source itself, not on what it does.

This exists because of one that got through: `"\;"` in a test fixture is not a
valid escape sequence, so Python kept it as a literal backslash-semicolon and
the test passed — while emitting a SyntaxWarning that says the behaviour will
change. It surfaced only when the suite was first run on the Pi, because the
warning fires once per compilation and a warm `__pycache__` hides it.

A warning nobody sees is a warning that does nothing.

The second check is here for the same reason. A test class redefined under a
name already used in the module silently replaces the first — Python does not
complain, `unittest` never sees the original, and the suite goes *green with
fewer tests in it*. That happened while adding two tests to `test_mounts.py`:
seven existing ones disappeared and everything still passed. The only signal
was the total dropping, which nothing was watching.
"""

from __future__ import annotations

import ast
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestSourceCompilesCleanly(unittest.TestCase):
    def test_no_file_raises_a_syntax_warning(self) -> None:
        # The builtin compile() rather than py_compile: it writes nothing, and
        # SyntaxWarning promoted to an error catches invalid escapes, `is`
        # against a literal, and whatever Python decides to warn about later.
        failures: list[str] = []
        paths = sorted((ROOT / "smbpal").rglob("*.py")) + sorted(
            (ROOT / "tests").rglob("*.py")
        )
        self.assertGreater(len(paths), 20, "found suspiciously few source files")
        for path in paths:
            with warnings.catch_warnings():
                warnings.simplefilter("error", SyntaxWarning)
                try:
                    compile(path.read_text(encoding="utf-8"), str(path), "exec")
                except (SyntaxError, SyntaxWarning) as exc:
                    failures.append(f"{path.relative_to(ROOT)}: {exc}")
        self.assertEqual(failures, [], "\n" + "\n".join(failures))


class TestNoNameIsDefinedTwice(unittest.TestCase):
    def test_no_module_redefines_a_top_level_name(self) -> None:
        """A redefined class or function deletes the first one, silently.

        In test modules that deletes tests. Anywhere else it deletes behaviour.
        Either way nothing fails, which is what makes it worth a check.
        """
        failures: list[str] = []
        paths = sorted((ROOT / "smbpal").rglob("*.py")) + sorted(
            (ROOT / "tests").rglob("*.py")
        )
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            seen: dict[str, int] = {}
            for node in tree.body:
                if not isinstance(
                    node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    continue
                first = seen.get(node.name)
                if first is not None:
                    failures.append(
                        f"{path.relative_to(ROOT)}: {node.name} defined at line "
                        f"{first} and again at line {node.lineno} — the first "
                        f"one is discarded"
                    )
                seen[node.name] = node.lineno
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_no_class_defines_a_method_twice(self) -> None:
        # The same trap one level down, and the more likely one in a long test
        # class: two tests with the same name means one of them never runs.
        failures: list[str] = []
        for path in sorted((ROOT / "tests").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                seen: dict[str, int] = {}
                for item in node.body:
                    if not isinstance(
                        item, (ast.FunctionDef, ast.AsyncFunctionDef)
                    ):
                        continue
                    first = seen.get(item.name)
                    if first is not None:
                        failures.append(
                            f"{path.relative_to(ROOT)}: {node.name}.{item.name} "
                            f"defined at lines {first} and {item.lineno}"
                        )
                    seen[item.name] = item.lineno
        self.assertEqual(failures, [], "\n" + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
