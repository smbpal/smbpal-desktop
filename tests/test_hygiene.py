r"""Checks on the source itself, not on what it does.

This exists because of one that got through: `"\;"` in a test fixture is not a
valid escape sequence, so Python kept it as a literal backslash-semicolon and
the test passed — while emitting a SyntaxWarning that says the behaviour will
change. It surfaced only when the suite was first run on the Pi, because the
warning fires once per compilation and a warm `__pycache__` hides it.

A warning nobody sees is a warning that does nothing.
"""

from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
