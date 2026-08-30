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


class TestNoPrivateNamesReachAUser(unittest.TestCase):
    """A rule made on 27 August 2026: end users see `nas.local`, never a real
    machine from the author's network.

    It got in as a placeholder in the "Connect to a share" dialog, where a
    placeholder reads as a suggestion, and it was spotted on the Pi rather than
    in review. **Docstrings and comments are deliberately exempt**: two of them
    quote M0's actual `findmnt` output, and replacing a real capture with an
    invented one makes it a worse record. Nobody running SMBPal reads those.

    So this checks string *literals* only — the things that can be printed,
    logged, or drawn.
    """

    # Not secret; the git history is full of it and that was decided to be
    # fine. The rule is about what reaches a screen.
    PRIVATE = ("rivendell",)

    def test_no_string_literal_in_the_package_names_a_private_machine(self) -> None:
        for path in sorted((ROOT / "smbpal").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                if _is_docstring(tree, node):
                    continue
                for name in self.PRIVATE:
                    with self.subTest(file=path.name, line=node.lineno):
                        self.assertNotIn(
                            name,
                            node.value.lower(),
                            f"{path.relative_to(ROOT)}:{node.lineno} puts a real "
                            f"machine name somewhere a user could see it",
                        )


try:
    from gi.repository import Gio, GLib
except ImportError:  # pragma: no cover - a machine without python3-gi
    Gio = None
    GLib = None


@unittest.skipIf(Gio is None, "python3-gi is not installed")
class TestEveryGiNameExists(unittest.TestCase):
    """`Gio.BusNameOwnerFlags.REPLACE_EXISTING`, which does not exist.

    GLib spells that bit `REPLACE`; `REPLACE_EXISTING` is the D-Bus *wire*
    protocol's name for it, and both spellings read as obviously correct. The
    result was an `AttributeError` raised from `tray.main` before `loop.run`,
    so on 30 August 2026 the packaged tray died at startup on a Pi while two
    trays that had outlived earlier logins went on drawing icons — which looks
    exactly like the new single-instance guard failing rather than never having
    run at all.

    **Nothing in the suite could have caught it, and that is the point.** The
    tray's 22 tests call its handlers directly; `main` is wiring, it needs a
    session bus to run, and it is the one part of the module no test enters. A
    wrong attribute name there is invisible until a desktop starts it. This is
    the ninth defect in this project of the form *correct, tested code that
    something never reaches*, so the check is on the class and not on the line:
    every `Gio.x.y` and `GLib.x.y` written anywhere in the package has to
    resolve, whether or not a test ever executes that statement.
    """

    def _chain(self, node: ast.Attribute) -> list[str] | None:
        """`Gio.BusNameOwnerFlags.REPLACE` -> ['Gio', 'BusNameOwnerFlags', ...]."""
        parts: list[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name) or current.id not in ("Gio", "GLib"):
            return None
        parts.append(current.id)
        return list(reversed(parts))

    def test_every_attribute_the_package_asks_gi_for_resolves(self) -> None:
        modules = {"Gio": Gio, "GLib": GLib}
        missing: list[str] = []
        checked = 0
        for path in sorted((ROOT / "smbpal").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Attribute):
                    continue
                chain = self._chain(node)
                if chain is None:
                    continue
                checked += 1
                target: object = modules[chain[0]]
                for step in chain[1:]:
                    target = getattr(target, step, None)
                    if target is None:
                        missing.append(
                            f"{path.relative_to(ROOT)}:{node.lineno}: "
                            f"{'.'.join(chain)}"
                        )
                        break
        self.assertGreater(checked, 20, "found suspiciously few gi attributes")
        self.assertEqual(missing, [], "these names do not exist in gi:\n  " +
                         "\n  ".join(missing))


def _is_docstring(tree: ast.Module, node: ast.Constant) -> bool:
    """True for a module, class or function docstring anywhere in the tree."""
    for parent in ast.walk(tree):
        if not isinstance(
            parent, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        body = getattr(parent, "body", [])
        if (
            body
            and isinstance(body[0], ast.Expr)
            and body[0].value is node
        ):
            return True
    return False


if __name__ == "__main__":
    unittest.main()
