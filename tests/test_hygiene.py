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
import os
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


MAINTAINER_SCRIPTS = ("preinst", "postinst", "prerm", "postrm")


class TestTheMaintainerScripts(unittest.TestCase):
    """`#DEBHELPER#` written inside a comment, which is not a comment.

    debhelper substitutes that token textually wherever it appears and has no
    idea what a comment is. A sentence in `smbpal.prerm` mentioning the token
    by name got a multi-line snippet spliced into the middle of it: the leading
    `#` covered only the first line, the injected code ran unprotected, and the
    tail of the sentence became a command called `is`. Every install and every
    removal then failed with `prerm: 28: is: not found`, which names nothing
    that appears in the source.

    It also put `deb-systemd-invoke stop` above the `case` instead of below it,
    silently inverting the ordering the sentence was there to explain — so the
    same line broke the script *and* the design it documented.

    Nothing in this suite had ever looked at a maintainer script. These are
    plain `sh` and the smallest checks worth having: they parse, and the token
    appears once, alone on its line.
    """

    def scripts(self) -> list[Path]:
        found = [
            path
            for name in MAINTAINER_SCRIPTS
            for path in (ROOT / "packaging" / "debian").glob(f"*.{name}")
        ]
        self.assertTrue(found, "found no maintainer scripts to check")
        return sorted(found)

    def test_the_debhelper_token_is_never_embedded_in_a_line(self) -> None:
        offenders: list[str] = []
        for path in self.scripts():
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "#DEBHELPER#" in line and line.strip() != "#DEBHELPER#":
                    offenders.append(f"{path.name}:{number}: {line.strip()}")
        self.assertEqual(
            offenders,
            [],
            "the token is substituted textually, comment or not:\n  "
            + "\n  ".join(offenders),
        )

    def test_every_script_has_exactly_one_token(self) -> None:
        """None means debhelper appends its snippets at the end by default.

        That is a different bug and a quieter one: the stop would land after
        `teardown` rather than never running, and nothing would say so.
        """
        for path in self.scripts():
            with self.subTest(script=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(text.count("#DEBHELPER#"), 1)

    def test_every_script_parses_as_sh(self) -> None:
        """`sh -n`, because a maintainer script that will not parse takes the
        install down with it and dpkg reports the line, not the cause."""
        import subprocess

        for path in self.scripts():
            with self.subTest(script=path.name):
                result = subprocess.run(
                    ["sh", "-n", str(path)], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_script_is_executable(self) -> None:
        """dpkg runs them directly. A non-executable one fails the install."""
        for path in self.scripts():
            with self.subTest(script=path.name):
                self.assertTrue(os.access(path, os.X_OK), f"{path.name} is not +x")


def _in_a_git_checkout() -> bool:
    import subprocess

    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


@unittest.skipUnless(_in_a_git_checkout(), "not a git checkout")
class TestNothingTheBuildNeedsIsIgnored(unittest.TestCase):
    """A source file that `.gitignore` swallows, which is invisible twice over.

    `smbpal/mounts/credentials.py` was matched by `credentials.*` — a rule
    written to keep captured secrets out of a repository that §11.3 publishes
    with full history — and was ignored from 20 August 2026 for ten days. It
    never showed, because neither machine needed the repository to have it: the
    Mac wrote the file, and the Pi receives the tree by rsync, which does not
    read `.gitignore`. Every test passed on both. A clone could not import the
    daemon, the CLI or the GUI.

    That is the shape of the bug this whole file exists for — code that is
    correct and that something never reaches — and the reason it is worth a
    test rather than a fixed `.gitignore` is that the next rule to do it will
    be a different rule against a different file.
    """

    def ignored(self, paths: list[Path]) -> list[str]:
        """The ones git will not hand to a clone. Tracked files are exempt:
        a force-added file matches a pattern and is still in the repository."""
        import subprocess

        tracked = set(
            subprocess.run(
                ["git", "-C", str(ROOT), "ls-files"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.splitlines()
        )
        offenders = []
        for path in paths:
            relative = path.relative_to(ROOT).as_posix()
            if relative in tracked:
                continue
            check = subprocess.run(
                ["git", "-C", str(ROOT), "check-ignore", "-v", relative],
                capture_output=True,
                text=True,
            )
            for line in check.stdout.splitlines():
                # `-v` prints negations too, and a negation means *kept*.
                pattern = line.split("\t")[0].rsplit(":", 1)[-1]
                if not pattern.startswith("!"):
                    offenders.append(line.strip())
        return offenders

    def test_no_python_module_is_ignored(self) -> None:
        sources = [
            path
            for directory in ("smbpal", "tests")
            for path in (ROOT / directory).rglob("*.py")
            if "__pycache__" not in path.parts
        ]
        self.assertTrue(sources, "found no Python to check")
        self.assertEqual(
            self.ignored(sources),
            [],
            "these are on disk and will not reach a clone",
        )

    def test_everything_the_package_installs_is_in_the_repository(self) -> None:
        """`smbpal.install` names its sources by path. One of them being absent
        from a clone is a package that builds and ships less than it says."""
        listed = []
        install = ROOT / "packaging/debian/smbpal.install"
        for line in install.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            listed.append(ROOT / line.split()[0])
        self.assertTrue(listed, "smbpal.install names nothing")
        for path in listed:
            with self.subTest(path=path.name):
                self.assertTrue(path.exists(), f"{path} is named but does not exist")
        self.assertEqual(self.ignored(listed), [])


class TestTheShippedShellScripts(unittest.TestCase):
    """The scripts in `packaging/` that are not maintainer scripts.

    Same two failures as the maintainer scripts and the same two checks, for
    the same reason: a script that will not parse fails where it is run rather
    than where it is written, and CI is a slower place to find that out than
    here. `check-installed-size.sh` is also documented as something to run by
    hand, which needs the executable bit as much as CI does.
    """

    def scripts(self) -> list[Path]:
        found = sorted((ROOT / "packaging").glob("*.sh"))
        self.assertTrue(found, "found no shell scripts in packaging/")
        return found

    def test_every_script_parses_as_sh(self) -> None:
        import subprocess

        for path in self.scripts():
            with self.subTest(script=path.name):
                result = subprocess.run(
                    ["sh", "-n", str(path)], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_script_is_executable(self) -> None:
        for path in self.scripts():
            with self.subTest(script=path.name):
                self.assertTrue(os.access(path, os.X_OK), f"{path.name} is not +x")


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
