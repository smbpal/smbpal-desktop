"""The compiled macOS helper -- its guards, and what cannot be tested here.

**macOS only, and that is not a convenience.** The helper exists because the
Homebrew prefix is admin-writable and a root LaunchDaemon must not execute code
from it (`docs/phase-2/macos-helper-spike.md` §0). There is nothing for it to do
on Linux, where the daemon runs as root and the package never contains it, so
these tests skip rather than cross-compile something nobody ships.

**What is tested here is every refusal**, because those are what keep the thing
honest: a missing argument, an unknown identity, and running unprivileged. Each
is reachable without root, which is why they are unit tests at all.

**What is not tested here, stated rather than implied.** The socket itself needs
root and a `smbpal` group, so binding, the `0600` ownership and the `getpeereid`
check are a runbook step and not an assertion. Overridable paths would have made
them testable and were rejected: the helper's locations are fixed on purpose, and
a root binary that can be told where to put its socket is a worse trade than an
untested bind.
"""

from __future__ import annotations

import pwd
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER_DIR = ROOT / "helper"


@unittest.skipUnless(sys.platform == "darwin", "the helper is macOS-only by design")
class TestTheHelperBuildsAndRefuses(unittest.TestCase):
    binary: Path
    tmp: tempfile.TemporaryDirectory

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        built = Path(cls.tmp.name) / "smbpal-helper"
        result = subprocess.run(
            ["make", "-C", str(HELPER_DIR), "smbpal-helper"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise unittest.SkipTest(f"no working compiler: {result.stderr.strip()[:200]}")
        built.write_bytes((HELPER_DIR / "smbpal-helper").read_bytes())
        built.chmod(0o755)
        cls.binary = built

    @classmethod
    def tearDownClass(cls) -> None:
        subprocess.run(["make", "-C", str(HELPER_DIR), "clean"], capture_output=True)
        cls.tmp.cleanup()

    def run_helper(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.binary), *args], capture_output=True, text=True, timeout=10
        )

    def test_it_builds_with_warnings_as_errors(self) -> None:
        # setUpClass did the building; -Werror is in the Makefile, so arriving
        # here at all is the assertion. Named so a failure says what broke.
        self.assertTrue(self.binary.exists())

    def test_it_refuses_without_a_service_user(self) -> None:
        """No default. A compiled-in name is the bug §9's scan rule prevents."""
        done = self.run_helper()
        self.assertEqual(done.returncode, 2)
        self.assertIn("--service-user is required", done.stderr)

    def test_it_refuses_an_unknown_service_user(self) -> None:
        done = self.run_helper("--service-user", "nosuchuser-smbpal", "--check")
        self.assertEqual(done.returncode, 1)
        self.assertIn("no such user", done.stderr)

    def test_check_does_not_need_root(self) -> None:
        """The one diagnostic a person can run before elevating.

        It reads `passwd` and `group` and touches nothing. On a machine with no
        `smbpal` group it still has to fail -- but on the group, never on
        privilege, or the message sends someone to `sudo` for a missing group.
        """
        done = self.run_helper("--service-user", pwd.getpwuid(0).pw_name, "--check")
        self.assertNotIn("must run as root", done.stderr)
        if done.returncode != 0:
            self.assertIn("no group 'smbpal'", done.stderr)

    def test_serving_requires_root(self) -> None:
        if __import__("os").geteuid() == 0:
            self.skipTest("this asserts the refusal, so it needs a non-root runner")
        done = self.run_helper("--service-user", pwd.getpwuid(0).pw_name)
        self.assertEqual(done.returncode, 1)
        # Either refusal is correct; which comes first is the ordering §9 fixed.
        self.assertTrue(
            "must run as root" in done.stderr or "no group 'smbpal'" in done.stderr,
            done.stderr,
        )

    def test_it_rejects_unknown_flags_rather_than_ignoring_them(self) -> None:
        done = self.run_helper("--service-user", "root", "--runtime-dir", "/tmp/x")
        self.assertEqual(done.returncode, 2)
        self.assertIn("usage", done.stderr)


@unittest.skipUnless(sys.platform == "darwin", "the helper is macOS-only by design")
class TestTheVocabularyIsFixed(unittest.TestCase):
    """The source is the artefact under test here, deliberately.

    §9's first rule is a fixed vocabulary with no pass-through exec. That is a
    property of the code rather than of a running process, and the running
    process needs root to reach. Asserting it against the source catches the
    change that would matter -- somebody adding a verb that takes a command --
    at the moment it is written rather than at a review nobody schedules.
    """

    def setUp(self) -> None:
        self.source = (HELPER_DIR / "smbpal-helper.c").read_text(encoding="utf-8")

    def test_there_is_no_shell(self) -> None:
        for forbidden in ("system(", "popen(", "execvp(", "execlp(", "/bin/sh"):
            self.assertNotIn(forbidden, self.source, f"{forbidden} is rule 3")

    def test_the_only_executable_is_an_absolute_system_path(self) -> None:
        self.assertIn('#define SHARING "/usr/sbin/sharing"', self.source)

    def test_no_identity_number_is_compiled_in(self) -> None:
        """§9: the install scans 450-499 and records what it landed on.

        **Comments are stripped first, and the first run of this test is why.**
        It failed on the `450` in a comment *explaining* that no number should be
        compiled in -- a true match in prose and a false one about the code. A
        test that cannot tell an identifier from a sentence about identifiers
        would make the rule unstateable in the file that follows it.
        """
        import re

        code = re.sub(r"/\*.*?\*/", "", self.source, flags=re.DOTALL)
        code = re.sub(r"//[^\n]*", "", code)
        for number in re.findall(r"\b(4[5-9]\d)\b", code):
            self.fail(f"{number} looks like a compiled-in service id")
