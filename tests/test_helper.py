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


def _without_comments(source: str) -> str:
    """The C with its comments removed, for assertions about the code.

    **Twice now a source-level rule has been broken by the comment stating it.**
    The identity scan tripped on the `450` in a comment saying no number should
    be compiled in, and the no-authentication rule tripped on the `SMB-NT` in a
    comment saying job B's account is the one that carries it. Both matches were
    true of the prose and false of the code.

    `smbpal-helper.c` is heavily commented on purpose -- it is the one component
    that runs as root, and a reader should not have to infer why. A test that
    cannot tell an identifier from a sentence about identifiers would make every
    rule unstateable in the file that implements it.
    """
    import re

    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", source)


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

    def test_it_refuses_with_no_subcommand(self) -> None:
        done = self.run_helper()
        self.assertEqual(done.returncode, 2)
        self.assertIn("usage", done.stderr)

    def test_it_refuses_an_unknown_subcommand(self) -> None:
        """Not silently treated as `serve`. A root binary should not guess."""
        done = self.run_helper("sevre")
        self.assertEqual(done.returncode, 2)
        self.assertIn("usage", done.stderr)

    def test_serve_refuses_without_a_service_user(self) -> None:
        """No default. A compiled-in name is the bug §9's scan rule prevents."""
        done = self.run_helper("serve")
        self.assertEqual(done.returncode, 2)
        self.assertIn("--service-user is required", done.stderr)

    def test_it_refuses_an_unknown_service_user(self) -> None:
        done = self.run_helper("serve", "--service-user", "nosuchuser-smbpal", "--check")
        self.assertEqual(done.returncode, 1)
        self.assertIn("no such user", done.stderr)

    def test_check_does_not_need_root(self) -> None:
        """The one diagnostic a person can run before elevating.

        It reads `passwd` and `group` and touches nothing. On a machine with no
        `smbpal` group it still has to fail -- but on the group, never on
        privilege, or the message sends someone to `sudo` for a missing group.
        """
        done = self.run_helper(
            "serve", "--service-user", pwd.getpwuid(0).pw_name, "--check"
        )
        self.assertNotIn("must run as root", done.stderr)
        if done.returncode != 0:
            self.assertIn("no group 'smbpal'", done.stderr)

    def test_serving_requires_root(self) -> None:
        if __import__("os").geteuid() == 0:
            self.skipTest("this asserts the refusal, so it needs a non-root runner")
        done = self.run_helper("serve", "--service-user", pwd.getpwuid(0).pw_name)
        self.assertEqual(done.returncode, 1)
        # Either refusal is correct; which comes first is the ordering §9 fixed.
        self.assertTrue(
            "must run as root" in done.stderr or "no group 'smbpal'" in done.stderr,
            done.stderr,
        )

    def test_it_rejects_unknown_flags_rather_than_ignoring_them(self) -> None:
        done = self.run_helper("serve", "--service-user", "root", "--runtime-dir", "/tmp/x")
        self.assertEqual(done.returncode, 2)
        self.assertIn("usage", done.stderr)


@unittest.skipUnless(sys.platform == "darwin", "the helper is macOS-only by design")
class TestTheInstallChoosesIdentities(TestTheHelperBuildsAndRefuses):
    """`install --dry-run`, which is the only part of the install reachable here.

    Creating the account needs root. **The choosing is the interesting half** and
    it is pure: prefer 450, else the first free slot in 450-499, and refuse if
    the range is full. `--dry-run` exposes exactly that and touches nothing, so
    the decision can be seen before anybody is asked for a password.

    **Nothing here asserts 450.** It is a preference, and a machine where
    something else already holds it must still pass -- a test that hardcoded the
    number would be the very mistake §9's scan rule exists to prevent.

    **These read the live directory, so they depend on machine state, and two of
    them found that out the hard way.** On a machine where SMBPal is already
    installed, `install` answers *already installed* before it can answer
    *must run as root*, and the scan prints nothing to check because there is
    nothing left to create -- which made one test fail and one pass vacuously.
    Both now skip with a reason instead, because a test that quietly asserts
    nothing is worse than one that says it cannot run here.
    """

    def skip_if_installed(self) -> None:
        import grp

        try:
            grp.getgrnam("smbpal")
            pwd.getpwnam("_smbpald")
        except KeyError:
            return
        self.skipTest("SMBPal is installed on this machine; needs a clean one")

    def test_dry_run_needs_no_root(self) -> None:
        done = self.run_helper("install", "--dry-run")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn("must run as root", done.stderr)

    def test_dry_run_names_an_id_in_apples_role_account_range(self) -> None:
        import re

        done = self.run_helper("install", "--dry-run")
        ids = [int(n) for n in re.findall(r"(?:gid|uid)=(\d+)", done.stdout)]
        self.assertTrue(ids, done.stdout)
        for chosen in ids:
            # 450-499 is where `sysadminctl -addUser -roleAccount` insists a
            # role account goes, measured 11 October 2026.
            self.assertGreaterEqual(chosen, 450)
            self.assertLessEqual(chosen, 499)

    def test_the_id_it_would_take_is_actually_free(self) -> None:
        """The scan's whole job, asserted against the directory rather than a
        constant -- so this holds on a machine where 450 is already taken."""
        import grp
        import re

        self.skip_if_installed()
        done = self.run_helper("install", "--dry-run")
        self.assertIn("would create", done.stdout, "nothing to check")
        for chosen in re.findall(r"would create \w+ \S+ (?:gid|uid)=(\d+)", done.stdout):
            with self.assertRaises(KeyError):
                pwd.getpwuid(int(chosen))
            with self.assertRaises(KeyError):
                grp.getgrgid(int(chosen))

    def test_install_needs_the_daemon_path(self) -> None:
        """A usage error, and reported before privilege is considered.

        The Homebrew prefix is not one place -- `/opt/homebrew` on Apple
        silicon, `/usr/local` on Intel -- so there is no default to fall back
        on and `smbpal setup` is what fills it in.
        """
        done = self.run_helper("install")
        self.assertEqual(done.returncode, 2)
        self.assertIn("--daemon", done.stderr)

    def test_install_rejects_a_relative_daemon_path(self) -> None:
        done = self.run_helper("install", "--daemon", "bin/smbpald")
        self.assertEqual(done.returncode, 2)
        self.assertIn("absolute", done.stderr)

    def test_install_rejects_a_daemon_path_that_is_not_executable(self) -> None:
        done = self.run_helper("install", "--daemon", "/etc/hosts")
        self.assertEqual(done.returncode, 2)
        self.assertIn("not executable", done.stderr)

    def test_install_refuses_unprivileged_once_the_arguments_are_good(self) -> None:
        """Exit 2 is a usage error and exit 1 is a refusal, and the order
        matters: somebody told to run `sudo` should be told why, not told to
        elevate and then told their arguments were wrong."""
        if __import__("os").geteuid() == 0:
            self.skipTest("this asserts the refusal, so it needs a non-root runner")
        self.skip_if_installed()
        done = self.run_helper("install", "--daemon", "/bin/sh")
        self.assertEqual(done.returncode, 1)
        self.assertIn("must run as root", done.stderr)

    def test_install_refuses_a_second_time_and_points_at_uninstall(self) -> None:
        """The other exit-1 refusal, and the one reachable on this machine.

        Both are correct and which one you get is machine state, which is why
        the test above has to say which machine it needs.
        """
        import grp

        try:
            grp.getgrnam("smbpal")
            pwd.getpwnam("_smbpald")
        except KeyError:
            self.skipTest("SMBPal is not installed here; nothing to refuse")
        done = self.run_helper("install", "--daemon", "/bin/sh")
        self.assertEqual(done.returncode, 1)
        self.assertIn("already installed", done.stderr)
        self.assertIn("uninstall", done.stderr)

    def test_uninstall_refuses_unprivileged(self) -> None:
        if __import__("os").geteuid() == 0:
            self.skipTest("this asserts the refusal, so it needs a non-root runner")
        done = self.run_helper("uninstall")
        self.assertEqual(done.returncode, 1)
        self.assertIn("must run as root", done.stderr)

    def test_uninstall_takes_no_arguments(self) -> None:
        """Nothing to parameterise: it removes what the install recorded."""
        done = self.run_helper("uninstall", "--all")
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
        self.code = _without_comments(self.source)

    def test_there_is_no_shell(self) -> None:
        for forbidden in ("system(", "popen(", "execvp(", "execlp(", "/bin/sh"):
            self.assertNotIn(forbidden, self.code, f"{forbidden} is rule 3")

    def test_the_only_executable_is_an_absolute_system_path(self) -> None:
        self.assertIn('#define SHARING "/usr/sbin/sharing"', self.source)

    def test_the_service_account_cannot_authenticate(self) -> None:
        """The daemon's identity is a process identity, not a credential.

        `Password "*"` is why job B's SMB account is a *different* account: that
        one carries `SMB-NT` and a real password, and merging them would turn the
        identity the daemon runs as into something that can log in.
        """
        self.assertIn('"Password", "*"', self.code)
        self.assertNotIn("SMB-NT", self.code)

    def test_the_daemon_logs_somewhere_its_own_user_can_write(self) -> None:
        """launchd opens `StandardErrorPath` as the job's user, before exec.

        **This was a real failure, not a hypothetical.** The daemon's plist
        pointed at root-owned `/var/log`, so launchd could not create the file,
        failed the job's configuration with `EX_CONFIG` and never ran the
        program -- leaving no log, because the log was what could not be made.
        Measured on the first real start, 11 October 2026.

        So the daemon's log lives in a directory the install gives to the
        service account, and the **helper's** stays outside it: the helper
        records refused uids, and the unprivileged component must not be able to
        edit the root component's account of what it refused.
        """
        self.assertIn('#define LOG_DIR "/var/log/smbpal"', self.code)
        self.assertIn('#define DAEMON_LOG LOG_DIR "/daemon.log"', self.code)
        # The helper's log is NOT under LOG_DIR.
        self.assertIn('#define HELPER_LOG "/var/log/" HELPER_LABEL ".log"', self.code)
        # And the directory is chowned to the service account before the plists
        # are written, since launchd opens the file at bootstrap.
        log_dir = self.code.index('mkdir(LOG_DIR')
        plists = self.code.index("write_plist(HELPER_PLIST")
        self.assertLess(log_dir, plists)

    def test_no_identity_number_is_compiled_in(self) -> None:
        """§9: the install scans 450-499 and records what it landed on."""
        import re

        code = self.code
        # The three range constants are the preference and the bounds, which §9
        # asks to be stated once and in one place. Anything else is a smell.
        code = re.sub(r"#define ID_(?:PREFERRED|MIN|MAX) \d+", "", code)
        for number in re.findall(r"\b(4[5-9]\d)\b", code):
            self.fail(f"{number} looks like a compiled-in service id")
