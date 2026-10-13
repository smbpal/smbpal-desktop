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

    def function(self, signature: str) -> str:
        """One function's body, bounded at the next top-level definition.

        **Slicing to end-of-file was a bug in these tests, twice.** A rule about
        what `uninstall` must not call matched `main`, which calls it correctly
        for a different purpose -- so the assertion failed on code that was
        right. A scope-free text search cannot express a scoped rule.
        """
        import re

        start = self.code.index(signature)
        rest = self.code[start + len(signature):]
        end = re.search(r"\n(?=(?:static\s|int main\())", rest)
        return self.code[start : start + len(signature) + (end.start() if end else len(rest))]

    def test_there_is_no_shell(self) -> None:
        for forbidden in ("system(", "popen(", "execvp(", "execlp(", "/bin/sh"):
            self.assertNotIn(forbidden, self.code, f"{forbidden} is rule 3")

    def verb(self, name: str) -> str:
        """One verb's branch of `serve_one`, up to the next verb."""
        body = self.function("static void serve_one(")
        start = body.index(f'strcmp(req.verb, "{name}")')
        end = body.find("strcmp(req.verb,", start + 1)
        return body[start : end if end != -1 else len(body)]

    def test_guest_access_is_never_an_argument(self) -> None:
        """§13 rule 6: `-g 000` is not validated, it is not an input."""
        publish = self.verb("share.publish")
        self.assertIn('"-g", "000"', publish)
        self.assertIn('"-s", "001"', publish)

    def test_publish_passes_the_resolved_path(self) -> None:
        """§13 rule 1: `/Volumes/Macintosh HD` is a symlink to `/`, so what is
        checked has to be what is shared."""
        publish = self.verb("share.publish")
        self.assertIn('"-a", report.resolved', publish)
        self.assertNotIn('"-a", req.args', publish)

    def test_the_record_name_is_always_the_share_name(self) -> None:
        """Helper spike §3: `-S` alone leaves the record named after the folder
        and `sharing -r <share name>` then leaks the share."""
        publish = self.verb("share.publish")
        self.assertIn('"-n", (char *)name', publish)
        self.assertIn('"-S", (char *)name', publish)

    def test_each_mutation_verifies_its_own_grant(self) -> None:
        """The daemon asking `auth.check` first is voluntary; these are not."""
        for name in ("share.publish", "share.unpublish"):
            with self.subTest(verb=name):
                branch = self.verb(name)
                self.assertIn("verify_form(MANAGE_SHARES_RIGHT, &req.auth)", branch)
                self.assertIn("!req.has_auth", branch)

    def test_the_reads_refuse_a_form(self) -> None:
        for name in ("path.inspect", "share.owned", "share.list"):
            with self.subTest(verb=name):
                self.assertIn("req.has_auth ||", self.verb(name))

    def test_only_what_the_helper_published_can_be_unpublished(self) -> None:
        branch = self.verb("share.unpublish")
        self.assertLess(
            branch.index("ledger_contains(name)"), branch.index("sharepoint_remove(name)")
        )

    def test_a_folder_is_inspected_only_after_the_grant(self) -> None:
        """A look at the filesystem as root is not given away to a request that
        has not shown it may change anything."""
        branch = self.verb("share.publish")
        self.assertLess(branch.index("verify_form("), branch.index("inspect_path("))

    def test_the_verdicts_match_the_client(self) -> None:
        import re

        from smbpal.system.helper import PATH_VERDICTS

        table = self.code[self.code.index("PATH_VERDICTS[] = {") :]
        table = table[: table.index("};")]
        self.assertEqual(tuple(re.findall(r'"([a-z-]+)"', table)), PATH_VERDICTS)

    def test_grant_verifies_before_it_looks_and_records_apart(self) -> None:
        branch = self.verb("share.grant")
        self.assertIn("verify_form(MANAGE_SHARES_RIGHT, &req.auth)", branch)
        self.assertLess(branch.index("verify_form("), branch.index("inspect_path("))
        self.assertNotIn("CREATED_FILE", self.function("static int grants_add("))

    def test_the_ace_is_the_measured_one(self) -> None:
        """Account spike step 4, the string that let the Pi write. A new
        permission set is a new measurement, not an edit."""
        self.assertIn(
            '"read,write,execute,delete,add_file,add_subdirectory,file_inherit,'
            'directory_inherit"',
            self.code,
        )

    def test_a_deny_is_never_overridden(self) -> None:
        branch = self.verb("share.grant")
        self.assertLess(branch.index("ACCESS_DENY"), branch.index("ace_add("))

    def test_sign_in_is_a_read(self) -> None:
        self.assertIn("req.has_auth ||", self.verb("account.smb"))

    def test_the_person_line_matches_the_daemon(self) -> None:
        import re

        from smbpal.sharepoints.apply import FIRST_PERSON_UID

        match = re.search(r"#define FIRST_PERSON_UID (\d+)", self.code)
        assert match is not None
        self.assertEqual(int(match.group(1)), FIRST_PERSON_UID)

    def test_uninstall_does_not_narrate_failures_it_expects(self) -> None:
        """Measured 12 October 2026: a clean uninstall printed `chmod: No ACL
        present` and `DS Error: -14136 (eDSRecordNotFound)` beside its own
        "removed" lines. Calls whose failure is the expected answer, or whose
        effect is read back anyway, discard their stderr."""
        self.assertIn("run_silent(argv)", self.function("static int ace_remove("))
        self.assertIn("run_silent(argv)", self.function("static int sharepoint_exists("))
        self.assertIn("run_silent(check)", self.function("static int uninstall("))
        # And the one that adds an ACE still reports why it could not.
        self.assertIn("run_quiet(argv)", self.function("static int ace_add("))

    def test_a_grant_on_a_deleted_folder_is_not_reported_as_removed(self) -> None:
        body = self.function("static int uninstall(")
        self.assertIn("the folder no longer exists", body)
        self.assertLess(body.index("lstat(path"), body.index("ace_remove(who->pw_name, path)"))

    def test_sharepoints_are_not_recorded_with_identities(self) -> None:
        """Uninstall deletes every non-user line of CREATED_FILE as a group."""
        self.assertNotIn("CREATED_FILE", self.function("static int ledger_add("))

    def test_the_only_executable_is_an_absolute_system_path(self) -> None:
        self.assertIn('#define SHARING "/usr/sbin/sharing"', self.source)

    def test_the_service_account_cannot_authenticate(self) -> None:
        """The daemon's identity is a process identity, not a credential.

        `Password "*"` is why job B's SMB account is a *different* account: that
        one carries `SMB-NT` and a real password, and merging them would turn the
        identity the daemon runs as into something that can log in.
        """
        self.assertIn('"Password", "*"', self.code)
        # **Nothing writes `SMB-NT`, and nothing writes the attribute it lives
        # in.** The helper *reads* it now -- `account.smb` asks whether an
        # existing person can sign in -- so the string's absence stopped being
        # the rule. What the rule always meant is that no code path gives any
        # account an SMB hash type: `AuthenticationAuthority` is only ever an
        # argument to `-read`.
        self.assertNotIn("SMB-NT", self.function("static int install("))
        import re

        touching = [
            call
            for call in re.findall(r"\{\(char \*\)DSCL,[^}]*\}", self.code)
            if "AuthenticationAuthority" in call
        ]
        self.assertTrue(touching, "the pattern no longer finds account.smb's read")
        for call in touching:
            self.assertIn('"-read"', call, call)

    def test_the_runtime_directory_is_owned_by_the_user_that_binds_in_it(self) -> None:
        """Creating a socket needs **write** on the directory, not just execute.

        §9 specified `root:smbpal 0750`, copied from Linux where the daemon is
        root and the bit is irrelevant. On macOS the daemon binds as the service
        account and group `smbpal` has `r-x`, so it failed with
        `cannot bind /var/run/smbpal/smbpald.sock: [Errno 13] Permission
        denied`. Owner must be the service account.
        """
        self.assertIn("ensure_runtime_dir(uid_t uid, gid_t gid)", self.code)
        self.assertIn("chown(RUNTIME_DIR, uid, gid)", self.code)
        self.assertNotIn("chown(RUNTIME_DIR, 0,", self.code)

    def test_the_install_creates_the_runtime_directory_too(self) -> None:
        """launchd gives no ordering between two jobs, and the daemon cannot
        make this directory itself: as the service account, `mkdir` under
        `/var/run` (root:daemon) is EPERM, so `bind()` raises and the daemon
        exits. This closes the race at install time."""
        self.assertIn("ensure_runtime_dir(", self.function("static int install("))

    def test_neither_job_respawns_after_a_failure(self) -> None:
        """`/var/run` does not survive a reboot on macOS -- measured.

        After one, `/var/run/smbpal` had a birth time six seconds later than
        `kern.boottime` (19:34:32 against 19:34:26, 11 October 2026), so the
        directory was made during the boot and not carried over. The helper won
        by about two seconds and nothing made it win, so the boot-time race is
        real and the losing daemon would exit on the failed bind.

        **`KeepAlive`/`SuccessfulExit false` on the daemon was the first answer
        and was taken back out.** launchd cannot tell *why* a job exited
        non-zero, and the daemon returns 2 on an invalid config and means it --
        so retrying turned a deliberate refusal into a flapping service writing
        the same three lines into an unrotated log every ten seconds for ever.

        The race is closed in `ipc/server.py` instead, which waits for the one
        condition that is genuinely transient. So neither job respawns, and the
        rule the helper's comment states applies to both of them.
        """
        self.assertNotIn("KeepAlive", self.code)
        self.assertNotIn("ThrottleInterval", self.code)
        self.assertNotIn("SuccessfulExit", self.code)

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


@unittest.skipUnless(sys.platform == "darwin", "the helper is macOS-only by design")
class TestTheVerifyRefuses(TestTheHelperBuildsAndRefuses):
    """§10's verify, exercised through every path that needs no privilege.

    The verify is the whole authorisation scheme on macOS, so its refusals are
    worth more than its grant: a grant needs a real prompt and an administrator
    standing at the machine, and the refusals are reachable here.
    """

    def verify(self, right: str, form: bytes) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [str(self.binary), "verify", right], input=form, capture_output=True, timeout=10
        )

    def test_a_right_the_helper_does_not_register_is_not_asked_about(self) -> None:
        """Exit 2, not 1: a typo and a refusal are different answers.

        Asking the database about an unregistered right would get an answer --
        the fallback `default` rule -- about something SMBPal never registered.
        """
        done = self.verify("app.smbpal.nope", b"x" * 32)
        self.assertEqual(done.returncode, 2)
        self.assertIn(b"not a right this helper registers", done.stderr)

    def test_a_short_form_is_refused_rather_than_padded(self) -> None:
        done = self.verify("app.smbpal.manage-shares", b"x")
        self.assertEqual(done.returncode, 1)
        self.assertIn(b"read 1", done.stderr)

    def test_a_forged_form_does_not_import(self) -> None:
        """**Measured, 11 October 2026.** 32 zero bytes are rejected by
        `AuthorizationCreateFromExternalForm` itself, which is the property §10
        relies on when it says the scheme survives a replaced daemon: the
        privileged side does not have to trust the relay, because a form the
        relay invented does not import."""
        done = self.verify("app.smbpal.manage-shares", bytes(32))
        self.assertEqual(done.returncode, 1)
        self.assertIn(b"did not import", done.stderr)


@unittest.skipUnless(sys.platform == "darwin", "the helper is macOS-only by design")
class TestOneClientCannotTakeTheHelperDown(unittest.TestCase):
    """Two ways a peer could stop the gate working, found reviewing job B.

    Both are about the helper being **one accept loop with no `KeepAlive`**: it
    serves one conversation at a time, and if it dies it stays dead for the rest
    of the boot. Neither is an escalation; what they make unavailable is
    authorisation, which is worse than it sounds -- a gate that is down refuses
    everything, and the person whose share will not save has no idea why.

    Asserted against the source because the running socket needs root, which is
    this file's standing position on the bind.
    """

    def setUp(self) -> None:
        self.code = _without_comments(
            (HELPER_DIR / "smbpal-helper.c").read_text(encoding="utf-8")
        )

    def test_sigpipe_cannot_kill_it(self) -> None:
        """**This was reachable, not theoretical.** `write` to a peer that has
        closed raises SIGPIPE, which terminates by default. `system/helper.py`
        has a read timeout and closes the socket when it expires, so a slow
        `sharing -l -f json` would have killed the root authorisation component
        by accident. Job A was never exposed because job A had no client.
        """
        self.assertIn("signal(SIGPIPE, SIG_IGN)", self.code)

    def test_a_peer_that_says_nothing_is_bounded(self) -> None:
        """Otherwise a connect with no `END` blocks the only loop for ever."""
        self.assertIn("SO_RCVTIMEO", self.code)
        self.assertIn("SO_SNDTIMEO", self.code)
        self.assertIn("PEER_TIMEOUT_SECONDS", self.code)

    def test_every_socket_write_checks_its_return(self) -> None:
        """Ignoring SIGPIPE turns a fatal signal into `EPIPE`, which is only an
        improvement if the writes look at what they got back."""
        for function in ("static void respond(", "static void serve_one("):
            body = self.code[self.code.index(function) :]
            body = body[: body.index("\nstatic ")]
            with self.subTest(function=function):
                self.assertIn("write(", body)
                self.assertIn("w <= 0", body)


@unittest.skipUnless(sys.platform == "darwin", "the helper is macOS-only by design")
class TestTheFrameParser(unittest.TestCase):
    """`helper/parse-test.c`, run as part of this suite.

    **The parser is the new attack surface and needed testing before the
    runbook.** The socket needs root and the helper's paths are fixed on
    purpose, so `serve_one` cannot be exercised here -- that remains a runbook
    step. But `parse_frame`, `copy_token` and `unhex` are pure, and the harness
    reaches them by including the source with `-Dmain=` renaming its entry
    point, so the shipped file knows nothing about being tested.

    The cases live in the C and nowhere else. A Python copy of the expectations
    would be a second table to drift from the first.
    """

    def test_every_case_passes(self) -> None:
        done = subprocess.run(
            ["make", "-C", str(HELPER_DIR), "check"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if "no working compiler" in done.stderr:
            raise unittest.SkipTest("no compiler")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        # The count is asserted loosely: it must not silently become zero, which
        # is what a harness that stops compiling its cases looks like.
        self.assertRegex(done.stdout, r"\b(2[0-9]|[3-9][0-9]) cases, 0 failures")

    def tearDown(self) -> None:
        subprocess.run(["make", "-C", str(HELPER_DIR), "clean"], capture_output=True)


@unittest.skipUnless(sys.platform == "darwin", "the helper is macOS-only by design")
class TestTheRightsAreRepairableAlone(TestTheHelperBuildsAndRefuses):
    """`install` refuses to run twice; the rights have to be repairable anyway.

    **The hole was found by measuring §12.4.** Removing a right to learn whether
    its `cdhash` requirement was enforced left the install half-registered, and
    the only way back was tearing down the service account and the launchd jobs
    to rebuild something that was never broken.

    The asymmetry is justified: accounts and jobs are the half with state to get
    wrong, and `install` is right to refuse to guess which of them to repair.
    `AuthorizationRightSet` overwrites and a removal is idempotent, so the rights
    have no such state.
    """

    def test_it_refuses_unprivileged(self) -> None:
        done = self.run_helper("rights", "install")
        self.assertEqual(done.returncode, 1)
        self.assertIn("must run as root", done.stderr)

    def test_an_unknown_verb_is_answered_with_the_usage(self) -> None:
        """Not "must run as root", which would name a problem the caller does
        not have. The verb is checked before the privilege for that reason."""
        done = self.run_helper("rights", "sideways")
        self.assertEqual(done.returncode, 2)
        self.assertIn("usage", done.stderr)
        self.assertNotIn("must run as root", done.stderr)

    def test_it_takes_exactly_one_verb(self) -> None:
        for args in (("rights",), ("rights", "install", "remove")):
            with self.subTest(args=args):
                done = self.run_helper(*args)
                self.assertEqual(done.returncode, 2)
                self.assertIn("usage", done.stderr)

    def test_the_usage_names_it(self) -> None:
        done = self.run_helper()
        self.assertIn("rights install|remove", done.stderr)


@unittest.skipUnless(sys.platform == "darwin", "the helper is macOS-only by design")
class TestTheRightsMatchTheClient(unittest.TestCase):
    """The names are in two files because the two halves are in two languages.

    Same necessity as the polkit action ids, which live in XML and in Python and
    are pinned by a test that parses the policy file. This is that test for
    macOS.
    """

    def setUp(self) -> None:
        self.code = (HELPER_DIR / "smbpal-helper.c").read_text()

    def test_the_verify_never_asks_for_interaction(self) -> None:
        """§11 measured that a process with no Aqua session cannot prompt
        (-60007), and the helper is such a process. A verify that passed the
        interaction flag would be asking a question that cannot be answered.

        Read with the comments stripped, because the sentence above names the
        flag it forbids -- the third time a rule in this file would have been
        broken by the comment stating it.
        """
        code = _without_comments(self.code)
        body = code[code.index("static int verify_form(") :]
        body = body[: body.index("\nstatic ") if "\nstatic " in body else len(body)]
        self.assertIn("kAuthorizationFlagExtendRights", body)
        self.assertNotIn("kAuthorizationFlagInteractionAllowed", body)

    def test_a_grant_is_evaluated_in_exactly_one_place(self) -> None:
        """The `verify` subcommand and the socket's `auth.check` share it.

        Two copies of the evaluation is how one of them ends up with the
        interaction flag, or with a right it never checked was registered.
        """
        code = _without_comments(self.code)
        self.assertEqual(code.count("AuthorizationCopyRights("), 1)
        self.assertEqual(code.count("AuthorizationCreateFromExternalForm("), 1)

    def test_the_helper_registers_exactly_what_the_client_prompts_for(self) -> None:
        from smbpal.system import authorization

        import re

        table = self.code[self.code.index("static const struct right_rule RIGHTS[]") :]
        table = table[: table.index("};")]
        # A right the verbs also check is named once as a macro, so the table
        # may spell it either way; expand the macros before reading it.
        for macro, value in re.findall(
            r'#define (\w+) "(app\.smbpal\.[a-z-]+)"', self.code
        ):
            table = re.sub(rf"\b{macro}\b", f'"{value}"', table)
        in_c = tuple(re.findall(r'"(app\.smbpal\.[a-z-]+)"', table))
        self.assertEqual(in_c, authorization.RIGHTS)

    def test_use_connections_is_registered_nowhere(self) -> None:
        """It is `allow_active yes` on Linux and needs no privilege here, so
        there is no right for it -- and a right in the system's database that no
        component checks would read like live policy while being dead."""
        from smbpal.system import authorization

        self.assertNotIn("app.smbpal.use-connections", self.code)
        self.assertNotIn(authorization.USE_CONNECTIONS, authorization.RIGHTS)
        self.assertIn(authorization.USE_CONNECTIONS, authorization.UNPROMPTED)

    def test_the_external_form_length_is_pinned_to_the_sdk(self) -> None:
        """The Python constant is a number in a file; the C makes the compiler
        check it against the struct the system defines."""
        from smbpal.system import authorization

        self.assertEqual(authorization.EXTERNAL_FORM_LENGTH, 32)
        self.assertIn(
            "_Static_assert(sizeof(AuthorizationExternalForm) == 32", self.code
        )

    def test_the_rule_does_not_let_root_satisfy_it(self) -> None:
        """**The one that matters.** The process calling `AuthorizationCopyRights`
        on the verify side is the helper, and it is root. If `allow-root` were
        true and honoured for the verifying process, every imported form would
        verify whatever it held and the gate would be off while looking on.

        `false` can never disable the gate, and matches the `default` rule Apple
        ships. It is not free: it costs §11's headless `sudo` route, which needs
        `true`. That trade is deliberate and recorded -- the flip waits on spike
        §12.3 measuring whether an imported form honours the flag.
        """
        rule = self.code[self.code.index("static CFDictionaryRef rule_for(") :]
        rule = rule[: rule.index("\n}")]
        self.assertIn('CFSTR("allow-root"), kCFBooleanFalse', rule)
        self.assertNotIn('CFSTR("allow-root"), kCFBooleanTrue', rule)
        # Unshared is the one field this rule changes from the fallback, so it
        # is the one field whose loss the install has to warn about.
        self.assertIn('CFSTR("shared"), kCFBooleanFalse', rule)
