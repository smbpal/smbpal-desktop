"""Installing the agent as a LaunchAgent.

Everything here runs on Linux, which is where CI runs, because `launchctl` is
behind an injected runner and `plistlib` is in the standard library. The one
thing that cannot be faked -- whether macOS itself accepts the plist -- is
checked with `plutil` where there is a `plutil` to check with.

**The fake is modelled on measured output.** The three shapes `launchctl print`
produces for a job that is not running were recorded from macOS 26.6 on
2 October 2026, including the detail that matters: a job killed by a signal has
no `last exit code` line at all, which is the only thing distinguishing it from
one that exited non-zero.
"""

from __future__ import annotations

import contextlib
import io
import plistlib
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from smbpal.agent import launchd
from smbpal.agent.main import build_parser, main
from smbpal.system.run import CommandResult

RUNNING = """\
gui/501/{label} = {{
	active count = 1
	path = {path}
	type = LaunchAgent
	state = running

	program = {program}
	runs = 1
	pid = 4242
	last exit code = (never exited)

	endpoints = {{
		"com.example.thing" = {{
			state = active
		}}
	}}
}}
"""

FAILING = """\
gui/501/{label} = {{
	active count = 0
	path = {path}
	type = LaunchAgent
	state = spawn scheduled

	program = {program}
	minimum runtime = 10
	runs = 3
	last exit code = 2
}}
"""

SIGNALLED = """\
gui/501/{label} = {{
	path = {path}
	type = LaunchAgent
	state = spawn scheduled

	program = {program}
	runs = 1
}}
"""

STOPPED = """\
gui/501/{label} = {{
	path = {path}
	type = LaunchAgent
	state = not running

	program = {program}
	runs = 1
	last exit code = 0
}}
"""


class FakeLaunchctl:
    """Callable with the CommandRunner signature, and not a rubber stamp.

    It refuses a second `bootstrap` of a loaded label the way launchd does, and
    answers `print` with exit 113 for a label it has never seen -- both measured.
    An installer that works against a fake which accepts everything is an
    installer that has not been tested.
    """

    def __init__(self, *, shape: str = RUNNING) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.loaded: dict[str, Path] = {}
        self.shape = shape
        # Set to make `print` claim the job vanished after a clean bootstrap,
        # which is the case `install()` is written to catch.
        self.print_lies = False
        # How many `print` calls a booted-out job lingers for. Real launchd
        # sends SIGTERM and returns, so the job outlives the command.
        self.bootout_lingers = 0
        self._draining = 0

    def __call__(self, argv, *, input=None, timeout=None) -> CommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        verb = argv[1]
        if verb == "bootstrap":
            path = Path(argv[3])
            label = plistlib.loads(path.read_bytes())["Label"]
            if label in self.loaded:
                return CommandResult(
                    argv, 5, "", "Bootstrap failed: 5: Input/output error\n"
                )
            self.loaded[label] = path
            return CommandResult(argv, 0, "", "")
        label = argv[2].rsplit("/", 1)[-1]
        if verb == "bootout":
            if label not in self.loaded:
                return CommandResult(
                    argv, 3, "", "Boot-out failed: 3: No such process\n"
                )
            if self.bootout_lingers:
                self._draining = self.bootout_lingers
            else:
                del self.loaded[label]
            return CommandResult(argv, 0, "", "")
        if verb == "print":
            if self._draining:
                self._draining -= 1
                if not self._draining:
                    self.loaded.pop(label, None)
            if label not in self.loaded or self.print_lies:
                return CommandResult(
                    argv,
                    113,
                    "",
                    f'Could not find service "{label}" in domain for user gui: 501\n',
                )
            plist = plistlib.loads(self.loaded[label].read_bytes())
            return CommandResult(
                argv,
                0,
                self.shape.format(
                    label=label,
                    path=self.loaded[label],
                    program=plist["ProgramArguments"][0],
                ),
                "",
            )
        raise AssertionError(f"the fake was asked for {verb}, which is not used")

    def verbs(self) -> list[str]:
        return [call[1] for call in self.calls]


class LaunchdTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name) / "home"
        self.prefix = Path(self.directory.name) / "opt"
        # The program has to exist, because `status` reports a program that has
        # gone missing as the problem it is.
        (self.prefix / "bin").mkdir(parents=True)
        self.program = self.prefix / "bin" / launchd.PROGRAM_NAME
        # Executable, because `install` refuses a program launchd could only
        # fail to run -- and a fixture without the bit would be testing that.
        self.program.write_text("#!/bin/sh\n")
        self.program.chmod(0o755)
        self.socket = self.home / "Library" / "Application Support" / "SMBPal" / "agent.sock"
        self.launchctl = FakeLaunchctl()

    def install(self, **kwargs):
        kwargs.setdefault("program", self.program)
        return launchd.install(
            socket=self.socket,
            home=self.home,
            uid=501,
            runner=self.launchctl,
            **kwargs,
        )

    def status(self, **kwargs):
        return launchd.status(
            socket=self.socket,
            program=self.program,
            home=self.home,
            uid=501,
            runner=self.launchctl,
            **kwargs,
        )

    def plist(self) -> dict:
        return plistlib.loads(launchd.plist_path(home=self.home).read_bytes())


class TestTheJobDefinition(LaunchdTestCase):
    def test_the_label_is_the_identifier_section_13_fixed(self) -> None:
        # Permanent per §13, and the per-user half of a pair whose other half is
        # app.smbpal.SMBPal.Helper. Changing it orphans every installed plist.
        self.assertEqual(launchd.LABEL, "app.smbpal.SMBPal.Agent")
        self.assertTrue(launchd.LABEL.startswith("app.smbpal.SMBPal"))
        self.assertNotIn("-", launchd.LABEL)

    def test_the_keys_are_an_allow_list_because_the_plist_is_readable(self) -> None:
        """A new key in here is a deliberate act, not a side effect.

        `~/Library/LaunchAgents` is conventionally world-readable, so the plist
        is the one part of the agent anybody on the machine can read. D13 keeps
        the credential in the Keychain and passes it as a CFString; this test is
        what stops a later convenience -- an EnvironmentVariables block, a
        --password flag -- from quietly ending up on disk.
        """
        self.install()
        self.assertEqual(
            set(self.plist()),
            {
                "Label",
                "ProgramArguments",
                "RunAtLoad",
                "KeepAlive",
                "LimitLoadToSessionType",
                "StandardOutPath",
                "StandardErrorPath",
            },
        )

    def test_keepalive_is_conditional_not_true(self) -> None:
        # `KeepAlive: true` would restart the agent after a clean exit, so
        # `launchctl bootout` and logout would both fight it.
        self.install()
        self.assertEqual(self.plist()["KeepAlive"], {"SuccessfulExit": False})
        self.assertTrue(self.plist()["RunAtLoad"])

    def test_it_loads_only_in_a_gui_session(self) -> None:
        # The session type and the domain have to agree: an agent in an SSH
        # login can read neither the login Keychain nor the user's Finder.
        self.install()
        self.assertEqual(self.plist()["LimitLoadToSessionType"], "Aqua")
        self.assertEqual(launchd.domain(uid=501), "gui/501")

    def test_the_socket_is_named_rather_than_left_to_the_default(self) -> None:
        self.install()
        self.assertEqual(
            self.plist()["ProgramArguments"][1:], ["--socket", str(self.socket)]
        )

    def test_output_goes_somewhere_a_person_can_read_it(self) -> None:
        # launchd sends a job's stdout and stderr to /dev/null without these,
        # and the agent's startup line and every error go to stderr.
        self.install()
        expected = str(launchd.log_path(home=self.home))
        self.assertEqual(self.plist()["StandardOutPath"], expected)
        self.assertEqual(self.plist()["StandardErrorPath"], expected)
        self.assertTrue(launchd.log_path(home=self.home).parent.is_dir())

    @unittest.skipUnless(
        sys.platform == "darwin" and shutil.which("plutil"), "plutil is macOS only"
    )
    def test_macos_itself_accepts_the_file(self) -> None:
        self.install()
        result = subprocess.run(
            ["plutil", "-lint", str(launchd.plist_path(home=self.home))],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class TestTheProgramPath(LaunchdTestCase):
    def test_a_symlink_is_kept_as_a_symlink(self) -> None:
        """The Homebrew upgrade guard, and the reason this is not `resolve()`.

        `/opt/homebrew/bin/smbpal-agent` is a symlink into
        `Cellar/smbpal/<version>/bin`. Record the target and the next
        `brew upgrade` leaves launchd pointing into a Cellar directory that no
        longer exists -- which `KeepAlive` turns into a spawn failure every ten
        seconds rather than a visible error.
        """
        cellar = self.prefix / "Cellar" / "smbpal" / "0.2.5" / "bin"
        cellar.mkdir(parents=True)
        real = cellar / launchd.PROGRAM_NAME
        real.write_text("#!/bin/sh\n")
        real.chmod(0o755)
        link = self.prefix / "bin" / "linked-agent"
        link.symlink_to(real)
        self.assertEqual(launchd.program_path(link), str(link))

    def test_a_relative_path_becomes_absolute_because_launchd_demands_it(self) -> None:
        with contextlib.chdir(self.prefix / "bin"):
            found = launchd.program_path(launchd.PROGRAM_NAME)
        # Not an equality check, for a macOS reason worth knowing: `getcwd`
        # resolves symlinks, so on a Mac this comes back under `/private/var`
        # where the fixture is under `/var`. The relative path has still become
        # the absolute one launchd requires.
        self.assertTrue(Path(found).is_absolute())
        self.assertTrue(found.endswith(f"/{self.prefix.name}/bin/{launchd.PROGRAM_NAME}"))

    def test_a_program_that_is_not_there_is_refused_before_anything_is_written(
        self,
    ) -> None:
        # KeepAlive turns a typo into a job launchd respawns every ten seconds
        # for as long as the account exists, so this is caught at the one moment
        # somebody is watching.
        with self.assertRaises(launchd.LaunchdError) as caught:
            self.install(program=self.prefix / "bin" / "typo")
        self.assertIn("not there", caught.exception.message)
        self.assertFalse(launchd.plist_path(home=self.home).exists())

    def test_a_program_with_no_execute_bit_is_refused_too(self) -> None:
        unrunnable = self.prefix / "bin" / "not-executable"
        unrunnable.write_text("#!/bin/sh\n")
        unrunnable.chmod(0o644)
        with self.assertRaises(launchd.LaunchdError) as caught:
            self.install(program=unrunnable)
        self.assertIn("not executable", caught.exception.message)

    def test_with_nothing_to_find_it_names_the_flag_that_fixes_it(self) -> None:
        with mock.patch.object(shutil, "which", return_value=None), \
             mock.patch.object(sys, "argv", ["/usr/bin/python3"]):
            with self.assertRaises(launchd.LaunchdError) as caught:
                launchd.program_path(None)
        self.assertIn("--program", caught.exception.detail)


class TestInstalling(LaunchdTestCase):
    def test_it_writes_then_loads_then_checks(self) -> None:
        done = self.install()
        self.assertEqual(self.launchctl.verbs(), ["bootout", "bootstrap", "print"])
        self.assertEqual(done["pid"], "4242")
        self.assertFalse(done["replaced"])

    def test_reinstalling_unloads_the_copy_that_is_there(self) -> None:
        self.install()
        again = self.install()
        self.assertTrue(again["replaced"], "the first copy was not unloaded")
        self.assertEqual(
            self.launchctl.verbs(),
            # The lone `print` in the middle is bootout confirming the old job
            # has gone; bootstrap over a loaded label is the error launchd
            # returns 5 for.
            ["bootout", "bootstrap", "print", "bootout", "print", "bootstrap", "print"],
        )

    def test_it_waits_for_the_old_job_to_actually_be_gone(self) -> None:
        """The race that produced *Bootstrap failed: 5: Input/output error*.

        `launchctl bootout` SIGTERMs the running process and returns, so the
        label is still loaded when `bootstrap` arrives. Reinstalling over an
        agent that was merely *scheduled* worked; over one that was running it
        did not, which is why this is modelled rather than assumed.
        """
        self.install()
        self.launchctl.bootout_lingers = 2
        again = self.install()
        self.assertTrue(again["replaced"])
        self.assertEqual(
            self.launchctl.verbs(),
            ["bootout", "bootstrap", "print", "bootout", "print", "print",
             "bootstrap", "print"],
            "the two extra prints are the wait for launchd to let go",
        )

    def test_a_job_that_never_lets_go_says_so_rather_than_erroring_oddly(self) -> None:
        self.install()
        self.launchctl.bootout_lingers = 10_000
        with self.assertRaises(launchd.LaunchdError) as caught:
            launchd.bootout(uid=501, runner=self.launchctl, timeout=0.2)
        self.assertIn("still has the old agent", caught.exception.message)
        self.assertIn("0.2 seconds later", caught.exception.detail)

    def test_a_bootstrap_that_succeeds_and_does_nothing_is_an_error(self) -> None:
        # Not hypothetical: `launchctl bootstrap` has exited 0 having loaded
        # nothing. Reporting an install that did not happen is the failure the
        # options probe cost an afternoon to.
        self.launchctl.print_lies = True
        with self.assertRaises(launchd.LaunchdError) as caught:
            self.install()
        self.assertIn("did not have it", caught.exception.message)

    def test_an_interrupted_write_leaves_no_half_plist_behind(self) -> None:
        self.install()
        directory = launchd.plist_path(home=self.home).parent
        self.assertEqual(
            [p.name for p in directory.iterdir()], [f"{launchd.LABEL}.plist"]
        )


class TestUninstalling(LaunchdTestCase):
    def test_it_unloads_removes_and_says_what_it_did(self) -> None:
        self.install()
        self.socket.parent.mkdir(parents=True, exist_ok=True)
        self.socket.touch()
        done = launchd.uninstall(
            home=self.home, uid=501, socket=self.socket, runner=self.launchctl
        )
        self.assertTrue(done["was_loaded"])
        self.assertTrue(done["plist_existed"])
        self.assertTrue(done["socket_removed"])
        self.assertFalse(launchd.plist_path(home=self.home).exists())
        self.assertFalse(self.socket.exists())

    def test_on_a_machine_that_never_installed_it_is_quiet(self) -> None:
        done = launchd.uninstall(
            home=self.home, uid=501, socket=self.socket, runner=self.launchctl
        )
        self.assertFalse(done["was_loaded"])
        self.assertFalse(done["plist_existed"])

    def test_it_leaves_the_log_alone(self) -> None:
        self.install()
        log = launchd.log_path(home=self.home)
        log.write_text("the mount that failed last Tuesday\n")
        launchd.uninstall(home=self.home, uid=501, runner=self.launchctl)
        self.assertTrue(log.exists(), "the log is the user's, and explains a failure")


class TestStatusDistinguishesTheThreeFailures(LaunchdTestCase):
    """D14 applied to a job state: one message per cause, or say which it cannot.

    `state = spawn scheduled` covers an agent that has never once started, one
    killed by a signal, and one that is between retries of a crash loop. The
    first version of `status()` reported all of them as a successfully installed
    agent and exited 0.
    """

    def test_running_is_the_only_state_that_counts_as_working(self) -> None:
        self.install()
        state = self.status()
        self.assertTrue(state["ok"])
        self.assertEqual(state["state"], "running")
        self.assertIsNone(state["failing"])
        self.assertEqual(state["pid"], "4242")

    def test_a_crash_loop_names_the_exit_code_and_the_log(self) -> None:
        self.install()
        self.launchctl.shape = FAILING
        state = self.status()
        self.assertFalse(state["ok"])
        self.assertIn("last exit code 2", state["failing"])
        self.assertIn(str(launchd.log_path(home=self.home)), state["failing"])

    def test_a_signal_death_is_not_reported_as_a_clean_exit(self) -> None:
        # launchd prints no `last exit code` line at all in this case. Reading a
        # missing key as 0 would say "exited cleanly" about a crash.
        self.install()
        self.launchctl.shape = SIGNALLED
        state = self.status()
        self.assertFalse(state["ok"])
        self.assertIn("killed", state["failing"])
        self.assertIsNone(state["last_exit_code"])
        self.assertEqual(state["runs"], "1")

    def test_a_clean_stop_says_how_to_start_it_again(self) -> None:
        self.install()
        self.launchctl.shape = STOPPED
        state = self.status()
        self.assertFalse(state["ok"])
        self.assertIn("launchctl kickstart", state["failing"])

    def test_not_installed_and_not_loaded_are_different_sentences(self) -> None:
        nothing = self.status()
        self.assertFalse(nothing["installed"])
        self.assertFalse(nothing["loaded"])
        self.install()
        launchd.bootout(uid=501, runner=self.launchctl)
        orphaned = self.status()
        self.assertTrue(orphaned["installed"], "the plist is still on disk")
        self.assertFalse(orphaned["loaded"])
        self.assertFalse(orphaned["ok"])

    def test_the_nested_blocks_do_not_shadow_the_jobs_own_state(self) -> None:
        # `launchctl print` repeats `state = active` inside its endpoints block.
        self.install()
        self.assertEqual(self.status()["state"], "running")


class TestStatusNoticesDrift(LaunchdTestCase):
    def test_a_program_that_has_gone_says_so(self) -> None:
        # `brew uninstall` without `--uninstall` first. KeepAlive then spawns a
        # missing file every ten seconds, and `launchctl print` describes a job
        # that exists.
        self.install()
        self.program.unlink()
        state = self.status()
        self.assertFalse(state["ok"])
        self.assertIn("is not there", state["stale"][0])

    def test_a_program_that_has_moved_says_both_paths(self) -> None:
        self.install()
        moved = self.prefix / "bin" / "smbpal-agent-moved"
        moved.write_text("#!/bin/sh\n")
        moved.chmod(0o755)
        state = launchd.status(
            socket=self.socket,
            program=moved,
            home=self.home,
            uid=501,
            runner=self.launchctl,
        )
        self.assertIn(str(moved), state["stale"][0])
        self.assertIn(str(self.program), state["stale"][0])

    def test_a_socket_the_default_no_longer_agrees_with(self) -> None:
        self.install()
        state = launchd.status(
            socket=self.home / "elsewhere.sock",
            program=self.program,
            home=self.home,
            uid=501,
            runner=self.launchctl,
        )
        self.assertFalse(state["ok"])
        self.assertIn("elsewhere.sock", state["stale"][0])

    def test_a_plist_that_is_not_a_plist_is_an_error_not_a_shrug(self) -> None:
        path = launchd.plist_path(home=self.home)
        path.parent.mkdir(parents=True)
        path.write_text("this was edited by hand\n")
        with self.assertRaises(launchd.LaunchdError) as caught:
            self.status()
        self.assertIn("is not a plist", caught.exception.message)


class TestTheCommandLine(unittest.TestCase):
    def test_the_actions_are_mutually_exclusive(self) -> None:
        # --install --uninstall is two intentions, and argparse should say so
        # rather than one of them silently winning.
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                build_parser().parse_args(["--install", "--uninstall"])

    @unittest.skipUnless(sys.platform == "darwin", "the agent only serves on macOS")
    def test_a_bind_failure_is_a_sentence_rather_than_a_traceback(self) -> None:
        """Found under launchd on 2 October 2026, where stderr is a log file.

        `ipc/server.py` raises `OSError` with a sentence in it and `smbpald`'s
        main catches exactly that; the agent caught only `SmbpalError`, so its
        entire output on a failure to bind was a Python traceback. A socket path
        over the 104-byte `sun_path` limit is the cheapest way to provoke one.
        """
        with TemporaryDirectory() as directory:
            too_long = Path(directory) / ("d" * 60) / ("e" * 60) / "agent.sock"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["--socket", str(too_long)])
        self.assertEqual(code, 2)
        self.assertIn("cannot bind", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    @unittest.skipIf(sys.platform == "darwin", "this is the not-macOS case")
    def test_on_linux_installing_refuses_before_touching_anything(self) -> None:
        self.assertEqual(main(["--install"]), 1)
        self.assertEqual(main(["--status"]), 1)


if __name__ == "__main__":
    unittest.main()
