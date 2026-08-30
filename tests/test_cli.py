"""The CLI against a real daemon over a real socket.

Deliberately not mocked. M2's whole argument is that building the CLI first
proves the IPC boundary is real; a CLI tested against a fake daemon would prove
nothing about it.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import threading
import unittest
from pathlib import Path

from smbpal.cli.main import (
    EXIT_ERROR,
    EXIT_NO_DAEMON,
    EXIT_OK,
    connection_notes,
    main,
)
from smbpal.config import ConfigStore
from smbpal.mounts.apply import MARKER, Mounter
from smbpal.mounts.credentials import CredentialsStore
from smbpal.mounts.probe import MountProbe
from smbpal.daemon.handlers import Authoriser, Dispatcher
from smbpal.ipc.server import UnixSocketTransport
from tests.fakes import FakeSamba


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-")
        self.addCleanup(self._dir.cleanup)
        root = Path(self._dir.name)
        self.socket_path = root / "s.sock"
        self.store = ConfigStore(root / "config.json")
        # These are CLI tests and the peer is whoever runs them, so the
        # daemon is started with authorisation off rather than with a fake
        # polkit that would answer yes to everything anyway. What guards the
        # gate itself is test_ipc, and it does it against the gate.
        self.dispatcher = Dispatcher(
            self.store, authoriser=Authoriser(policy="group")
        )
        self.transport = UnixSocketTransport(self.socket_path, group=None)
        self.transport.bind()
        self.thread = threading.Thread(
            target=self.transport.serve_forever,
            args=(self.dispatcher.handle,),
            daemon=True,
        )
        self.thread.start()
        self.addCleanup(self._stop)

    def _stop(self) -> None:
        self.transport.shutdown()
        self.thread.join(timeout=5)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--socket", str(self.socket_path), *argv])
        return code, out.getvalue(), err.getvalue()


class TestBasics(CliTestCase):
    def test_ping(self) -> None:
        code, out, _ = self.run_cli("ping")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("answering", out)

    def test_status_on_an_empty_config(self) -> None:
        code, out, _ = self.run_cli("status")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("no shares configured", out)
        self.assertIn("no connections configured", out)

    def test_json_output_is_parseable(self) -> None:
        import json

        self.run_cli("share", "add", "Media", "/srv/media")
        code, out, _ = self.run_cli("--json", "share", "list")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)[0]["name"], "Media")


class TestConnectionNotes(unittest.TestCase):
    """The sentence under the one-word state."""

    def test_a_problem_gets_its_reason(self) -> None:
        notes = connection_notes(
            [{"id": "nas", "state": "auth_failed", "is_problem": True,
              "message": "the username or password was refused by the server"}]
        )
        self.assertEqual(len(notes), 1)
        self.assertIn("password was refused", notes[0])

    def test_a_read_only_mount_gets_one_even_though_it_is_not_a_problem(self) -> None:
        # `connected` is correct and is not a problem state, so without this
        # the table shows one reassuring word and the person goes looking at
        # the mountpoint's ownership for an answer that is not there.
        notes = connection_notes(
            [{"id": "nas", "state": "connected", "is_problem": False,
              "read_only": True,
              "message": "mounted read-only — writes will be refused"}]
        )
        self.assertEqual(len(notes), 1)
        self.assertIn("read-only", notes[0])

    def test_a_healthy_connection_stays_quiet(self) -> None:
        notes = connection_notes(
            [{"id": "nas", "state": "connected", "is_problem": False,
              "read_only": False, "message": "mounted"}]
        )
        self.assertEqual(notes, [])


class TestShares(CliTestCase):
    def test_add_list_remove(self) -> None:
        code, out, _ = self.run_cli("share", "add", "Media", "/srv/media")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("added share 'Media' (media)", out)

        _, out, _ = self.run_cli("share", "list")
        self.assertIn("Media", out)
        self.assertIn("/srv/media", out)

        code, out, _ = self.run_cli("share", "remove", "Media")
        self.assertEqual(code, EXIT_OK)
        _, out, _ = self.run_cli("share", "list")
        self.assertIn("no shares configured", out)

    def test_a_relative_path_is_resolved_against_the_callers_directory(self) -> None:
        # The daemon's cwd is not the user's, so `./media` has to be resolved
        # here or it means something different at the other end.
        self.run_cli("share", "add", "Rel", "relative-dir")
        stored = self.store.load()["shares"][0]["path"]
        self.assertTrue(stored.startswith("/"))
        self.assertTrue(stored.endswith("relative-dir"))

    def test_read_only_and_disabled_flags_reach_the_record(self) -> None:
        self.run_cli("share", "add", "RO", "/srv/ro", "--read-only", "--disabled")
        share = self.store.load()["shares"][0]
        self.assertTrue(share["read_only"])
        self.assertFalse(share["enabled"])

    def test_a_rejected_share_name_reports_the_field_not_an_index(self) -> None:
        code, _, err = self.run_cli("share", "add", "bad\nname", "/srv/x")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("- name:", err)
        self.assertNotIn("shares[", err)

    def test_a_duplicate_name_is_refused_with_a_reason(self) -> None:
        self.run_cli("share", "add", "Media", "/srv/a")
        code, _, err = self.run_cli("share", "add", "media", "/srv/b")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("case-insensitive", err)

    def test_removing_something_absent_exits_nonzero(self) -> None:
        code, _, err = self.run_cli("share", "remove", "ghost")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no share called 'ghost'", err)


class TestConnections(CliTestCase):
    def test_add_list_remove(self) -> None:
        code, out, _ = self.run_cli(
            "connection", "add", "rivendell.local", "Media", "/mnt/nas"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("//rivendell.local/Media -> /mnt/nas", out)

        _, out, _ = self.run_cli("connection", "list")
        self.assertIn("rivendell.local", out)

        code, _, _ = self.run_cli("connection", "remove", "/mnt/nas")
        self.assertEqual(code, EXIT_OK)

    def test_the_mountpoint_can_be_left_out(self) -> None:
        # The whole path: an omitted positional must not become a resolved
        # path from the CLI's working directory on the way to the daemon.
        code, out, _ = self.run_cli(
            "connection", "add", "rivendell.local", "Media", "--owner", "pi"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("-> /media/pi/Media", out)
        self.assertEqual(
            self.store.load()["connections"][0]["mountpoint"], "/media/pi/Media"
        )

    def test_a_given_mountpoint_is_still_used(self) -> None:
        self.run_cli("connection", "add", "rivendell.local", "Media", "/srv/backups")
        self.assertEqual(
            self.store.load()["connections"][0]["mountpoint"], "/srv/backups"
        )

    def test_auto_connect_defaults_to_on_this_network(self) -> None:
        self.run_cli("connection", "add", "h", "S", "/mnt/x")
        self.assertEqual(
            self.store.load()["connections"][0]["auto_connect"], "on_this_network"
        )


class TestNoApply(CliTestCase):
    def test_a_config_only_daemon_says_the_share_is_not_being_served(self) -> None:
        # D12: a config edit the daemon has not applied is a lie. This test case
        # runs without an applier, which is exactly --no-apply, so every add is
        # one unless it says so.
        code, out, _ = self.run_cli("share", "add", "Test", "/srv/test")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("recorded only", out)
        self.assertIn("--no-apply", out)


class TestErrors(CliTestCase):
    def test_no_traceback_ever_reaches_the_user(self) -> None:
        code, out, err = self.run_cli("share", "add", "bad\nname", "/srv/x")
        self.assertEqual(code, EXIT_ERROR)
        self.assertNotIn("Traceback", err + out)
        self.assertTrue(err.startswith("smbpal: "))

    def test_an_absent_daemon_has_its_own_exit_code(self) -> None:
        # Distinguishable from "the daemon refused", so a script can tell
        # "not running" from "not allowed" (D12).
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--socket", "/tmp/smbpal-definitely-absent.sock", "status"])
        self.assertEqual(code, EXIT_NO_DAEMON)
        self.assertIn("no SMBPal daemon", err.getvalue())

    def test_an_unknown_subcommand_is_a_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.run_cli("share", "frobnicate")
        self.assertEqual(caught.exception.code, 2)


class TestBrowse(CliTestCase):
    def test_browse_reports_missing_avahi_rather_than_crashing(self) -> None:
        import smbpal.discovery.browse as browse

        original = browse.shutil.which
        browse.shutil.which = lambda _name: None
        self.addCleanup(setattr, browse.shutil, "which", original)
        code, _, err = self.run_cli("browse")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("avahi-browse", err)

    def test_browse_renders_one_row_per_machine(self) -> None:
        import smbpal.daemon.handlers as handlers
        from tests.test_discovery import M0_CAPTURE
        from smbpal.discovery import SMB_SERVICE, discover

        def fake(_request: object, _peer: object) -> list[dict[str, object]]:
            runner = lambda t, _to: M0_CAPTURE if t == SMB_SERVICE else ""  # noqa: E731
            return [m.to_wire() for m in discover(runner=runner)]

        original = handlers._METHODS["browse"]
        handlers._METHODS["browse"] = lambda _self, req, peer: fake(req, peer)
        self.addCleanup(handlers._METHODS.__setitem__, "browse", original)

        code, out, _ = self.run_cli("browse")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("RASPBERRYPI", out)
        self.assertIn("192.168.0.210", out)
        self.assertNotIn("127.0.0.1", out)
        self.assertEqual(out.count("RASPBERRYPI"), 1)


class TestTeardownConfirmation(CliTestCase):
    """A destructive verb asks first, and takes silence for no."""

    def run_with_input(self, answer: str | None, *argv: str):
        import builtins

        def fake_input(prompt: str = "") -> str:
            if answer is None:
                raise EOFError
            return answer

        original = builtins.input
        builtins.input = fake_input
        self.addCleanup(setattr, builtins, "input", original)
        return self.run_cli(*argv)

    def test_declining_changes_nothing(self) -> None:
        code, out, _ = self.run_with_input("n", "teardown")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("cancelled", out)

    def test_piped_silence_is_not_consent(self) -> None:
        # `yes '' | smbpal teardown` and a closed stdin must not tear down.
        code, out, _ = self.run_with_input(None, "teardown")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("cancelled", out)

    def test_the_warning_says_the_config_survives(self) -> None:
        _, out, _ = self.run_with_input("n", "teardown")
        self.assertIn("configuration is kept", out)


class TestUnaccounted(CliTestCase):
    """A share mounting on access that the config knows nothing about."""

    def setUp(self) -> None:
        super().setUp()
        root = Path(self._dir.name)
        self.unit_dir = root / "units"
        self.unit_dir.mkdir()
        # A real path under the temp root rather than /mnt, so that adding the
        # same connection back can actually create it.
        # resolve(): the CLI resolves the path it sends, and on macOS /tmp is a
        # symlink to /private/tmp. The fixture has to agree with what the
        # daemon will store or the mountpoints compare unequal for a reason
        # that has nothing to do with what is being tested.
        self.mountpoint = str((root / "mnt" / "smbpal-test").resolve())
        self.mountinfo = root / "mountinfo"
        self.mountinfo.write_text(
            f"83 36 0:44 / {self.mountpoint} rw,relatime shared:45 - cifs "
            "//rivendell.local/Media rw,vers=3.1.1\n",
            encoding="utf-8",
        )
        (self.unit_dir / "mnt-smbpal.mount").write_text(
            f"{MARKER}rivendell-local-media. Do not edit.\n"
            f"[Mount]\nWhere={self.mountpoint}\n",
            encoding="utf-8",
        )
        self.dispatcher.mounter = Mounter(
            unit_dir=self.unit_dir,
            credentials=CredentialsStore(root / "creds"),
            probe=MountProbe(mountinfo=self.mountinfo),
            runner=FakeSamba(root / "smb.conf"),
        )

    def test_status_says_so_without_being_asked(self) -> None:
        # The Pi run that produced this had an empty config, a correct
        # `connection list`, and a share mounting on access. Nothing surfaced
        # it, so nothing was going to be noticed.
        code, out, _ = self.run_cli("status")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("no connections configured", out)
        self.assertIn("Not in the config (1)", out)
        self.assertIn(self.mountpoint, out)
        self.assertIn("rivendell-local-media", out)

    def test_connection_live_lists_it(self) -> None:
        code, out, _ = self.run_cli("connection", "live")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("//rivendell.local/Media", out)

    def test_connection_live_is_quiet_when_there_is_nothing(self) -> None:
        self.mountinfo.write_text("", encoding="utf-8")
        (self.unit_dir / "mnt-smbpal.mount").unlink()
        code, out, _ = self.run_cli("connection", "live")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("nothing on this machine is unaccounted for", out)

    def test_a_commit_does_not_reap_units_this_config_never_knew(self) -> None:
        # The 27 August near-miss, end to end. The daemon is looking at a
        # config that has never mentioned this unit; adding an unrelated
        # connection must not tear the existing one down.
        # Nothing mounted, so the only thing that can protect the unit is the
        # diff rule — not the "do not destroy the evidence" check, which needs
        # a live mount to fire.
        self.mountinfo.write_text("", encoding="utf-8")
        root = Path(self._dir.name)
        other = str((root / "mnt" / "other").resolve())
        code, _, err = self.run_cli("connection", "add", "moria.local", "Backups", other)
        self.assertEqual(code, EXIT_OK, err)
        self.assertTrue((self.unit_dir / "mnt-smbpal.mount").exists())

    def test_the_daemon_tells_the_derivation_what_is_mounted(self) -> None:
        # The derivation cannot see the filesystem — that is deliberate, these
        # are pure functions — so the daemon has to hand it the live
        # mountpoints. Unit tests over add_connection cannot catch the handler
        # forgetting to.
        from smbpal.daemon import handlers

        seen: dict = {}
        original = handlers.ops.add_connection

        def spy(*args, **kwargs):
            seen.update(kwargs)
            return original(*args, **kwargs)

        handlers.ops.add_connection = spy
        self.addCleanup(setattr, handlers.ops, "add_connection", original)

        other = str((Path(self._dir.name) / "mnt" / "other").resolve())
        self.run_cli("connection", "add", "moria.local", "Backups", other)
        self.assertIn(self.mountpoint, seen.get("in_use") or set())

    def test_a_configured_connection_is_not_reported_as_unaccounted(self) -> None:
        self.run_cli(
            "connection", "add", "rivendell.local", "Media", self.mountpoint
        )
        _, out, _ = self.run_cli("status")
        self.assertNotIn("Not in the config", out)


if __name__ == "__main__":
    unittest.main()
