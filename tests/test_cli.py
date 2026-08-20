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

from smbpal.cli.main import EXIT_ERROR, EXIT_NO_DAEMON, EXIT_OK, main
from smbpal.config import ConfigStore
from smbpal.daemon.handlers import Dispatcher
from smbpal.ipc.server import UnixSocketTransport


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-")
        self.addCleanup(self._dir.cleanup)
        root = Path(self._dir.name)
        self.socket_path = root / "s.sock"
        self.store = ConfigStore(root / "config.json")
        self.dispatcher = Dispatcher(self.store)
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


if __name__ == "__main__":
    unittest.main()
