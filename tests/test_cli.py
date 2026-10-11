"""The CLI against a real daemon over a real socket.

Deliberately not mocked. M2's whole argument is that building the CLI first
proves the IPC boundary is real; a CLI tested against a fake daemon would prove
nothing about it.
"""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import threading
import unittest
from unittest import mock
import unittest.mock
from pathlib import Path

from smbpal.cli import main as cli_main
from smbpal.cli.main import (
    EXIT_ERROR,
    EXIT_NO_DAEMON,
    EXIT_OK,
    _connect_line,
    _disconnect_line,
    connection_notes,
    main,
)
from smbpal.config import ConfigStore
from smbpal.config import operations
from smbpal.mounts.apply import MARKER, Mounter
from smbpal.mounts.credentials import CredentialsStore
from smbpal.mounts.probe import MountProbe
from smbpal.daemon.handlers import Authoriser, Dispatcher
from smbpal.discovery.identity import Identity
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
        # A fixed identity, so what `status` prints does not depend on the
        # machine running the tests.
        self.dispatcher = Dispatcher(
            self.store,
            authoriser=Authoriser(policy="group"),
            identity=lambda: Identity("nas", "nas.local", ["192.0.2.10"]),
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
        # `connection add` asks whether anything answers on 445 before it says
        # the connection will mount. No test opens a socket to find out: the
        # ones about that note say what the answer is, and every other one
        # wants a plain yes.
        self.reachable = True
        patch = unittest.mock.patch(
            "smbpal.cli.main.server_reachable", lambda host: self.reachable
        )
        patch.start()
        self.addCleanup(patch.stop)

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

    def test_status_says_how_to_reach_this_computer(self) -> None:
        _, out, _ = self.run_cli("status")
        self.assertIn("reach this computer at nas.local · 192.0.2.10", out)

    def test_status_json_carries_the_identity(self) -> None:
        import json

        _, out, _ = self.run_cli("--json", "status")
        self.assertEqual(
            json.loads(out)["host"],
            {"hostname": "nas", "mdns": "nas.local", "addresses": ["192.0.2.10"]},
        )

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
            "connection", "add", "nas.local", "Media", "/mnt/nas"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("//nas.local/Media -> /mnt/nas", out)

        _, out, _ = self.run_cli("connection", "list")
        self.assertIn("nas.local", out)

        code, _, _ = self.run_cli("connection", "remove", "/mnt/nas")
        self.assertEqual(code, EXIT_OK)

    def _fake_shares(self, rows: object) -> list[dict[str, object]]:
        """Patch `server.shares` to answer `rows`, or raise if it is an error.

        Returns the list of params it was called with, so a test can assert
        what the CLI sent as well as what it printed.
        """
        import smbpal.daemon.handlers as handlers

        seen: list[dict[str, object]] = []

        def fake(_self: object, request: object, _peer: object) -> object:
            seen.append(dict(request.params))  # type: ignore[attr-defined]
            if isinstance(rows, Exception):
                raise rows
            return rows

        original = handlers._METHODS["server.shares"]
        handlers._METHODS["server.shares"] = fake
        self.addCleanup(
            handlers._METHODS.__setitem__, "server.shares", original
        )
        return seen

    def test_add_warns_when_the_server_has_no_share_by_that_name(self) -> None:
        """§6.19, and the problem that started it.

        The share on a Mac is called `Luke H's Public Folder`; the obvious
        guess is `Public`; and until `browse` existed the only thing that ever
        said so was a mount failure days later.
        """
        self._fake_shares(
            [
                {"name": "Luke H\u2019s Public Folder", "kind": "disk", "comment": ""},
                {"name": "smbpal", "kind": "disk", "comment": ""},
                {"name": "IPC$", "kind": "ipc", "comment": ""},
            ]
        )
        code, out, _ = self.run_cli(
            "connection", "add", "nas.local", "Public", "/mnt/nas"
        )
        # Advisory, never a refusal: the connection is saved either way.
        self.assertEqual(code, EXIT_OK)
        self.assertIn("has no share called 'Public'", out)
        self.assertIn("Luke H\u2019s Public Folder", out)
        # Disk shares only. Offering IPC$ as a suggestion would be worse than
        # offering nothing.
        self.assertNotIn("IPC$", out)
        # D14: the port answers, so the reachability line used to promise
        # `it will mount on first access` directly under a line saying the
        # share does not exist. Reachability is not the binding constraint
        # once the name is known to be wrong.
        self.assertNotIn("mount on first access", out)
        self.assertIn("once the name is right", out)

    def test_add_says_nothing_when_the_name_is_right(self) -> None:
        self._fake_shares([{"name": "Media", "kind": "disk", "comment": ""}])
        code, out, _ = self.run_cli(
            "connection", "add", "nas.local", "Media", "/mnt/nas"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertNotIn("warning", out)

    def test_a_difference_in_case_is_not_a_typo(self) -> None:
        # SMB matches share names case-insensitively, so this mounts fine.
        self._fake_shares([{"name": "Media", "kind": "disk", "comment": ""}])
        _, out, _ = self.run_cli(
            "connection", "add", "nas.local", "media", "/mnt/nas"
        )
        self.assertNotIn("warning", out)

    def test_add_is_silent_when_the_listing_cannot_be_had(self) -> None:
        # macOS refuses an anonymous listing outright, and a server may be
        # switched off. A line about it on every guest add would be noise
        # standing where the useful note goes.
        from smbpal.errors import Unavailable

        self._fake_shares(Unavailable("cannot list shares on nas.local"))
        code, out, _ = self.run_cli(
            "connection", "add", "nas.local", "Public", "/mnt/nas"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("added connection", out)
        self.assertNotIn("warning", out)

    def test_add_checks_the_name_with_the_credential_it_just_collected(self) -> None:
        # The whole reason the check runs after the credential is stored:
        # macOS will not list anonymously, so checking before would be silent
        # in exactly the case that motivated it.
        import smbpal.daemon.handlers as handlers

        seen = self._fake_shares([{"name": "Media", "kind": "disk", "comment": ""}])
        # Storing a credential needs a mounter, which a --no-apply daemon has
        # not got, and without this the add fails before the check is reached.
        original = handlers._METHODS["connection.set_credentials"]
        handlers._METHODS["connection.set_credentials"] = lambda *_a: {
            "id": "nas-local-media",
            "username": "pi",
        }
        self.addCleanup(
            handlers._METHODS.__setitem__, "connection.set_credentials", original
        )
        with unittest.mock.patch(
            "smbpal.cli.main.getpass.getpass", return_value="hunter2"
        ):
            self.run_cli(
                "connection", "add", "nas.local", "Media", "/mnt/nas", "--user", "pi"
            )
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["username"], "pi")
        self.assertEqual(seen[0]["password"], "hunter2")

    def test_set_credentials_passes_the_reference_through_and_renders_the_note(
        self,
    ) -> None:
        """The gap this closed: a password could be set once and never again.

        An id is derived from host and share, so re-adding to correct a
        password is refused as a duplicate, and remove-then-add throws away
        the mountpoint, the auto-connect choice and the fallback address to
        fix a typo. Found costing something on a Pi, 10 October 2026.

        The RPC is faked because storing a credential needs a mounter, which
        a `--no-apply` daemon has not got. What is under test here is the CLI
        half: what it sends, and what it prints.
        """
        import smbpal.daemon.handlers as handlers

        seen: list[dict[str, object]] = []

        def fake(_self: object, request: object, _peer: object) -> dict[str, str]:
            seen.append(dict(request.params))  # type: ignore[attr-defined]
            return {
                "id": "nas-local-media",
                "username": "pi",
                "note": "stored in the login Keychain",
            }

        original = handlers._METHODS["connection.set_credentials"]
        handlers._METHODS["connection.set_credentials"] = fake
        self.addCleanup(
            handlers._METHODS.__setitem__, "connection.set_credentials", original
        )

        with unittest.mock.patch(
            "smbpal.cli.main.getpass.getpass", return_value="hunter2"
        ):
            code, out, _ = self.run_cli(
                "connection", "set-credentials", "/mnt/nas",
                "--user", "pi", "--domain", "WORKGROUP",
            )

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(
            seen,
            [
                {
                    "ref": "/mnt/nas",
                    "username": "pi",
                    "password": "hunter2",
                    "domain": "WORKGROUP",
                }
            ],
        )
        self.assertIn("credentials stored for pi", out)
        # macOS says where it put them; `connection add --user` already
        # prints this and the new verb has to as well, or replacing a
        # Keychain item happens silently.
        self.assertIn("login Keychain", out)

    def test_set_credentials_refuses_an_empty_password_without_calling_the_daemon(
        self,
    ) -> None:
        import smbpal.daemon.handlers as handlers

        called: list[object] = []
        original = handlers._METHODS["connection.set_credentials"]
        handlers._METHODS["connection.set_credentials"] = lambda *a: called.append(a)
        self.addCleanup(
            handlers._METHODS.__setitem__, "connection.set_credentials", original
        )

        with unittest.mock.patch("smbpal.cli.main.getpass.getpass", return_value=""):
            code, _, err = self.run_cli(
                "connection", "set-credentials", "/mnt/nas", "--user", "pi"
            )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("must not be empty", err)
        self.assertEqual(called, [])

    def test_set_credentials_needs_a_username(self) -> None:
        # Without one there is nothing to store the password against, and
        # defaulting to the local user would send a credential to somebody
        # else's server under a name they did not choose. argparse exits 2.
        with self.assertRaises(SystemExit) as raised:
            self.run_cli("connection", "set-credentials", "/mnt/nas")
        self.assertEqual(raised.exception.code, 2)

    def test_the_mountpoint_can_be_left_out(self) -> None:
        # The whole path: an omitted positional must not become a resolved
        # path from the CLI's working directory on the way to the daemon.
        code, out, _ = self.run_cli(
            "connection", "add", "nas.local", "Media", "--owner", "pi"
        )
        self.assertEqual(code, EXIT_OK)
        # The platform's own root, because the daemon now derives for the
        # machine it runs on rather than always for Linux -- on a Mac it had
        # been producing /media/<user>/..., a path macOS ignores.
        expected = operations.default_mountpoint(
            "Media", "pi", set(), host="nas.local",
            style=operations.platform_style(sys.platform),
        )
        self.assertIn(f"-> {expected}", out)
        # And it is written into the config rather than re-derived on read:
        # defaulting is an input convenience, and a stored mountpoint that
        # depends on which version of the function last ran is not a record.
        self.assertEqual(
            self.store.load()["connections"][0]["mountpoint"], expected
        )

    def test_a_given_mountpoint_is_still_used(self) -> None:
        self.run_cli("connection", "add", "nas.local", "Media", "/srv/backups")
        self.assertEqual(
            self.store.load()["connections"][0]["mountpoint"], "/srv/backups"
        )

    def test_it_says_the_share_will_mount_when_the_server_answers(self) -> None:
        _, out, _ = self.run_cli("connection", "add", "nas.local", "Media", "/mnt/nas")
        self.assertIn("it will mount on first access", out)

    def test_it_says_so_when_nothing_answers_at_that_name(self) -> None:
        """Fedora, 27 September 2026.

        `rivendell.local` had stopped being the NAS's hostname. The connection
        was saved, the monitor declined to prime it every five seconds because
        nothing answered there, and nothing anywhere said so. It is still saved
        — a server that is switched off is an ordinary thing to configure — but
        the person who typed the name is told while they are still looking.
        """
        self.reachable = False
        code, out, _ = self.run_cli(
            "connection", "add", "gone.local", "Media", "/mnt/nas"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("nothing answers on port 445 at gone.local", out)
        self.assertIn("it will mount when something does", out)
        self.assertEqual(len(self.store.load()["connections"]), 1)

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
        # **The message says what it found, because this failed once in CI and
        # could not be reproduced.** `redirect_stderr` catches everything the
        # process writes while it is in force, not only the CLI: a WARNING from
        # any thread reaches `logging.lastResort`, and `warnings.warn` goes to
        # stderr too. Either lands in front of the CLI's own line and fails this
        # assertion, and knowing *which* is the difference between a fix and a
        # guess. The bare assertTrue said only "False is not true".
        self.assertTrue(
            err.startswith("smbpal: "),
            f"something wrote to stderr before the CLI did: {err!r}",
        )

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
        self.assertIn("192.0.2.210", out)
        self.assertNotIn("127.0.0.1", out)
        self.assertEqual(out.count("RASPBERRYPI"), 1)


    def test_browse_with_a_host_lists_that_server_s_shares(self) -> None:
        # docs §6.19: the share on a Mac is called `Luke H's Public Folder`
        # and the obvious guess is `Public`. Before this existed, a wrong
        # guess had no way to become a right one.
        import smbpal.daemon.handlers as handlers
        from tests.test_shares import MAC_LISTING
        from smbpal.discovery.shares import interpret

        def fake(_self: object, _req: object, _peer: object) -> list[dict[str, str]]:
            return [s.to_wire() for s in interpret(MAC_LISTING)]

        original = handlers._METHODS["server.shares"]
        handlers._METHODS["server.shares"] = fake
        self.addCleanup(handlers._METHODS.__setitem__, "server.shares", original)

        code, out, _ = self.run_cli("browse", "mac.local")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Luke H\u2019s Public Folder", out)
        self.assertIn("smbpal", out)
        # The kind column is why IPC$ can be shown without being confusing.
        self.assertIn("ipc", out)

    def test_browse_with_no_host_still_finds_machines(self) -> None:
        # One command, two jobs: the host argument is what separates them, and
        # adding it must not have changed the no-argument behaviour.
        import smbpal.daemon.handlers as handlers

        called: list[str] = []
        original = handlers._METHODS["browse"]
        handlers._METHODS["browse"] = lambda _s, _r, _p: called.append("browse") or []
        self.addCleanup(handlers._METHODS.__setitem__, "browse", original)

        code, _, _ = self.run_cli("browse")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(called, ["browse"])

class TestBrowseHeadingSaysWhatItMeasures(CliTestCase):
    """D14, and the reason it is a test rather than a tidier word.

    The column is fed by an `_smbpal._tcp` advertisement, which §3f publishes
    only while a share is active. `RUNNING SMBPAL` therefore answered "no" for
    a machine running SMBPal with nothing shared -- including, on the 64-bit Pi
    on 30 September 2026, the machine the command was typed on, while its
    daemon was answering. The one row a reader can check independently is
    their own, which is the worst place to be wrong.
    """

    def test_the_header_is_not_the_field_name(self) -> None:
        from smbpal.cli.format import render_table

        rows = [{"name": "PI", "running_smbpal": False}]
        out = render_table(
            rows, ("name", "running_smbpal"), headers={"running_smbpal": "SHARING NOW"}
        )
        self.assertIn("SHARING NOW", out)
        self.assertNotIn("RUNNING SMBPAL", out)

    def test_the_wire_field_is_unchanged_for_json_consumers(self) -> None:
        # The header is a presentation fix. Renaming the field would break
        # anything reading `smbpal browse --json`, and the field name is not
        # what misled anybody.
        from smbpal.discovery.browse import Machine

        self.assertIn("running_smbpal", Machine("PI", "pi.local").to_wire())

    def test_a_header_defaults_to_the_key_when_none_is_given(self) -> None:
        from smbpal.cli.format import render_table

        out = render_table([{"host_name": "pi"}], ("host_name",))
        self.assertIn("HOST NAME", out)


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
            "//nas.local/Media rw,vers=3.1.1\n",
            encoding="utf-8",
        )
        (self.unit_dir / "mnt-smbpal.mount").write_text(
            f"{MARKER}nas-local-media. Do not edit.\n"
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
        self.assertIn("nas-local-media", out)

    def test_connection_live_lists_it(self) -> None:
        code, out, _ = self.run_cli("connection", "live")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("//nas.local/Media", out)

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
            "connection", "add", "nas.local", "Media", self.mountpoint
        )
        _, out, _ = self.run_cli("status")
        self.assertNotIn("Not in the config", out)



class TestTheConnectLine(unittest.TestCase):
    """It read `result['unit']` unconditionally, which macOS does not send.

    A mount through the agent has no systemd unit and the reply says
    `mountpoint` instead, so the first successful macOS mount would have ended
    in a `KeyError` traceback. Every macOS test until now was against a server
    that does not exist, so only the failure path had ever run.
    """

    def test_linux_names_the_unit(self) -> None:
        self.assertEqual(
            _connect_line({"id": "nas-media", "unit": "mnt-nas.mount"}),
            "mounted nas-media (mnt-nas.mount)",
        )

    def test_macos_names_the_mountpoint(self) -> None:
        self.assertEqual(
            _connect_line({"id": "nas-media", "mountpoint": "/Volumes/Media"}),
            "mounted nas-media at /Volumes/Media",
        )

    def test_a_reply_with_neither_still_says_something(self) -> None:
        self.assertEqual(_connect_line({"id": "nas-media"}), "mounted nas-media")

    def test_the_note_about_a_moved_mountpoint_is_shown(self) -> None:
        line = _connect_line(
            {"id": "x", "mountpoint": "/Volumes/Media", "note": "macOS chose this."}
        )
        self.assertIn("macOS chose this.", line)


class TestTheDisconnectLine(unittest.TestCase):
    """The verb has to match what happened, on both platforms.

    The CLI said "it will remount on next access" unconditionally -- a Linux
    automount talking. On macOS nothing remounts it, and when nothing was
    mounted nothing happened at all. The daemon knows which of the three it was
    and says so in `note`; this stopped printing over the top of it.
    """

    def line(self, **result: object) -> str:
        return _disconnect_line({"id": "nas-media", **result})

    def test_a_daemon_that_reports_nothing_gets_the_plain_line(self) -> None:
        # The systemd path sends no `unmounted` key, so Linux must read exactly
        # as it did before any of this.
        self.assertEqual(self.line(), "unmounted nas-media")

    def test_the_daemons_note_is_used_rather_than_a_guess(self) -> None:
        line = self.line(note="It will mount again as soon as anything opens the folder.")
        self.assertEqual(
            line,
            "unmounted nas-media; it will mount again as soon as anything "
            "opens the folder.",
        )

    def test_nothing_mounted_does_not_claim_an_unmount(self) -> None:
        # "unmounted X; nothing was mounted there" was the first attempt, and
        # it claims an unmount in its first word and denies it in its last.
        line = self.line(unmounted=False, note="Nothing was mounted there.")
        self.assertEqual(line, "nas-media was not mounted, so nothing changed")
        self.assertNotIn("unmounted", line)


if __name__ == "__main__":
    unittest.main()


class TestShareNotes(unittest.TestCase):
    def test_a_share_nobody_can_open_gets_the_command_that_fixes_it(self) -> None:
        from smbpal.cli.main import share_notes

        notes = share_notes(
            [
                {"name": "Media", "credential_ref": "luke", "can_sign_in": False},
                {"name": "Fine", "credential_ref": "luke", "can_sign_in": True},
                {"name": "Old", "credential_ref": "luke"},
            ]
        )
        text = "\n".join(notes)
        self.assertIn("Media: nobody can sign in yet", text)
        self.assertIn("smbpal credential set luke", text)
        self.assertNotIn("Fine", text)
        self.assertNotIn("Old", text)

    def test_nothing_to_say_says_nothing(self) -> None:
        from smbpal.cli.main import share_notes

        self.assertEqual(share_notes([{"name": "Fine", "can_sign_in": True}]), [])



class TestSambaNotRunningNotes(unittest.TestCase):
    """Fedora, 27 September 2026.

    A Fedora package never starts its service, so `samba` arrived installed and
    stopped: the share was added, `smbpal status` showed it served, and the Pi
    could not reach it. The share rows were not wrong — the share *is*
    configured — so the sentence has to come from beside them.
    """

    def notes(self, samba, shares=({"name": "Media"},)):
        from smbpal.cli.main import samba_notes

        return "\n".join(samba_notes(samba, list(shares)))

    def test_a_stopped_samba_is_named_with_the_command_that_starts_it(self) -> None:
        note = self.notes({"unit": "smb.service", "active": False, "installed": True})
        self.assertIn("Samba is not running", note)
        self.assertIn("sudo systemctl enable --now smb.service", note)

    def test_the_unit_name_is_the_one_this_machine_has(self) -> None:
        # Debian calls it smbd.service and Fedora smb.service; advice that
        # names the wrong one is worse than none.
        note = self.notes({"unit": "smbd.service", "active": False, "installed": True})
        self.assertIn("smbd.service", note)
        self.assertNotIn("--now smb.service", note)

    def test_samba_missing_is_a_different_sentence(self) -> None:
        note = self.notes({"unit": None, "active": False, "installed": False})
        self.assertIn("not installed", note)
        self.assertNotIn("systemctl", note)

    def test_a_running_samba_says_nothing(self) -> None:
        self.assertEqual(
            self.notes({"unit": "smb.service", "active": True}), ""
        )

    def test_nothing_is_said_on_a_machine_that_only_mounts(self) -> None:
        # No shares, so nothing is going unserved and the line would be noise.
        self.assertEqual(
            self.notes(
                {"unit": "smb.service", "active": False, "installed": True}, shares=()
            ),
            "",
        )


class TestSelinuxNotes(unittest.TestCase):
    """Fedora, 27 September 2026, §6b of the runbook.

    `/home/luke/Testshare` was `drwxr-xr-x luke luke` and
    `unconfined_u:object_r:user_home_t:s0`. The share mounted from a Pi,
    authenticated, and refused every write; nothing in that failure said
    SELinux. Relabelling it `samba_share_t` fixed it.
    """

    def note(self, **overrides: str) -> str:
        from smbpal.cli.main import selinux_notes

        problem = {
            "path": "/home/luke/Testshare",
            "type": "user_home_t",
            "wanted": "samba_share_t",
            "label": 'sudo semanage fcontext -a -t samba_share_t '
            '"/home/luke/Testshare(/.*)?"',
            "restore": "sudo restorecon -Rv /home/luke/Testshare",
            **overrides,
        }
        return "\n".join(selinux_notes([problem]))

    def test_it_names_the_label_the_path_has_and_the_one_it_needs(self) -> None:
        note = self.note()
        self.assertIn("user_home_t", note)
        self.assertIn("samba_share_t", note)
        self.assertIn("/home/luke/Testshare", note)

    def test_it_describes_the_symptom_somebody_will_actually_see(self) -> None:
        # The point of the note: connecting works, so nobody looks at the
        # share's configuration when writes fail.
        self.assertIn("refuse writes", self.note())

    def test_it_gives_both_commands_and_semanage_before_restorecon(self) -> None:
        note = self.note()
        self.assertIn("semanage fcontext", note)
        self.assertIn("restorecon -Rv", note)
        self.assertLess(note.index("semanage"), note.index("restorecon"))

    def test_nothing_is_said_when_there_is_nothing_to_say(self) -> None:
        from smbpal.cli.main import selinux_notes

        self.assertEqual(selinux_notes([]), [])


class TestSetupSaysWhatIsLeftToDoByHand(unittest.TestCase):
    """`smbpal setup`, which must work when there is no daemon at all.

    That is the whole situation it exists for -- a macOS install where the
    launchd jobs have not been created yet -- so it is dispatched before the
    client is built. A `setup` routed through `Client` would answer *no daemon is
    listening* to the one question whose answer is why.

    **Both platform branches are exercised wherever this runs.** The macOS path
    is the interesting one and CI is Linux, so the platform is patched rather
    than skipped: `config/operations.py`'s `platform_style` takes a platform for
    the same reason.
    """

    def run_setup(self) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["setup"])
        return code, out.getvalue()

    def test_on_linux_it_says_the_package_did_it(self) -> None:
        with mock.patch.object(cli_main.sys, "platform", "linux"):
            code, out = self.run_setup()
        self.assertEqual(code, 0)
        self.assertIn("Nothing to do", out)
        self.assertIn("systemctl", out)

    def test_it_prints_the_three_commands_in_order(self) -> None:
        with (
            mock.patch.object(cli_main.sys, "platform", "darwin"),
            mock.patch.object(cli_main, "HELPER_INSTALLED", Path("/nope/smbpal-helper")),
            mock.patch.object(cli_main, "_group_exists", return_value=False),
            mock.patch.object(cli_main, "_helper_source", return_value=Path("/src/helper")),
            mock.patch.object(cli_main.shutil, "which", return_value="/opt/hb/bin/smbpald"),
        ):
            code, out = self.run_setup()
        self.assertEqual(code, 0)
        install_d = out.index("install -d")
        copy = out.index("/src/helper /nope/smbpal-helper")
        helper_install = out.index("install --daemon /opt/hb/bin/smbpald")
        # The order is the point: nothing of ours runs as root until the copy
        # has landed in root-owned storage.
        self.assertLess(install_d, copy)
        self.assertLess(copy, helper_install)

    def test_it_names_the_daemon_path_it_found_rather_than_a_prefix(self) -> None:
        """The Homebrew prefix is not one place: `/opt/homebrew` on Apple
        silicon, `/usr/local` on Intel. The helper takes `--daemon` for that
        reason and this is what fills it in."""
        with (
            mock.patch.object(cli_main.sys, "platform", "darwin"),
            mock.patch.object(cli_main, "HELPER_INSTALLED", Path("/nope/h")),
            mock.patch.object(cli_main, "_group_exists", return_value=False),
            mock.patch.object(cli_main, "_helper_source", return_value=Path("/src/h")),
            mock.patch.object(cli_main.shutil, "which", return_value="/usr/local/bin/smbpald"),
        ):
            _, out = self.run_setup()
        self.assertIn("--daemon /usr/local/bin/smbpald", out)

    def test_when_set_up_it_points_at_uninstall_rather_than_repeating_itself(self) -> None:
        """The install refuses to run twice, so `setup` must not suggest it."""
        with tempfile.TemporaryDirectory() as tmp:
            installed = Path(tmp) / "smbpal-helper"
            installed.write_text("")
            with (
                mock.patch.object(cli_main.sys, "platform", "darwin"),
                mock.patch.object(cli_main, "HELPER_INSTALLED", installed),
                mock.patch.object(cli_main, "_group_exists", return_value=True),
                mock.patch.object(cli_main.shutil, "which", return_value="/x/smbpald"),
            ):
                code, out = self.run_setup()
        self.assertEqual(code, 0)
        self.assertIn("uninstall", out)
        self.assertNotIn("--daemon", out)

    def test_it_says_so_when_the_helper_is_not_built(self) -> None:
        with (
            mock.patch.object(cli_main.sys, "platform", "darwin"),
            mock.patch.object(cli_main, "HELPER_INSTALLED", Path("/nope/h")),
            mock.patch.object(cli_main, "_group_exists", return_value=False),
            mock.patch.object(cli_main, "_helper_source", return_value=None),
        ):
            code, out = self.run_setup()
        self.assertEqual(code, 1)
        self.assertIn("make -C helper", out)

    def test_it_says_so_when_smbpald_is_not_on_path(self) -> None:
        with (
            mock.patch.object(cli_main.sys, "platform", "darwin"),
            mock.patch.object(cli_main, "HELPER_INSTALLED", Path("/nope/h")),
            mock.patch.object(cli_main, "_group_exists", return_value=False),
            mock.patch.object(cli_main, "_helper_source", return_value=Path("/src/h")),
            mock.patch.object(cli_main.shutil, "which", return_value=None),
        ):
            code, out = self.run_setup()
        self.assertEqual(code, 1)
        self.assertIn("not on PATH", out)
