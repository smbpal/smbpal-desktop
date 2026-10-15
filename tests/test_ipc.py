"""The socket end to end: a real daemon dispatcher over a real Unix socket."""

from __future__ import annotations

import grp
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from smbpal import PROTOCOL_VERSION
from smbpal.config import ConfigStore, empty_config
from smbpal.daemon.handlers import Authoriser, Dispatcher
from smbpal.daemon import polkit as polkit_module
from smbpal.daemon.polkit import MANAGE_SHARES
from smbpal.ipc import client as client_module
from smbpal.ipc import server as server_module
from smbpal.errors import (
    BadRequest,
    DaemonUnreachable,
    NotFound,
    NotPermitted,
    SmbpalError,
    NotSupported,
    UnknownMethod,
    UnsupportedVersion,
)
from smbpal.ipc.client import Client, _how_to_start
from smbpal.ipc.peer import PeerCredentials
from smbpal.ipc.protocol import MAX_FRAME_BYTES, encode_event
from smbpal.ipc.server import UnixSocketTransport


class ServerTestCase(unittest.TestCase):
    """Spins up a transport on a short temp path.

    Short because sun_path is ~104 bytes and macOS's default temp directory
    eats most of that.
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-")
        self.addCleanup(self._dir.cleanup)
        root = Path(self._dir.name)
        self.socket_path = root / "s.sock"
        self.store = ConfigStore(root / "config.json")
        self.dispatcher = self.make_dispatcher()
        # No group: tests do not run as root and must not need to.
        self.transport = UnixSocketTransport(self.socket_path, group=None)
        self.transport.bind()
        self.thread = threading.Thread(
            target=self.transport.serve_forever,
            args=(self.dispatcher.handle,),
            daemon=True,
        )
        self.thread.start()
        self.addCleanup(self._stop)

    def make_dispatcher(self) -> Dispatcher:
        """Overridden by cases that need a differently configured daemon.

        A hook rather than a copy of `setUp`: the binding, the thread and the
        cleanup are the fiddly part and are the same every time.
        """
        return Dispatcher(self.store)

    def _stop(self) -> None:
        self.transport.shutdown()
        self.thread.join(timeout=5)

    def client(self, **kwargs: object) -> Client:
        client = Client(self.socket_path, timeout=5.0, reply_timeout=5.0, **kwargs)  # type: ignore[arg-type]
        client.connect()
        self.addCleanup(client.close)
        return client

    def raw(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(str(self.socket_path))
        self.addCleanup(sock.close)
        return sock


class TestStoppingBeforeServing(unittest.TestCase):
    """`shutdown()` can land before the serve thread has registered anything.

    The CLI tests start a server thread and, for a test that never connects,
    stop it almost at once. Once in a while the listener was closed between
    the thread starting and it registering the socket, and the selector
    refused fd -1 with a traceback that ended up in the next test's stderr.
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-")
        self.addCleanup(self._dir.cleanup)
        self.transport = UnixSocketTransport(
            Path(self._dir.name) / "s.sock", group=None
        )
        self.transport.bind()

    def test_shutdown_first_means_serve_returns_quietly(self) -> None:
        self.transport.shutdown()
        self.transport.serve_forever(lambda _c, _f: None)

    def test_a_listener_closed_under_it_is_a_stop_not_a_crash(self) -> None:
        """The exact interleaving: the thread has the listener, then it closes."""
        self.transport._stopping.set()
        self.transport._listener.close()
        self.transport.serve_forever(lambda _c, _f: None)
        self.transport.shutdown()


class TestMethods(ServerTestCase):
    def test_ping(self) -> None:
        self.assertEqual(self.client().call("ping"), {"pong": True})

    def test_version_reports_both_versions(self) -> None:
        result = self.client().call("version")
        self.assertEqual(result["protocol"], PROTOCOL_VERSION)
        self.assertIn("version", result)

    def test_config_get_returns_the_stored_config(self) -> None:
        doc = {
            "version": 1,
            "shares": [{"type": "os", "id": "m", "name": "M", "path": "/srv/m"}],
            "connections": [],
        }
        self.store.save(doc)
        self.assertEqual(self.client().call("config.get"), doc)

    def test_config_get_on_a_first_boot_returns_an_empty_config(self) -> None:
        self.assertEqual(self.client().call("config.get"), empty_config())

    def test_several_calls_on_one_connection(self) -> None:
        client = self.client()
        for _ in range(5):
            self.assertEqual(client.call("ping"), {"pong": True})

    def test_concurrent_clients(self) -> None:
        results: list[object] = []
        errors: list[BaseException] = []

        def hammer() -> None:
            try:
                with Client(self.socket_path, timeout=5.0) as client:
                    for _ in range(10):
                        results.append(client.call("ping"))
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 40)


class TestErrors(ServerTestCase):
    def test_unknown_method(self) -> None:
        with self.assertRaises(UnknownMethod):
            self.client().call("nope")

    def test_malformed_json_is_reported_not_fatal(self) -> None:
        sock = self.raw()
        sock.sendall(b"{not json\n")
        reply = json.loads(sock.recv(4096).decode("utf-8"))
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], BadRequest.code)
        # The daemon is still serving afterwards.
        self.assertEqual(self.client().call("ping"), {"pong": True})

    def test_a_wrong_protocol_version_is_refused(self) -> None:
        sock = self.raw()
        sock.sendall(
            json.dumps({"v": 99, "id": "1", "method": "ping"}).encode("utf-8") + b"\n"
        )
        reply = json.loads(sock.recv(4096).decode("utf-8"))
        self.assertEqual(reply["error"]["code"], UnsupportedVersion.code)

    def test_a_request_without_an_id_is_refused_with_a_null_id(self) -> None:
        sock = self.raw()
        sock.sendall(json.dumps({"v": 1, "method": "ping"}).encode("utf-8") + b"\n")
        reply = json.loads(sock.recv(4096).decode("utf-8"))
        self.assertFalse(reply["ok"])
        self.assertIsNone(reply["id"])

    def test_an_unframed_flood_closes_the_connection(self) -> None:
        # A client that never sends a newline must not be able to make the
        # daemon buffer without bound.
        sock = self.raw()
        try:
            sock.sendall(b"x" * (MAX_FRAME_BYTES + 4096))
        except OSError:
            pass  # The daemon may close mid-write, which is the point.
        sock.settimeout(5.0)
        try:
            self.assertEqual(sock.recv(1), b"")
        except OSError:
            pass  # A reset is an equally good answer.
        self.assertEqual(self.client().call("ping"), {"pong": True})

    def test_a_handler_raising_does_not_kill_the_daemon(self) -> None:
        def explode(*_args: object) -> None:
            raise RuntimeError("boom")

        from smbpal.daemon import handlers

        handlers._METHODS["boom"] = explode  # type: ignore[assignment]
        self.addCleanup(handlers._METHODS.pop, "boom", None)
        Authoriser.READ_ONLY = frozenset(Authoriser.READ_ONLY | {"boom"})
        self.addCleanup(
            setattr, Authoriser, "READ_ONLY", frozenset(Authoriser.READ_ONLY - {"boom"})
        )

        client = self.client()
        with self.assertRaises(Exception) as caught:
            client.call("boom")
        self.assertEqual(getattr(caught.exception, "code", None), "internal")
        self.assertEqual(client.call("ping"), {"pong": True})


class RecordingChecker:
    """A polkit that says the same thing every time and remembers being asked.

    The interesting half is `calls`. A gate that lets the right things through
    is only half of it; the other half is that it asked about the right action,
    for the right peer, and did not ask at all about the read-only ones.
    """

    def __init__(self, *, answer: bool) -> None:
        self.answer = answer
        self.calls: list[tuple[PeerCredentials, str]] = []

    def check(self, peer: PeerCredentials, action: str) -> bool:
        self.calls.append((peer, action))
        return self.answer


class ScriptedChecker:
    """Answers from a list, so a refusal can be followed by a grant."""

    def __init__(self, *answers: bool) -> None:
        self.answers = list(answers)
        self.calls = 0

    def check(self, peer: PeerCredentials, action: str) -> bool:
        self.calls += 1
        return self.answers.pop(0) if self.answers else False


class TestARefusalGetsOneSecondChance(ServerTestCase):
    """`on_denied`: the CLI's hook for starting a polkit agent and asking again.

    The case it exists for is an ssh session with no agent in it, where polkit
    refuses because there was nobody to ask rather than because the answer is
    no. Starting an agent and repeating the request is the difference between
    that and `sudo`, which would skip authorisation altogether.
    """

    def test_a_refusal_is_retried_once_and_can_then_succeed(self) -> None:
        self.dispatcher.authoriser = Authoriser(
            policy="polkit", checker=ScriptedChecker(False, True)
        )
        tries: list[int] = []

        def denied() -> bool:
            tries.append(1)
            return True

        client = self.client(on_denied=denied)
        share = client.call("share.add", {"name": "X", "path": "/srv/x"})
        self.assertEqual(share["id"], "x")
        self.assertEqual(len(tries), 1)

    def test_a_second_refusal_is_final(self) -> None:
        """The user said no, or is not allowed. A program that asked again
        would be arguing with them."""
        checker = ScriptedChecker(False, False)
        self.dispatcher.authoriser = Authoriser(policy="polkit", checker=checker)
        with self.assertRaises(NotPermitted):
            self.client(on_denied=lambda: True).call(
                "share.add", {"name": "X", "path": "/srv/x"}
            )
        self.assertEqual(checker.calls, 2)

    def test_nothing_is_retried_when_the_hook_cannot_help(self) -> None:
        checker = ScriptedChecker(False, True)
        self.dispatcher.authoriser = Authoriser(policy="polkit", checker=checker)
        with self.assertRaises(NotPermitted):
            self.client(on_denied=lambda: False).call(
                "share.add", {"name": "X", "path": "/srv/x"}
            )
        self.assertEqual(checker.calls, 1)

    def test_a_client_with_no_hook_behaves_as_it_always_did(self) -> None:
        checker = ScriptedChecker(False, True)
        self.dispatcher.authoriser = Authoriser(policy="polkit", checker=checker)
        with self.assertRaises(NotPermitted):
            self.client().call("share.add", {"name": "X", "path": "/srv/x"})
        self.assertEqual(checker.calls, 1)

    def test_the_client_waits_longer_than_the_daemon_will(self) -> None:
        """A prompt is a person reading a dialog, and the client is blocked for
        the whole of it. If the client gave up first, the mutation would still
        go through once they typed their password — after the command that
        asked for it had already reported failure."""
        self.assertGreater(client_module.REPLY_TIMEOUT, polkit_module.DEFAULT_TIMEOUT)


class TestPeerAndAuthorisation(ServerTestCase):
    def test_the_peer_identity_comes_from_the_kernel(self) -> None:
        seen: list[PeerCredentials] = []
        original = self.dispatcher.handle

        def spy(connection: object, frame: bytes) -> bytes | None:
            seen.append(connection.peer)  # type: ignore[attr-defined]
            return original(connection, frame)  # type: ignore[arg-type]

        self.transport.shutdown()
        self.thread.join(timeout=5)
        self.transport = UnixSocketTransport(self.socket_path, group=None)
        self.transport.bind()
        self.thread = threading.Thread(
            target=self.transport.serve_forever, args=(spy,), daemon=True
        )
        self.thread.start()

        self.client().call("ping")
        self.assertEqual(seen[0].uid, os.getuid())
        self.assertEqual(seen[0].gid, os.getgid())

    def test_the_root_policy_refuses_a_mutation_from_a_non_root_peer(self) -> None:
        if os.getuid() == 0:
            self.skipTest("running as root; the refusal path needs a non-root peer")
        self.dispatcher.authoriser = Authoriser(policy="root")
        with self.assertRaises(NotPermitted):
            self.client().call("share.add", {"name": "X", "path": "/srv/x"})

    def test_a_mutation_is_put_to_polkit_and_allowed_if_it_says_yes(self) -> None:
        asked = RecordingChecker(answer=True)
        self.dispatcher.authoriser = Authoriser(policy="polkit", checker=asked)
        share = self.client().call("share.add", {"name": "X", "path": "/srv/x"})
        self.assertEqual(share["id"], "x")
        self.assertEqual([action for _peer, action in asked.calls], [MANAGE_SHARES])

    def test_a_mutation_is_refused_when_polkit_says_no(self) -> None:
        self.dispatcher.authoriser = Authoriser(
            policy="polkit", checker=RecordingChecker(answer=False)
        )
        with self.assertRaises(NotPermitted) as raised:
            self.client().call("share.add", {"name": "X", "path": "/srv/x"})
        # The action is in the detail because the person who has to fix this is
        # writing a polkit rule, and a rule is written against an action id.
        self.assertIn(MANAGE_SHARES, raised.exception.detail or "")

    def test_polkit_is_asked_about_the_peer_the_kernel_reported(self) -> None:
        """Not about anything in the message, which D4 does not trust."""
        asked = RecordingChecker(answer=True)
        self.dispatcher.authoriser = Authoriser(policy="polkit", checker=asked)
        self.client().call("share.add", {"name": "X", "path": "/srv/x"})
        peer, _action = asked.calls[0]
        self.assertEqual(peer.uid, os.getuid())

    def test_a_read_only_method_never_reaches_polkit(self) -> None:
        asked = RecordingChecker(answer=False)
        self.dispatcher.authoriser = Authoriser(policy="polkit", checker=asked)
        self.assertEqual(self.client().call("ping"), {"pong": True})
        self.assertEqual(self.client().call("share.list"), [])
        self.assertEqual(asked.calls, [])

    def test_read_only_methods_never_reach_the_mutation_gate(self) -> None:
        self.dispatcher.authoriser = Authoriser(policy="root")
        self.assertEqual(self.client().call("ping"), {"pong": True})
        self.assertEqual(self.client().call("share.list"), [])

    def test_an_unknown_method_says_so_rather_than_blaming_permissions(self) -> None:
        with self.assertRaises(UnknownMethod):
            self.client().call("definitely.not.a.method")


class TestStopping(unittest.TestCase):
    """`shutdown()` from another thread must actually stop the serve loop.

    It did not on Linux, and it did on macOS, so nothing said so for two weeks:
    closing a listening socket wakes a thread blocked in `accept()` on BSD and
    leaves it blocked on Linux. The daemon survived on the accident that
    SIGTERM interrupts the syscall, so the handler's `shutdown()` ran and the
    retried `accept()` failed on a closed descriptor — but every `test_cli`
    test paid a five-second `join` timeout on Linux, which is how CI found it:
    528 tests in 391 seconds against 8 on the machine they were written on.

    This asserts the contract rather than the mechanism, so it holds whatever
    the platform does with a closed descriptor.
    """

    def test_the_serve_loop_ends_when_it_is_told_to(self) -> None:
        directory = tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-")
        self.addCleanup(directory.cleanup)
        transport = UnixSocketTransport(Path(directory.name) / "s.sock", group=None)
        transport.bind()
        thread = threading.Thread(
            target=transport.serve_forever, args=(lambda *_: None,), daemon=True
        )
        thread.start()
        transport.shutdown()
        thread.join(timeout=2.0)
        self.assertFalse(
            thread.is_alive(),
            "serve_forever was still running two seconds after shutdown()",
        )


class TestSocket(ServerTestCase):
    def test_the_socket_is_removed_on_shutdown(self) -> None:
        self.assertTrue(self.socket_path.exists())
        self.transport.shutdown()
        self.thread.join(timeout=5)
        self.assertFalse(self.socket_path.exists())

    def test_a_second_daemon_refuses_to_steal_a_live_socket(self) -> None:
        rival = UnixSocketTransport(self.socket_path, group=None)
        with self.assertRaises(OSError) as caught:
            rival.bind()
        self.assertIn("already listening", str(caught.exception))

    def test_a_stale_socket_is_reclaimed(self) -> None:
        self.transport.shutdown()
        self.thread.join(timeout=5)
        # Leave a socket file behind with nothing listening.
        leftover = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        leftover.bind(str(self.socket_path))
        leftover.close()
        self.assertTrue(self.socket_path.exists())

        self.transport = UnixSocketTransport(self.socket_path, group=None)
        self.transport.bind()  # must not raise
        self.thread = threading.Thread(
            target=self.transport.serve_forever,
            args=(self.dispatcher.handle,),
            daemon=True,
        )
        self.thread.start()
        self.assertEqual(self.client().call("ping"), {"pong": True})

    def test_shutting_down_hangs_up_rather_than_leaving_clients_hanging(self) -> None:
        """A stopped daemon must be *discoverably* stopped.

        The client's own socket timeout would eventually notice, but a GUI that
        held a live-looking connection to a daemon that had gone would sit
        there for the length of that timeout showing state nobody is updating.
        Asserting on which error arrives is the point: the timeout raises the
        same class, so only the message tells the two apart.
        """
        client = Client(self.socket_path, timeout=5.0)
        client.connect()
        self.addCleanup(client.close)
        self.assertEqual(client.call("ping"), {"pong": True})

        self.transport.shutdown()
        self.thread.join(timeout=5)
        with self.assertRaises(DaemonUnreachable) as caught:
            client.call("ping")
        self.assertIn("closed the connection", caught.exception.message)

    def test_shutting_down_with_a_client_attached_still_removes_the_socket(self) -> None:
        """Found by the GUI: `shutdown` used to be able to raise part-way.

        It recorded each client's thread before starting it, so a shutdown that
        landed in that window joined an unstarted thread and raised
        RuntimeError — out of the one code path that removes the socket file,
        which then made the next start think a daemon was already running.
        """
        client = self.client()
        client.call("ping")
        self.transport.shutdown()
        self.thread.join(timeout=5)
        self.assertFalse(self.socket_path.exists())

    def test_the_socket_is_not_world_accessible(self) -> None:
        mode = stat.S_IMODE(self.socket_path.stat().st_mode)
        self.assertEqual(mode & stat.S_IRWXO, 0, f"world bits set: {mode:04o}")


def _a_group_we_belong_to() -> str | None:
    """A group name we can chown to without being root.

    chown(-1, gid) is permitted for the owner of a file when the gid is one
    they are already in, so the directory guard is testable unprivileged.
    """
    for gid in os.getgroups():
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            continue
    return None


class TestTheDirectoryTheSocketIsIn(unittest.TestCase):
    """A guarded socket in an unenterable directory admits nobody.

    Found on a Pi on 29 August 2026: the socket was `0660 root:smbpal`,
    exactly as designed, inside a `/run/smbpal` that systemd had made `0750
    root:root`. `connect()` needs execute on every directory in the path, so
    the group could not reach the socket its membership was the key to, and
    the error said *membership of the smbpal group is required* to somebody
    about to join it and find nothing changed.
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-")
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)

    def transport(self, path: Path, group: str | None) -> UnixSocketTransport:
        transport = UnixSocketTransport(path, group=group)
        self.addCleanup(transport.shutdown)
        return transport

    @unittest.skipUnless(_a_group_we_belong_to(), "no named group to chown to")
    def test_the_group_can_enter_the_directory_not_just_open_the_socket(self) -> None:
        group = _a_group_we_belong_to()
        assert group is not None
        directory = self.root / "run"
        directory.mkdir(mode=0o700)
        self.transport(directory / "s.sock", group).bind()

        info = directory.stat()
        self.assertEqual(grp.getgrgid(info.st_gid).gr_name, group)
        mode = stat.S_IMODE(info.st_mode)
        self.assertTrue(mode & stat.S_IXGRP, f"group cannot enter: {mode:04o}")
        self.assertEqual(mode & stat.S_IRWXO, 0, f"world bits set: {mode:04o}")

    @unittest.skipUnless(_a_group_we_belong_to(), "no named group to chown to")
    def test_a_shared_directory_is_refused_rather_than_taken_over(self) -> None:
        """The flag that would otherwise chown /run to the socket group."""
        path = Path("/tmp/smbpal-shared-dir-probe.sock")
        self.addCleanup(path.unlink, True)
        transport = self.transport(path, _a_group_we_belong_to())
        with self.assertRaises(OSError) as caught:
            transport.bind()
        self.assertIn("directory of its own", str(caught.exception))

    @unittest.skipUnless(_a_group_we_belong_to(), "no named group to chown to")
    def test_a_refused_bind_leaves_no_socket_behind(self) -> None:
        """Otherwise the next start finds a stale socket it has to reason about."""
        path = Path("/tmp/smbpal-shared-dir-probe.sock")
        self.addCleanup(path.unlink, True)
        with self.assertRaises(OSError):
            self.transport(path, _a_group_we_belong_to()).bind()
        self.assertFalse(path.exists())


class TestWhereTheSocketGoesByDefault(unittest.TestCase):
    """§6.20. The constant named a path macOS cannot have.

    `/run` does not exist on macOS and cannot be created — `/` is the Signed
    System Volume — so `/run/smbpal/smbpald.sock` was a default the daemon
    could not bind and the CLI could not find, and every macOS invocation
    needed `--socket`. Nine sessions of macOS work missed it because every
    runbook passes `--socket` for an unrelated reason; a Homebrew install run
    the way a user would is what found it, on 10 October 2026.
    """

    def path_on(self, platform: str) -> Path:
        with mock.patch.object(server_module.sys, "platform", platform):
            return server_module.default_socket_path()

    def test_linux_keeps_its_exact_string(self) -> None:
        # Not `/var/run/...`, though that resolves to the same place through
        # the symlink: this string is also in the systemd units, the polkit
        # rules and the group-guard documentation.
        self.assertEqual(
            self.path_on("linux"), Path("/run/smbpal/smbpald.sock")
        )

    def test_macos_gets_the_path_it_can_actually_have(self) -> None:
        self.assertEqual(
            self.path_on("darwin"), Path("/var/run/smbpal/smbpald.sock")
        )

    def test_neither_default_lands_in_a_directory_bind_would_refuse(self) -> None:
        """The property that makes a default usable rather than merely present.

        `_apply_directory_ownership` refuses to take over a shared directory,
        so a default whose parent is on that list would fail at `bind()` —
        swapping one unusable default for another.
        """
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform):
                parent = self.path_on(platform).parent
                self.assertNotIn(parent, server_module._SHARED_DIRS)

    def test_the_macos_resolved_spellings_are_refused(self) -> None:
        # The resolve step only helps when what it produces is in the set, and
        # `/var/run` on macOS resolves to `/private/var/run`, which is
        # drwxrwxr-x — caught by neither the name check nor the world-writable
        # one unless it is named.
        for shared in ("/private/var/run", "/private/tmp", "/private/var/tmp"):
            with self.subTest(directory=shared):
                self.assertIn(Path(shared), server_module._SHARED_DIRS)


class TestEvents(ServerTestCase):
    def test_a_broadcast_event_reaches_a_connected_client(self) -> None:
        # Nothing emits events yet. M5 will, and retrofitting a push channel
        # into a request/response-only protocol is what this proves unnecessary.
        client = self.client()
        client.call("ping")  # ensure the connection is registered
        self.transport.broadcast(encode_event("state.changed", {"id": "nas"}))
        event = next(client.events())
        self.assertEqual(event["event"], "state.changed")
        self.assertEqual(event["data"], {"id": "nas"})

    def test_an_event_arriving_mid_call_is_not_mistaken_for_the_reply(self) -> None:
        client = self.client()
        client.call("ping")
        received: list[dict[str, object]] = []
        client.on_event = received.append

        # Push an event, then make a call. The client must skip the event and
        # still return the right result.
        self.transport.broadcast(encode_event("noise", {"n": 1}))
        self.assertEqual(client.call("ping"), {"pong": True})
        self.assertEqual(received, [{"v": PROTOCOL_VERSION, "event": "noise", "data": {"n": 1}}])


class TestClientWithoutDaemon(unittest.TestCase):
    def test_a_missing_socket_is_a_clear_error_not_a_stack_trace(self) -> None:
        # D12's stated consequence, tested rather than hoped for.
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-") as root:
            client = Client(Path(root) / "absent.sock", timeout=1.0)
            with self.assertRaises(DaemonUnreachable) as caught:
                client.connect()
            self.assertIn("no SMBPal daemon", caught.exception.message)
            self.assertIn(_how_to_start(), caught.exception.detail or "")

    def test_it_does_not_send_a_mac_user_to_systemctl(self) -> None:
        """The first message a Homebrew install produces, and it was wrong.

        `systemctl start smbpald` names a command macOS does not have, for a
        daemon that is not ported there. Found by running the CLI on a Mac on
        2 October 2026, while writing the formula that puts it there.
        """
        if sys.platform == "darwin":
            self.assertNotIn("systemctl", _how_to_start())
            self.assertIn("smbpal-agent", _how_to_start())
        else:
            self.assertIn("systemctl", _how_to_start())


class TestWhyTheSocketRefusedUs(unittest.TestCase):
    """Three situations produce EACCES, and they need three answers.

    The sentence they all used to get — *membership of the smbpal group is
    required* — described the rarest of them. Somebody who had just run
    `usermod -aG` and not yet logged out read it as the command having
    failed, on a Debian 13 desktop on 20 September 2026, which is the same
    misreading the Pi's directory bug caused on 29 August.
    """

    def group(self, gid: int = 9999, members: tuple[str, ...] = ()) -> Any:
        return grp.struct_group(("smbpal", "x", gid, list(members)))

    def answer(
        self,
        group: Any,
        held: tuple[int, ...] = (),
        user: str = "someone",
        socket_path: str | None = None,
        platform: str = "linux",
    ) -> str:
        """**The platform is pinned, and these tests needed it pinned.**

        They assert the Linux wording and passed on a Mac only because the code
        was platform-blind. The moment `why_refused` learned that `usermod` does
        not exist on macOS, three of them failed on a Mac while being perfectly
        correct about Linux -- a test that depends on the host has to say so.
        `TestTheGroupAdviceFitsThePlatform` covers the darwin branch.
        """
        with mock.patch.object(client_module.sys, "platform", platform), \
             mock.patch.object(client_module.grp, "getgrnam", return_value=group), \
             mock.patch.object(client_module.os, "getgroups", return_value=list(held)), \
             mock.patch.object(client_module.os, "getgid", return_value=1000), \
             mock.patch.object(client_module.getpass, "getuser", return_value=user):
            return client_module.why_refused(socket_path=socket_path)

    def test_the_advice_names_the_socket_in_use_not_the_default(self) -> None:
        """It read the constant, so it could name a path nothing was using.

        A `--socket` run was sent to inspect the default instead of its own
        socket — and until §6.20 the default on macOS was a directory that
        cannot exist, advised in the middle of a message about permissions.
        D14: a message may not name a fix that is not one.
        """
        said = self.answer(
            self.group(members=("someone",)),
            held=(9999,),
            socket_path="/tmp/smbpal-elsewhere/smbpald.sock",
        )
        self.assertIn(
            "ls -ld /tmp/smbpal-elsewhere /tmp/smbpal-elsewhere/smbpald.sock", said
        )
        self.assertNotIn(str(server_module.DEFAULT_SOCKET_PATH), said)

    def test_a_member_whose_session_predates_it_is_told_to_log_out(self) -> None:
        said = self.answer(self.group(members=("someone",)), held=())
        self.assertIn("log out", said.lower())
        self.assertIn("session started before", said)
        # And it must not tell them to run the command they already ran.
        self.assertNotIn("usermod", said)

    def test_ssh_is_named_because_logging_out_of_the_desktop_is_not_enough(self) -> None:
        """The case that wastes the most time: a desktop log-out leaves an
        existing ssh session with the groups it was created with."""
        self.assertIn("ssh", self.answer(self.group(members=("someone",)), held=()))

    def test_somebody_who_is_not_a_member_gets_the_command(self) -> None:
        said = self.answer(self.group(members=("otherperson",)))
        self.assertIn("sudo usermod -aG smbpal someone", said)
        self.assertIn("log out", said.lower())

    def test_a_session_that_already_holds_the_group_is_sent_to_the_socket(self) -> None:
        """The Pi's directory bug. Saying "membership is required" to somebody
        who has it sends them round a loop they cannot get out of."""
        said = self.answer(self.group(gid=4242, members=("someone",)), held=(4242,))
        self.assertIn("already", said)
        self.assertIn("ls -ld", said)

    def test_a_primary_group_counts_as_holding_it(self) -> None:
        said = self.answer(self.group(gid=1000, members=()), held=())
        self.assertIn("already", said)

    def test_no_group_at_all_says_the_install_is_incomplete(self) -> None:
        with mock.patch.object(client_module.grp, "getgrnam", side_effect=KeyError):
            said = client_module.why_refused()
        self.assertIn("no 'smbpal' group", said)
        self.assertIn("reinstalling", said)

    def test_a_broken_name_service_does_not_replace_the_real_error(self) -> None:
        """This runs while reporting a failure. It may not raise a new one."""
        with mock.patch.object(client_module.grp, "getgrnam", side_effect=OSError("nss")):
            self.assertIsInstance(client_module.why_refused(), str)
        with mock.patch.object(client_module.grp, "getgrnam", return_value=self.group()), \
             mock.patch.object(client_module.getpass, "getuser", side_effect=KeyError):
            self.assertIn("is required", client_module.why_refused())



class TestADirectoryThatIsAlreadyCorrect(unittest.TestCase):
    """The daemon must not try to change what is already right.

    **This is the macOS case, and it was a real blocker.** There the daemon runs
    as a service account and the compiled helper creates the runtime directory
    for it, so an unconditional `chown` fails -- changing a directory's group
    needs root or ownership, and the daemon has neither. The spike's §9 claimed
    *nothing in `ipc/server.py` asserts the uid is 0*, which was true of the
    assertions and false of the behaviour.

    On Linux nothing changes: the package creates the directory with the group
    already set, so the check passes there too and the `chown` it skips was a
    no-op anyway.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "run"
        self.directory.mkdir(mode=0o750)

    def transport(self) -> UnixSocketTransport:
        return UnixSocketTransport(self.directory / "smbpald.sock", group="smbpal")

    def test_a_matching_directory_is_left_alone(self) -> None:
        """No `chown` attempted, so no permission error to handle."""
        gid = self.directory.stat().st_gid
        os.chmod(self.directory, 0o750)
        with mock.patch.object(os, "chown") as chown:
            self.transport()._apply_directory_ownership(gid)
        chown.assert_not_called()

    def test_a_mismatched_directory_is_still_changed(self) -> None:
        os.chmod(self.directory, 0o700)
        gid = self.directory.stat().st_gid
        with mock.patch.object(os, "chown") as chown, mock.patch.object(os, "chmod"):
            self.transport()._apply_directory_ownership(gid)
        chown.assert_called_once()

    def test_the_refusal_names_the_numbers_instead_of_asserting_root(self) -> None:
        """The message this replaces said *the daemon is a root service*.

        That is no longer true on macOS, and a message that states a false
        premise sends the reader to fix the wrong thing -- D14's whole subject.
        """
        os.chmod(self.directory, 0o700)
        gid = self.directory.stat().st_gid + 1
        with (
            mock.patch.object(os, "chown", side_effect=PermissionError),
            self.assertRaises(OSError) as raised,
        ):
            self.transport()._apply_directory_ownership(gid)
        message = str(raised.exception)
        self.assertNotIn("root service", message)
        self.assertIn("0750", message)
        self.assertIn("smbpal setup", message)


class TestTheGroupAdviceFitsThePlatform(unittest.TestCase):
    """`why_refused` named a Linux command on a Mac, and a remedy it does not need.

    Reported from a Mac on 11 October 2026, the first time the daemon listened
    there: *"Add yourself with: sudo usermod -aG smbpal luke — then log out and
    back in."* **`usermod` does not exist on macOS**, and macOS resolves group
    membership **live** through `membershipd` rather than fixing it when a
    session starts -- the helper spike's §4 measured a shell started *before the
    group existed* using it without restarting.

    So the message named a command that is not there and a remedy that is not
    needed. D14 with a platform attached: true somewhere, and presented as true
    here.
    """

    def advice(self, platform: str, *, member: bool) -> str:
        fake = type("G", (), {"gr_gid": 4242, "gr_mem": ["someone"] if not member else ["me"]})
        with (
            mock.patch.object(client_module.sys, "platform", platform),
            mock.patch.object(client_module.grp, "getgrnam", return_value=fake),
            mock.patch.object(client_module.getpass, "getuser", return_value="me"),
            mock.patch.object(client_module.os, "getgroups", return_value=[20]),
            mock.patch.object(client_module.os, "getgid", return_value=20),
        ):
            return client_module.why_refused("smbpal")

    def test_macos_is_told_dscl_and_not_usermod(self) -> None:
        said = self.advice("darwin", member=False)
        self.assertIn("dscl . -append /Groups/smbpal GroupMembership me", said)
        self.assertNotIn("usermod", said)

    def test_macos_is_told_to_open_a_new_terminal(self) -> None:
        """**This assertion is the reverse of what it said four hours ago.**

        It asserted *no need to log out*, following the helper spike's §4. Then
        a real daemon refused a pre-existing session on 11 October 2026 while
        every membership query said member, and a new terminal worked at once.
        The message that shipped in between was wrong.
        """
        said = self.advice("darwin", member=False)
        self.assertIn("open a new terminal", said)
        self.assertNotIn("no need to log out", said)

    def test_linux_keeps_usermod_and_the_re_login(self) -> None:
        said = self.advice("linux", member=False)
        self.assertIn("usermod -aG smbpal me", said)
        self.assertIn("log out and back in", said)
        self.assertNotIn("dscl", said)

    def test_a_macos_member_is_not_told_the_session_is_ruled_out(self) -> None:
        """On macOS nothing queryable reflects the running credential.

        `held` was true -- `os.getgroups()` contained the gid -- and the kernel
        refused anyway. So this branch must not say *the refusal is about the
        socket rather than about you*: it offers the new terminal first, because
        that is what worked, and the socket second.
        """
        said = self.advice("darwin", member=True)
        self.assertIn("Open a new", said)
        self.assertIn("ls -ld", said)
        self.assertLess(said.index("new terminal"), said.index("ls -ld"))
        self.assertNotIn("rather than about you", said)

    def test_a_linux_member_is_told_about_the_session(self) -> None:
        said = self.advice("linux", member=True)
        self.assertIn("Log out and back in", said)


class TestWaitingForTheRuntimeDirectory(unittest.TestCase):
    """The boot race, closed where the condition actually is.

    **`/var/run` does not survive a reboot on macOS** -- `/var/run/smbpal` had a
    birth time six seconds later than `kern.boottime`, measured 11 October 2026
    -- and there the daemon is not root, so `mkdir` under `/var/run`
    (`root:daemon`) is `EPERM`. The privileged helper creates the directory,
    launchd gives no ordering between the two jobs, and a daemon that loses the
    race would exit on the failed bind.

    `KeepAlive` was the first answer and came back out: launchd cannot tell a
    lost race from a config the daemon refused to start on, and it refuses on
    purpose. So the wait is here, and what these tests pin is that it waits for
    **one** condition and reports everything else at once.
    """

    def transport(self, path: Path) -> UnixSocketTransport:
        return UnixSocketTransport(path=path, group=None)

    def test_it_creates_the_directory_when_it_can(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "runtime" / "smbpald.sock"
            self.transport(target)._ensure_runtime_directory()
            self.assertTrue(target.parent.is_dir())

    def test_it_returns_as_soon_as_the_directory_appears(self) -> None:
        """The helper creating it is the thing being waited for, so the wait
        must end on the directory existing and not on the clock."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "runtime"
            transport = self.transport(directory / "smbpald.sock")
            attempts = []
            real_mkdir = Path.mkdir

            def refuse_once(self: Path, *args: object, **kwargs: object) -> None:
                attempts.append(self)
                if len(attempts) == 1:
                    # What macOS does: not allowed, and somebody else will.
                    real_mkdir(self, parents=True, exist_ok=True)
                    raise PermissionError(13, "Permission denied")

            with mock.patch.object(Path, "mkdir", refuse_once):
                with mock.patch("smbpal.ipc.server.time.sleep") as slept:
                    transport._ensure_runtime_directory()
            self.assertEqual(len(attempts), 1)
            slept.assert_not_called()

    def test_it_does_not_wait_for_anything_but_permission(self) -> None:
        """**The point of the whole design.** Waiting on any error would turn a
        real misconfiguration into a thirty-second pause followed by the same
        message, which is the behaviour `KeepAlive` was removed for."""
        with tempfile.TemporaryDirectory() as tmp:
            transport = self.transport(Path(tmp) / "runtime" / "smbpald.sock")
            with mock.patch.object(
                Path, "mkdir", side_effect=OSError(28, "No space left on device")
            ):
                with mock.patch("smbpal.ipc.server.time.sleep") as slept:
                    with self.assertRaises(OSError) as caught:
                        transport._ensure_runtime_directory()
            self.assertEqual(caught.exception.errno, 28)
            slept.assert_not_called()

    def test_it_gives_up_rather_than_waiting_for_ever(self) -> None:
        """A helper that never starts is a different problem, and a daemon that
        hangs on it instead of exiting is one nobody can diagnose."""
        with tempfile.TemporaryDirectory() as tmp:
            transport = self.transport(Path(tmp) / "runtime" / "smbpald.sock")
            clock = iter([0.0] + [100.0] * 8)
            with mock.patch.object(
                Path, "mkdir", side_effect=PermissionError(13, "Permission denied")
            ):
                with mock.patch("smbpal.ipc.server.time.monotonic", lambda: next(clock)):
                    with mock.patch("smbpal.ipc.server.time.sleep"):
                        with self.assertRaises(PermissionError):
                            transport._ensure_runtime_directory()



class TestAPlatformThatCannotServe(ServerTestCase):
    """What a macOS user saw when they tried to share a folder.

    ```
    smbpal: cannot write /etc/samba/smbpal.conf
      [Errno 13] Permission denied: '/etc/samba'
    ```

    A path that has never existed on their machine, naming a program they do
    not have, suggesting a `chmod` that would not help -- and reached **after**
    an administrator password prompt, because the write is deep inside the
    handler and authorisation happens before the handler runs.

    `smbpal setup` installing a daemon on macOS is what made these methods
    reachable at all. D12 is why there is no partial answer to offer instead:
    `_commit` is save-then-apply because "a config edit that the daemon has not
    applied is a lie", so no define-but-do-not-serve state exists.
    """

    def make_dispatcher(self) -> Dispatcher:
        return Dispatcher(self.store, serving=False)

    def test_every_serving_method_is_refused_by_name(self) -> None:
        client = self.client()
        for method in sorted(Dispatcher.SERVING_METHODS):
            with self.subTest(method=method):
                with self.assertRaises(NotSupported) as caught:
                    client.call(method, {})
                self.assertIn(method, caught.exception.message)

    def test_the_refusal_names_nothing_this_platform_lacks(self) -> None:
        """The whole point. A permission error about `/etc/samba` sends someone
        looking for a permission to grant."""
        with self.assertRaises(NotSupported) as caught:
            self.client().call("share.add", {})
        blob = f"{caught.exception.message} {caught.exception.detail}"
        self.assertNotIn("/etc/samba", blob)
        self.assertNotIn("Permission denied", blob)
        # And it points at the half that does work.
        self.assertIn("connection add", blob)

    def test_reading_still_works(self) -> None:
        """`share.list` asks Samba what it is serving and already treats no
        answer as unknown, so it degrades rather than failing. Refusing it would
        remove the one thing still able to say what is configured."""
        self.assertNotIn("share.list", Dispatcher.SERVING_METHODS)
        self.assertEqual(self.client().call("share.list"), [])

    def test_connections_are_untouched(self) -> None:
        """Mounting needs no Samba at all -- on macOS it is the user's own
        agent (D13), which is the half that works."""
        for method in ("connection.add", "connection.remove", "connection.connect"):
            with self.subTest(method=method):
                self.assertNotIn(method, Dispatcher.SERVING_METHODS)


class TestItIsRefusedBeforeAuthorisation(ServerTestCase):
    """Prompting for an administrator password and *then* saying the platform
    cannot do it is worse than either answer on its own.

    Same family as the existing existence-before-permission rule, and the
    reason the guard sits beside it in `handle` rather than inside `_commit`.
    """

    def make_dispatcher(self) -> Dispatcher:
        self.checker = RecordingChecker(answer=True)
        return Dispatcher(
            self.store,
            authoriser=Authoriser(policy="polkit", checker=self.checker),
            serving=False,
        )

    def test_the_authoriser_is_never_asked(self) -> None:
        with self.assertRaises(NotSupported):
            self.client().call("share.add", {})
        self.assertEqual(self.checker.calls, [])


class TestServingIsTheDefault(ServerTestCase):
    def test_so_linux_is_unaffected(self) -> None:
        self.assertTrue(self.dispatcher.serving)


class TestAShareNeedsAnAccountThatExists(ServerTestCase):
    """Measured on a Mac, 12 October 2026: `share add … --user OTHER` was
    accepted with no such account, and `status` showed the share serving with
    nothing to say. Refused now, on both platforms, before any prompt."""

    MISSING = "smbpal-no-such-account"

    def test_a_missing_account_is_refused_before_the_authoriser_is_asked(self) -> None:
        checker = RecordingChecker(answer=True)
        self.dispatcher.authoriser = Authoriser(policy="polkit", checker=checker)
        # The client keeps the code and has no class for it, so it arrives as
        # the base class carrying `not_found`.
        with self.assertRaises(SmbpalError) as caught:
            self.client().call(
                "share.add",
                {"name": "X", "path": "/srv/x", "credential_ref": self.MISSING},
            )
        self.assertEqual(caught.exception.code, NotFound.code)
        self.assertIn(self.MISSING, caught.exception.message)
        self.assertEqual(checker.calls, [], "nobody may be asked for a password")
        self.assertEqual(self.store.load().get("shares", []), [])

    def test_an_account_that_exists_goes_on_to_authorisation(self) -> None:
        import os
        import pwd

        checker = RecordingChecker(answer=True)
        self.dispatcher.authoriser = Authoriser(policy="polkit", checker=checker)
        me = pwd.getpwuid(os.getuid()).pw_name
        share = self.client().call(
            "share.add", {"name": "X", "path": "/srv/x", "credential_ref": me}
        )
        self.assertEqual(share["credential_ref"], me)
        self.assertEqual(len(checker.calls), 1)

    def test_no_account_named_is_not_checked(self) -> None:
        self.dispatcher.authoriser = Authoriser(
            policy="polkit", checker=RecordingChecker(answer=True)
        )
        share = self.client().call("share.add", {"name": "X", "path": "/srv/x"})
        self.assertIsNone(share.get("credential_ref"))


if __name__ == "__main__":
    unittest.main()


class TestADismissedDialog(unittest.TestCase):
    """A refused or dismissed authorisation dialog gives up quietly.

    `_acquire` logged through a module logger that did not exist, so the one
    path meant to turn a dismissed dialog into the daemon's own refusal raised
    `NameError` instead. Nothing in the suite reached it, because nothing
    raised `AuthorizationError` here; pyflakes found it on 15 October 2026.
    """

    def test_the_refusal_is_reported_rather_than_a_crash(self) -> None:
        from smbpal.errors import NeedsAuthorisation
        from smbpal.system import authorization

        needed = NeedsAuthorisation("ask first", right="app.smbpal.manage-shares")
        with mock.patch.object(authorization, "available", return_value=True), \
                mock.patch.object(
                    authorization,
                    "grant_for",
                    side_effect=authorization.AuthorizationError(
                        "not authorised", detail="the dialog was dismissed"
                    ),
                ):
            held = client_module.Client("/nonexistent")._acquire(needed)
        self.assertIsNone(held)
        self.assertEqual(needed.detail, "the dialog was dismissed")
