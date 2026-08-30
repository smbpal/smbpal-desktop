"""The socket end to end: a real daemon dispatcher over a real Unix socket."""

from __future__ import annotations

import grp
import json
import os
import socket
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from smbpal import PROTOCOL_VERSION
from smbpal.config import ConfigStore, empty_config
from smbpal.daemon.handlers import Authoriser, Dispatcher
from smbpal.daemon import polkit as polkit_module
from smbpal.daemon.polkit import MANAGE_SHARES
from smbpal.ipc import client as client_module
from smbpal.errors import (
    BadRequest,
    DaemonUnreachable,
    NotPermitted,
    UnknownMethod,
    UnsupportedVersion,
)
from smbpal.ipc.client import Client
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
        self.dispatcher = Dispatcher(self.store)
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
            self.assertIn("systemctl start smbpald", caught.exception.detail or "")


if __name__ == "__main__":
    unittest.main()
