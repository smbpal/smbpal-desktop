"""The agent dials the daemon, and the daemon's requests come back down it.

Since the daemon runs as `_smbpald` it cannot open an agent's socket, so the
link is the agent's connection to the daemon (`AgentLinks`, `agent/link.py`).
The registry is tested on its own first, then a real daemon and a real agent on
a real socket, faked only at NetFS and the Keychain.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from smbpal.agent.client import AgentLinks, AgentUnreachable
from smbpal.agent.handlers import AgentDispatcher
from smbpal.agent.link import DaemonLink
from smbpal.config import ConfigStore
from smbpal.daemon.handlers import Authoriser, Dispatcher
from smbpal.errors import SmbpalError
from smbpal.ipc.client import Client
from smbpal.ipc.peer import PeerCredentials
from smbpal.ipc.server import UnixSocketTransport

from tests.test_agent import FakeMounter
from tests.test_agent_link import FakeKeychain


class FakeConnection:
    def __init__(self, uid: int) -> None:
        self.peer = PeerCredentials(uid=uid, gid=20)
        self.sent: list[dict[str, Any]] = []
        self.arrived = threading.Event()

    def send(self, payload: bytes) -> None:
        self.sent.append(json.loads(payload))
        self.arrived.set()

    def close(self) -> None:
        pass


def in_background(target: Any) -> tuple[threading.Thread, dict[str, Any]]:
    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["result"] = target()
        except Exception as exc:  # noqa: BLE001 - handed to the test
            outcome["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, outcome


class TheRegistry(unittest.TestCase):
    def setUp(self) -> None:
        self.links = AgentLinks()
        self.agent = FakeConnection(501)
        self.links.register(self.agent)

    def ask(self, uid: int = 501, timeout: float = 5.0) -> tuple[threading.Thread, dict[str, Any]]:
        return in_background(
            lambda: self.links.request(uid, "agent.ping", {"x": 1}, timeout=timeout)
        )

    def request_sent(self) -> dict[str, Any]:
        self.assertTrue(self.agent.arrived.wait(5))
        event = self.agent.sent[-1]
        self.assertEqual(event["event"], "agent.request")
        return event["data"]

    def test_a_request_goes_down_the_link_and_the_reply_comes_back(self) -> None:
        thread, outcome = self.ask()
        data = self.request_sent()
        self.assertEqual((data["method"], data["params"]), ("agent.ping", {"x": 1}))
        self.links.reply(self.agent, {"rid": data["rid"], "ok": True, "result": {"ok": 1}})
        thread.join(5)
        self.assertEqual(outcome, {"result": {"ok": 1}})

    def test_nobody_registered_is_a_sentence(self) -> None:
        with self.assertRaises(AgentUnreachable) as caught:
            self.links.request(502, "agent.ping", None, timeout=1)
        self.assertIn("smbpal-agent --install", caught.exception.detail or "")

    def test_a_request_for_one_user_never_reaches_another(self) -> None:
        other = FakeConnection(502)
        self.links.register(other)
        thread, _ = self.ask(uid=501)
        self.request_sent()
        self.assertEqual(other.sent, [])
        self.links.drop(self.agent)
        thread.join(5)

    def test_only_the_connection_asked_may_answer(self) -> None:
        thread, outcome = self.ask()
        data = self.request_sent()
        impostor = FakeConnection(501)
        with self.assertRaises(SmbpalError):
            self.links.reply(impostor, {"rid": data["rid"], "ok": True, "result": "forged"})
        self.links.reply(self.agent, {"rid": data["rid"], "ok": True, "result": "real"})
        thread.join(5)
        self.assertEqual(outcome, {"result": "real"})

    def test_an_unknown_reply_is_refused(self) -> None:
        with self.assertRaises(SmbpalError):
            self.links.reply(self.agent, {"rid": "999", "ok": True})

    def test_an_error_reply_keeps_its_code(self) -> None:
        thread, outcome = self.ask()
        data = self.request_sent()
        self.links.reply(
            self.agent,
            {"rid": data["rid"], "ok": False,
             "error": {"code": "netfs", "message": "there is no route to the server"}},
        )
        thread.join(5)
        self.assertEqual(outcome["error"].code, "netfs")
        self.assertEqual(outcome["error"].message, "there is no route to the server")

    def test_a_dropped_agent_fails_its_requests_at_once(self) -> None:
        thread, outcome = self.ask(timeout=60)
        self.request_sent()
        started = time.monotonic()
        self.links.drop(self.agent)
        thread.join(5)
        self.assertLess(time.monotonic() - started, 2)
        self.assertIsInstance(outcome["error"], AgentUnreachable)
        self.assertFalse(self.links.connected(501))

    def test_silence_times_out(self) -> None:
        with self.assertRaises(AgentUnreachable):
            self.links.request(501, "agent.ping", None, timeout=0.05)

    def test_a_reconnected_agent_replaces_the_old_connection(self) -> None:
        newer = FakeConnection(501)
        self.links.register(newer)
        self.links.drop(self.agent)  # the old one closing must not unregister the new
        self.assertTrue(self.links.connected(501))


class TheDispatcher(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.store = ConfigStore(Path(self._dir.name) / "config.json")

    def handle(self, dispatcher: Dispatcher, connection: FakeConnection,
               method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        frame = json.dumps({"v": 1, "id": "1", "method": method,
                            "params": params or {}}).encode()
        reply = dispatcher.handle(connection, frame)
        assert reply is not None
        return json.loads(reply)

    def test_registering_needs_no_authorisation(self) -> None:
        links = AgentLinks()
        dispatcher = Dispatcher(self.store, authoriser=Authoriser(policy="root"), agents=links)
        reply = self.handle(dispatcher, FakeConnection(501), "agent.register")
        self.assertTrue(reply["ok"], reply)
        self.assertTrue(links.connected(501))

    def test_a_daemon_without_the_link_refuses_it(self) -> None:
        dispatcher = Dispatcher(self.store, authoriser=Authoriser(policy="group"))
        reply = self.handle(dispatcher, FakeConnection(501), "agent.register")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "not_supported")

    def test_a_closed_connection_is_unregistered(self) -> None:
        links = AgentLinks()
        dispatcher = Dispatcher(self.store, authoriser=Authoriser(policy="group"), agents=links)
        connection = FakeConnection(501)
        self.handle(dispatcher, connection, "agent.register")
        dispatcher.disconnected(connection)
        self.assertFalse(links.connected(501))


class EndToEnd(unittest.TestCase):
    """A real daemon socket, a real agent dialling it, and a CLI-shaped client."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-")
        self.addCleanup(self._dir.cleanup)
        root = Path(self._dir.name)
        self.uid = os.getuid()
        self.store = ConfigStore(root / "config.json")
        self.store.save(
            {
                "version": 1,
                "shares": [],
                "connections": [
                    {
                        "type": "os",
                        "id": "nas-media",
                        "host": "nas.example",
                        "share": "Media",
                        "mountpoint": "/Volumes/Media",
                    }
                ],
            }
        )
        self.socket = root / "d.sock"
        self.links = AgentLinks()
        self.daemon = Dispatcher(
            self.store, authoriser=Authoriser(policy="group"), agents=self.links
        )
        self.transport = UnixSocketTransport(self.socket, group=None, mode=0o600)
        self.transport.bind()
        threading.Thread(
            target=self.transport.serve_forever,
            args=(self.daemon.handle, self.daemon.disconnected),
            daemon=True,
        ).start()
        self.addCleanup(self.transport.shutdown)

        self.mounter = FakeMounter()
        self.keychain = FakeKeychain()
        self.agent = AgentDispatcher(
            uid=self.uid, mounter=self.mounter, keychain=self.keychain, mounts=lambda: []
        )

    def dial(self, trusted: set[int] | None = None) -> DaemonLink:
        link = DaemonLink(
            self.agent,
            self.socket,
            trusted=lambda: {self.uid} if trusted is None else trusted,
        )
        link.start()
        self.addCleanup(link.stop)
        return link

    def call(self, method: str, params: dict[str, Any]) -> Any:
        with Client(self.socket, timeout=5, reply_timeout=10) as client:
            return client.call(method, params)

    def test_connect_mounts_in_the_agent(self) -> None:
        link = self.dial()
        self.assertTrue(link.registered.wait(5))
        result = self.call("connection.connect", {"ref": "nas-media"})
        self.assertEqual(result["mountpoint"], "/Volumes/Media")
        self.assertEqual(self.mounter.mounted[0][0], "smb://nas.example/Media")

    def test_a_password_reaches_the_keychain(self) -> None:
        link = self.dial()
        self.assertTrue(link.registered.wait(5))
        result = self.call(
            "connection.set_credentials",
            {"ref": "nas-media", "username": "pi", "password": "throwaway"},
        )
        self.assertEqual(result["keychain"], "created")
        self.assertEqual(self.keychain.items, {("nas.example", "pi"): "throwaway"})

    def test_disconnect_reaches_the_agent(self) -> None:
        link = self.dial()
        self.assertTrue(link.registered.wait(5))
        self.call("connection.disconnect", {"ref": "nas-media"})
        self.assertEqual(self.mounter.unmounted, ["/Volumes/Media"])

    def test_a_disconnect_is_recorded_and_a_connect_clears_it(self) -> None:
        link = self.dial()
        self.assertTrue(link.registered.wait(5))
        self.call("connection.disconnect", {"ref": "nas-media"})
        self.assertIs(self.store.load()["connections"][0].get("disconnected"), True)
        self.call("connection.connect", {"ref": "nas-media"})
        self.assertNotIn("disconnected", self.store.load()["connections"][0])

    def test_the_agent_will_not_talk_to_a_listener_it_does_not_trust(self) -> None:
        link = self.dial(trusted=set())
        self.assertFalse(link.registered.wait(0.5))
        self.assertFalse(self.links.connected(self.uid))

    def test_a_stopped_agent_is_reported_not_waited_for(self) -> None:
        link = self.dial()
        self.assertTrue(link.registered.wait(5))
        link.stop()
        deadline = time.monotonic() + 5
        while self.links.connected(self.uid) and time.monotonic() < deadline:
            time.sleep(0.02)
        with self.assertRaises(SmbpalError) as caught:
            self.call("connection.connect", {"ref": "nas-media"})
        self.assertEqual(caught.exception.code, "agent_unreachable")


if __name__ == "__main__":
    unittest.main()


class TheMacDaemonDoesNotMount(unittest.TestCase):
    """Found adding a share Finder had mounted, 15 October 2026.

    The installed Mac daemon still built the Linux `Mounter`, so every
    `connection add` tried to create its mountpoint in root's `/Volumes` as
    `_smbpald` and was rolled back.
    """

    def test_the_platform_decides_who_mounts(self) -> None:
        from smbpal.daemon.main import mounts_via_agent

        self.assertTrue(mounts_via_agent("auto", "darwin"))
        self.assertFalse(mounts_via_agent("auto", "linux"))
        self.assertTrue(mounts_via_agent("agent", "linux"))
        self.assertFalse(mounts_via_agent("systemd", "darwin"))

    def test_adding_a_connection_creates_no_mountpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory) / "config.json")
            dispatcher = Dispatcher(
                store, authoriser=Authoriser(policy="group"), agents=AgentLinks()
            )
            frame = json.dumps({
                "v": 1, "id": "1", "method": "connection.add",
                "params": {"host": "nas.example", "share": "Code",
                           "mountpoint": str(Path(directory) / "Volumes" / "Code")},
            }).encode()
            reply = json.loads(dispatcher.handle(FakeConnection(os.getuid()), frame))
            self.assertTrue(reply["ok"], reply)
            self.assertFalse((Path(directory) / "Volumes").exists())
            self.assertEqual(len(store.load()["connections"]), 1)
