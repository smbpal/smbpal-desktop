"""The daemon and the agent, connected.

**This is the first thing in the project where two of its own processes talk.**
The CLI talks to the daemon and the window talks to the daemon, but the daemon
has only ever talked to `systemd`, `samba` and `polkit`. On macOS it has to ask
a process it does not own, in a session it is not in, to do the one thing it
cannot do itself (D13).

So most of this runs a **real agent on a real socket** rather than a fake:
`AgentClient` exists to cross a process boundary, and a test that stubs the
boundary out tests the half that was never in doubt. What is faked is the
mounting, because NetFS is macOS-only and CI is Linux -- the same split
`test_netfs.py` draws.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from smbpal.agent.client import (
    AgentClient,
    AgentClients,
    AgentUnreachable,
    socket_path_for,
    username_for_uid,
)
from smbpal.agent.handlers import AgentDispatcher
from smbpal.config import ConfigStore
from smbpal.daemon.handlers import Dispatcher, _smb_url
from smbpal.errors import SmbpalError
from smbpal.ipc.peer import PeerCredentials
from smbpal.ipc.protocol import Request
from smbpal.ipc.server import UnixSocketTransport

from tests.test_agent import FakeMounter


class LiveAgent:
    """A real agent, on a real socket, in a thread. Faked only at NetFS."""

    def __init__(self, directory: Path, uid: int) -> None:
        self.mounter = FakeMounter()
        self.path = directory / f"agent-{uid}.sock"
        self.dispatcher = AgentDispatcher(uid=uid, mounter=self.mounter)
        self.transport = UnixSocketTransport(self.path, group=None, mode=0o600)
        self.transport.bind()
        self.thread = threading.Thread(
            target=self.transport.serve_forever,
            args=(self.dispatcher.handle,),
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        self.transport.shutdown()
        self.thread.join(timeout=5)


class AgentLinkTestCase(unittest.TestCase):
    """Short socket directory: `sun_path` is 104 bytes and macOS's TMPDIR is long.

    The agent found that the hard way under launchd on 2 October 2026, which is
    why `/tmp` is named here rather than left to the default.
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="smbpal-")
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.uid = os.getuid()
        self.agent = LiveAgent(self.root, self.uid)
        self.addCleanup(self.agent.stop)
        self.clients = AgentClients(directory=self.root)

    def client(self) -> AgentClient:
        return self.clients.for_uid(self.uid)


class TestTheClientReachesARealAgent(AgentLinkTestCase):
    def test_ping_crosses_the_socket(self) -> None:
        reply = self.client().ping()
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["uid"], self.uid)

    def test_mount_returns_the_mountpoint_the_agent_chose(self) -> None:
        # Not the one the caller asked for: on macOS the mountpoint is NetFS's
        # to decide, and `/Volumes/Media` may become `/Volumes/Media-1`.
        where = self.client().mount("smb://nas.example/Media", user="pi")
        self.assertEqual(where, "/Volumes/Media")
        self.assertEqual(self.agent.mounter.mounted, [("smb://nas.example/Media", "pi", None)])

    def test_no_password_ever_crosses_this_link(self) -> None:
        """The rule, asserted at the boundary rather than trusted to a comment.

        `CredentialsStore` has `username_for` and deliberately no
        `password_for`: the file is written for `mount.cifs` to read, and a
        daemon that read it back would make root a party to every credential it
        stores. On macOS it does not need to be, because the credential belongs
        to the session (D13). So the client has no password parameter at all --
        the strongest form of this rule available.
        """
        self.client().mount("smb://nas.example/Public")
        self.assertEqual(self.agent.mounter.mounted[0][2], None)
        self.assertNotIn("password", AgentClient.mount.__code__.co_varnames)

    def test_unmount_says_whether_anything_was_mounted(self) -> None:
        self.assertTrue(self.client().unmount("/Volumes/Media"))

    def test_remount_url_of_something_unknown_is_none(self) -> None:
        self.assertIsNone(self.client().remount_url("/Volumes/Gone"))

    def test_an_error_from_the_agent_arrives_as_an_error_here(self) -> None:
        # Not as a dict with an "error" key in it: the protocol's failure
        # reply becomes an exception on this side, which is what lets the
        # daemon's handler do nothing special at all.
        with self.assertRaises(SmbpalError) as caught:
            self.client().mount("")
        self.assertIn("url", caught.exception.message)


class TestAnAgentThatIsNotRunning(AgentLinkTestCase):
    def test_the_message_names_the_person_and_the_command(self) -> None:
        self.agent.stop()
        with self.assertRaises(AgentUnreachable) as caught:
            self.client().ping()
        detail = caught.exception.detail or ""
        if sys.platform == "darwin":
            # The likeliest failure on a Mac by a distance: the plist is
            # per-user and installed by the person, so a fresh machine has a
            # daemon and no agent. "Connection refused" names neither of them.
            self.assertIn(username_for_uid(self.uid), caught.exception.message)
            self.assertIn("smbpal-agent --install", detail)
        else:
            # And on Linux the honest answer is about the daemon's own flags,
            # not about a macOS agent nobody asked for.
            self.assertIn("--mount-via agent", detail)

    def test_a_uid_the_machine_does_not_know(self) -> None:
        with self.assertRaises(AgentUnreachable) as caught:
            socket_path_for(4294967290)
        self.assertIn("4294967290", caught.exception.message)

    def test_the_default_path_is_in_that_users_home(self) -> None:
        # From the password database, not from /Users/<name>: a Mac bound to a
        # directory service frequently puts homes elsewhere.
        self.assertEqual(
            socket_path_for(self.uid),
            Path.home() / "Library/Application Support/SMBPal/agent.sock",
        )


class TestTheDaemonRoutesToTheAgent(AgentLinkTestCase):
    """`connection.connect` with an agent configured, end to end over sockets."""

    def setUp(self) -> None:
        super().setUp()
        self.store = ConfigStore(self.root / "config.json")
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
        self.dispatcher = Dispatcher(self.store, agents=self.clients)
        self.peer = PeerCredentials(uid=self.uid, gid=20)

    def call(self, method: str, **params: object) -> dict:
        request = Request(id="1", method=method, params=params)
        handler = {
            "connection.connect": Dispatcher._connection_connect,
            "connection.disconnect": Dispatcher._connection_disconnect,
        }[method]
        return handler(self.dispatcher, request, self.peer)

    def test_connect_mounts_through_the_agent(self) -> None:
        result = self.call("connection.connect", ref="nas-media")
        self.assertEqual(result["url"], "smb://nas.example/Media")
        self.assertEqual(result["mountpoint"], "/Volumes/Media")
        self.assertEqual(
            self.agent.mounter.mounted, [("smb://nas.example/Media", None, None)]
        )

    def test_it_mounts_in_the_session_of_whoever_asked(self) -> None:
        """The uid is not guessed and not configured: it is the caller's.

        The daemon acts for everyone, so "which session" is a question it may
        not answer by assumption. `peer.uid` is the kernel's answer to it, and
        the same one polkit was asked about a moment earlier.
        """
        other = PeerCredentials(uid=self.uid + 1, gid=20)
        request = Request(id="1", method="connection.connect", params={"ref": "nas-media"})
        with self.assertRaises(AgentUnreachable) as caught:
            Dispatcher._connection_connect(self.dispatcher, request, other)
        # It looked for a *different* socket, which is the whole point.
        self.assertIn(f"agent-{self.uid + 1}.sock", caught.exception.detail or "")
        self.assertEqual(self.agent.mounter.mounted, [], "nothing mounted for them")

    def test_disconnect_does_not_promise_a_remount_that_will_not_happen(self) -> None:
        """D14 with the sign reversed.

        Linux's note warns that the automount is still armed and the share
        comes back the moment anything opens the folder -- true there, and the
        reason the note exists. §6.8 measured macOS refusing to reconnect a
        lost mount at all, which is why the agent exists. Repeating the Linux
        sentence here would promise the opposite of what happens.
        """
        note = self.call("connection.disconnect", ref="nas-media")["note"]
        self.assertIn("will not mount it again", note)
        self.assertNotIn("as soon as anything opens", note)

    def test_disconnect_reports_that_nothing_was_mounted(self) -> None:
        self.agent.mounter.unmount_result = False
        result = self.call("connection.disconnect", ref="nas-media")
        self.assertFalse(result["unmounted"])
        self.assertIn("nothing changed", result["note"])

    def test_with_no_agent_configured_nothing_changes_on_linux(self) -> None:
        # The systemd path is untouched when `agents` is None, which is every
        # platform but macOS. The guard is the first line of both handlers.
        self.assertIsNone(Dispatcher(self.store).agents)


class TestTheUrlCarriesNothingItNeedNot(unittest.TestCase):
    def test_host_and_share_only(self) -> None:
        self.assertEqual(
            _smb_url({"host": "nas.local", "share": "Media"}), "smb://nas.local/Media"
        )

    def test_a_share_name_with_a_space_is_encoded(self) -> None:
        # `netfs.mount` refuses a string CoreFoundation cannot parse, before it
        # touches the network -- so this would fail as "not a URL" and say
        # nothing about the share.
        self.assertEqual(
            _smb_url({"host": "nas.local", "share": "My Share"}),
            "smb://nas.local/My%20Share",
        )

    def test_an_ipv6_literal_is_bracketed(self) -> None:
        self.assertEqual(
            _smb_url({"host": "2001:db8::1", "share": "Media"}),
            "smb://[2001:db8::1]/Media",
        )

    def test_no_credential_is_in_it(self) -> None:
        # §3.2 ruled out `mount_smbfs` because it takes the password in the URL.
        # NetFS takes both as arguments, so the URL has no reason to carry one.
        url = _smb_url({"host": "nas.local", "share": "Media"})
        self.assertNotIn("@", url)


class TestRootMayAskTheAgent(unittest.TestCase):
    """The one authorisation change this link required.

    Root arrives because the daemon is root. Admitting it is not a hole: root
    can `launchctl asuser` into the session and run anything in it, including
    something that reads the Keychain, so refusing here protects nothing and
    leaves the daemon unable to mount. Every other uid stays refused.
    """

    def setUp(self) -> None:
        self.dispatcher = AgentDispatcher(uid=501, mounter=FakeMounter())

    def test_the_owner_and_root_may(self) -> None:
        self.assertTrue(self.dispatcher._may(501))
        self.assertTrue(self.dispatcher._may(0))

    def test_and_nobody_else(self) -> None:
        for uid in (1, 502, 99, 65534):
            with self.subTest(uid=uid):
                self.assertFalse(self.dispatcher._may(uid))


if __name__ == "__main__":
    unittest.main()
