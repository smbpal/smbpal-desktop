"""The per-user agent: what it answers, and who it refuses.

The mounting itself is faked throughout. `test_netfs` covers the mechanism and
a live mount needs a server and a password, so what is worth testing here is
the part that is the agent's own: the four methods, and the one-line
authorisation that replaces the daemon's polkit.
"""

from __future__ import annotations

import os
import sys
import unittest
from typing import Any

from smbpal.agent.handlers import AgentDispatcher
from smbpal.agent.main import build_parser, default_socket_path, main
import json

from smbpal.ipc.peer import PeerCredentials


class FakeMounter:
    """Stands in for `netfs`, and records what it was handed."""

    def __init__(self) -> None:
        self.mounted: list[tuple[str, str | None, str | None]] = []
        self.unmounted: list[str] = []

    def mount(self, url: str, *, user: str | None = None,
              password: str | None = None) -> str:
        self.mounted.append((url, user, password))
        return "/Volumes/Media"

    def unmount(self, mountpoint: str, *, force: bool = False) -> None:
        self.unmounted.append(mountpoint)

    def remount_url(self, mountpoint: str) -> str | None:
        return "smb://nas.example/Media" if mountpoint == "/Volumes/Media" else None


class FakeConnection:
    def __init__(self, uid: int) -> None:
        self.peer = PeerCredentials(uid=uid, gid=20)

    def send(self, payload: bytes) -> None:  # pragma: no cover - unused
        raise AssertionError("the agent answers by return, not by push")


class AgentTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.mounter = FakeMounter()
        self.dispatcher = AgentDispatcher(uid=501, mounter=self.mounter)

    def call(self, method: str, uid: int = 501, **params: Any) -> dict[str, Any]:
        frame = json.dumps(
            {"v": 1, "id": "1", "method": method, "params": params}
        ).encode() + b"\n"
        reply = self.dispatcher.handle(FakeConnection(uid), frame)
        assert reply is not None
        return json.loads(reply.decode())


class TestTheFourMethods(AgentTestCase):
    def test_ping_says_whether_this_platform_can_mount(self) -> None:
        reply = self.call("agent.ping")
        self.assertTrue(reply["result"]["ok"])
        self.assertEqual(reply["result"]["uid"], 501)
        self.assertEqual(
            reply["result"]["platform_supported"], sys.platform == "darwin"
        )

    def test_mount_passes_the_credential_straight_through(self) -> None:
        reply = self.call(
            "agent.mount",
            url="smb://nas.example/Media",
            user="pi",
            password="throwaway",
        )
        self.assertEqual(reply["result"]["mountpoint"], "/Volumes/Media")
        self.assertEqual(
            self.mounter.mounted, [("smb://nas.example/Media", "pi", "throwaway")]
        )

    def test_a_mount_without_credentials_is_allowed(self) -> None:
        # Guest shares, and a share whose password the Keychain already holds.
        self.call("agent.mount", url="smb://nas.example/Public")
        self.assertEqual(self.mounter.mounted[0][1:], (None, None))

    def test_unmount_and_remount_url(self) -> None:
        self.call("agent.unmount", mountpoint="/Volumes/Media")
        self.assertEqual(self.mounter.unmounted, ["/Volumes/Media"])
        reply = self.call("agent.remount_url", mountpoint="/Volumes/Media")
        self.assertEqual(reply["result"]["url"], "smb://nas.example/Media")

    def test_remount_url_of_something_unknown_is_null_not_an_error(self) -> None:
        reply = self.call("agent.remount_url", mountpoint="/Volumes/Gone")
        self.assertIsNone(reply["result"]["url"])


class TestItServesExactlyOnePerson(AgentTestCase):
    """The daemon has polkit because it acts for everyone. This does not.

    It runs in one session and can read one Keychain, so the only question is
    whether the caller is that person -- and `ipc/peer.py` answers it from the
    kernel rather than from anything in the message.
    """

    def test_another_uid_is_refused(self) -> None:
        reply = self.call("agent.mount", uid=502, url="smb://nas.example/Media")
        self.assertEqual(reply["error"]["code"], "not_yours")
        self.assertEqual(self.mounter.mounted, [], "nothing was mounted for them")

    def test_the_refusal_says_both_uids_because_that_is_the_whole_answer(self) -> None:
        reply = self.call("agent.ping", uid=502)
        self.assertIn("501", reply["error"]["detail"])
        self.assertIn("502", reply["error"]["detail"])

    def test_an_unknown_method_is_unknown_before_it_is_unauthorised(self) -> None:
        # The daemon's rule, for the daemon's reason: answering "not yours" for
        # a method that does not exist sends somebody hunting a permission
        # problem they do not have.
        reply = self.call("agent.explode", uid=502)
        self.assertEqual(reply["error"]["code"], "unknown_method")


class TestTheEntryPoint(unittest.TestCase):
    def test_the_socket_is_per_user_and_not_in_tmp(self) -> None:
        path = default_socket_path()
        self.assertIn(str(Path_home := os.path.expanduser("~")), str(path))
        self.assertTrue(str(path).endswith("SMBPal/agent.sock"))
        self.assertNotIn("/tmp", str(path))
        del Path_home

    def test_check_reports_the_platform_and_sets_the_exit_code(self) -> None:
        code = main(["--check"])
        self.assertEqual(code, 0 if sys.platform == "darwin" else 1)

    @unittest.skipIf(sys.platform == "darwin", "this is the not-macOS case")
    def test_on_linux_it_says_what_is_wrong_and_what_runs_instead(self) -> None:
        self.assertEqual(main([]), 1)

    def test_version_is_the_one_number(self) -> None:
        self.assertEqual(main(["--version"]), 0)

    def test_the_parser_takes_a_socket_override(self) -> None:
        args = build_parser().parse_args(["--socket", "/tmp/x.sock"])
        self.assertEqual(str(args.socket), "/tmp/x.sock")


if __name__ == "__main__":
    unittest.main()
