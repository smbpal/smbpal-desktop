"""The `helper` policy: macOS's answer to *may act*, and the only one where the
daemon is not the authority.

§10 put the verify in the privileged helper because §9 established that
`smbpald` is admin-writable code. So what is asserted here is that the daemon
relays and does not decide -- and that a method with no grant yet is told what
to acquire rather than simply refused.
"""

from __future__ import annotations

import unittest
from typing import Any

from smbpal.daemon.handlers import Authoriser
from smbpal.daemon import polkit
from smbpal.errors import NeedsAuthorisation, NotPermitted
from smbpal.ipc.peer import PeerCredentials
from smbpal.system import authorization


class Recorder:
    """A stand-in for the helper. Records what it was asked, answers as told."""

    def __init__(self, answer: bool = True, *, there: bool = True) -> None:
        self.answer = answer
        self.there = there
        self.asked: list[tuple[str, bytes]] = []
        self.path = "/var/run/smbpal/helper.sock"

    def available(self) -> bool:
        return self.there

    def check(self, right: str, auth: bytes) -> bool:
        self.asked.append((right, auth))
        return self.answer


def peer(uid: int = 501) -> PeerCredentials:
    return PeerCredentials(uid=uid, gid=20, pid=None)


class TestTheTablesAgree(unittest.TestCase):
    def test_every_polkit_action_has_a_macos_right(self) -> None:
        """So the `None` branch in `check` is a backstop and not the plan."""
        for action in polkit.ACTIONS:
            with self.subTest(action=action):
                self.assertIn(action, Authoriser.MACOS_RIGHTS)

    def test_every_mutating_method_reaches_a_right(self) -> None:
        for method, action in Authoriser.ACTIONS.items():
            with self.subTest(method=method):
                self.assertIn(Authoriser.MACOS_RIGHTS[action], (*authorization.RIGHTS, *authorization.UNPROMPTED))

    def test_macos_is_the_default_on_darwin_and_nowhere_else(self) -> None:
        self.assertEqual(Authoriser.DEFAULT_POLICY, {"darwin": "helper"})


class TestWhatTheDaemonDoesWithAGrant(unittest.TestCase):
    def authoriser(self, **kwargs: Any) -> tuple[Authoriser, Recorder]:
        checker = Recorder(**kwargs)
        return Authoriser(policy="helper", checker=checker), checker

    def test_a_mutation_with_no_grant_names_the_right_to_acquire(self) -> None:
        """`NeedsAuthorisation`, not `NotPermitted`. "You may not" and "ask the
        person first" are different answers, and the mapping from method to
        right stays here so no client keeps a second copy of it."""
        auth, checker = self.authoriser()
        with self.assertRaises(NeedsAuthorisation) as caught:
            auth.check(peer(), "share.add")
        self.assertEqual(caught.exception.right, authorization.MANAGE_SHARES)
        self.assertEqual(checker.asked, [])

    def test_a_grant_is_relayed_untouched(self) -> None:
        auth, checker = self.authoriser()
        form = bytes(range(32))
        auth.check(peer(), "share.add", form)
        self.assertEqual(checker.asked, [(authorization.MANAGE_SHARES, form)])

    def test_the_helpers_no_is_final(self) -> None:
        auth, _ = self.authoriser(answer=False)
        with self.assertRaises(NotPermitted):
            auth.check(peer(), "share.add", bytes(32))

    def test_connections_use_their_own_right(self) -> None:
        auth, checker = self.authoriser()
        auth.check(peer(), "connection.add", bytes(32))
        self.assertEqual(checker.asked[0][0], authorization.MANAGE_CONNECTIONS)

    def test_using_a_connection_asks_for_nothing(self) -> None:
        """`allow_active yes` on Linux, and no privilege here at all: the mount
        is the user's own agent acting as itself, so there is no right
        registered and nothing to check against."""
        auth, checker = self.authoriser()
        auth.check(peer(), "connection.connect", None)
        self.assertEqual(checker.asked, [])

    def test_a_read_is_never_authorised(self) -> None:
        auth, checker = self.authoriser()
        auth.check(peer(), "status")
        self.assertEqual(checker.asked, [])

    def test_root_is_let_past_before_the_helper_is_asked(self) -> None:
        """Root can already do all of this with an editor, and the package's own
        teardown runs as root while the installer holds the machine."""
        auth, checker = self.authoriser()
        auth.check(peer(uid=0), "share.add")
        self.assertEqual(checker.asked, [])


class TestTheStartupNoteSaysWhatIsInForce(unittest.TestCase):
    def test_it_names_the_socket_when_the_helper_is_there(self) -> None:
        auth = Authoriser(policy="helper", checker=Recorder())
        self.assertIn("/var/run/smbpal/helper.sock", auth.policy_note())

    def test_a_missing_helper_is_announced_as_refusing_everything(self) -> None:
        """The property that mattered about `polkit, via NOT FOUND`: the daemon
        says which rules are in force, including when the answer is none."""
        auth = Authoriser(policy="helper", checker=Recorder(there=False))
        note = auth.policy_note()
        self.assertIn("NOT RUNNING", note)
        self.assertIn("smbpal setup", note)
