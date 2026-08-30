"""Authorisation: the action table, the shipped policy file, and asking polkit.

D4 says *may talk is not may act*, and from M2 until 30 August 2026 the daemon
only answered the first half. These tests are the second half. They are split
three ways on purpose:

- the **table** is where a new method gets forgotten,
- the **policy file** is where the answer to a prompt is actually decided, and
  it is XML that nothing else in the project reads,
- **asking** is the part with a subprocess, a timeout and a pid in it.

Nothing here needs polkit installed. A test that only ran where polkit exists
would not run on the machine this is written on, which is where the mistakes
are made.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from smbpal.daemon import polkit
from smbpal.daemon.handlers import Authoriser, _METHODS
from smbpal.errors import NotPermitted
from smbpal.ipc.peer import PeerCredentials

POLICY_FILE = Path(__file__).resolve().parent.parent / "packaging/polkit/org.smbpal.policy"


class NeverAsked:
    """A checker that fails the test by being used."""

    def __init__(self) -> None:
        self.calls = 0

    def check(self, peer: PeerCredentials, action: str) -> bool:
        self.calls += 1
        return True


class TestTheActionTable(unittest.TestCase):
    """Every method is read-only or has an action, and nothing is both."""

    def test_every_method_is_classified(self) -> None:
        classified = Authoriser.READ_ONLY | set(Authoriser.ACTIONS)
        missing = set(_METHODS) - classified
        extra = classified - set(_METHODS)
        self.assertEqual(
            (missing, extra),
            (set(), set()),
            "a method is in the dispatch table and not in the authoriser, or "
            "the other way round",
        )

    def test_nothing_is_both_read_only_and_mutating(self) -> None:
        self.assertEqual(Authoriser.READ_ONLY & set(Authoriser.ACTIONS), set())

    def test_every_action_used_is_one_that_exists(self) -> None:
        self.assertEqual(
            set(Authoriser.ACTIONS.values()) - set(polkit.ACTIONS), set()
        )

    def test_every_action_that_exists_is_used(self) -> None:
        """An action nobody asks for is one nobody can grant, and it would still
        appear in a user's list of things they can authorise."""
        self.assertEqual(
            set(polkit.ACTIONS) - set(Authoriser.ACTIONS.values()), set()
        )

    def test_a_mutating_method_with_no_action_is_refused(self) -> None:
        """The backstop under the test above, for when someone adds a method
        and the table test is the thing they run last."""
        checker = NeverAsked()
        authoriser = Authoriser(policy="polkit", checker=checker)
        with self.assertRaises(NotPermitted):
            authoriser.check(PeerCredentials(uid=1000, gid=1000, pid=1), "share.explode")
        self.assertEqual(checker.calls, 0)

    def test_root_is_never_put_to_polkit(self) -> None:
        """`prerm` runs `smbpal teardown` as root while dpkg holds the machine.
        A prompt there is a package removal hanging on a dialog nobody is
        looking at, on a session that may not exist."""
        checker = NeverAsked()
        authoriser = Authoriser(policy="polkit", checker=checker)
        authoriser.check(PeerCredentials(uid=0, gid=0, pid=1), "teardown")
        self.assertEqual(checker.calls, 0)

    def test_the_insecure_policy_says_so_where_it_will_be_seen(self) -> None:
        note = Authoriser(policy="group").policy_note()
        self.assertIn("INSECURE", note)

    def test_an_unknown_policy_is_refused_at_construction(self) -> None:
        """Not at the first request, when the daemon is already listening."""
        with self.assertRaises(ValueError):
            Authoriser(policy="permissive")


class TestTheShippedPolicyFile(unittest.TestCase):
    """The XML polkit reads. Nothing else in the project parses it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.root = ET.parse(POLICY_FILE).getroot()
        cls.actions = {a.get("id"): a for a in cls.root.findall("action")}

    def test_it_declares_exactly_the_actions_the_daemon_asks_about(self) -> None:
        self.assertEqual(set(self.actions), set(polkit.ACTIONS))

    def test_every_action_has_something_to_show_a_person(self) -> None:
        """`message` is the sentence in the password dialog. An action without
        one gets a generic prompt, which is how a user ends up authorising
        something the box did not describe."""
        for action_id, action in self.actions.items():
            with self.subTest(action=action_id):
                for tag in ("description", "message"):
                    text = action.findtext(tag)
                    self.assertTrue(text and text.strip(), f"{action_id} has no {tag}")

    def test_no_action_is_granted_to_a_remote_or_inactive_session(self) -> None:
        """`allow_any` and `allow_inactive` cover somebody who is not sitting at
        the machine. Nothing SMBPal does is safe to hand out on that basis."""
        for action_id, action in self.actions.items():
            defaults = action.find("defaults")
            assert defaults is not None
            for tag in ("allow_any", "allow_inactive"):
                with self.subTest(action=action_id, default=tag):
                    self.assertEqual(defaults.findtext(tag), "auth_admin")

    def test_only_using_a_connection_is_free_at_the_console(self) -> None:
        """The one `yes` in the file, and the reason is in a comment beside it:
        the automount already mounts on any user's `ls`, so a prompt on the
        button would guard nothing and devalue the prompts that do."""
        granted = {
            action_id
            for action_id, action in self.actions.items()
            if action.findtext("defaults/allow_active") == "yes"
        }
        self.assertEqual(granted, {polkit.USE_CONNECTIONS})

    def test_configuring_the_machine_always_authenticates(self) -> None:
        for action_id in (polkit.MANAGE_SHARES, polkit.MANAGE_CONNECTIONS):
            with self.subTest(action=action_id):
                self.assertEqual(
                    self.actions[action_id].findtext("defaults/allow_active"),
                    "auth_admin_keep",
                )


class TestStartTime(unittest.TestCase):
    def stat_line(self, comm: str, starttime: int) -> bytes:
        fields = [str(n) for n in range(3, 23)]
        fields[22 - 3] = str(starttime)
        return (f"1234 ({comm}) " + " ".join(fields) + "\n").encode()

    def parse(self, raw: bytes) -> int:
        with mock.patch("builtins.open", mock.mock_open(read_data=raw)):
            return polkit.start_time(1234)

    def test_it_reads_field_22(self) -> None:
        self.assertEqual(self.parse(self.stat_line("smbpal-gui", 987654)), 987654)

    def test_a_process_cannot_name_itself_into_a_different_start_time(self) -> None:
        """Field 2 is the executable name and the kernel does not escape it. A
        program is free to call itself `x) 1 2 3 4` — and if this were parsed by
        splitting on spaces, it would be choosing its own answer here, which is
        the whole identity of the subject polkit is asked about."""
        self.assertEqual(self.parse(self.stat_line("x) 1 2 3 4 5", 555)), 555)

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs /proc")
    def test_it_works_on_this_process(self) -> None:
        self.assertGreater(polkit.start_time(os.getpid()), 0)


class TestAskingPkcheck(unittest.TestCase):
    """The subprocess, with a `pkcheck` we wrote. Never the real one: a test
    that depended on the machine's polkit policy would pass or fail for reasons
    that have nothing to do with this code."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.tmp = Path(self._dir.name)
        self.argv = self.tmp / "argv"
        self.peer = PeerCredentials(uid=1000, gid=1000, pid=4242)
        patcher = mock.patch.object(polkit, "start_time", return_value=99)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake(self, body: str) -> str:
        path = self.tmp / "pkcheck"
        path.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" > "{self.argv}"\n{body}\n')
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)

    def test_exit_zero_is_a_yes(self) -> None:
        checker = polkit.Polkit(pkcheck=self.fake("exit 0"))
        self.assertTrue(checker.check(self.peer, polkit.MANAGE_SHARES))

    def test_exit_one_is_a_no(self) -> None:
        checker = polkit.Polkit(pkcheck=self.fake("exit 1"))
        self.assertFalse(checker.check(self.peer, polkit.MANAGE_SHARES))

    def test_any_other_exit_is_also_a_no(self) -> None:
        """'Not authorised', 'the user closed the dialog' and 'polkit is broken'
        are the same answer to the question that was asked. A caller able to
        tell them apart would eventually treat one of them as a yes."""
        for code in (2, 3, 127):
            with self.subTest(code=code):
                checker = polkit.Polkit(pkcheck=self.fake(f"exit {code}"))
                self.assertFalse(checker.check(self.peer, polkit.MANAGE_SHARES))

    def test_a_missing_pkcheck_is_a_no(self) -> None:
        checker = polkit.Polkit(pkcheck=str(self.tmp / "not-installed"))
        self.assertFalse(checker.check(self.peer, polkit.MANAGE_SHARES))

    def test_an_answer_that_never_comes_is_a_no(self) -> None:
        """Someone walked away from the password dialog. The client is blocked
        on this and the thread is held for as long as it takes, so it has to
        end by itself."""
        checker = polkit.Polkit(pkcheck=self.fake("sleep 5"), timeout=0.3)
        self.assertFalse(checker.check(self.peer, polkit.MANAGE_SHARES))

    def test_the_subject_is_pid_start_time_and_uid(self) -> None:
        checker = polkit.Polkit(pkcheck=self.fake("exit 0"))
        checker.check(self.peer, polkit.MANAGE_SHARES)
        argv = self.argv.read_text()
        self.assertIn("4242,99,1000", argv)
        self.assertIn(polkit.MANAGE_SHARES, argv)

    def test_it_asks_for_the_password_dialog(self) -> None:
        checker = polkit.Polkit(pkcheck=self.fake("exit 0"))
        checker.check(self.peer, polkit.MANAGE_SHARES)
        self.assertIn("--allow-user-interaction", self.argv.read_text())

    def test_interaction_can_be_turned_off(self) -> None:
        checker = polkit.Polkit(pkcheck=self.fake("exit 0"), allow_interaction=False)
        checker.check(self.peer, polkit.MANAGE_SHARES)
        self.assertNotIn("--allow-user-interaction", self.argv.read_text())

    def test_nothing_secret_is_ever_on_the_command_line(self) -> None:
        """§2's rule, applied here because this is the only place the daemon
        execs anything with the peer's identity in it. `sudo` and the audit log
        record argv verbatim for anyone in `adm` to read."""
        checker = polkit.Polkit(pkcheck=self.fake("exit 0"))
        checker.check(self.peer, polkit.MANAGE_SHARES)
        words = self.argv.read_text().split()
        self.assertEqual(
            set(words),
            {
                "--action-id",
                polkit.MANAGE_SHARES,
                "--process",
                "4242,99,1000",
                "--allow-user-interaction",
            },
        )

    def test_a_peer_with_no_pid_is_a_no(self) -> None:
        """macOS `getpeereid` gives uid and gid only, so no subject can be
        built. The development fallback says so rather than inventing one."""
        checker = polkit.Polkit(pkcheck=self.fake("exit 0"))
        self.assertFalse(
            checker.check(PeerCredentials(uid=1000, gid=1000), polkit.MANAGE_SHARES)
        )
        self.assertFalse(self.argv.exists())

    def test_a_process_that_has_gone_is_a_no(self) -> None:
        with mock.patch.object(polkit, "start_time", side_effect=FileNotFoundError):
            checker = polkit.Polkit(pkcheck=self.fake("exit 0"))
            self.assertFalse(checker.check(self.peer, polkit.MANAGE_SHARES))
        self.assertFalse(self.argv.exists())


if __name__ == "__main__":
    unittest.main()
