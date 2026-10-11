"""The client half of §10: prompting, and everything that must not prompt.

**The grant itself is not tested and cannot be.** It needs an administrator
standing at the machine typing a password into SecurityAgent, which is the point
of it. What is testable is every path that returns without asking, and those are
the ones that would silently disable the gate if they were wrong.
"""

from __future__ import annotations

import sys
import unittest
from unittest import mock

from smbpal.system import authorization


class TestTheRightsAreClosed(unittest.TestCase):
    def test_an_unknown_right_is_not_passed_to_the_system(self) -> None:
        """Asking the database about a right SMBPal never registered gets an
        answer -- the fallback `default` rule -- about nothing of ours."""
        with self.assertRaises(authorization.AuthorizationError) as caught:
            authorization.grant("app.smbpal.invent-a-right")
        self.assertIn("unknown right", str(caught.exception))

    def test_use_connections_is_not_a_right_that_can_be_prompted_for(self) -> None:
        with self.assertRaises(authorization.AuthorizationError):
            authorization.grant(authorization.USE_CONNECTIONS)


class TestNothingPromptsWhenItShouldNot(unittest.TestCase):
    def test_use_connections_needs_no_grant(self) -> None:
        """`allow_active yes` on Linux, and no privilege at all here: the mount
        is the user's own agent acting as themselves."""
        self.assertIsNone(authorization.grant_for(authorization.USE_CONNECTIONS))

    def test_root_is_never_prompted(self) -> None:
        """`handlers.py` lets uid 0 past before a checker is consulted, so a
        client under `sudo` has nothing to ask for -- and a dialog there would be
        a question with no consequence attached to either answer.

        It also keeps the one behaviour §10 left unmeasured out of the way:
        whether an *imported* form honours a right's `allow-root`. Nothing root
        does reaches a form at all.
        """
        with mock.patch("os.geteuid", return_value=0):
            self.assertIsNone(authorization.grant_for(authorization.MANAGE_SHARES))

    def test_an_ordinary_user_is_not_short_circuited(self) -> None:
        """The mirror of the test above: if `grant_for` returned `None` for
        everyone, every mutation would be unauthorised and look authorised."""
        sentinel = object()
        with mock.patch("os.geteuid", return_value=501):
            with mock.patch.object(authorization, "grant", return_value=sentinel) as asked:
                self.assertIs(
                    authorization.grant_for(authorization.MANAGE_SHARES), sentinel
                )
            asked.assert_called_once_with(authorization.MANAGE_SHARES)


class TestAGrantDiesWithItsReference(unittest.TestCase):
    """**Measured, 11 October 2026, and it was a bug in this module.**

    `AuthorizationFree` on the creating reference is enough to make
    `AuthorizationCreateFromExternalForm` reject the form: verify returned 0 and
    `allowed` with the reference alive, and `did not import` one `Free` later,
    same bytes, same process. The first version of `grant` freed in a `finally`
    and returned the form, so every grant it issued was already dead.

    These tests hold the invariant without needing a prompt: a closed grant must
    refuse to hand out bytes rather than hand out bytes that cannot work.
    """

    def grant(self) -> authorization.Grant:
        return authorization.Grant(authorization.MANAGE_SHARES, object(), b"\x01" * 32)

    def test_an_open_grant_hands_over_the_form(self) -> None:
        self.assertEqual(len(self.grant().form), authorization.EXTERNAL_FORM_LENGTH)

    def test_a_closed_grant_refuses_rather_than_returning_dead_bytes(self) -> None:
        held = self.grant()
        with mock.patch.object(authorization, "_security"):
            held.close()
        with self.assertRaises(authorization.AuthorizationError) as caught:
            held.form
        self.assertIn("does not outlive", str(caught.exception.detail))

    def test_closing_twice_frees_once(self) -> None:
        """A double free in the one component whose job is authorisation is not
        a tidy-up question."""
        held = self.grant()
        with mock.patch.object(authorization, "_security") as sec:
            held.close()
            held.close()
        self.assertEqual(sec.return_value.AuthorizationFree.call_count, 1)

    def test_closing_does_not_destroy_the_cached_credential(self) -> None:
        """Flag 0, not `kAuthorizationFlagDestroyRights`. Destroying would make
        the next mutation in one intention prompt again, which is exactly what
        the right's timeout exists to prevent."""
        held = self.grant()
        with mock.patch.object(authorization, "_security") as sec:
            held.close()
        _ref, flags = sec.return_value.AuthorizationFree.call_args.args
        self.assertEqual(flags, 0)

    def test_it_is_a_context_manager(self) -> None:
        held = self.grant()
        with mock.patch.object(authorization, "_security"):
            with held as inner:
                self.assertIs(inner, held)
        with self.assertRaises(authorization.AuthorizationError):
            held.form


class TestItIsMacOsOnly(unittest.TestCase):
    def test_a_non_darwin_platform_says_so_rather_than_crashing(self) -> None:
        with mock.patch.object(authorization.sys, "platform", "linux"):
            self.assertFalse(authorization.available())
            with mock.patch.dict(authorization._loaded, {}, clear=True):
                with self.assertRaises(authorization.AuthorizationError) as caught:
                    authorization._security()
        self.assertIn("polkit", str(caught.exception.detail))


@unittest.skipUnless(sys.platform == "darwin", "Security.framework is macOS only")
class TestTheFrameworkBinds(unittest.TestCase):
    def test_every_entry_point_resolves(self) -> None:
        """§10 recorded all five resolving on 11 October 2026. This is that
        claim as a test, so an SDK that drops one is a failure and not a
        surprise at the first prompt."""
        sec = authorization._security()
        for name in (
            "AuthorizationCreate",
            "AuthorizationCopyRights",
            "AuthorizationMakeExternalForm",
            "AuthorizationCreateFromExternalForm",
            "AuthorizationFree",
        ):
            self.assertTrue(hasattr(sec, name), name)
