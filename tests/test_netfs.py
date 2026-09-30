"""The macOS mount mechanism (D13), and the half of it that tests on Linux.

The suite runs on `ubuntu-latest`, so everything here that needs the frameworks
says so and skips. What does *not* need them is the part most likely to rot:
the numbers, and the sentences they carry.
"""

from __future__ import annotations

import errno
import sys
import unittest

from smbpal.mounts import netfs
from smbpal.state import translate

darwin_only = unittest.skipUnless(
    sys.platform == "darwin", "NetFS is macOS only; the frameworks are not here"
)


class TestItImportsAnywhere(unittest.TestCase):
    """CI is Linux and this module is macOS. Importing must still be free.

    The frameworks load at first call rather than at import for exactly this
    reason, and a regression would not be subtle -- it would be the whole test
    suite failing to collect.
    """

    def test_importing_does_not_load_a_framework(self) -> None:
        self.assertEqual(netfs.available(), sys.platform == "darwin")

    @unittest.skipIf(sys.platform == "darwin", "this is the not-macOS case")
    def test_calling_on_linux_says_what_is_wrong_and_what_to_use(self) -> None:
        with self.assertRaises(netfs.NetFSError) as caught:
            netfs.mount("smb://nas.example/Media")
        self.assertIn("macOS only", caught.exception.message)
        self.assertIn("mount.cifs", caught.exception.detail)


class TestTheNumbersAreThisPlatforms(unittest.TestCase):
    def test_the_table_uses_symbols_because_it_must(self) -> None:
        """The macOS table cannot be Linux's re-keyed, and here is why.

        `EAUTH` and `ENEEDAUTH` are BSD extensions Linux has no name for, so
        `errno.EAUTH` raises `AttributeError` there. That is what makes this
        a second table rather than the first one rearranged, and it is the
        refinement §6.9 needed after an authenticated NetFS call returned 80.
        """
        self.assertFalse(hasattr(errno, "EAUTH") and sys.platform == "linux")
        # Whatever this platform calls them, the table holds no None key.
        self.assertNotIn(None, netfs._STATUS)

    def test_an_osstatus_is_reported_as_itself_not_guessed_at(self) -> None:
        # NetFS.h documents negative OSStatus values. We have never seen one,
        # so the honest answer is the number rather than an invented meaning.
        state, message, retryable = netfs.describe(-5045)
        self.assertEqual(state, "failed")
        self.assertIn("-5045", message)
        self.assertIn("macOS status", message)
        self.assertTrue(retryable)

    def test_an_unknown_positive_status_still_says_something(self) -> None:
        _state, message, _retryable = netfs.describe(9999)
        self.assertIn("9999", message)


class TestOneCauseSaysOneThing(unittest.TestCase):
    """D14, applied across a platform boundary.

    The numbers differ -- `ECONNREFUSED` is 111 on Linux and 61 on macOS -- and
    the *words* must not, because somebody reading them on two machines is
    reading about one thing. Nothing enforces that except this, so drift is a
    failing test rather than something noticed in a screenshot a year later.
    """

    def assert_same_sentence(self, linux_errno: int, symbol: str) -> None:
        theirs = translate._LINUX_MOUNT_ERRNO[linux_errno]
        ours = netfs._STATUS[getattr(errno, symbol)]
        self.assertEqual(ours[0], theirs[0], f"{symbol}: state differs")
        self.assertEqual(ours[1], theirs[1], f"{symbol}: message differs")
        self.assertEqual(ours[2], theirs[2], f"{symbol}: retryable differs")

    def test_a_refused_connection_reads_the_same_on_both(self) -> None:
        # The D14 message in full, including "smbpal status on that machine",
        # which is as true from macOS as from Linux.
        self.assert_same_sentence(111, "ECONNREFUSED")

    def test_so_do_the_other_network_failures(self) -> None:
        for linux_errno, symbol in (
            (110, "ETIMEDOUT"),
            (112, "EHOSTDOWN"),
            (113, "EHOSTUNREACH"),
            (101, "ENETUNREACH"),
        ):
            with self.subTest(symbol=symbol):
                self.assert_same_sentence(linux_errno, symbol)

    def test_and_the_two_that_coincide_by_accident(self) -> None:
        # 1 to 34 are fixed by POSIX, which is why these two numbers match
        # across the platforms while none of the above do.
        self.assert_same_sentence(13, "EACCES")
        self.assert_same_sentence(2, "ENOENT")


@darwin_only
class TestAgainstTheRealFrameworks(unittest.TestCase):
    """No network, no credential, no mount. Only that the glue holds.

    A live mount needs a server and a password and belongs in
    `phase-2/netfs-mount.py`, which is where it was proven on 30 September
    2026. What is worth having in the suite is the part that breaks silently:
    building CoreFoundation objects and releasing them.
    """

    def test_a_malformed_url_is_refused_before_anything_is_attempted(self) -> None:
        with self.assertRaises(netfs.NetFSError) as caught:
            netfs.mount("not a url at all")
        self.assertIn("not a URL", caught.exception.message)

    def test_remount_url_of_something_unmounted_is_none_not_a_crash(self) -> None:
        self.assertIsNone(netfs.remount_url("file:///nonexistent-smbpal-test"))

    def test_the_frameworks_load_once_and_are_reused(self) -> None:
        first = netfs._frameworks()
        self.assertIs(first, netfs._frameworks())
        self.assertIn("NetFSMountURLSync", dir(first["netfs"]))


if __name__ == "__main__":
    unittest.main()
